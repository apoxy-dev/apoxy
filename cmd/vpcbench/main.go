// SPDX-License-Identifier: AGPL-3.0-only

// Command vpcbench measures TCP flows between two VPC agents, through a v2
// relay or directly. The relay makes a CA and serves relay sessions with test
// fakes, with no apiserver. The server and the client get the CA on the
// control port of the relay. The client prints one JSON line that "perfrig run
// -workload exec" reads. The relay is the sidecar of the server. perfrig stops
// it after the server exits:
//
//	perfrig run -workload exec -name vpc-netstack-psp -ready tcp:4433 -streams 4 -omit 5s -duration 30s \
//	  -sidecar-argv '["vpcbench","relay","-listen","$RELAY_IP:4443"]' \
//	  -server-argv '["vpcbench","server","-relay","$RELAY_IP:4443","-listen","$SERVER_IP:4433"]' \
//	  -client-argv '["vpcbench","client","-relay","$RELAY_IP:4443","-server","$SERVER_IP:4433","-cc","bbr","-streams","$STREAMS","-omit","${OMIT_S}s","-duration","${DURATION_S}s"]'
//
// With -stop-relay, the client stops the relay at the end. "perfrig node" uses
// it when the relay runs on its own host.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"

	"github.com/apoxy-dev/apoxy/cmd/internal/bench"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/vpc/agent"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	relayID  = "vpcbench-relay"
	project  = "vpcbench"
	vpcName  = "bench"
	vni      = 0x7662
	sinkPort = 5201
	echoPort = 7
	// callTimeout limits each control call.
	callTimeout = 30 * time.Second
	// echoWait is how long the client waits for the last probe echoes.
	echoWait = time.Second
)

// Overlay addresses of -via direct.
var (
	directClient = netip.MustParseAddr("fd61:706f:7879:12:3400:1::1")
	directServer = netip.MustParseAddr("fd61:706f:7879:12:3400:2::1")
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if len(os.Args) < 2 || (os.Args[1] != "relay" && os.Args[1] != "server" && os.Args[1] != "client") {
		fmt.Fprintln(os.Stderr, "usage: vpcbench relay -listen HOST:PORT [flags]\n"+
			"       vpcbench server -listen HOST:PORT -relay HOST:PORT [flags]\n"+
			"       vpcbench client -server HOST:PORT -relay HOST:PORT [flags]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	o, err := parseFlags(cmd, os.Args[2:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	stopProfiles, err := o.Profiles.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch cmd {
	case "relay":
		err = runRelay(ctx, o, nil)
	case "server":
		err = runServer(ctx, o, nil)
	default:
		err = runClient(ctx, o, os.Stdout)
	}
	if perr := stopProfiles(); perr != nil {
		slog.Warn("Failed to write the profiles", "error", perr)
	}
	if err != nil {
		slog.Error("Benchmark failed", "error", err)
		stop()
		os.Exit(1)
	}
}

// options are the flags of all commands.
type options struct {
	Listen, Relay, Server, WorkDir string
	Driver, Transport, Via, CC     string
	XDP                            string
	MTU, Streams                   int
	Omit, Duration                 time.Duration
	Idle, ProbeInterval            time.Duration
	// StartTimeout limits each wait for the relay, an attach or a peer session.
	StartTimeout time.Duration
	// StopRelay makes the client stop the relay at the end.
	StopRelay bool
	Profiles  bench.Profiles
}

// parseFlags reads the flags of cmd and checks them.
func parseFlags(cmd string, args []string, out io.Writer) (options, error) {
	o := options{WorkDir: os.Getenv("WORK_DIR")}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&o.WorkDir, "work-dir", o.WorkDir, "directory of the CA file and the agent certs (default $WORK_DIR)")
	fs.IntVar(&o.MTU, "mtu", 0, "relay: VPC MTU; agents: device MTU (0 means the default)")
	o.Profiles.AddFlags(fs)
	if cmd != "client" {
		fs.StringVar(&o.Listen, "listen", "", "relay: UDP and TCP control address; server: TCP control address, and UDP with -via direct")
	}
	if cmd == "relay" {
		fs.StringVar(&o.XDP, "xdp", "", "link on which XDP forwards the PSP packets in generic mode, as on ENA; the relay CPU then includes the program run time (empty: the socket forwards them)")
	}
	if cmd != "relay" {
		fs.StringVar(&o.Relay, "relay", "", "relay address host:port")
		fs.StringVar(&o.Driver, "driver", "netstack", "data path driver: netstack or tun")
		fs.StringVar(&o.Transport, "transport", "psp", "data transport through the relay: psp or quic")
		fs.StringVar(&o.Via, "via", "relay", "data path: relay, or direct with no relay and no agent")
		fs.DurationVar(&o.StartTimeout, "start-timeout", 30*time.Second, "time limit of each wait for the relay, the server, an attach or a peer session")
	}
	if cmd == "client" {
		fs.StringVar(&o.Server, "server", "", "server control address host:port")
		fs.StringVar(&o.CC, "cc", "", "TCP congestion control, for example bbr or cubic (default: the stack default)")
		fs.IntVar(&o.Streams, "streams", 4, "parallel TCP flows")
		fs.DurationVar(&o.Omit, "omit", 5*time.Second, "warm-up of the flows before the measurement")
		fs.DurationVar(&o.Duration, "duration", 30*time.Second, "measured time")
		fs.DurationVar(&o.Idle, "idle", time.Second, "RTT probe time before the flows start")
		fs.DurationVar(&o.ProbeInterval, "probe-interval", 10*time.Millisecond, "RTT probe interval")
		fs.BoolVar(&o.StopRelay, "stop-relay", false, "stop the relay at the end of the run")
	}
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	return o, o.check(cmd)
}

func (o options) check(cmd string) error {
	agentCmd := cmd != "relay"
	switch {
	case agentCmd && o.Driver != "netstack" && o.Driver != "tun":
		return fmt.Errorf("unknown -driver %q: want netstack or tun", o.Driver)
	case agentCmd && o.Transport != "psp" && o.Transport != "quic":
		return fmt.Errorf("unknown -transport %q: want psp or quic", o.Transport)
	case agentCmd && o.Via != "relay" && o.Via != "direct":
		return fmt.Errorf("unknown -via %q: want relay or direct", o.Via)
	case o.Via == "direct" && o.Transport == "quic":
		return errors.New("-via direct sends only PSP")
	case cmd != "client" && o.Listen == "":
		return errors.New("-listen is required")
	case cmd == "client" && o.Server == "":
		return errors.New("-server is required")
	case o.Via == "relay" && o.Relay == "":
		return errors.New("-relay is required with -via relay")
	case agentCmd && o.Via == "relay" && o.WorkDir == "":
		return errors.New("set -work-dir or WORK_DIR")
	case agentCmd && o.StartTimeout <= 0:
		return errors.New("-start-timeout must be positive")
	case o.MTU < 0:
		return errors.New("-mtu must not be negative")
	case cmd == "client" && (o.Streams < 1 || o.Duration <= 0 || o.Omit < 0 || o.Idle < 0 || o.ProbeInterval <= 0):
		return errors.New("-streams and -duration must be positive, -omit and -idle must not be negative, and -probe-interval must be positive")
	}
	return nil
}

// overlay is the network of the TCP flows: a netstack, or the kernel through
// a TUN device.
type overlay interface {
	Listen(a netip.AddrPort) (net.Listener, error)
	ListenUDP(a netip.AddrPort) (net.PacketConn, error)
	Dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	DialUDP(dst netip.AddrPort) (net.Conn, error)
	// TCPCounters returns the TCP segments sent and retransmitted.
	TCPCounters() (sent, retrans uint64)
	// LinkDrops returns the packets that the overlay dropped before the
	// driver got them, or -1.
	LinkDrops() int64
	CC() string
	Close()
}

// side is one agent: its binding and the overlay on it.
type side struct {
	a    *agent.Agent // Nil with -via direct.
	uc   *net.UDPConn // The agent socket.
	b    *psp.Binding
	addr netip.Addr // Overlay address.
	net  overlay
	stop []func() // close runs them in reverse order.
}

func (s *side) close() {
	for i := len(s.stop) - 1; i >= 0; i-- {
		s.stop[i]()
	}
	s.stop = nil
}

// startNet runs the driver of o on the binding, with a route to dst.
func (s *side) startNet(ctx context.Context, fail context.CancelCauseFunc, o options, dst netip.Prefix) error {
	slog.Info("Agent socket is ready", "address", s.uc.LocalAddr().String(), "rcvbuf", sockRcvbuf(s.uc))
	ctx, cancel := context.WithCancel(ctx)
	var err error
	if o.Driver == "tun" {
		s.net, err = startTun(ctx, fail, s.b, s.addr, dst, o.CC)
	} else {
		s.net, err = startNetstack(ctx, fail, s.b, s.addr, o.CC)
	}
	if err != nil {
		cancel()
		return err
	}
	s.stop = append(s.stop, func() {
		cancel()
		s.net.Close()
	})
	return nil
}

// startAgent runs an agent that attaches at the relay of o with a cert from
// ca, and starts its driver.
func startAgent(ctx context.Context, fail context.CancelCauseFunc, o options, name string, ca *vpctest.CA) (*side, error) {
	cred := filepath.Join(o.WorkDir, name+"-cred.json")
	// A cert from the CA of an earlier run does not work.
	if err := os.Remove(cred); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	uc, err := listenUDPFor(o.Relay)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: uc}
	s := &side{uc: uc, stop: []func(){func() {
		_ = tr.Close()
		_ = uc.Close()
	}}}
	mode := agent.TransportPSP
	if o.Transport == "quic" {
		mode = agent.TransportQUIC
	}
	var mu sync.Mutex
	attached := make(chan struct{})
	s.a = agent.New(agent.Config{
		Identity: identity.NewManager(cred, func(context.Context) (*identity.Credential, error) {
			return ca.Credential(project, vpcName, name, 24*time.Hour)
		}),
		Relays:        []identity.Relay{{ID: relayID, Addresses: []string{o.Relay}}},
		RelayRoots:    ca.Pool(),
		Sessions:      1,
		Transport:     tr,
		TransportMode: mode,
		Name:          name,
		MTU:           o.MTU,
		OnAttach: func(b *psp.Binding, addr netip.Addr, _ []netip.Prefix) {
			mu.Lock()
			defer mu.Unlock()
			switch {
			case !s.addr.IsValid():
				s.b, s.addr = b, addr
				close(attached)
			case addr != s.addr:
				fail(fmt.Errorf("agent %s attached again with the new address %s", name, addr))
			}
		},
	})
	actx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.a.Run(actx); err != nil && actx.Err() == nil {
			fail(fmt.Errorf("agent %s: %w", name, err))
		}
	}()
	s.stop = append(s.stop, func() {
		cancel()
		<-done
	})
	select {
	case <-attached:
	case <-ctx.Done():
		s.close()
		return nil, context.Cause(ctx)
	case <-time.After(o.StartTimeout):
		s.close()
		return nil, fmt.Errorf("agent %s did not attach in %s", name, o.StartTimeout)
	}
	if err := s.startNet(ctx, fail, o, tunnet.NetworkPrefixOf(s.addr)); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

// listenUDPFor opens an agent socket in the address family of addr.
func listenUDPFor(addr string) (*net.UDPConn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	network := "udp6"
	if ua.IP.To4() != nil {
		network = "udp4"
	}
	return net.ListenUDP(network, nil)
}

// newDirect makes a binding on uc with one peer at peerAddr that routes the
// overlay address peer. It is the -via direct side, with no agent.
func newDirect(o options, uc *net.UDPConn, self, peer netip.Addr, peerAddr netip.AddrPort) (*side, *psp.Peer, error) {
	dm := &psp.Demux{}
	tr := &quic.Transport{Conn: uc, EnableGRO: true, NonQUICPacketHandler: dm.Handle, NonQUICBatchEnd: dm.BatchEnd}
	b, err := psp.New(psp.Config{Transport: tr, Demux: dm, VNI: vni, MTU: o.MTU})
	if err != nil {
		return nil, nil, err
	}
	s := &side{uc: uc, b: b, addr: self, stop: []func(){func() {
		_ = b.Close()
		_ = tr.Close()
	}}}
	p, err := b.AddPeer(peerAddr)
	if err == nil {
		err = b.AddRoute(netip.PrefixFrom(peer, peer.BitLen()), p)
	}
	if err != nil {
		s.close()
		return nil, nil, err
	}
	return s, p, nil
}

func offerKeys(p *psp.Peer) ([]byte, error) {
	req, err := p.Offer(time.Now())
	if err != nil {
		return nil, err
	}
	return proto.Marshal(keyproto.ToProto(req))
}

func applyKeys(p *psp.Peer, b []byte) error {
	var m dp.KeysRequest
	if err := proto.Unmarshal(b, &m); err != nil {
		return err
	}
	req, err := keyproto.FromProto(&m)
	if err != nil {
		return err
	}
	_, err = p.Apply(req, time.Now())
	return err
}

// request is one control message: ca, hello, mark or stop.
type request struct {
	Op   string `json:"op"`
	Port int    `json:"port,omitempty"` // Hello with -via direct: UDP port of the client.
	Keys []byte `json:"keys,omitempty"` // Hello with -via direct: a dp.KeysRequest.
}

// reply answers a request.
type reply struct {
	CA    []byte `json:"ca,omitempty"`   // Ca: the CA cert and key in PEM.
	Addr  string `json:"addr,omitempty"` // Hello: overlay address of the server.
	Keys  []byte `json:"keys,omitempty"`
	Mark  mark   `json:"mark"`
	Error string `json:"error,omitempty"`
}

// ctl is a control connection, with one JSON line each way for each call.
type ctl struct {
	c   net.Conn
	enc *json.Encoder
	dec *json.Decoder
}

func newCtl(c net.Conn) *ctl {
	return &ctl{c: c, enc: json.NewEncoder(c), dec: json.NewDecoder(bufio.NewReader(c))}
}

// dialCtl connects to the control port at addr. It tries again until the
// port opens or timeout ends.
func dialCtl(ctx context.Context, addr string, timeout time.Duration) (*ctl, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	for {
		c, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			return newCtl(c), nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("connect to the control port %s: %w", addr, err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (c *ctl) call(req request) (reply, error) {
	var rep reply
	_ = c.c.SetDeadline(time.Now().Add(callTimeout))
	if err := c.enc.Encode(req); err != nil {
		return rep, fmt.Errorf("send %s to %s: %w", req.Op, c.c.RemoteAddr(), err)
	}
	if err := c.dec.Decode(&rep); err != nil {
		return rep, fmt.Errorf("read the %s reply of %s: %w", req.Op, c.c.RemoteAddr(), err)
	}
	if rep.Error != "" {
		return rep, fmt.Errorf("%s at %s: %s", req.Op, c.c.RemoteAddr(), rep.Error)
	}
	return rep, nil
}

func (c *ctl) mark() (mark, error) {
	rep, err := c.call(request{Op: "mark"})
	return rep.Mark, err
}

// serveCtl answers the requests on c with handle until c closes.
func serveCtl(c net.Conn, handle func(request) (reply, error)) error {
	sc := newCtl(c)
	for {
		var req request
		if err := sc.dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		rep, err := handle(req)
		if err != nil {
			rep.Error = err.Error()
		}
		if err := sc.enc.Encode(rep); err != nil {
			return err
		}
	}
}

// relayCA waits until the relay of o serves its control port, then gets the
// CA from it.
func relayCA(ctx context.Context, o options) (*vpctest.CA, *ctl, error) {
	c, err := dialCtl(ctx, o.Relay, o.StartTimeout)
	if err != nil {
		return nil, nil, err
	}
	rep, err := c.call(request{Op: "ca"})
	var ca *vpctest.CA
	if err == nil {
		ca, err = decodeCA(rep.CA)
	}
	if err != nil {
		_ = c.c.Close()
		return nil, nil, err
	}
	return ca, c, nil
}

// runErr returns the cause of a failed part of the run, else err.
func runErr(ctx context.Context, err error) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return err
}

// serverErr is runErr, but nil after a signal: perfrig stops the server with one.
func serverErr(parent, ctx context.Context, err error) error {
	if parent.Err() != nil {
		return nil
	}
	return runErr(ctx, err)
}

// runServer serves the sink and the echo on its overlay, and answers the
// client on the control port. It returns when the client disconnects.
func runServer(parent context.Context, o options, ready func(netip.AddrPort)) error {
	ctx, fail := context.WithCancelCause(parent)
	defer fail(nil)
	start := time.Now()
	var got atomic.Uint64
	var s *side
	defer func() {
		if s != nil {
			s.close()
		}
	}()
	if o.Via == "relay" {
		ca, c, err := relayCA(ctx, o)
		if err != nil {
			return err
		}
		_ = c.c.Close()
		if s, err = startAgent(ctx, fail, o, "server", ca); err != nil {
			return serverErr(parent, ctx, err)
		}
		if err := serveSinks(s, &got); err != nil {
			return err
		}
	}
	// The control port opens after the attach, so that a client finds the server ready.
	ln, err := net.Listen("tcp", o.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	lnAddr := ln.Addr().(*net.TCPAddr).AddrPort()
	var uc *net.UDPConn
	if o.Via == "direct" {
		if uc, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(lnAddr)); err != nil {
			return err
		}
		defer uc.Close()
	}
	if ready != nil {
		ready(lnAddr)
	}
	defer context.AfterFunc(ctx, func() { _ = ln.Close() })()
	c, err := ln.Accept()
	if err != nil {
		return serverErr(parent, ctx, err)
	}
	defer c.Close()
	_ = ln.Close()
	defer context.AfterFunc(ctx, func() { _ = c.Close() })()

	err = serveCtl(c, func(req request) (reply, error) {
		switch req.Op {
		case "hello":
			if s == nil {
				ds, keys, err := serverDirect(ctx, fail, o, uc, c.RemoteAddr(), req)
				if err != nil {
					return reply{}, err
				}
				s = ds
				if err := serveSinks(s, &got); err != nil {
					return reply{}, err
				}
				return reply{Addr: s.addr.String(), Keys: keys}, nil
			}
			return reply{Addr: s.addr.String()}, nil
		case "mark":
			if s == nil {
				return reply{}, errors.New("mark before hello")
			}
			st := s.b.Stats()
			_, retrans := s.net.TCPCounters()
			return reply{Mark: mark{
				Nanos: time.Since(start).Nanoseconds(), CPU: bench.CPUSeconds(), HostCPU: bench.HostCPUSeconds(), Retrans: retrans,
				Bytes: got.Load(), RxPackets: st.RxPackets, Drops: st.RxDrops + st.RxNoDriver,
				RcvbufErrors: snmpCounter("Udp:", "RcvbufErrors"), SockDrops: sockDrops(s.uc), LinkDrops: s.net.LinkDrops(),
			}}, nil
		}
		return reply{}, fmt.Errorf("unknown op %q", req.Op)
	})
	return serverErr(parent, ctx, err)
}

// serverDirect makes the -via direct side of the server for the hello of the
// client at remote, and returns its keys for the client.
func serverDirect(ctx context.Context, fail context.CancelCauseFunc, o options, uc *net.UDPConn, remote net.Addr, req request) (*side, []byte, error) {
	ta, ok := remote.(*net.TCPAddr)
	if !ok || req.Port <= 0 || req.Port > 0xffff {
		return nil, nil, errors.New("hello has no client UDP port")
	}
	s, p, err := newDirect(o, uc, directServer, directClient, netip.AddrPortFrom(ta.AddrPort().Addr().Unmap(), uint16(req.Port)))
	if err != nil {
		return nil, nil, err
	}
	keys, err := offerKeys(p)
	if err == nil {
		err = applyKeys(p, req.Keys)
	}
	if err == nil {
		err = s.startNet(ctx, fail, o, netip.PrefixFrom(directClient, directClient.BitLen()))
	}
	if err != nil {
		s.close()
		return nil, nil, err
	}
	return s, keys, nil
}

// serveSinks counts the bytes of the TCP connections to the sink port, and
// echoes the UDP probes on the echo port.
func serveSinks(s *side, got *atomic.Uint64) error {
	data, err := s.net.Listen(netip.AddrPortFrom(s.addr, sinkPort))
	if err != nil {
		return fmt.Errorf("listen on the sink port: %w", err)
	}
	pc, err := s.net.ListenUDP(netip.AddrPortFrom(s.addr, echoPort))
	if err != nil {
		_ = data.Close()
		return fmt.Errorf("listen on the echo port: %w", err)
	}
	s.stop = append(s.stop, func() {
		_ = data.Close()
		_ = pc.Close()
	})
	go sink(data, got)
	go echo(pc)
	return nil
}

// sink counts the bytes of each connection of ln.
func sink(ln net.Listener, got *atomic.Uint64) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			buf := make([]byte, 256<<10)
			for {
				n, err := c.Read(buf)
				got.Add(uint64(n))
				if err != nil {
					return
				}
			}
		}()
	}
}

// runClient runs the flows and the RTT probes to the server, and prints the
// JSON line to out.
func runClient(parent context.Context, o options, out io.Writer) error {
	ctx, fail := context.WithCancelCause(parent)
	defer fail(nil)
	start := time.Now()
	var relay *ctl
	var s *side
	defer func() {
		if s != nil {
			s.close()
		}
		if relay != nil {
			if o.StopRelay {
				if _, err := relay.call(request{Op: "stop"}); err != nil {
					slog.Warn("Failed to stop the relay", "error", err)
				}
			}
			_ = relay.c.Close()
		}
	}()
	if o.Via == "relay" {
		var ca *vpctest.CA
		var err error
		if ca, relay, err = relayCA(ctx, o); err != nil {
			return err
		}
		if s, err = startAgent(ctx, fail, o, "client", ca); err != nil {
			return runErr(ctx, err)
		}
	}
	srv, err := dialCtl(ctx, o.Server, o.StartTimeout)
	if err != nil {
		return err
	}
	defer srv.c.Close()
	var peer netip.Addr
	if o.Via == "relay" {
		rep, err := srv.call(request{Op: "hello"})
		if err != nil {
			return err
		}
		if peer, err = netip.ParseAddr(rep.Addr); err != nil {
			return fmt.Errorf("server overlay address: %w", err)
		}
		cctx, cancel := context.WithTimeout(ctx, o.StartTimeout)
		err = s.a.Connect(cctx, peer)
		cancel()
		if err != nil {
			return runErr(ctx, fmt.Errorf("peer session to the server: %w", err))
		}
	} else {
		if s, err = clientDirect(ctx, fail, o, srv); err != nil {
			return runErr(ctx, err)
		}
		peer = directServer
	}
	res, err := measure(ctx, o, s, peer, srv, relay, start)
	if err := runErr(ctx, err); err != nil {
		return err
	}
	slog.Info("Run done", "via", res.Via, "driver", res.Driver, "transport", res.Transport, "cc", res.CC,
		"gbps", res.BitsPerSecond/1e9, "retrans_percent", res.RetransPercent,
		"load_rtt_p50_ms", res.LoadRTT.P50, "load_rtt_p99_ms", res.LoadRTT.P99)
	return json.NewEncoder(out).Encode(res)
}

// clientDirect makes the -via direct side of the client and exchanges keys
// with the server on srv.
func clientDirect(ctx context.Context, fail context.CancelCauseFunc, o options, srv *ctl) (*side, error) {
	sa, err := netip.ParseAddrPort(o.Server)
	if err != nil {
		return nil, fmt.Errorf("-server with -via direct must be IP:port: %w", err)
	}
	network := "udp6"
	if sa.Addr().Unmap().Is4() {
		network = "udp4"
	}
	uc, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	s, p, err := newDirect(o, uc, directClient, directServer, sa)
	if err != nil {
		_ = uc.Close()
		return nil, err
	}
	s.stop = append([]func(){func() { _ = uc.Close() }}, s.stop...)
	keys, err := offerKeys(p)
	if err == nil {
		var rep reply
		rep, err = srv.call(request{Op: "hello", Port: uc.LocalAddr().(*net.UDPAddr).Port, Keys: keys})
		if err == nil {
			err = applyKeys(p, rep.Keys)
		}
	}
	if err == nil {
		err = s.startNet(ctx, fail, o, netip.PrefixFrom(directServer, directServer.BitLen()))
	}
	if err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

// measure runs the probes and the flows, and takes the marks of all sides at
// the flow start, at the window start and at the window end.
func measure(ctx context.Context, o options, s *side, peer netip.Addr, srv, relay *ctl, start time.Time) (result, error) {
	echoConn, err := s.net.DialUDP(netip.AddrPortFrom(peer, echoPort))
	if err != nil {
		return result{}, err
	}
	defer echoConn.Close()
	// The flows and the probes stop before the driver, so late echoes still arrive.
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	p := bench.NewProber(echoConn, start, o.ProbeInterval, o.Idle+o.Omit+o.Duration)
	go p.Receive()
	go p.Send(runCtx, o.ProbeInterval)
	if err := bench.Sleep(ctx, o.Idle, nil); err != nil {
		return result{}, err
	}
	idleEnd := time.Since(start)

	conns := make([]net.Conn, 0, o.Streams)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for range o.Streams {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		c, err := s.net.Dial(dctx, netip.AddrPortFrom(peer, sinkPort))
		cancel()
		if err != nil {
			return result{}, fmt.Errorf("dial the sink: %w", err)
		}
		conns = append(conns, c)
	}
	done := make(chan error, o.Streams)
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Go(func() { done <- flow(runCtx, c) })
	}
	go func() {
		wg.Wait()
		close(done)
	}()

	// The marks are at the flow start, at the window start and at the window end.
	var client, server, rel [3]mark
	var at [3]time.Duration
	var wall [3]time.Time
	takeMarks := func(i int) error {
		wall[i] = time.Now()
		at[i] = wall[i].Sub(start)
		_, retrans := s.net.TCPCounters()
		st := s.b.Stats()
		// With GSO, the TCP segments sent are not packets, so the packets of the binding
		// are the base of the retransmit percent.
		client[i] = mark{
			Nanos: at[i].Nanoseconds(), CPU: bench.CPUSeconds(), HostCPU: bench.HostCPUSeconds(), Segments: st.TxPackets, Retrans: retrans,
			Drops: st.TxDrops + st.TxLimitDrops, LinkDrops: s.net.LinkDrops(),
		}
		var err error
		if server[i], err = srv.mark(); err != nil {
			return err
		}
		if relay != nil {
			if rel[i], err = relay.mark(); err != nil {
				return err
			}
		}
		return nil
	}
	if err := takeMarks(0); err != nil {
		return result{}, err
	}
	for i, wait := range []time.Duration{o.Omit, o.Duration} {
		if err := bench.Sleep(ctx, wait, done); err != nil {
			return result{}, err
		}
		if err := takeMarks(i + 1); err != nil {
			return result{}, err
		}
	}
	stopRun()
	for err := range done {
		if err != nil {
			return result{}, err
		}
	}
	if err := bench.Sleep(ctx, echoWait, nil); err != nil {
		return result{}, err
	}

	span := func(m [3]mark, i int) [2]mark { return [2]mark{m[i], m[i+1]} }
	res := newResult(span(client, 1), span(server, 1), span(rel, 1))
	res.IdleRTT = bench.NewRTTStats(p.Window(0, idleEnd))
	res.LoadRTT = bench.NewRTTStats(p.Window(at[1], at[2]))
	res.Omit = newPeriod(span(client, 0), span(server, 0), span(rel, 0))
	res.Omit.RTT = bench.NewRTTStats(p.Window(at[0], at[1]))
	res.FlowStartUnixMS, res.WindowStartUnixMS, res.WindowEndUnixMS = wall[0].UnixMilli(), wall[1].UnixMilli(), wall[2].UnixMilli()
	res.Driver, res.Transport, res.Via, res.CC = o.Driver, o.Transport, o.Via, s.net.CC()
	res.Streams, res.DeviceMTU = o.Streams, s.b.DeviceMTU()
	return res, nil
}

// flow writes to c until ctx ends.
func flow(ctx context.Context, c net.Conn) error {
	defer context.AfterFunc(ctx, func() { _ = c.Close() })()
	buf := make([]byte, 1<<20)
	for {
		if _, err := c.Write(buf); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("write: %w", err)
		}
	}
}
