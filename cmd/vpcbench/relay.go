// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/cmd/internal/bench"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// relaySockBuf is the socket buffer size of the relay socket, as in the relay.
const relaySockBuf = 16 << 20

// runRelay serves relay sessions of one VPC with the vpctest fakes until ctx
// ends or a client sends stop. The CA signs the relay cert and the agent
// certs; the control port gives it to the server and the client. With -join,
// the relay takes the CA of the relay at that address, and the two relays have
// a mesh session.
func runRelay(ctx context.Context, o options, ready func(netip.AddrPort)) error {
	start := time.Now()
	ua, err := net.ResolveUDPAddr("udp", o.Listen)
	if err != nil {
		return err
	}
	uc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	defer uc.Close()
	if err := errors.Join(uc.SetReadBuffer(relaySockBuf), uc.SetWriteBuffer(relaySockBuf)); err != nil {
		slog.Warn("Failed to set the relay socket buffers", "bytes", relaySockBuf, "error", err)
	}
	addr := uc.LocalAddr().(*net.UDPAddr).AddrPort()
	slog.Info("Relay socket is ready", "address", addr, "rcvbuf", sockRcvbuf(uc))

	// The relay of -join has its control port only after the join, so its agents
	// get the CA of the two relays.
	var ca *vpctest.CA
	var first relay.MeshMember
	if o.Join != "" {
		ca, first, err = joinRelay(ctx, o, addr.Port())
	} else {
		ca, err = vpctest.NewCA()
	}
	if err != nil {
		return err
	}
	cert, err := ca.RelayCert(relayID)
	if err != nil {
		return err
	}

	// A driver can stop the link when it gets the XDP program, and the host can then
	// take the address off for a short time. So the control port opens first.
	cl, err := net.Listen("tcp", addr.String())
	if err != nil {
		return err
	}
	defer cl.Close()

	r := relay.NewRouter(vpctest.NewTrust(ca), relay.Config{LaneSources: o.Lanes})
	xdpCPU := func() float64 { return 0 }
	var xdpMode string
	if o.XDP != "" {
		x, mode, err := r.StartXDP(relay.XDPConfig{Port: addr.Port(), Iface: o.XDP, Generic: o.XDPMode != "driver", NextHopCache: o.XDPHop})
		if err != nil {
			return err
		}
		defer x.Close()
		slog.Info("Relay forwards PSP packets in XDP", "iface", o.XDP, "mode", mode)
		sec, stop, err := xdpSeconds(o.XDP)
		if err != nil {
			return fmt.Errorf("read the XDP run time: %w", err)
		}
		defer stop()
		xdpCPU, xdpMode = sec, mode
	}
	// The kernel joins the datagrams of a socket with UDP GRO before generic
	// XDP runs, so the relay socket has no GRO with XDP in generic mode.
	tr := &quic.Transport{Conn: uc, EnableGRO: xdpMode != "generic"}
	defer tr.Close()
	tr.NonQUICPacketHandler, tr.NonQUICBatchEnd = r.PacketHandler(ctx, tr)
	tlsConf, quicConf := r.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*cert}}), tunnel.RelayQUICConfig()
	var mesh *relay.Mesh
	if o.Mesh != "" {
		// As at a real relay, the mesh sessions use the socket of the agents.
		mesh, err = relay.NewMesh(o.Mesh, relay.MeshConfig{
			Relay:  &dp.RelayRef{Id: relayID, Addresses: []string{addr.String()}},
			TLS:    &tls.Config{Certificates: []tls.Certificate{*cert}, InsecureSkipVerify: true},
			Verify: verifyMember(ca),
		})
		if err != nil {
			return err
		}
		mesh.SetRouter(r)
		agents, members := tlsConf, mesh.TLSConfig()
		tlsConf = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			if slices.Contains(h.SupportedProtos, dp.ALPNMesh) {
				return members, nil
			}
			return agents, nil
		}}
		quicConf = mesh.ListenConfig(quicConf)
		if first.Name != "" {
			mesh.SetMembers([]relay.MeshMember{first})
		}
	}
	ln, err := tr.Listen(tlsConf, quicConf)
	if err != nil {
		return err
	}
	defer ln.Close()
	srv := &relay.Server{
		R:         r,
		Networks:  vpctest.Networks{Project: project, VPC: vpcName, Net: relay.Network{ID: vni, MTU: uint32(o.MTU)}},
		Addresses: &addresses{joined: o.Join != ""},
		Cert:      func() (*tls.Certificate, error) { return cert, nil },
		RelayID:   relayID,
	}

	caPEM := encodeCA(ca)
	if ready != nil {
		ready(addr)
	}
	slog.Info("Serving relay sessions", "address", addr)

	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wg.Go(func() { r.Run(ctx) })
	if mesh != nil {
		wg.Go(func() { mesh.Run(ctx, tr, tunnel.RelayQUICConfig()) })
	}
	wg.Go(func() {
		serveMarks(ctx, cl, func(remote net.Addr, req request) (reply, error) {
			// A relay that stops gives no CA: the process of the next run has a new one.
			if ctx.Err() != nil && (req.Op == "ca" || req.Op == "join") {
				return reply{}, errors.New("the relay stops")
			}
			switch req.Op {
			case "ca":
				return reply{CA: caPEM}, nil
			case "join":
				m, err := joinMember(mesh, remote, req)
				if err != nil {
					return reply{}, err
				}
				mesh.SetMembers([]relay.MeshMember{m})
				slog.Info("A relay joined the mesh", "name", m.Name, "address", m.Addr)
				return reply{CA: caPEM, Name: o.Mesh}, nil
			case "mark":
				drops, reasons, xdp, passed := relayCounters(r)
				xdpS := xdpCPU()
				m := mark{
					Nanos: time.Since(start).Nanoseconds(), CPU: bench.CPUSeconds() + xdpS, HostCPU: bench.HostCPUSeconds(),
					Drops: drops, DropReasons: reasons, SockDrops: sockDrops(uc),
					XDPPackets: xdp, XDPPassed: passed, XDPSeconds: xdpS, XDPMode: xdpMode,
					Sends: r.ForwardStats(), CPUs: bench.PerCPU(),
				}
				if mesh != nil {
					m.Trunk = trunkCounters(r)
				}
				m.Socket = socketCounters(r)
				o.marked(req.Index, req.Window)
				return reply{Mark: m}, nil
			case "stop":
				slog.Info("A client stopped the relay")
				cancel()
				return reply{}, nil
			}
			return reply{}, fmt.Errorf("unknown op %q", req.Op)
		})
	})
	if mesh != nil {
		err = serveMesh(ctx, ln, srv, mesh)
	} else {
		err = srv.Serve(ctx, ln)
	}
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// serveMesh gives the connections of the other relays to mesh and the
// connections of agents to srv, until ctx ends.
func serveMesh(ctx context.Context, ln *quic.Listener, srv *relay.Server, mesh *relay.Mesh) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		qc, err := ln.Accept(ctx)
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		if qc.ConnectionState().TLS.NegotiatedProtocol == dp.ALPNMesh {
			wg.Go(func() { mesh.ServeConn(ctx, qc) })
			continue
		}
		wg.Go(func() { srv.ServeConn(ctx, qc) })
	}
}

// joinRetry is the time between two tries of a join.
const joinRetry = 200 * time.Millisecond

// joinRelay makes this relay, with its socket on port, a member of the mesh of the
// relay at o.Join. It returns the CA of that relay and that relay as a member. It
// tries again until o.StartTimeout: the relay of the run before can still stop.
func joinRelay(ctx context.Context, o options, port uint16) (*vpctest.CA, relay.MeshMember, error) {
	to, err := netip.ParseAddrPort(o.Join)
	if err != nil {
		return nil, relay.MeshMember{}, fmt.Errorf("-join must be IP:port: %w", err)
	}
	deadline := time.Now().Add(o.StartTimeout)
	for {
		ca, name, err := join(ctx, o, port, time.Until(deadline))
		if err == nil {
			slog.Info("Joined the mesh of a relay", "name", name, "address", to)
			return ca, relay.MeshMember{Name: name, Addr: to}, nil
		}
		if time.Now().After(deadline) {
			return nil, relay.MeshMember{}, fmt.Errorf("join the relay at %s: %w", o.Join, err)
		}
		select {
		case <-ctx.Done():
			return nil, relay.MeshMember{}, ctx.Err()
		case <-time.After(joinRetry):
		}
	}
}

// join does one join call. It returns the CA and the mesh name of the other relay.
func join(ctx context.Context, o options, port uint16, timeout time.Duration) (*vpctest.CA, string, error) {
	c, err := dialCtl(ctx, o.Join, max(timeout, time.Second))
	if err != nil {
		return nil, "", err
	}
	defer c.c.Close()
	rep, err := c.call(request{Op: "join", Name: o.Mesh, Port: int(port)})
	if err != nil {
		return nil, "", err
	}
	if rep.Name == "" || rep.Name == o.Mesh {
		return nil, "", fmt.Errorf("the relay has the mesh name %q, and this relay %q", rep.Name, o.Mesh)
	}
	ca, err := decodeCA(rep.CA)
	return ca, rep.Name, err
}

// joinMember returns the relay of a join call as a member of mesh. Its relay
// socket has the source address of the call and the port of the request, so
// the address is the one that this relay can send to.
func joinMember(mesh *relay.Mesh, remote net.Addr, req request) (relay.MeshMember, error) {
	ta, ok := remote.(*net.TCPAddr)
	switch {
	case mesh == nil:
		return relay.MeshMember{}, errors.New("the relay has no mesh: start it with -mesh")
	case !ok || req.Name == "" || req.Port <= 0 || req.Port > 0xffff:
		return relay.MeshMember{}, errors.New("join has no mesh name or no relay port")
	}
	return relay.MeshMember{Name: req.Name, Addr: netip.AddrPortFrom(ta.AddrPort().Addr().Unmap(), uint16(req.Port))}, nil
}

// verifyMember returns the check of the certificate of another relay: the CA of
// the run signed it.
func verifyMember(ca *vpctest.CA) relay.MeshVerify {
	return func(chain []*x509.Certificate, _ string, _ netip.AddrPort) error {
		if len(chain) == 0 {
			return errors.New("the relay gave no certificate")
		}
		_, err := chain[0].Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		return err
	}
}

// addresses is a relay.Addresses that gives each attachment the next /96 of the
// VPC network. A relay that joined another relay uses the high half of the
// network, so the two relays give different addresses.
type addresses struct {
	joined bool
	mu     sync.Mutex
	next   int
}

var _ relay.Addresses = (*addresses)(nil)

func (a *addresses) Assign(context.Context, *relay.Attachment, func()) ([]netip.Prefix, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.next >= 0x7fff {
		return nil, errors.New("address pool is full")
	}
	a.next++
	n := a.next
	if a.joined {
		n += 0x8000
	}
	return []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("fd61:706f:7879:12:3400:%x::/96", n))}, nil
}

func (a *addresses) Attached(*relay.Attachment) {}

func (a *addresses) Release(*relay.Attachment) {}

// serveMarks answers the control connections of ln until ctx ends. handle gets
// the remote address of the connection of each request.
func serveMarks(ctx context.Context, ln net.Listener, handle func(net.Addr, request) (reply, error)) {
	var wg sync.WaitGroup
	defer wg.Wait()
	defer context.AfterFunc(ctx, func() { _ = ln.Close() })()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		wg.Go(func() {
			defer c.Close()
			defer context.AfterFunc(ctx, func() { _ = c.Close() })()
			err := serveCtl(c, func(req request) (reply, error) { return handle(c.RemoteAddr(), req) })
			if err != nil && ctx.Err() == nil {
				slog.Warn("Control connection failed", "remote", c.RemoteAddr(), "error", err)
			}
		})
	}
}

// relayCounters returns the sum of the drop counters of r and the drops by
// reason, the packets that its XDP program forwarded, and the packets that it
// gave to the socket path, by result. The maps have only the counters that are not 0.
func relayCounters(r *relay.Router) (drops uint64, reasons map[string]uint64, xdp uint64, passed map[string]uint64) {
	ch := make(chan prometheus.Metric, 8)
	go func() {
		r.Collect(ch)
		close(ch)
	}()
	for m := range ch {
		var d dto.Metric
		if m.Write(&d) != nil {
			continue
		}
		n := uint64(d.GetCounter().GetValue())
		switch desc := m.Desc().String(); {
		case strings.Contains(desc, `"apoxy_vpc_relay_dropped_packets_total"`):
			drops += n
			if n > 0 {
				if reasons == nil {
					reasons = map[string]uint64{}
				}
				reasons[label(&d, "reason")] += n
			}
		case !strings.Contains(desc, `"apoxy_vpc_relay_xdp_packets_total"`):
		case label(&d, "result") == "forwarded":
			xdp += n
		case n > 0:
			if passed == nil {
				passed = map[string]uint64{}
			}
			passed[label(&d, "result")] += n
		}
	}
	return drops, reasons, xdp, passed
}

// trunkCounters returns the packets of agents that r sent to the other relays of
// its mesh and got from them, and the packets of the trunks that it dropped.
func trunkCounters(r *relay.Router) *trunkCount {
	ch := make(chan prometheus.Metric, 8)
	go func() {
		r.Collect(ch)
		close(ch)
	}()
	t := &trunkCount{}
	for m := range ch {
		var d dto.Metric
		if m.Write(&d) != nil {
			continue
		}
		n := uint64(d.GetCounter().GetValue())
		switch desc := m.Desc().String(); {
		case strings.Contains(desc, `"apoxy_vpc_relay_trunk_dropped_packets_total"`):
			t.Drops += n
		case !strings.Contains(desc, `"apoxy_vpc_relay_trunk_packets_total"`):
		case label(&d, "direction") == "tx":
			t.TxPackets += n
		default:
			t.RxPackets += n
		}
	}
	return t
}

// socketCounters returns the PSP packets that the socket path of r took, by class.
func socketCounters(r *relay.Router) map[string]uint64 {
	ch := make(chan prometheus.Metric, 8)
	go func() {
		r.Collect(ch)
		close(ch)
	}()
	out := map[string]uint64{}
	for m := range ch {
		var d dto.Metric
		if m.Write(&d) != nil || !strings.Contains(m.Desc().String(), `"apoxy_vpc_relay_socket_packets_total"`) {
			continue
		}
		out[label(&d, "class")] = uint64(d.GetCounter().GetValue())
	}
	return out
}

// label returns the value of the label name of a counter.
func label(d *dto.Metric, name string) string {
	for _, l := range d.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

// encodeCA returns the CA cert and key in PEM.
func encodeCA(ca *vpctest.CA) []byte {
	key, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		return nil
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	return append(b, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key})...)
}

// decodeCA reads the CA cert and key from PEM.
func decodeCA(b []byte) (*vpctest.CA, error) {
	ca := &vpctest.CA{}
	var err error
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			ca.Cert, err = x509.ParseCertificate(blk.Bytes)
		case "EC PRIVATE KEY":
			ca.Key, err = x509.ParseECPrivateKey(blk.Bytes)
		}
		if err != nil {
			return nil, fmt.Errorf("parse the CA: %w", err)
		}
	}
	if ca.Cert == nil || ca.Key == nil {
		return nil, errors.New("the relay sent no CA cert and key")
	}
	return ca, nil
}
