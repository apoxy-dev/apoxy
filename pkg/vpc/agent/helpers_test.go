// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
)

const (
	testProject = "project-a"
	testVPC     = "vpc-1"
	testVNI     = 0x0a0b0c
)

func TestMain(m *testing.M) {
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	shuffleRelays = false
	os.Exit(m.Run())
}

// testCA is a vpctest.CA whose helpers fail the test on an error.
type testCA struct{ *vpctest.CA }

func newCA(t testing.TB) *testCA {
	t.Helper()
	ca, err := vpctest.NewCA()
	require.NoError(t, err)
	return &testCA{ca}
}

// credential issues a credential for agent name, valid for life.
func (ca *testCA) credential(t testing.TB, project, vpc, name string, life time.Duration) *identity.Credential {
	t.Helper()
	cred, err := ca.Credential(project, vpc, name, life)
	require.NoError(t, err)
	return cred
}

// relayCert issues a relay cert that names only id.
func (ca *testCA) relayCert(t testing.TB, id string) *tls.Certificate {
	t.Helper()
	cert, err := ca.RelayCert(id)
	require.NoError(t, err)
	return cert
}

// fakeAddresses is a vpctest.Addresses with a hold. While the hold is set,
// Assign waits for the attachments with names that start with holdName.
type fakeAddresses struct {
	*vpctest.Addresses
	mu               sync.Mutex
	holdDone         chan struct{}
	holdName         string
	inHold, mostHold int // Assign calls that wait now, and the most at once.
}

func (f *fakeAddresses) Assign(ctx context.Context, a *relay.Attachment, onLost func()) ([]netip.Prefix, error) {
	f.mu.Lock()
	if done := f.holdDone; done != nil && strings.HasPrefix(a.Name, f.holdName) {
		f.inHold++
		f.mostHold = max(f.mostHold, f.inHold)
		f.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
		}
		f.mu.Lock()
		f.inHold--
		if ctx.Err() != nil {
			f.mu.Unlock()
			return nil, ctx.Err()
		}
	}
	f.mu.Unlock()
	return f.Addresses.Assign(ctx, a, onLost)
}

// hold makes Assign wait for the names with prefix until release runs.
func (f *fakeAddresses) hold(prefix string) (release func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	done := make(chan struct{})
	f.holdDone, f.holdName = done, prefix
	return func() {
		f.mu.Lock()
		f.holdDone = nil
		f.mu.Unlock()
		close(done)
	}
}

// held returns the Assign calls that wait now, and the most that waited at once.
func (f *fakeAddresses) held() (now, most int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inHold, f.mostHold
}

// world is the CAs and the address pool of one test.
type world struct {
	mu               sync.Mutex
	agentCA, relayCA *testCA
	trust            *vpctest.Trust
	addrs            *fakeAddresses
	mtu              uint32 // VPC MTU of the relays.
	dns, search      []string
	relayCfg         relay.Config // Meters of the relays.
}

// rotateAgentCA makes a new agent CA for enrolls and relays.
func (w *world) rotateAgentCA(t testing.TB) {
	ca := newCA(t)
	w.mu.Lock()
	w.agentCA = ca
	w.mu.Unlock()
	w.trust.SetCA(ca.CA)
}

func (w *world) enrollCA() *testCA {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.agentCA
}

func newWorld(t testing.TB) *world {
	w := &world{agentCA: newCA(t), relayCA: newCA(t), addrs: &fakeAddresses{Addresses: &vpctest.Addresses{}}}
	w.trust = vpctest.NewTrust(w.agentCA.CA)
	return w
}

// testRelay is a relay that forwards PSP packets and peer frames.
type testRelay struct {
	id   string
	srv  *relay.Server
	r    *relay.Router
	addr string
	// stopAccept stops the Accept calls, as a relay host in its lame duck. The
	// listener still completes handshakes, and no session serves them.
	stopAccept func()
}

func (r *testRelay) ref() identity.Relay {
	return identity.Relay{ID: r.id, Addresses: []string{r.addr}}
}

// deadRelay returns the address of a socket that drops all packets.
func deadRelay(t testing.TB) string {
	t.Helper()
	udp := loopback(t)
	t.Cleanup(func() { _ = udp.Close() })
	return udp.LocalAddr().String()
}

// loopback opens a UDP socket on 127.0.0.1.
func loopback(t testing.TB) *net.UDPConn {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	return udp
}

// relay starts a relay on loopback.
func (w *world) relay(t testing.TB, id string) *testRelay {
	t.Helper()
	return w.relayOn(t, id, loopback(t))
}

// relayOn starts a relay on udp, and closes udp at the end of the test.
func (w *world) relayOn(t testing.TB, id string, udp net.PacketConn) *testRelay {
	t.Helper()
	cert := w.relayCA.relayCert(t, id)
	r := relay.NewRouter(w.trust, w.relayCfg)
	tr := &quic.Transport{Conn: udp}
	tr.NonQUICPacketHandler, tr.NonQUICBatchEnd = r.PacketHandler(t.Context(), tr)
	// As at a real relay, the packets are Not-ECT, and the stream limit takes
	// the Attach calls of extra attachments.
	ln, err := tr.Listen(r.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*cert}}), &quic.Config{EnableDatagrams: true, DisableECN: true, MaxIncomingStreams: 512})
	require.NoError(t, err)
	srv := &relay.Server{
		R: r, Addresses: w.addrs, RelayID: id,
		Networks: vpctest.Networks{Project: testProject, VPC: testVPC, Net: relay.Network{
			ID: testVNI, MTU: w.mtu, DNSServers: w.dns, DNSSearchDomains: w.search,
		}},
		Cert: func() (*tls.Certificate, error) { return cert, nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	// As Serve, but stopAccept ends only the Accept calls. The end of the ctx
	// of Serve also closes the sessions.
	actx, stopAccept := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			qc, err := ln.Accept(actx)
			if err != nil {
				return
			}
			wg.Go(func() { srv.ServeConn(ctx, qc) })
		}
	})
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		wg.Wait()
		_ = tr.Close()
		_ = udp.Close()
	})
	return &testRelay{id: id, srv: srv, r: r, addr: udp.LocalAddr().String(), stopAccept: stopAccept}
}

// attachEvent is one OnAttach call.
type attachEvent struct {
	addr     netip.Addr
	prefixes []netip.Prefix
}

// testAgent is an agent with a netstack on its binding.
type testAgent struct {
	a       *Agent
	tr      *quic.Transport
	enrolls atomic.Int32
	attach  chan attachEvent
	cancel  context.CancelFunc
	done    chan struct{}

	stackOnce sync.Once
	stack     *stack.Stack
	vpcStack  bool
	ns        *netstack.Stack // Set with vpcStack.

	routesMu sync.Mutex
	routes   map[netip.Prefix]bool // From OnRoutes.
	routeLog []string              // "+prefix" or "-prefix" from OnRoutes, in order.

	extraMu sync.Mutex
	extras  map[string]netip.Addr // From OnAttachment and OnDetach.
	log     []string              // "attach name address" or "detach name address", in order.
}

type agentOptions struct {
	life   time.Duration // Cert life. Zero means 24 hours.
	mtu    int           // Config.MTU.
	conn   *lossyConn    // Wraps the agent socket if set.
	move   *moveConn     // Wraps the agent socket if set.
	mode   TransportMode
	udp    *net.UDPConn // Agent socket. Nil means a new socket on loopback.
	tcp    bool         // Adds TCP to the netstack.
	routes []netip.Prefix

	relays   []identity.Relay // Config.Relays. Nil means the relay of the agent.
	sessions int              // Config.Sessions.
	noRoots  bool             // No Config.RelayRoots.
	// enrolled gives the relays and the relay roots of enroll n, from 1. Then
	// Config.Relays is empty.
	enrolled func(n int32) ([]identity.Relay, []byte, error)

	// vpcStack makes the netstack with pkg/netstack.NewStack and its VPC
	// options, as vpc connect does. It always has TCP.
	vpcStack bool
}

// lossyConn drops the packets that it sends if they are larger than max.
// Zero means no limit. While limitProbes is set, it sends only probeBudget
// more path probes.
type lossyConn struct {
	net.PacketConn
	max         atomic.Int32
	limitProbes atomic.Bool
	probeBudget atomic.Int32
	probes      atomic.Int32 // Path probes to send, with the dropped ones.
}

func (c *lossyConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > 0 && p[0] == p2p.TypeProbe {
		c.probes.Add(1)
		if c.limitProbes.Load() && c.probeBudget.Add(-1) < 0 {
			return len(p), nil
		}
	}
	if m := int(c.max.Load()); m != 0 && len(p) > m {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (w *world) agent(t *testing.T, name string, r *testRelay, opts agentOptions) *testAgent {
	t.Helper()
	if opts.life == 0 {
		opts.life = 24 * time.Hour
	}
	udp := opts.udp
	if udp == nil {
		udp = loopback(t)
	}
	var conn net.PacketConn = udp
	if opts.conn != nil {
		opts.conn.PacketConn = udp
		conn = opts.conn
	}
	if opts.move != nil {
		opts.move.PacketConn = udp
		conn = opts.move
	}
	ta := &testAgent{
		tr: &quic.Transport{Conn: conn}, attach: make(chan attachEvent, 16), done: make(chan struct{}),
		routes: map[netip.Prefix]bool{}, extras: map[string]netip.Addr{}, vpcStack: opts.vpcStack,
	}
	enroll := func(context.Context) (*identity.Credential, error) {
		n := ta.enrolls.Add(1)
		cred := w.enrollCA().credential(t, testProject, testVPC, name, opts.life)
		if opts.enrolled == nil {
			return cred, nil
		}
		relays, roots, err := opts.enrolled(n)
		if err != nil {
			return nil, err
		}
		return cred, cred.SetRelays(relays, roots)
	}
	cfg := Config{
		Identity:      identity.NewManager(filepath.Join(t.TempDir(), "cred.json"), enroll),
		Relays:        opts.relays,
		RelayRoots:    w.relayCA.Pool(),
		Sessions:      opts.sessions,
		Transport:     ta.tr,
		TransportMode: opts.mode,
		Name:          name,
		Routes:        opts.routes,
		MTU:           opts.mtu,
		OnAttach: func(b *psp.Binding, addr netip.Addr, prefixes []netip.Prefix) {
			ta.netstack(t, b, addr, opts.tcp)
			ta.attach <- attachEvent{addr, prefixes}
		},
		OnRoutes: func(add, remove []netip.Prefix) {
			ta.routesMu.Lock()
			defer ta.routesMu.Unlock()
			for _, p := range remove {
				if !ta.routes[p] {
					t.Errorf("agent %s: OnRoutes removes %s, which it does not have", name, p)
				}
				delete(ta.routes, p)
				ta.routeLog = append(ta.routeLog, "-"+p.String())
			}
			for _, p := range add {
				if ta.routes[p] {
					t.Errorf("agent %s: OnRoutes adds %s again", name, p)
				}
				ta.routes[p] = true
				ta.routeLog = append(ta.routeLog, "+"+p.String())
			}
		},
		OnAttachment: func(at Attachment) {
			ta.extraMu.Lock()
			old := ta.extras[at.Name]
			ta.extras[at.Name] = at.Address
			ta.log = append(ta.log, "attach "+at.Name+" "+at.Address.String())
			ta.extraMu.Unlock()
			if old != at.Address {
				ta.removeAddr(t, old)
				ta.netstack(t, ta.binding(), at.Address, opts.tcp)
			}
		},
		OnDetach: func(at Attachment) {
			ta.extraMu.Lock()
			old := ta.extras[at.Name]
			delete(ta.extras, at.Name)
			ta.log = append(ta.log, "detach "+at.Name+" "+at.Address.String())
			ta.extraMu.Unlock()
			ta.removeAddr(t, old)
		},
	}
	if cfg.Relays == nil && opts.enrolled == nil {
		cfg.Relays = []identity.Relay{r.ref()}
	}
	if opts.noRoots {
		cfg.RelayRoots = nil
	}
	ta.a = New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	ta.cancel = cancel
	go func() {
		defer close(ta.done)
		if err := ta.a.Run(ctx); err != nil {
			t.Errorf("agent %s: %v", name, err)
		}
	}()
	t.Cleanup(func() {
		ta.stop()
		_ = ta.tr.Close()
		_ = udp.Close()
	})
	return ta
}

func (ta *testAgent) stop() {
	ta.cancel()
	<-ta.done
}

func (ta *testAgent) binding() *psp.Binding {
	ta.a.mu.Lock()
	defer ta.a.mu.Unlock()
	return ta.a.bind
}

// reconnect closes the relay session. The agent then opens a new one.
func (ta *testAgent) reconnect() {
	ta.a.mu.Lock()
	rc := ta.a.rc
	ta.a.mu.Unlock()
	_ = rc.qc.CloseWithError(0, "next session")
}

// current returns the attached session.
func (ta *testAgent) current() *relayConn {
	ta.a.mu.Lock()
	defer ta.a.mu.Unlock()
	return ta.a.rc
}

// spare returns the first spare session, or nil.
func (ta *testAgent) spare() *relayConn {
	ta.a.mu.Lock()
	defer ta.a.mu.Unlock()
	if len(ta.a.spares) == 0 {
		return nil
	}
	return ta.a.spares[0]
}

// extraAddr returns the address of the extra attachment name from OnAttachment.
func (ta *testAgent) extraAddr(name string) netip.Addr {
	ta.extraMu.Lock()
	defer ta.extraMu.Unlock()
	return ta.extras[name]
}

// events returns the OnAttachment and OnDetach calls for name.
func (ta *testAgent) events(name string) []string {
	ta.extraMu.Lock()
	defer ta.extraMu.Unlock()
	var out []string
	for _, e := range ta.log {
		if strings.Fields(e)[1] == name {
			out = append(out, e)
		}
	}
	return out
}

// removeAddr removes addr from the netstack, if it is valid.
func (ta *testAgent) removeAddr(t *testing.T, addr netip.Addr) {
	if !addr.IsValid() {
		return
	}
	var err error
	if ta.ns != nil {
		err = ta.ns.DelAddr(netip.PrefixFrom(addr, addr.BitLen()))
	} else if terr := ta.stack.RemoveAddress(1, tcpip.AddrFromSlice(addr.AsSlice())); terr != nil {
		err = errors.New(terr.String())
	}
	if err != nil {
		t.Errorf("remove address %s: %v", addr, err)
	}
}

// routeSet returns the prefixes that OnRoutes gave.
func (ta *testAgent) routeSet() []netip.Prefix {
	ta.routesMu.Lock()
	defer ta.routesMu.Unlock()
	return slices.Collect(maps.Keys(ta.routes))
}

// routeEvents returns the OnRoutes changes of p, in order.
func (ta *testAgent) routeEvents(p netip.Prefix) []string {
	ta.routesMu.Lock()
	defer ta.routesMu.Unlock()
	var out []string
	for _, e := range ta.routeLog {
		if e[1:] == p.String() {
			out = append(out, e)
		}
	}
	return out
}

// attached waits for the next OnAttach call.
func (ta *testAgent) attached(t *testing.T) attachEvent {
	t.Helper()
	select {
	case ev := <-ta.attach:
		return ev
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not attach in 10 s")
		return attachEvent{}
	}
}

// netstack starts a netstack with the device MTU on b at the first attach,
// and adds addr.
func (ta *testAgent) netstack(t *testing.T, b *psp.Binding, addr netip.Addr, withTCP bool) {
	ta.stackOnce.Do(func() {
		var s *stack.Stack
		var ep *channel.Endpoint
		if ta.vpcStack {
			ns, err := netstack.NewStack(b.DeviceMTU(), "", netstack.WithoutIPTables(), netstack.WithGSO())
			if err != nil {
				t.Errorf("new stack: %v", err)
				return
			}
			ta.ns, s, ep = ns, ns.Stack, ns.Endpoint
		} else {
			protos := []stack.TransportProtocolFactory{udp.NewProtocol}
			if withTCP {
				// The idle TCP processors use all CPUs in -race builds.
				protos = append(protos, tcp.NewProtocol)
			}
			s = stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: protos,
			})
			ep = channel.New(256, uint32(b.DeviceMTU()), "")
			if err := s.CreateNIC(1, ep); err != nil {
				t.Errorf("create NIC: %v", err)
				return
			}
			s.SetRouteTable([]tcpip.Route{{Destination: header.IPv6EmptySubnet, NIC: 1}})
		}
		d, err := b.Netstack(ep)
		if err != nil {
			t.Errorf("netstack: %v", err)
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			if err := d.Run(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				t.Logf("netstack: %v", err)
			}
		}()
		t.Cleanup(func() {
			// The driver ends when the agent closes the binding.
			ta.stop()
			cancel()
			<-done
			if ta.ns != nil {
				ta.ns.Close()
			} else {
				s.Close()
			}
		})
		ta.stack = s
	})
	if ta.ns != nil {
		if err := ta.ns.AddAddr(netip.PrefixFrom(addr, addr.BitLen())); err != nil {
			t.Errorf("add address: %v", err)
		}
		return
	}
	pa := tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix()}
	if err := ta.stack.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		t.Errorf("add address: %v", err)
	}
}
