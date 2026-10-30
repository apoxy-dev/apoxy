// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
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
	relaydp "github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	testProject = "project-a"
	testVPC     = "vpc-1"
	testVNI     = 0x0a0b0c
	// filePoll is the time between two reads of an identity file.
	filePoll = 50 * time.Millisecond
	// testWindow is the wait of the relay choice in the tests that do not check it.
	testWindow = 250 * time.Millisecond
)

func TestMain(m *testing.M) {
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
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
	// same has the first address of each subject when the allocator gives it again.
	same map[string][]netip.Prefix
	// fixed has the address of the next attachment of each name, in place of
	// the next address of the pool.
	fixed map[string]netip.Prefix
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
	if p, ok := f.same[a.Subject]; ok {
		f.mu.Unlock()
		return p, nil
	}
	if p, ok := f.fixed[a.Name]; ok {
		delete(f.fixed, a.Name)
		f.mu.Unlock()
		return []netip.Prefix{p}, nil
	}
	f.mu.Unlock()
	p, err := f.Addresses.Assign(ctx, a, onLost)
	f.mu.Lock()
	if err == nil && f.same != nil {
		f.same[a.Subject] = p
	}
	f.mu.Unlock()
	return p, err
}

// fix makes Assign give the address p to the next attachment named name.
func (f *fakeAddresses) fix(name string, p netip.Prefix) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fixed == nil {
		f.fixed = map[string]netip.Prefix{}
	}
	f.fixed[name] = p
}

// sameAgain makes Assign give each subject its first address again.
func (f *fakeAddresses) sameAgain() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.same = map[string][]netip.Prefix{}
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
	// refuse gives the close reason of each relay that refuses all agents as
	// too old, by the relay ID. Such a relay opens no session.
	refuse map[string]string
	// mesh gives each relay a mesh. joinMesh makes the members.
	mesh bool
	// advertise gives the addresses that a relay sends to agents and members,
	// by the relay ID. Else it sends the address of its QUIC socket.
	advertise map[string][]string
	// streamWindow sets the QUIC stream receive window of the relays. Zero
	// keeps the default.
	streamWindow uint64
	relays       []*testRelay
}

// relayAt returns the relay with the QUIC address addr, or nil.
func (w *world) relayAt(addr string) *testRelay {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range w.relays {
		if r.addr == addr {
			return r
		}
	}
	return nil
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

// testRelay is a relay with its data plane on a UDP socket.
type testRelay struct {
	id   string
	srv  *relay.Server
	r    *relay.Router
	addr string // Address of the QUIC socket.
	psp  string // Address of the data socket.
	// stopAccept stops the Accept calls, as a relay host in its lame duck. The
	// listener still completes handshakes, and no session serves them.
	stopAccept func()
	refused    atomic.Int32 // Connections that the relay refused as too old.

	connsMu sync.Mutex
	conns   []acceptedConn // Agent connections that the relay accepted, in order.

	callsMu          sync.Mutex
	calls, mostCalls int // Open calls after the Session call of each connection, now and the most at once.
}

// openCalls returns the calls that are open at the relay now and the most at once.
func (r *testRelay) openCalls() (now, most int) {
	r.callsMu.Lock()
	defer r.callsMu.Unlock()
	return r.calls, r.mostCalls
}

func (r *testRelay) addCall(n int) {
	r.callsMu.Lock()
	defer r.callsMu.Unlock()
	r.calls += n
	r.mostCalls = max(r.mostCalls, r.calls)
}

// acceptedConn is an agent connection and its remote address at the accept.
type acceptedConn struct {
	qc   *quic.Conn
	from netip.AddrPort
	kind *atomic.Int32 // connUnknown until the relay reads the Hello.
	tap  *sessionTap   // The Session call of the connection.
}

// Kinds of an agent connection, from its Hello.
const (
	connUnknown int32 = iota
	connSession
)

// keep records the agent connection qc. The relay serves the calls on the
// streams that keep returns, which find the kind of qc in its Hello.
func (r *testRelay) keep(qc *quic.Conn) rpc.Streams {
	r.connsMu.Lock()
	defer r.connsMu.Unlock()
	c := acceptedConn{qc, unmap(qc.RemoteAddr().(*net.UDPAddr).AddrPort()), new(atomic.Int32), &sessionTap{}}
	r.conns = append(r.conns, c)
	return &helloConn{qc: qc, r: r, kind: c.kind, tap: c.tap}
}

// tapOf returns the tap of the Session call of the agent connection qc.
func (r *testRelay) tapOf(qc *quic.Conn) *sessionTap {
	r.connsMu.Lock()
	defer r.connsMu.Unlock()
	for _, c := range r.conns {
		if c.qc == qc {
			return c.tap
		}
	}
	return nil
}

// helloConn reads the Hello of the Session call on the first stream, and
// counts the open calls on the other streams.
type helloConn struct {
	qc    *quic.Conn
	r     *testRelay
	kind  *atomic.Int32
	tap   *sessionTap
	first atomic.Bool
}

func (c *helloConn) OpenStreamSync(ctx context.Context) (rpc.Stream, error) {
	return c.qc.OpenStreamSync(ctx)
}

func (c *helloConn) AcceptStream(ctx context.Context) (rpc.Stream, error) {
	st, err := c.qc.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	if c.first.Swap(true) {
		c.r.addCall(1)
		return &callStream{Stream: st, r: c.r}, nil
	}
	return &helloStream{Stream: st, kind: c.kind, tap: c.tap}, nil
}

// callStream is a call stream that the relay ends with Close or CancelWrite.
type callStream struct {
	*quic.Stream
	r     *testRelay
	ended atomic.Bool
}

func (s *callStream) end() {
	if !s.ended.Swap(true) {
		s.r.addCall(-1)
	}
}

func (s *callStream) Close() error {
	s.end()
	return s.Stream.Close()
}

func (s *callStream) CancelWrite(code quic.StreamErrorCode) {
	s.end()
	s.Stream.CancelWrite(code)
}

// helloStream is the Session stream at the relay. It gives the bytes in both
// directions to the tap of its connection, which finds the Hello.
type helloStream struct {
	*quic.Stream
	kind *atomic.Int32
	tap  *sessionTap
}

func (s *helloStream) Read(p []byte) (int, error) {
	ctx := s.Stream.Context()
	if err := s.tap.wait(ctx); err != nil {
		return 0, err
	}
	n, err := s.Stream.Read(p)
	if s.tap.read(p[:n]) {
		s.kind.Store(connSession)
	}
	if err != nil {
		// After a stop, the error of CancelRead waits for the end of the stream,
		// so the relay keeps the call.
		if werr := s.tap.wait(ctx); werr != nil {
			return n, werr
		}
	}
	return n, err
}

func (s *helloStream) Write(p []byte) (int, error) {
	if s.tap.takeStop() {
		// The STOP_SENDING goes before the bytes of p, so each agent send after
		// the agent reads p fails.
		s.Stream.CancelRead(0)
	}
	n, err := s.Stream.Write(p)
	s.tap.wrote(p[:n])
	return n, err
}

// sessionTap is the relay side of the Session call of one agent connection. It
// decodes the messages in both directions. A test can make the relay stop the
// agent sends while the connection stays open.
type sessionTap struct {
	mu       sync.Mutex
	in, out  []byte // Read and written bytes that are not a whole frame yet.
	inStart  bool   // The relay read the preamble of the call.
	resps    []*dp.SessionResponse
	stopNext bool // The next write of the relay stops the agent sends first.
	stopped  bool
	paused   chan struct{} // Not nil: the reads of the relay wait until it closes.
}

// rpcMessage is the kind of an rpc message frame.
const rpcMessage = 0x02

// frames takes the whole frames from the start of b: each is a kind, a length
// varint and the message. It returns the messages of the message frames, and
// the bytes after the last whole frame.
func frames(b []byte) (msgs [][]byte, rest []byte) {
	for len(b) > 1 {
		n, w := binary.Uvarint(b[1:])
		if w <= 0 || uint64(len(b)-1-w) < n {
			break
		}
		if b[0] == rpcMessage {
			msgs = append(msgs, b[1+w:1+w+int(n)])
		}
		b = b[1+w+int(n):]
	}
	return msgs, b
}

// read takes the bytes that the relay read, and reports whether they have the
// Hello. The call starts with its type and version, and a header frame.
func (t *sessionTap) read(b []byte) (hello bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.in = append(t.in, b...)
	if !t.inStart {
		if len(t.in) < 2 {
			return false
		}
		t.in, t.inStart = t.in[2:], true
	}
	msgs, rest := frames(t.in)
	for _, b := range msgs {
		m := &dp.SessionRequest{}
		if proto.Unmarshal(b, m) == nil {
			hello = hello || m.GetHello() != nil
		}
	}
	t.in = slices.Clone(rest)
	return hello
}

// wrote takes the bytes that the relay wrote.
func (t *sessionTap) wrote(b []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.out = append(t.out, b...)
	msgs, rest := frames(t.out)
	for _, b := range msgs {
		m := &dp.SessionResponse{}
		if proto.Unmarshal(b, m) == nil {
			t.resps = append(t.resps, m)
		}
	}
	t.out = slices.Clone(rest)
}

// responses returns the messages that the relay sent, in order.
func (t *sessionTap) responses() []*dp.SessionResponse {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.resps)
}

// pause stops the reads of the relay until resume runs. When the stream window
// of the relay is full, the agent sends then wait.
func (t *sessionTap) pause() (resume func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ch := make(chan struct{})
	t.paused = ch
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			t.paused = nil
			t.mu.Unlock()
			close(ch)
		})
	}
}

// stopAgentSends makes the relay send STOP_SENDING before its next message.
// The relay then reads no more, and keeps the call until the stream ends.
func (t *sessionTap) stopAgentSends() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopNext = true
}

func (t *sessionTap) takeStop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.stopNext {
		return false
	}
	t.stopNext, t.stopped = false, true
	return true
}

// wait waits while the reads are paused, and for the end of ctx after a stop.
func (t *sessionTap) wait(ctx context.Context) error {
	t.mu.Lock()
	paused, stopped := t.paused, t.stopped
	t.mu.Unlock()
	switch {
	case stopped:
		<-ctx.Done()
		return context.Cause(ctx)
	case paused != nil:
		select {
		case <-paused:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	return nil
}

// sessionConns returns the connections from the address from with a Session
// call, in the order that the relay accepted them.
func (r *testRelay) sessionConns(from net.Addr) []*quic.Conn {
	r.connsMu.Lock()
	defer r.connsMu.Unlock()
	var out []*quic.Conn
	for _, qc := range r.agentConnsLocked(from, false) {
		for _, c := range r.conns {
			if c.qc == qc && c.kind.Load() == connSession {
				out = append(out, qc)
			}
		}
	}
	return out
}

// agentConns returns the agent connections from the address from, at the
// accept or now, in the order that the relay accepted them. With open, only
// the ones that did not close.
func (r *testRelay) agentConns(from net.Addr, open bool) []*quic.Conn {
	r.connsMu.Lock()
	defer r.connsMu.Unlock()
	return r.agentConnsLocked(from, open)
}

func (r *testRelay) agentConnsLocked(from net.Addr, open bool) []*quic.Conn {
	want := unmap(from.(*net.UDPAddr).AddrPort())
	var out []*quic.Conn
	// An agent socket on the unspecified address has the port only.
	match := func(ap netip.AddrPort) bool {
		return ap == want || want.Addr().IsUnspecified() && ap.Port() == want.Port()
	}
	for _, c := range r.conns {
		now := unmap(c.qc.RemoteAddr().(*net.UDPAddr).AddrPort())
		if (match(c.from) || match(now)) && (!open || c.qc.Context().Err() == nil) {
			out = append(out, c.qc)
		}
	}
	return out
}

// refuse closes qc with UPGRADE and reason, as a relay that needs a newer
// agent. It waits for the first stream, so that the Session call is open.
func (r *testRelay) refuse(ctx context.Context, qc *quic.Conn, reason string) {
	if _, err := qc.AcceptStream(ctx); err != nil {
		_ = qc.CloseWithError(0, "")
		return
	}
	r.refused.Add(1)
	_ = qc.CloseWithError(quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_UPGRADE), reason)
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
	return w.relayOn(t, id, loopback(t), loopback(t))
}

// relayOn starts a relay with the QUIC socket quicSock and the data plane on
// pspSock, and closes them at the end of the test.
func (w *world) relayOn(t testing.TB, id string, quicSock, pspSock net.PacketConn) *testRelay {
	t.Helper()
	cert := w.relayCA.relayCert(t, id)
	plane := vpctest.NewSocketTarget(pspSock)
	cfg := w.relayCfg
	cfg.Relay = &dp.RelayRef{Id: id, Addresses: []string{quicSock.LocalAddr().String()}}
	if a, ok := w.advertise[id]; ok {
		cfg.Relay.Addresses = a
	}
	cfg.Trust, cfg.Addresses, cfg.Target = w.trust, w.addrs, plane
	r, err := relay.NewRouter(cfg)
	require.NoError(t, err)
	r.AddTenant(testProject)
	r.AddVPC(relay.VPCKey{Project: testProject, UID: testVPC}, relay.Network{
		ID: testVNI, Name: testVPC, MTU: w.mtu, DNSServers: w.dns, DNSSearchDomains: w.search,
	})
	tr := &quic.Transport{Conn: quicSock}
	// As at a real relay, the packets are Not-ECT, and the stream limit takes
	// the Attach calls of extra attachments.
	quicConf := &quic.Config{
		EnableDatagrams: true, DisableECN: true, MaxIncomingStreams: 512,
		KeepAlivePeriod: relay.AgentKeepAlive,
	}
	if w.streamWindow != 0 {
		quicConf.InitialStreamReceiveWindow, quicConf.MaxStreamReceiveWindow = w.streamWindow, w.streamWindow
	}
	if w.mesh {
		// As at a real relay, the mesh sessions use the socket of the agents.
		require.NoError(t, r.SetMesh(id, relay.MeshConfig{
			TLS:    &tls.Config{Certificates: []tls.Certificate{*cert}, InsecureSkipVerify: true},
			Verify: w.verifyRelay,
		}, tr, quicConf))
	}
	ln, err := tr.Listen(r.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*cert}}), r.ListenConfig(quicConf))
	require.NoError(t, err)
	srv := &relay.Server{R: r}
	ctx, cancel := context.WithCancel(context.Background())
	// As Serve, but stopAccept ends only the Accept calls. The end of the ctx
	// of Serve also closes the sessions.
	actx, stopAccept := context.WithCancel(ctx)
	out := &testRelay{
		id: id, srv: srv, r: r, addr: quicSock.LocalAddr().String(), psp: pspSock.LocalAddr().String(), stopAccept: stopAccept,
	}
	reason, refuse := w.refuse[id]
	w.mu.Lock()
	w.relays = append(w.relays, out)
	w.mu.Unlock()
	var wg sync.WaitGroup
	wg.Go(func() { _ = r.Run(ctx) })
	wg.Go(func() {
		buf := make([]byte, 65535)
		rx := make([]relaydp.RxPacket, 1)
		var tx relaydp.TxBatch
		for {
			n, from, err := pspSock.ReadFrom(buf)
			if err != nil {
				return
			}
			if ua, ok := from.(*net.UDPAddr); ok {
				rx[0] = relaydp.RxPacket{From: unmap(ua.AddrPort()), Payload: buf[:n]}
				plane.Receive(rx, &tx)
			}
		}
	})
	wg.Go(func() {
		for {
			qc, err := ln.Accept(actx)
			if err != nil {
				return
			}
			if qc.ConnectionState().TLS.NegotiatedProtocol == dp.ALPNMesh {
				wg.Go(func() { srv.ServeConn(ctx, qc) })
				continue
			}
			if refuse {
				wg.Go(func() { out.refuse(ctx, qc, reason) })
				continue
			}
			sc := out.keep(qc)
			wg.Go(func() { srv.ServeConn(ctx, qc, rpc.WithStreams(sc)) })
		}
	})
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		_ = tr.Close()
		_ = quicSock.Close()
		_ = pspSock.Close()
		wg.Wait()
	})
	return out
}

// verifyRelay accepts a relay cert of the relay CA that names the relay.
func (w *world) verifyRelay(chain []*x509.Certificate, name string, _ netip.AddrPort) error {
	if len(chain) == 0 {
		return errors.New("no certificate")
	}
	_, err := chain[0].Verify(x509.VerifyOptions{Roots: w.relayCA.Pool(), DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

// meshRelays returns a new world with two relays of one mesh.
func meshRelays(t *testing.T) (w *world, r1, r2 *testRelay) {
	t.Helper()
	w = newWorld(t)
	w.mesh = true
	r1, r2 = w.relay(t, "relay-1"), w.relay(t, "relay-2")
	joinMesh(t, r1, r2)
	return w, r1, r2
}

// joinMesh makes each relay a member of the mesh of the others, and waits
// until each has the others up. The relays are from a world with mesh.
func joinMesh(t *testing.T, relays ...*testRelay) {
	t.Helper()
	for _, r := range relays {
		var members []relay.MeshMember
		for _, o := range relays {
			if o != r {
				members = append(members, relay.MeshMember{Name: o.id, Addr: netip.MustParseAddrPort(o.addr)})
			}
		}
		r.r.SetMembers(members)
	}
	require.Eventually(t, func() bool {
		for _, r := range relays {
			for _, o := range relays {
				if o != r && !r.r.Up(o.id) {
					return false
				}
			}
		}
		return true
	}, 10*time.Second, 10*time.Millisecond, "mesh sessions")
}

// countConn counts the PSP packets that a relay socket gets from each address.
type countConn struct {
	net.PacketConn
	mu  sync.Mutex
	psp map[netip.AddrPort]int
}

// wrap makes c read from pc.
func (c *countConn) wrap(pc net.PacketConn) *countConn {
	c.PacketConn = pc
	return c
}

func (c *countConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if ua, ok := addr.(*net.UDPAddr); ok && err == nil && isPSP(p[:n]) {
		c.mu.Lock()
		if c.psp == nil {
			c.psp = map[netip.AddrPort]int{}
		}
		c.psp[unmap(ua.AddrPort())]++
		c.mu.Unlock()
	}
	return n, addr, err
}

// got returns the PSP packets that c got from the address from.
func (c *countConn) got(from netip.AddrPort) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.psp[from]
}

// gotPort returns the PSP packets that c got from the port, from each address.
func (c *countConn) gotPort(port uint16) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for from, k := range c.psp {
		if from.Port() == port {
			n += k
		}
	}
	return n
}

// attachEvent is one OnAttach call.
type attachEvent struct {
	addr     netip.Addr
	prefixes []netip.Prefix
}

// testAgent is an agent with a netstack on its binding.
type testAgent struct {
	a       *Agent
	w       *world
	tr      *quic.Transport
	ids     *identity.Manager
	enrolls atomic.Int32
	bind    atomic.Pointer[psp.Binding] // From OnAttach.
	// writeIdentity replaces the identity file with a new cert that is valid
	// for life. Nil without agentOptions.identityFile.
	writeIdentity func(life time.Duration)
	attach        chan attachEvent
	cancel        context.CancelFunc
	done          chan struct{}
	// pspPath reports whether the PSP probes of the agent get a reply. Then
	// attached waits for PSP mode.
	pspPath func() bool
	// noPSP makes attached wait until the first probe of the session fails.
	noPSP bool

	stackOnce sync.Once
	stack     *stack.Stack
	vpcStack  bool
	ns        *netstack.Stack // Set with vpcStack.

	routesMu sync.Mutex
	routes   map[netip.Prefix]bool // From OnRoutes.
	routeLog []string              // "+prefix" or "-prefix" from OnRoutes, in order.

	extraMu sync.Mutex
	extras  map[string]netip.Addr // Last address of each extra attachment, from OnAttachment and OnDetach.
	// log has "attach name address", "deprecate name address", "prefer name
	// address" or "detach name address" for each callback of an address, in order.
	log []string
}

type agentOptions struct {
	life  time.Duration // Cert life. Zero means 24 hours.
	mtu   int           // Config.MTU.
	conn  *lossyConn    // Wraps the agent socket if set.
	block *blockConn    // Wraps the agent socket if set.
	flood *floodConn    // Wraps the agent socket if set.
	slow  *slowConn     // Wraps the agent socket if set.
	move  *moveConn     // Wraps the agent socket if set.
	// noPSP makes the agent socket a vpctest.NoProbeConn, so the sessions fall
	// back to QUIC mode. attached then waits for the probe timeout.
	noPSP bool
	// quicStart makes attached return while the session is in QUIC mode. Else it
	// waits for PSP mode when the PSP probes of the agent get a reply.
	quicStart bool
	udp       *net.UDPConn // Agent socket. Nil means a new socket on loopback.
	tcp       bool         // Adds TCP to the netstack.
	routes    []netip.Prefix

	// identity is the name in the agent cert. Empty means the agent name. The
	// attachment always has the agent name.
	identity string
	// identityFile gives the agent an identity file in place of an enroll
	// function. The file has the relays and the relay roots, and Config has none.
	identityFile bool
	// identityPath is the path of the identity file. Empty means a new file
	// for the agent. A file that is there stays, so agents can have one file.
	identityPath string

	relays   []identity.Relay // Config.Relays. Nil means the relay of the agent.
	sessions int              // Config.Sessions. Zero means 1.
	noRoots  bool             // No Config.RelayRoots.
	// enrolled gives the relays and the relay roots of enroll n, from 1. Then
	// Config.Relays is empty.
	enrolled func(n int32) ([]identity.Relay, []byte, error)

	// vpcStack makes the netstack with pkg/netstack.NewStack and its VPC
	// options, as vpc connect does. It always has TCP.
	vpcStack bool

	// runErr gets the result of Run. Nil means that an error of Run fails the test.
	runErr chan error
	// localRoutesOnly sets Config.LocalRoutesOnly.
	localRoutesOnly bool
	// rttChoice keeps the band and the wait of the relay choice. Else the relays
	// that answer in testWindow are equal, so the first relay of the list wins.
	rttChoice bool
	// rttWait sets the wait of the relay choice. Zero keeps it.
	rttWait time.Duration
	// pspRetry sets Config.PSPRetryMin, PSPRetryMax and PSPRetryNext. A zero
	// keeps the value of the test constructor.
	pspRetry [3]time.Duration
	// relist sets Config.RelistMin and RelistMax.
	relist [2]time.Duration
	// lanes sets Config.Lanes.
	lanes int
	// onAttach and onAttachment run at the start of the OnAttach and the
	// OnAttachment callbacks.
	onAttach     func(addr netip.Addr)
	onAttachment func(at Attachment)
}

// lossyConn drops the sent packets that are larger than a max that is not zero.
// While limitProbes is set, it sends only probeBudget more path probes.
type lossyConn struct {
	net.PacketConn
	max         atomic.Int32
	bigProbes   atomic.Bool // Path probes larger than max are sent too.
	limitProbes atomic.Bool
	probeBudget atomic.Int32
	probes      atomic.Int32 // Path probes to send, with the dropped ones.

	mu   sync.Mutex
	runs []probeRun // Path probes of each session, oldest first.
}

// probeRun is the number of path probes with one session ID.
type probeRun struct {
	sid [8]byte
	n   int
}

// probeRuns returns a copy of the probe counts for each session.
func (c *lossyConn) probeRuns() []probeRun {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.runs)
}

func (c *lossyConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if sid, ok := p2p.ProbeSID(p); ok {
		c.mu.Lock()
		i := slices.IndexFunc(c.runs, func(r probeRun) bool { return r.sid == sid })
		if i < 0 {
			i, c.runs = len(c.runs), append(c.runs, probeRun{sid: sid})
		}
		c.runs[i].n++
		c.mu.Unlock()
	}
	probe := len(p) > 0 && p[0] == p2p.TypeProbe
	if probe {
		c.probes.Add(1)
		if c.limitProbes.Load() && c.probeBudget.Add(-1) < 0 {
			return len(p), nil
		}
	}
	if m := int(c.max.Load()); m != 0 && len(p) > m && !(probe && c.bigProbes.Load()) {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

// slowConn sends the packets to a relay after a delay, which adds the delay to
// the round-trip time of that relay.
type slowConn struct {
	net.PacketConn
	mu     sync.Mutex
	delays map[string]time.Duration // By relay address.
	late   map[string]*lateStart    // By relay address.
}

// lateStart holds packets to a relay: all packets in the time open after the
// first one, as a path that opens late, or the first path probe for the time probe.
type lateStart struct {
	open, probe time.Duration
	first       time.Time // Send time of the first packet.
	probed      bool
}

// hold returns the time that the packet p, sent at now, waits.
func (l *lateStart) hold(p []byte, now time.Time) time.Duration {
	if l.first.IsZero() {
		l.first = now
	}
	if len(p) > 0 && p[0] == p2p.TypeProbe && !l.probed {
		l.probed = true
		return l.probe
	}
	return max(l.open-now.Sub(l.first), 0)
}

func (c *slowConn) set(r *testRelay, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.delays == nil {
		c.delays = map[string]time.Duration{}
	}
	c.delays[r.addr], c.delays[r.psp] = d, d
}

// setLate makes the start of the path to r late.
func (c *slowConn) setLate(r *testRelay, l lateStart) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.late == nil {
		c.late = map[string]*lateStart{}
	}
	c.late[r.addr], c.late[r.psp] = &l, &l
}

func (c *slowConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	d := c.delays[addr.String()]
	if l := c.late[addr.String()]; l != nil {
		d += l.hold(p, time.Now())
	}
	c.mu.Unlock()
	if d == 0 {
		return c.PacketConn.WriteTo(p, addr)
	}
	b := bytes.Clone(p)
	time.AfterFunc(d, func() { _, _ = c.PacketConn.WriteTo(b, addr) })
	return len(p), nil
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
	if opts.noPSP {
		conn = vpctest.NoProbeConn{UDPConn: udp}
	}
	if opts.conn != nil {
		opts.conn.PacketConn = conn
		conn = opts.conn
	}
	if opts.block != nil {
		opts.block.PacketConn = conn
		conn = opts.block
	}
	if opts.flood != nil {
		opts.flood.PacketConn = conn
		conn = opts.flood
	}
	if opts.move != nil {
		opts.move.PacketConn = conn
		conn = opts.move
	}
	if opts.slow != nil {
		opts.slow.PacketConn = conn
		conn = opts.slow
	}
	ta := &testAgent{
		w: w, tr: &quic.Transport{Conn: conn}, attach: make(chan attachEvent, 16), done: make(chan struct{}),
		routes: map[netip.Prefix]bool{}, extras: map[string]netip.Addr{}, vpcStack: opts.vpcStack,
	}
	ta.pspPath = func() bool {
		return !opts.noPSP && !opts.quicStart && (opts.conn == nil || !opts.conn.limitProbes.Load())
	}
	ta.noPSP = opts.noPSP && !opts.quicStart
	enroll := func(context.Context) (*identity.Credential, error) {
		n := ta.enrolls.Add(1)
		cred := w.enrollCA().credential(t, testProject, testVPC, cmp.Or(opts.identity, name), opts.life)
		if opts.enrolled == nil {
			return cred, nil
		}
		relays, roots, err := opts.enrolled(n)
		if err != nil {
			return nil, err
		}
		return cred, cred.SetRelays(relays, roots)
	}
	ids := identity.NewManager(filepath.Join(t.TempDir(), "cred.json"), enroll)
	if opts.identityFile {
		path := cmp.Or(opts.identityPath, filepath.Join(t.TempDir(), "identity.json"))
		relays := opts.relays
		if relays == nil {
			relays = []identity.Relay{r.ref()}
		}
		roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.relayCA.Cert.Raw})
		ta.writeIdentity = func(life time.Duration) {
			cred := w.enrollCA().credential(t, testProject, testVPC, cmp.Or(opts.identity, name), life)
			require.NoError(t, cred.SetRelays(relays, roots))
			require.NoError(t, identity.SaveCredential(path, cred))
		}
		if _, err := os.Stat(path); err != nil {
			ta.writeIdentity(opts.life)
		}
		ids = identity.NewFileManager(path, identity.WithPollInterval(filePoll))
		opts.relays, opts.noRoots = nil, true
	}
	cfg := Config{
		Identity:   ids,
		Relays:     opts.relays,
		RelayRoots: w.relayCA.Pool(),
		Sessions:   cmp.Or(opts.sessions, 1),
		Transport:  ta.tr,
		Name:       name,
		Routes:     opts.routes,
		MTU:        opts.mtu,

		LocalRoutesOnly: opts.localRoutesOnly,
		// A first PSP probe that a loaded host loses must not keep a session in QUIC mode.
		PSPRetryMin:  cmp.Or(opts.pspRetry[0], 200*time.Millisecond),
		PSPRetryMax:  opts.pspRetry[1],
		PSPRetryNext: cmp.Or(opts.pspRetry[2], 100*time.Millisecond),
		RelistMin:    opts.relist[0],
		RelistMax:    opts.relist[1],
		Lanes:        opts.lanes,
		OnAttach: func(b *psp.Binding, addr netip.Addr, prefixes []netip.Prefix) {
			if opts.onAttach != nil {
				opts.onAttach(addr)
			}
			if old := ta.bind.Swap(b); old != nil && old != b {
				t.Errorf("agent %s: OnAttach of %s gives another binding", name, addr)
			}
			ta.note(t, "attach", name, addr)
			ta.netstack(t, b, addr, opts.tcp)
			ta.attach <- attachEvent{addr, prefixes}
		},
		OnRoutes: func(add, remove []netip.Prefix) {
			if len(ta.events(name)) == 0 {
				t.Errorf("agent %s: OnRoutes before the first OnAttach: add %v, remove %v", name, add, remove)
			}
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
			if opts.onAttachment != nil {
				opts.onAttachment(at)
			}
			ta.extraMu.Lock()
			ta.extras[at.Name] = at.Address
			ta.extraMu.Unlock()
			ta.note(t, "attach", at.Name, at.Address)
			ta.netstack(t, ta.binding(), at.Address, opts.tcp)
		},
		OnDeprecated: func(at Attachment) {
			ta.note(t, "deprecate", at.Name, at.Address)
			ta.deprecateAddr(t, at.Address)
		},
		OnPreferred: func(at Attachment) {
			ta.note(t, "prefer", at.Name, at.Address)
			ta.preferAddr(t, at.Address)
		},
		OnDetach: func(at Attachment) {
			ta.extraMu.Lock()
			if ta.extras[at.Name] == at.Address {
				delete(ta.extras, at.Name)
			}
			ta.extraMu.Unlock()
			ta.note(t, "detach", at.Name, at.Address)
			ta.removeAddr(t, at.Address)
		},
	}
	if cfg.Relays == nil && opts.enrolled == nil && !opts.identityFile {
		cfg.Relays = []identity.Relay{r.ref()}
	}
	if opts.noRoots {
		cfg.RelayRoots = nil
	}
	if !opts.rttChoice {
		cfg.RTTBand, cfg.RTTWaitMin, cfg.RTTWaitMax = time.Hour, testWindow, testWindow
	}
	if opts.rttWait != 0 {
		cfg.RTTWaitMin, cfg.RTTWaitMax = opts.rttWait, opts.rttWait
	}
	ta.ids = ids
	ta.a = New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	ta.cancel = cancel
	go func() {
		defer close(ta.done)
		err := ta.a.Run(ctx)
		if opts.runErr != nil {
			opts.runErr <- err
		} else if err != nil {
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

// binding returns the binding of the last OnAttach.
func (ta *testAgent) binding() *psp.Binding { return ta.bind.Load() }

// sessionRef is a relay session of an agent as its relay sees it.
type sessionRef struct {
	addr string     // Address of the relay.
	self netip.Addr // Overlay address of the agent on the session.
	qc   *quic.Conn // The connection at the relay. Nil when the relay has none.
}

// sameSession checks that got is the session want. It compares the
// connections by identity, as assert.Equal reads their internals.
func sameSession(t *testing.T, want, got sessionRef, msgAndArgs ...any) bool {
	t.Helper()
	if want.qc == nil {
		return assert.Fail(t, fmt.Sprintf("relay %s has no connection of the session %s", want.addr, want.self), msgAndArgs...)
	}
	if want == got {
		return true
	}
	return assert.Fail(t, fmt.Sprintf("other relay session: want %s %s, got %s %s", want.addr, want.self, got.addr, got.self), msgAndArgs...)
}

// ended reports whether the relay side of the session closed.
func (s sessionRef) ended() bool { return s.qc == nil || s.qc.Context().Err() != nil }

// sessionOf returns the session of c: the oldest open connection of the agent
// on the relay of c.
func (ta *testAgent) sessionOf(c ConnStatus) sessionRef {
	ref := sessionRef{addr: c.Relay, self: c.Address}
	if r := ta.w.relayAt(c.Relay); r != nil {
		if qcs := r.agentConns(ta.tr.Conn.LocalAddr(), true); len(qcs) > 0 {
			ref.qc = qcs[0]
		}
	}
	return ref
}

// sessions returns the attached sessions of ta in rank order.
func (ta *testAgent) sessions() []sessionRef {
	var out []sessionRef
	for _, c := range ta.a.Status().Connections {
		if !c.Draining {
			out = append(out, ta.sessionOf(c))
		}
	}
	return out
}

// current returns the session with the default address: the attached session
// with the lowest rank, else the draining one.
func (ta *testAgent) current() sessionRef {
	cs := ta.a.Status().Connections
	for _, c := range cs {
		if !c.Draining {
			return ta.sessionOf(c)
		}
	}
	if len(cs) > 0 {
		return ta.sessionOf(cs[0])
	}
	return sessionRef{}
}

// reconnect makes the relay close the current session. The agent then opens a new one.
func (ta *testAgent) reconnect() {
	if qc := ta.current().qc; qc != nil {
		_ = qc.CloseWithError(0, "next session")
	}
}

// extraAddr returns the address of the extra attachment name from OnAttachment.
func (ta *testAgent) extraAddr(name string) netip.Addr {
	ta.extraMu.Lock()
	defer ta.extraMu.Unlock()
	return ta.extras[name]
}

// note adds a callback of an address to the log. It fails t when an address
// gets OnAttach before the OnDetach of its last OnAttach, or OnDetach with none.
func (ta *testAgent) note(t *testing.T, event, name string, addr netip.Addr) {
	ta.extraMu.Lock()
	defer ta.extraMu.Unlock()
	held := false
	for _, e := range ta.log {
		if f := strings.Fields(e); f[2] == addr.String() && (f[0] == "attach" || f[0] == "detach") {
			held = f[0] == "attach"
		}
	}
	if (event == "attach" || event == "detach") && held == (event == "attach") {
		t.Errorf("agent %s: %s of address %s in the wrong order: %v", name, event, addr, ta.log)
	}
	ta.log = append(ta.log, event+" "+name+" "+addr.String())
}

// deprecateAddr makes addr not preferred in the netstack.
func (ta *testAgent) deprecateAddr(t *testing.T, addr netip.Addr) {
	var err error
	if ta.ns != nil {
		err = ta.ns.DeprecateAddr(netip.PrefixFrom(addr, addr.BitLen()))
	} else if terr := ta.stack.SetAddressLifetimes(1, tcpip.AddrFromSlice(addr.AsSlice()), stack.AddressLifetimes{Deprecated: true}); terr != nil {
		err = errors.New(terr.String())
	}
	if err != nil {
		t.Errorf("deprecate address %s: %v", addr, err)
	}
}

// preferAddr makes addr preferred again in the netstack.
func (ta *testAgent) preferAddr(t *testing.T, addr netip.Addr) {
	var err error
	if ta.ns != nil {
		err = ta.ns.PreferAddr(netip.PrefixFrom(addr, addr.BitLen()))
	} else if terr := ta.stack.SetAddressLifetimes(1, tcpip.AddrFromSlice(addr.AsSlice()), stack.AddressLifetimes{}); terr != nil {
		err = errors.New(terr.String())
	}
	if err != nil {
		t.Errorf("prefer address %s: %v", addr, err)
	}
}

// events returns the callbacks for the addresses of the attachment name.
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

// modeOf returns the data mode of the session with the address addr.
func (ta *testAgent) modeOf(addr netip.Addr) dp.Mode {
	for _, c := range ta.a.Status().Connections {
		if c.Address == addr {
			return c.Mode
		}
	}
	return dp.Mode_MODE_UNSPECIFIED
}

// fellBack reports whether the session with the address addr is in QUIC mode
// because its probe failed.
func (ta *testAgent) fellBack(addr netip.Addr) bool {
	for _, c := range ta.a.Status().Connections {
		if c.Address == addr {
			return c.Mode == dp.Mode_MODE_QUIC && c.Reason == dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT
		}
	}
	return false
}

// attached waits for the next OnAttach call, then for PSP mode of an agent with a
// PSP path, or for the probe timeout of an agent with agentOptions.noPSP.
func (ta *testAgent) attached(t *testing.T) attachEvent {
	t.Helper()
	select {
	case ev := <-ta.attach:
		switch {
		case ta.pspPath():
			require.Eventually(t, func() bool { return ta.modeOf(ev.addr) == dp.Mode_MODE_PSP }, 10*time.Second, time.Millisecond,
				"session did not change to PSP mode")
		case ta.noPSP:
			require.Eventually(t, func() bool { return ta.fellBack(ev.addr) }, 10*time.Second, time.Millisecond,
				"session did not fall back to QUIC mode")
		}
		return ev
	case <-time.After(10 * time.Second):
		t.Log(vpcStacks())
		t.Fatal("agent did not attach in 10 s")
		return attachEvent{}
	}
}

// vpcStacks returns the stacks of the goroutines that are in the agent, the
// relay or rpc.
func vpcStacks() string {
	buf := make([]byte, 64<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var b strings.Builder
	for g := range strings.SplitSeq(string(buf), "\n\n") {
		if strings.Contains(g, "/pkg/vpc/agent.") || strings.Contains(g, "/pkg/vpc/relay.") || strings.Contains(g, "/pkg/vpc/rpc.") {
			b.WriteString(g)
			b.WriteString("\n\n")
		}
	}
	return b.String()
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

// closed reports whether ch is closed.
func closed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// send sends msg once from src to dst:port.
func send(t *testing.T, s *stack.Stack, src, dst netip.Addr, port uint16, msg string) {
	t.Helper()
	c, err := gonet.DialUDP(s, fullAddr(src, 0), fullAddr(dst, port), ipv6.ProtocolNumber)
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Write([]byte(msg))
	require.NoError(t, err)
}

// pspPackets returns the sum of the PSP packet counts of the lanes of a binding.
func pspPackets(lanes []uint64) (n uint64) {
	for _, c := range lanes {
		n += c
	}
	return n
}

// unreachableIn returns the ICMPv6 destination unreachable errors that the
// netstack of ta got.
func unreachableIn(ta *testAgent) uint64 {
	return ta.stack.Stats().ICMP.V6.PacketsReceived.DstUnreachable.Value()
}
