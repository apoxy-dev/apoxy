// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// whoMethod is a test call on a mesh session. The called relay answers with
// the name of the caller, which it knows from Open.
const whoMethod = "/test.Mesh/Who"

// meshCert issues a cert that names relay name. A relay uses it on both ends
// of a mesh session.
func (ca *testCA) meshCert(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(6),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// verifyName is the MeshVerify of the tests: the cert is from ca and names
// the relay.
func (ca *testCA) verifyName(chain []*x509.Certificate, name string, _ netip.AddrPort) error {
	if len(chain) == 0 {
		return errors.New("no certificate")
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: ca.pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return err
	}
	if cn := chain[0].Subject.CommonName; cn != name {
		return fmt.Errorf("certificate is for %q, not for %q", cn, name)
	}
	return nil
}

// meshTLS is the TLS config of a test relay. The handshake checks nothing,
// so the verify hook makes the decision.
func meshTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
}

// cutConn is a UDP socket that can lose all its packets, as a dead path does,
// or the packets that it sends above a size, as a path with a low MTU does.
type cutConn struct {
	net.PacketConn
	cut atomic.Bool
	max atomic.Int64 // Longest packet that WriteTo sends. Zero is no limit.
}

func (c *cutConn) WriteTo(b []byte, to net.Addr) (int, error) {
	if max := c.max.Load(); c.cut.Load() || max > 0 && int64(len(b)) > max {
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, to)
}

func (c *cutConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.PacketConn.ReadFrom(b)
		if err != nil || !c.cut.Load() {
			return n, from, err
		}
	}
}

// verifyCall is one call of the verify hook of a node.
type verifyCall struct {
	name string
	from netip.AddrPort
}

// meshNode is a relay with a mesh on a loopback socket.
type meshNode struct {
	m    *Mesh
	name string
	addr netip.AddrPort
	cut  *atomic.Bool // On a node from newCutNode: true loses all packets of the socket.
	tr   *quic.Transport

	changes   chan MeshChange
	sessions  chan *MeshSession
	datagrams chan string // "<name of the sender>:<data>".

	mu       sync.Mutex
	verified []verifyCall

	ctx    context.Context
	cancel context.CancelFunc // Ends Run, as when the relay stops.
	wg     sync.WaitGroup
}

// newMeshNode returns a relay name with a cert from ca. It does not listen
// or dial before start.
func newMeshNode(t *testing.T, ca *testCA, name string) *meshNode {
	t.Helper()
	return newNode(t, ca, name, false)
}

// newCutNode returns a node with a socket that the test can cut.
func newCutNode(t *testing.T, ca *testCA, name string) *meshNode {
	t.Helper()
	return newNode(t, ca, name, true)
}

func newNode(t *testing.T, ca *testCA, name string, cut bool) *meshNode {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	n := &meshNode{
		name:      name,
		addr:      netip.MustParseAddrPort(udp.LocalAddr().String()),
		changes:   make(chan MeshChange, 256),
		sessions:  make(chan *MeshSession, 256),
		datagrams: make(chan string, 256),
	}
	cfg := MeshConfig{
		Relay: &dp.RelayRef{Id: "region-1.relay.example.net", Addresses: []string{n.addr.String()}},
		TLS:   meshTLS(ca.meshCert(t, name)),
		Verify: func(chain []*x509.Certificate, name string, from netip.AddrPort) error {
			n.mu.Lock()
			n.verified = append(n.verified, verifyCall{name, from})
			n.mu.Unlock()
			return ca.verifyName(chain, name, from)
		},
	}
	var pc net.PacketConn = udp
	if cut {
		c := &cutConn{PacketConn: udp}
		n.cut, pc = &c.cut, c
	}
	n.m, err = NewMesh(name, cfg)
	require.NoError(t, err)
	n.m.OnChange(func(c MeshChange) { n.changes <- c })
	n.m.OnSession(func(s *MeshSession) { n.sessions <- s })
	n.m.OnDatagram(func(s *MeshSession, b []byte) { n.datagrams <- s.Name() + ":" + string(b) })
	rpc.HandleUnary(n.m.mux, whoMethod, func(ctx context.Context, _ *dp.MeshOpenRequest) (*dp.MeshOpenResponse, error) {
		s, err := n.m.SessionOf(ctx)
		if err != nil {
			return nil, err
		}
		return &dp.MeshOpenResponse{Name: s.Name()}, nil
	})
	n.tr = &quic.Transport{Conn: pc}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	t.Cleanup(func() {
		n.cancel()
		n.wg.Wait()
		_ = n.tr.Close()
		_ = udp.Close()
	})
	return n
}

func (n *meshNode) member() MeshMember { return MeshMember{Name: n.name, Addr: n.addr} }

// listen accepts mesh sessions on the socket of n, as a relay host does.
func (n *meshNode) listen(t *testing.T) {
	t.Helper()
	ln, err := n.tr.Listen(n.m.TLSConfig(), n.m.ListenConfig(&quic.Config{EnableDatagrams: true}))
	require.NoError(t, err)
	n.wg.Go(func() {
		defer ln.Close()
		for {
			qc, err := ln.Accept(n.ctx)
			if err != nil {
				return
			}
			n.wg.Go(func() { n.m.ServeConn(n.ctx, qc) })
		}
	})
}

// run starts Run of the mesh on the socket of n.
func (n *meshNode) run() {
	n.wg.Go(func() { n.m.Run(n.ctx, n.tr, &quic.Config{EnableDatagrams: true}) })
}

func (n *meshNode) start(t *testing.T) {
	t.Helper()
	n.listen(t)
	n.run()
}

// count returns the number of connections that the mesh of n keeps.
func (n *meshNode) count() int {
	n.m.mu.Lock()
	defer n.m.mu.Unlock()
	return len(n.m.sessions)
}

func (n *meshNode) verifyCalls() []verifyCall {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]verifyCall(nil), n.verified...)
}

// change returns the next change of n. It fails after d with no change.
func (n *meshNode) change(t *testing.T, d time.Duration) MeshChange {
	t.Helper()
	select {
	case c := <-n.changes:
		return c
	case <-time.After(d):
		t.Fatalf("%s: no change of a member in %v", n.name, d)
		return MeshChange{}
	}
}

// session returns the next new session of n.
func (n *meshNode) session(t *testing.T) *MeshSession {
	t.Helper()
	select {
	case s := <-n.sessions:
		return s
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: no new session in 10 s", n.name)
		return nil
	}
}

// meshPair starts relay-a, which dials, and relay-b, and waits for their
// session. With cutB, the test can cut the socket of relay-b.
func meshPair(t *testing.T, cutB bool) (a, b *meshNode, sa, sb *MeshSession) {
	t.Helper()
	ca := newCA(t)
	a, b = newMeshNode(t, ca, "relay-a"), newNode(t, ca, "relay-b", cutB)
	a.m.SetMembers([]MeshMember{b.member()})
	b.m.SetMembers([]MeshMember{a.member()})
	b.start(t)
	a.start(t)
	require.Equal(t, MeshChange{Name: "relay-b", Up: true}, a.change(t, 10*time.Second))
	require.Equal(t, MeshChange{Name: "relay-a", Up: true}, b.change(t, 10*time.Second))
	return a, b, a.session(t), b.session(t)
}

// one reports whether n keeps one connection and it is an open session. A
// refused connection stays for a short time after its close.
func (n *meshNode) one() bool {
	n.m.mu.Lock()
	defer n.m.mu.Unlock()
	for _, s := range n.m.sessions {
		select {
		case <-s.ready:
			return len(n.m.sessions) == 1
		default:
		}
	}
	return false
}

// stays checks that each node keeps one connection for a short time.
func stays(t *testing.T, nodes ...*meshNode) {
	t.Helper()
	for _, n := range nodes {
		require.Eventually(t, n.one, 10*time.Second, 10*time.Millisecond, "%s keeps one session", n.name)
	}
	for _, n := range nodes {
		assert.Never(t, func() bool { return n.count() != 1 }, 500*time.Millisecond, 10*time.Millisecond, "%s keeps one session", n.name)
	}
}

// TestMeshSession starts two relays. The relay with the lower name dials one
// session from its listening socket, and each side calls and sends datagrams.
func TestMeshSession(t *testing.T) {
	t.Parallel()
	a, b, sa, sb := meshPair(t, false)

	assert.True(t, sa.dialer, "relay-a dialed")
	assert.False(t, sb.dialer, "relay-b accepted")
	assert.Same(t, sa, a.m.Session("relay-b"))
	assert.Same(t, sb, b.m.Session("relay-a"))
	assert.True(t, a.m.Up("relay-b"))
	assert.True(t, b.m.Up("relay-a"))
	assert.False(t, a.m.Up("relay-c"), "a relay that is not a member is not up")
	stays(t, a, b)

	// Open gave each side the name, the RelayRef and the version of the other.
	for _, tc := range []struct {
		s    *MeshSession
		peer *meshNode
	}{{sa, b}, {sb, a}} {
		assert.Equal(t, tc.peer.name, tc.s.Name())
		assert.Equal(t, "region-1.relay.example.net", tc.s.Relay().GetId())
		assert.Equal(t, []string{tc.peer.addr.String()}, tc.s.Relay().GetAddresses())
		assert.Equal(t, dp.Revision, tc.s.Version().GetRevision())
	}
	// Each side checked the cert of the other with the name and the address of
	// the member. relay-b saw the listening socket of relay-a as the source.
	assert.Equal(t, []verifyCall{{"relay-b", b.addr}}, a.verifyCalls())
	assert.Equal(t, []verifyCall{{"relay-a", a.addr}}, b.verifyCalls())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, tc := range []struct {
		from *meshNode
		s    *MeshSession
		to   *meshNode
	}{{a, sa, b}, {b, sb, a}} {
		// A handler on the called relay knows the caller from the session.
		out := &dp.MeshOpenResponse{}
		require.NoError(t, tc.s.conn.Invoke(ctx, whoMethod, &dp.MeshOpenRequest{}, out))
		assert.Equal(t, tc.from.name, out.GetName())
		// A relay with no router has no trunk, and that answer is not a session error.
		_, err := tc.s.Client().TrunkKeys(ctx, &dp.KeysRequest{})
		assert.Equal(t, rpc.Unimplemented, rpc.CodeOf(err))
		// A second Open does not change the session.
		_, err = tc.s.Client().Open(ctx, &dp.MeshOpenRequest{Version: tc.from.m.ver, Name: tc.from.name})
		assert.Equal(t, rpc.FailedPrecondition, rpc.CodeOf(err))

		require.NoError(t, tc.s.SendDatagram([]byte("hello")))
		select {
		case got := <-tc.to.datagrams:
			assert.Equal(t, tc.from.name+":hello", got)
		case <-ctx.Done():
			t.Fatalf("%s got no datagram", tc.to.name)
		}
	}
	stays(t, a, b)
}

// TestMeshOneSession makes more dials than the one that the mesh needs. One
// session of the two relays stays, and the relay with the lower name dialed it.
func TestMeshOneSession(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		// dial makes the extra dials after both relays listen and relay-b runs.
		// runA starts the dial loop of relay-a.
		dial func(t *testing.T, a, b *meshNode, runA func())
	}{
		{
			name: "both relays dial at the same time",
			dial: func(t *testing.T, a, b *meshNode, runA func()) {
				var wg sync.WaitGroup
				for range 4 {
					wg.Go(func() {
						_, err := b.m.dial(b.ctx, b.m.member("relay-a"))
						assert.ErrorContains(t, err, "the relay with the lower name dials")
					})
				}
				runA()
				wg.Wait()
			},
		},
		{
			name: "the relay with the higher name dials first",
			dial: func(t *testing.T, a, b *meshNode, runA func()) {
				_, err := b.m.dial(b.ctx, b.m.member("relay-a"))
				assert.ErrorContains(t, err, "the relay with the lower name dials")
				assert.False(t, a.m.Up("relay-b"))
				runA()
			},
		},
		{
			name: "the relay with the higher name dials an open session",
			dial: func(t *testing.T, a, b *meshNode, runA func()) {
				runA()
				old := a.session(t)
				_, err := b.m.dial(b.ctx, b.m.member("relay-a"))
				assert.ErrorContains(t, err, "the relay with the lower name dials")
				assert.Same(t, old, a.m.Session("relay-b"), "the session stays")
				assert.NoError(t, old.Context().Err())
			},
		},
		{
			name: "the relay with the lower name dials again",
			dial: func(t *testing.T, a, b *meshNode, runA func()) {
				runA()
				old := a.session(t)
				// The second session replaces the first. Then the dial loop of relay-a
				// sees the end of its session and dials the third, which stays.
				second, err := a.m.dial(a.ctx, a.m.member("relay-b"))
				require.NoError(t, err)
				require.Same(t, second, a.session(t))
				third := a.session(t)
				for _, s := range []*MeshSession{old, second} {
					select {
					case <-s.Context().Done():
					case <-time.After(5 * time.Second):
						t.Fatal("a replaced session did not close in 5 s")
					}
				}
				assert.Same(t, third, a.m.Session("relay-b"))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ca := newCA(t)
			a, b := newMeshNode(t, ca, "relay-a"), newMeshNode(t, ca, "relay-b")
			a.m.SetMembers([]MeshMember{b.member()})
			b.m.SetMembers([]MeshMember{a.member()})
			b.start(t)
			a.listen(t)
			// relay-b has its transport after Run starts.
			require.Eventually(t, func() bool {
				b.m.mu.Lock()
				defer b.m.mu.Unlock()
				return b.m.tr != nil
			}, 5*time.Second, time.Millisecond)

			tc.dial(t, a, b, a.run)

			stays(t, a, b)
			sa, sb := a.m.Session("relay-b"), b.m.Session("relay-a")
			require.NotNil(t, sa)
			require.NotNil(t, sb)
			assert.True(t, sa.dialer, "relay-a dialed the session that stays")
			assert.False(t, sb.dialer)
			assert.True(t, a.m.Up("relay-b"))
			assert.True(t, b.m.Up("relay-a"))
			// The two ends are one connection: a call on it gets an answer.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			out := &dp.MeshOpenResponse{}
			require.NoError(t, sb.conn.Invoke(ctx, whoMethod, &dp.MeshOpenRequest{}, out))
			assert.Equal(t, "relay-b", out.GetName())
		})
	}
}

// rawDial dials the mesh of n with cert, as a relay that is not in the test.
func (n *meshNode) rawDial(t *testing.T, cert tls.Certificate) quic.Connection {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udp}
	t.Cleanup(func() { _ = tr.Close(); _ = udp.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conf := meshTLS(cert)
	conf.NextProtos = []string{dp.ALPNMesh}
	qc, err := tr.Dial(ctx, net.UDPAddrFromAddrPort(n.addr), conf, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	return qc
}

// TestMeshOpenAccept sends Open from a dialer that the test controls: an old
// revision gets UPGRADE, and a relay that is not a member gets NOT_MEMBER.
func TestMeshOpenAccept(t *testing.T) {
	t.Parallel()
	ok := dp.LocalVersion("test")
	cases := []struct {
		name    string
		cert    string      // Name in the cert of the dialer. Empty is the name in Open.
		otherCA bool        // The cert of the dialer is from another CA.
		min     uint32      // Minimum revision of the relay. Zero keeps it.
		open    string      // Name in Open.
		version *dp.Version // Version in Open.
		opens   bool        // The relay opens the session.
		want    dp.MeshCloseCode
		reason  string
	}{
		{name: "member at this revision", open: "relay-a", version: ok, opens: true},
		{name: "member at a later revision", open: "relay-a", version: &dp.Version{Revision: dp.Revision + 1}, opens: true},
		{
			name: "revision from before the mesh", open: "relay-a", version: &dp.Version{Revision: meshRevision - 1},
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_UPGRADE,
			reason: fmt.Sprintf("relay revision %d is below the minimum %d", meshRevision-1, meshRevision),
		},
		{
			name: "no version", open: "relay-a",
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_UPGRADE,
			reason: fmt.Sprintf("relay revision 0 is below the minimum %d", meshRevision),
		},
		{
			name: "revision below the minimum of the relay", open: "relay-a", version: ok, min: dp.Revision + 1,
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_UPGRADE,
			reason: fmt.Sprintf("relay revision %d is below the minimum %d", dp.Revision, dp.Revision+1),
		},
		{
			name: "name that is not a member", open: "relay-x", version: ok,
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER,
			reason: `relay "relay-x" is not a member`,
		},
		{
			name: "no name", open: "", cert: "relay-a", version: ok,
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER,
			reason: "relay certificate rejected",
		},
		{
			name: "name that is not a member with the cert of a member", open: "relay-x", cert: "relay-a", version: ok,
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER,
			reason: "relay certificate rejected",
		},
		{
			name: "member with a higher name and a cert of another CA", open: "relay-z", otherCA: true, version: ok,
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER,
			reason: "relay certificate rejected",
		},
		{
			name: "name of the relay itself", open: "relay-m", version: ok,
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER,
			reason: `relay "relay-m" is not a member`,
		},
		{
			name: "name of a member with the cert of another relay", open: "relay-a", cert: "relay-c", version: ok,
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER,
			reason: "relay certificate rejected",
		},
		{
			name: "name of a member with a cert of another CA", open: "relay-a", otherCA: true, version: ok,
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER,
			reason: "relay certificate rejected",
		},
		{
			name: "member with a higher name", open: "relay-z", version: ok,
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED,
			reason: "the relay with the lower name dials the mesh session",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ca := newCA(t)
			n := newMeshNode(t, ca, "relay-m")
			if tc.min != 0 {
				n.m.ver = &dp.Version{Revision: max(dp.Revision, tc.min), MinRevision: tc.min}
			}
			// The members do not listen, so the relay opens no session itself.
			n.m.SetMembers([]MeshMember{
				{Name: "relay-a", Addr: netip.MustParseAddrPort("127.0.0.1:1")},
				{Name: "relay-z", Addr: netip.MustParseAddrPort("127.0.0.1:2")},
			})
			n.listen(t)

			certCA, certName := ca, tc.open
			if tc.otherCA {
				certCA = newCA(t)
			}
			if tc.cert != "" {
				certName = tc.cert
			}
			qc := n.rawDial(t, certCA.meshCert(t, certName))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			res, err := dp.NewMeshClient(rpc.NewConn(qc, nil)).Open(ctx, &dp.MeshOpenRequest{Version: tc.version, Name: tc.open})
			if tc.opens {
				require.NoError(t, err)
				assert.Equal(t, "relay-m", res.GetName())
				assert.Equal(t, n.m.ver.GetRevision(), res.GetVersion().GetRevision())
				assert.Equal(t, []string{n.addr.String()}, res.GetRelay().GetAddresses())
				assert.True(t, n.m.Up(tc.open))
				assert.NoError(t, qc.Context().Err(), "the session stays open")
				return
			}
			require.Error(t, err)
			assert.Equal(t, quic.ApplicationErrorCode(tc.want), closeCode(t, qc))
			var ae *quic.ApplicationError
			require.ErrorAs(t, context.Cause(qc.Context()), &ae)
			assert.True(t, ae.Remote, "the relay closed the session")
			assert.Equal(t, tc.reason, ae.ErrorMessage)
			assert.False(t, n.m.Up(tc.open))
			assert.Nil(t, n.m.Session(tc.open))
			require.Eventually(t, func() bool { return n.count() == 0 }, 5*time.Second, 5*time.Millisecond)
		})
	}
}

// fakeMesh is the listening end of a mesh session that the test controls. It
// answers Open with res, or with err.
type fakeMesh struct {
	dp.UnimplementedMeshServer
	res *dp.MeshOpenResponse
	err error
}

func (f fakeMesh) Open(context.Context, *dp.MeshOpenRequest) (*dp.MeshOpenResponse, error) {
	return f.res, f.err
}

// listenFake starts a relay that the test controls, with cert. It returns its
// address and the connections that it accepts, in order.
func listenFake(t *testing.T, cert tls.Certificate, f fakeMesh) (netip.AddrPort, <-chan quic.Connection) {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udp}
	conf := meshTLS(cert)
	conf.NextProtos = []string{dp.ALPNMesh}
	conf.ClientAuth = tls.RequireAnyClientCert
	ln, err := tr.Listen(conf, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	mux := rpc.NewMux()
	dp.RegisterMeshServer(mux, f)
	ctx, cancel := context.WithCancel(context.Background())
	conns := make(chan quic.Connection, 64)
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			qc, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			conns <- qc
			wg.Go(func() { _ = rpc.NewConn(qc, mux).Serve(ctx) })
		}
	})
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		wg.Wait()
		_ = tr.Close()
		_ = udp.Close()
	})
	return netip.MustParseAddrPort(udp.LocalAddr().String()), conns
}

// TestMeshOpenDial lets a relay dial a listener that the test controls. The
// relay closes a session with the wrong member or with an old revision.
func TestMeshOpenDial(t *testing.T) {
	t.Parallel()
	ok := dp.LocalVersion("test")
	cases := []struct {
		name   string
		cert   string // Name in the cert of the listener.
		res    *dp.MeshOpenResponse
		want   dp.MeshCloseCode
		opens  bool
		reason string
	}{
		{name: "the member", cert: "relay-z", res: &dp.MeshOpenResponse{Version: ok, Name: "relay-z"}, opens: true},
		{
			name: "listener with another name", cert: "relay-z", res: &dp.MeshOpenResponse{Version: ok, Name: "relay-y"},
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER,
			reason: `relay "relay-y" is not the member "relay-z" that this relay dialed`,
		},
		{
			name: "listener with the cert of another relay", cert: "relay-y", res: &dp.MeshOpenResponse{Version: ok, Name: "relay-z"},
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER,
			reason: "relay certificate rejected",
		},
		{
			name: "listener at a revision from before the mesh", cert: "relay-z",
			res:    &dp.MeshOpenResponse{Version: &dp.Version{Revision: meshRevision - 1}, Name: "relay-z"},
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_UPGRADE,
			reason: fmt.Sprintf("relay revision %d is below the minimum %d", meshRevision-1, meshRevision),
		},
		{
			name: "listener with no version", cert: "relay-z", res: &dp.MeshOpenResponse{Name: "relay-z"},
			want:   dp.MeshCloseCode_MESH_CLOSE_CODE_UPGRADE,
			reason: fmt.Sprintf("relay revision 0 is below the minimum %d", meshRevision),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ca := newCA(t)
			addr, conns := listenFake(t, ca.meshCert(t, tc.cert), fakeMesh{res: tc.res})
			n := newMeshNode(t, ca, "relay-m")
			n.m.SetMembers([]MeshMember{{Name: "relay-z", Addr: addr}})
			n.start(t)

			var qc quic.Connection
			select {
			case qc = <-conns:
			case <-time.After(10 * time.Second):
				t.Fatal("the relay did not dial its member in 10 s")
			}
			if tc.opens {
				require.Equal(t, MeshChange{Name: "relay-z", Up: true}, n.change(t, 10*time.Second))
				s := n.session(t)
				assert.Equal(t, "relay-z", s.Name())
				assert.True(t, s.dialer)
				assert.NoError(t, qc.Context().Err(), "the session stays open")
				return
			}
			assert.Equal(t, quic.ApplicationErrorCode(tc.want), closeCode(t, qc))
			var ae *quic.ApplicationError
			require.ErrorAs(t, context.Cause(qc.Context()), &ae)
			assert.True(t, ae.Remote, "the relay closed the session")
			assert.Equal(t, tc.reason, ae.ErrorMessage)
			assert.False(t, n.m.Up("relay-z"))
			assert.Nil(t, n.m.Session("relay-z"))
		})
	}
}

// TestMeshRedialWait checks the wait before each dial: 200 ms, then two times
// the wait before up to 10 s, each with at most 50% more.
func TestMeshRedialWait(t *testing.T) {
	t.Parallel()
	cases := []struct {
		dial int // Number of the dial, from 0.
		base time.Duration
	}{
		{0, 200 * time.Millisecond},
		{1, 400 * time.Millisecond},
		{2, 800 * time.Millisecond},
		{3, 1600 * time.Millisecond},
		{4, 3200 * time.Millisecond},
		{5, 6400 * time.Millisecond},
		{6, 10 * time.Second},
		{7, 10 * time.Second},
		{20, 10 * time.Second},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("dial %d", tc.dial), func(t *testing.T) {
			least, most := time.Duration(1<<62), time.Duration(0)
			for range 2000 {
				var w redial
				for range tc.dial {
					w.next()
				}
				d := w.next()
				require.GreaterOrEqual(t, d, tc.base)
				require.LessOrEqual(t, d, tc.base*3/2)
				least, most = min(least, d), max(most, d)
			}
			// The random part uses most of its range.
			assert.Less(t, least, tc.base*11/10)
			assert.Greater(t, most, tc.base*14/10)
		})
	}
}

// TestMeshRedial lets a relay dial a member that refuses each session. The
// time between two dials is the wait of that dial.
func TestMeshRedial(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	addr, conns := listenFake(t, ca.meshCert(t, "relay-z"), fakeMesh{err: rpc.Errorf(rpc.PermissionDenied, "not a member")})
	n := newMeshNode(t, ca, "relay-m")
	n.m.SetMembers([]MeshMember{{Name: "relay-z", Addr: addr}})
	n.start(t)

	// slack is the time of one dial and of a late timer on a busy host.
	const slack = 500 * time.Millisecond
	var last time.Time
	for i, base := range []time.Duration{0, 200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond, 1600 * time.Millisecond} {
		select {
		case <-conns:
		case <-time.After(10 * time.Second):
			t.Fatalf("no dial %d in 10 s", i)
		}
		now := time.Now()
		if i > 0 {
			wait := now.Sub(last)
			assert.GreaterOrEqual(t, wait, base, "wait before dial %d", i)
			assert.LessOrEqual(t, wait, base*3/2+slack, "wait before dial %d", i)
		}
		last = now
	}
	assert.False(t, n.m.Up("relay-z"))
}

// TestMeshLostSession cuts the path with no close. Each relay sees the loss in
// 5 s to 6 s, has the member as down 3 s later, and as up when the path works.
func TestMeshLostSession(t *testing.T) {
	t.Parallel()
	a, b, sa, sb := meshPair(t, true)
	// Let the keep-alives run, so that the cut is not at the start of a session.
	time.Sleep(1500 * time.Millisecond)

	// The numbers of the protocol. The test does not read them from the code.
	const idle, keepAlive, downAfter = 5 * time.Second, time.Second, 3 * time.Second
	// slack is for late timers on a busy host.
	const slack = 500 * time.Millisecond
	type timedChange struct {
		c  MeshChange
		at time.Time
	}
	type end struct {
		n      *meshNode
		s      *MeshSession
		peer   string
		lost   chan time.Time   // Time of the end of s.
		change chan timedChange // Next change of n and its time.
		at     time.Time
	}
	ends := []*end{{n: a, s: sa, peer: "relay-b"}, {n: b, s: sb, peer: "relay-a"}}
	for _, e := range ends {
		e.lost, e.change = make(chan time.Time, 1), make(chan timedChange, 1)
		context.AfterFunc(e.s.Context(), func() { e.lost <- time.Now() })
		go func() { e.change <- timedChange{<-e.n.changes, time.Now()} }()
	}
	b.cut.Store(true)
	cut := time.Now()
	for _, e := range ends {
		select {
		case e.at = <-e.lost:
		case <-time.After(idle + keepAlive + 5*time.Second):
			t.Fatalf("%s did not see the loss of its session", e.n.name)
		}
		lost := e.at.Sub(cut)
		t.Logf("%s saw the loss %v after the cut", e.n.name, lost.Round(time.Millisecond))
		var timeout *quic.IdleTimeoutError
		assert.ErrorAs(t, context.Cause(e.s.Context()), &timeout, "%s: the idle timeout ended the session", e.n.name)
		// The idle timeout starts again at the first keep-alive after the last
		// packet, so the loss shows up to one keep-alive time later.
		assert.GreaterOrEqual(t, lost, idle-keepAlive, "%s", e.n.name)
		assert.LessOrEqual(t, lost, idle+keepAlive+slack, "%s", e.n.name)
	}
	// For 3 s after the loss, the member is not down.
	for _, e := range ends {
		if time.Since(e.at) < downAfter-slack {
			assert.True(t, e.n.m.Up(e.peer), "%s has %s as up before the down time", e.n.name, e.peer)
		}
	}
	for _, e := range ends {
		var got timedChange
		select {
		case got = <-e.change:
		case <-time.After(downAfter + 5*time.Second):
			t.Fatalf("%s did not have %s as down", e.n.name, e.peer)
		}
		require.Equal(t, MeshChange{Name: e.peer, Down: MeshLost}, got.c)
		down := got.at.Sub(e.at)
		t.Logf("%s had %s as down %v after the loss", e.n.name, e.peer, down.Round(time.Millisecond))
		assert.GreaterOrEqual(t, down, downAfter-slack/5, "%s", e.n.name)
		assert.LessOrEqual(t, down, downAfter+slack, "%s", e.n.name)
		assert.False(t, e.n.m.Up(e.peer))
		assert.Nil(t, e.n.m.Session(e.peer))
	}

	// The path works again: relay-a dials, and each relay has the other as up.
	b.cut.Store(false)
	for _, e := range ends {
		require.Equal(t, MeshChange{Name: e.peer, Up: true}, e.n.change(t, 30*time.Second))
		assert.NotSame(t, e.s, e.n.session(t))
	}
	stays(t, a, b)
}

// TestMeshDown ends the session of two relays in different ways and checks
// when each relay has the other as down.
func TestMeshDown(t *testing.T) {
	t.Parallel()
	// downAfter is the down time of the protocol. soon is much less: a change
	// in this time did not wait for the down time.
	const downAfter, soon = 3 * time.Second, time.Second
	cases := []struct {
		name string
		run  func(t *testing.T, a, b *meshNode, sa, sb *MeshSession)
	}{
		{
			name: "a new session opens before the down time",
			run: func(t *testing.T, a, b *meshNode, sa, sb *MeshSession) {
				// relay-b closes the session, and relay-a dials again after 200 ms.
				sb.close(dp.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, "test")
				assert.NotSame(t, sa, a.session(t))
				assert.NotSame(t, sb, b.session(t))
				// The down time of the old session passes with no change.
				select {
				case c := <-a.changes:
					t.Errorf("relay-a got the change %+v", c)
				case c := <-b.changes:
					t.Errorf("relay-b got the change %+v", c)
				case <-time.After(downAfter + soon):
				}
				assert.True(t, a.m.Up("relay-b"))
				assert.True(t, b.m.Up("relay-a"))
				stays(t, a, b)
			},
		},
		{
			name: "the relay that accepted stops",
			run: func(t *testing.T, a, b *meshNode, sa, sb *MeshSession) {
				b.cancel()
				assert.Equal(t, MeshChange{Name: "relay-b", Down: MeshRestart}, a.change(t, soon))
				assert.False(t, a.m.Up("relay-b"))
				assert.Equal(t, quic.ApplicationErrorCode(dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART), closeCode(t, sa.qc))
			},
		},
		{
			name: "the relay that dialed stops",
			run: func(t *testing.T, a, b *meshNode, sa, sb *MeshSession) {
				a.cancel()
				assert.Equal(t, MeshChange{Name: "relay-a", Down: MeshRestart}, b.change(t, soon))
				assert.False(t, b.m.Up("relay-a"))
				assert.Equal(t, quic.ApplicationErrorCode(dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART), closeCode(t, sb.qc))
			},
		},
		{
			name: "the relay that accepted removes the member",
			run: func(t *testing.T, a, b *meshNode, sa, sb *MeshSession) {
				b.m.SetMembers(nil)
				// relay-b closes the session, and the member is down at once.
				assert.Equal(t, MeshChange{Name: "relay-a", Down: MeshRemoved}, b.change(t, soon))
				assert.Equal(t, quic.ApplicationErrorCode(dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER), closeCode(t, sa.qc))
				lost := time.Now()
				assert.False(t, b.m.Up("relay-a"))
				assert.Nil(t, b.m.Session("relay-a"))
				// relay-a dials again and relay-b refuses, so relay-b is down
				// for relay-a after the down time.
				assert.True(t, a.m.Up("relay-b"))
				assert.Equal(t, MeshChange{Name: "relay-b", Down: MeshLost}, a.change(t, downAfter+5*time.Second))
				assert.GreaterOrEqual(t, time.Since(lost), downAfter-soon)
				assert.Nil(t, a.m.Session("relay-b"))
			},
		},
		{
			name: "the relay that dialed removes the member",
			run: func(t *testing.T, a, b *meshNode, sa, sb *MeshSession) {
				a.m.SetMembers(nil)
				assert.Equal(t, MeshChange{Name: "relay-b", Down: MeshRemoved}, a.change(t, soon))
				assert.Equal(t, quic.ApplicationErrorCode(dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER), closeCode(t, sb.qc))
				assert.False(t, a.m.Up("relay-b"))
				assert.Nil(t, a.m.Session("relay-b"))
				// relay-a does not dial again.
				assert.Equal(t, MeshChange{Name: "relay-a", Down: MeshLost}, b.change(t, downAfter+5*time.Second))
				assert.Equal(t, 0, a.count())
				assert.Equal(t, 0, b.count())
			},
		},
		{
			name: "the member comes back in the set",
			run: func(t *testing.T, a, b *meshNode, sa, sb *MeshSession) {
				a.m.SetMembers(nil)
				assert.Equal(t, MeshChange{Name: "relay-b", Down: MeshRemoved}, a.change(t, soon))
				a.m.SetMembers([]MeshMember{b.member()})
				assert.Equal(t, MeshChange{Name: "relay-b", Up: true}, a.change(t, 10*time.Second))
				assert.NotSame(t, sa, a.session(t))
				// relay-b got the new session before the down time.
				assert.NotSame(t, sb, b.session(t))
				assert.True(t, b.m.Up("relay-a"))
				stays(t, a, b)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b, sa, sb := meshPair(t, false)
			tc.run(t, a, b, sa, sb)
		})
	}
}

// stubConn is a QUIC connection that only closes. The tests with the fake
// clock use it, because a real connection does not run on that clock.
type stubConn struct {
	quic.Connection
	ctx    context.Context
	cancel context.CancelCauseFunc
}

func newStubConn() *stubConn {
	c := &stubConn{}
	c.ctx, c.cancel = context.WithCancelCause(context.Background())
	return c
}

func (c *stubConn) Context() context.Context { return c.ctx }

func (c *stubConn) RemoteAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:6081"))
}

func (c *stubConn) CloseWithError(code quic.ApplicationErrorCode, msg string) error {
	c.cancel(&quic.ApplicationError{ErrorCode: code, ErrorMessage: msg})
	return nil
}

// TestMeshDownTime checks with the fake clock when a member is down after
// the end of its session: 3 s later if no new session opened, or at once.
func TestMeshDownTime(t *testing.T) {
	const downAfter = 3 * time.Second
	// almost is the last moment before the down time.
	const almost = downAfter - time.Nanosecond
	up := []MeshChange{{Name: "relay-a", Up: true}}
	down := func(d MeshDown) []MeshChange { return []MeshChange{{Name: "relay-a", Down: d}} }
	type step struct {
		// act is "open", "lose" (idle timeout), "restart" or "close" (relay-a closes
		// with RESTART or the normal code), "remove" or "add" (member set), or empty.
		act  string
		wait time.Duration // Time that passes after act.
		want []MeshChange  // Changes in that time.
		up   bool          // The member is up at the end of that time.
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{"no new session", []step{
			{"open", 0, up, true},
			{"lose", almost, nil, true},
			{"", time.Nanosecond, down(MeshLost), false},
			{"", time.Minute, nil, false},
		}},
		{"new session before the down time", []step{
			{"open", 0, up, true},
			{"lose", almost, nil, true},
			{"open", time.Minute, nil, true},
			// The down time starts again at the end of the new session.
			{"lose", almost, nil, true},
			{"", time.Nanosecond, down(MeshLost), false},
		}},
		{"new session after the down time", []step{
			{"open", 0, up, true},
			{"lose", downAfter, down(MeshLost), false},
			{"open", time.Minute, up, true},
		}},
		{"new session replaces an open session", []step{
			{"open", 0, up, true},
			{"open", time.Minute, nil, true},
			{"lose", almost, nil, true},
			{"", time.Nanosecond, down(MeshLost), false},
		}},
		{"the other relay stops", []step{
			{"open", 0, up, true},
			{"restart", 0, down(MeshRestart), false},
			{"", time.Minute, nil, false},
			{"open", 0, up, true},
		}},
		{"the other relay closes with the normal code", []step{
			{"open", 0, up, true},
			{"close", almost, nil, true},
			{"", time.Nanosecond, down(MeshLost), false},
		}},
		{"the member leaves the set in the down time", []step{
			{"open", 0, up, true},
			{"lose", time.Second, nil, true},
			{"remove", 0, down(MeshRemoved), false},
			{"", time.Minute, nil, false},
		}},
		{"the member leaves the set and comes back", []step{
			{"open", 0, up, true},
			{"lose", time.Second, nil, true},
			{"remove", 0, down(MeshRemoved), false},
			{"add", time.Minute, nil, false},
			{"open", 0, up, true},
		}},
	}
	ca := newCA(t)
	cfg := MeshConfig{TLS: meshTLS(ca.meshCert(t, "relay-m")), Verify: ca.verifyName}
	member := []MeshMember{{Name: "relay-a", Addr: netip.MustParseAddrPort("192.0.2.1:6081")}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m, err := NewMesh("relay-m", cfg)
				require.NoError(t, err)
				changes := make(chan MeshChange, 16)
				m.OnChange(func(c MeshChange) { changes <- c })
				m.SetMembers(member)
				// relay-a has the lower name, so this relay does not dial it
				// and needs no transport.
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() { defer close(done); m.Run(ctx, nil, nil) }()
				defer func() { cancel(); <-done }()

				var conn *stubConn
				for i, st := range tc.steps {
					switch st.act {
					case "open":
						// The steps of a passed Open call on a session that relay-a dialed.
						conn = newStubConn()
						sess := m.newSession(conn, false)
						require.True(t, m.track(sess))
						require.NoError(t, m.admit(sess, "relay-a", nil, m.ver, nil))
					case "lose":
						conn.cancel(&quic.IdleTimeoutError{})
					case "restart":
						conn.cancel(&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART)})
					case "close":
						conn.cancel(&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(dp.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED)})
					case "remove":
						m.SetMembers(nil)
					case "add":
						m.SetMembers(member)
					}
					time.Sleep(st.wait)
					synctest.Wait()
					var got []MeshChange
					for more := true; more; {
						select {
						case c := <-changes:
							got = append(got, c)
						default:
							more = false
						}
					}
					assert.Equal(t, st.want, got, "changes in step %d (%s)", i, st.act)
					assert.Equal(t, st.up, m.Up("relay-a"), "member state after step %d (%s)", i, st.act)
				}
			})
		})
	}
}

// TestMeshMembers changes the member set of a relay that runs: a new member and
// a member with a new address get a session, and the other sessions stay.
func TestMeshMembers(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	a, c := newMeshNode(t, ca, "relay-a"), newMeshNode(t, ca, "relay-c")
	// Two relays have the name relay-b, as before and after a move.
	b1, b2 := newMeshNode(t, ca, "relay-b"), newMeshNode(t, ca, "relay-b")
	for _, n := range []*meshNode{b1, b2, c} {
		n.m.SetMembers([]MeshMember{a.member()})
		n.start(t)
	}
	a.start(t)
	assert.Equal(t, 0, a.count(), "a relay with no members dials no relay")

	a.m.SetMembers([]MeshMember{b1.member()})
	require.Equal(t, MeshChange{Name: "relay-b", Up: true}, a.change(t, 10*time.Second))
	require.Equal(t, MeshChange{Name: "relay-a", Up: true}, b1.change(t, 10*time.Second))
	toB1 := a.session(t)
	assert.Equal(t, b1.addr, addrPort(toB1.qc.RemoteAddr()))

	a.m.SetMembers([]MeshMember{b1.member(), c.member()})
	require.Equal(t, MeshChange{Name: "relay-c", Up: true}, a.change(t, 10*time.Second))
	require.Equal(t, MeshChange{Name: "relay-a", Up: true}, c.change(t, 10*time.Second))
	toC := a.session(t)
	assert.Equal(t, "relay-c", toC.Name())
	assert.Same(t, toB1, a.m.Session("relay-b"), "the session of the other member stays")

	a.m.SetMembers([]MeshMember{c.member(), b2.member()})
	require.Equal(t, MeshChange{Name: "relay-b", Down: MeshRemoved}, a.change(t, 10*time.Second))
	require.Equal(t, MeshChange{Name: "relay-b", Up: true}, a.change(t, 10*time.Second))
	require.Equal(t, MeshChange{Name: "relay-a", Up: true}, b2.change(t, 10*time.Second))
	toB2 := a.session(t)
	assert.Equal(t, b2.addr, addrPort(toB2.qc.RemoteAddr()))
	assert.Equal(t, quic.ApplicationErrorCode(dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER), closeCode(t, b1.session(t).qc))
	assert.Same(t, toC, a.m.Session("relay-c"), "the session of the other member stays")
	assert.NoError(t, toC.Context().Err())
	require.Eventually(t, func() bool { return a.count() == 2 }, 5*time.Second, 5*time.Millisecond)
}

// TestMeshListenConfig checks which connections get the timers of a mesh
// session from the listener: those from the address of a member.
func TestMeshListenConfig(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	m, err := NewMesh("relay-m", MeshConfig{TLS: meshTLS(ca.meshCert(t, "relay-m")), Verify: ca.verifyName})
	require.NoError(t, err)
	m.SetMembers([]MeshMember{
		{Name: "relay-a", Addr: netip.MustParseAddrPort("192.0.2.1:6081")},
		{Name: "relay-m", Addr: netip.MustParseAddrPort("192.0.2.9:6081")},
		{Name: "", Addr: netip.MustParseAddrPort("192.0.2.8:6081")},
		{Name: "relay-n"},
		{Name: "relay-z", Addr: netip.MustParseAddrPort("[::ffff:192.0.2.2]:6081")},
	})
	base := &quic.Config{KeepAlivePeriod: 5 * time.Second, MaxIdleTimeout: 15 * time.Second, MaxIncomingStreams: 512}
	other := &quic.Config{KeepAlivePeriod: 7 * time.Second, MaxIdleTimeout: 21 * time.Second, MaxIncomingStreams: 9}
	withNext := base.Clone()
	withNext.GetConfigForClient = func(*quic.ClientInfo) (*quic.Config, error) { return other, nil }
	refuses := base.Clone()
	refuses.GetConfigForClient = func(*quic.ClientInfo) (*quic.Config, error) { return nil, errors.New("refused") }

	cases := []struct {
		name    string
		base    *quic.Config
		from    string
		mesh    bool         // The connection gets the timers of a mesh session.
		rest    *quic.Config // The other values come from this config.
		wantErr bool
	}{
		{name: "address of a member", base: base, from: "192.0.2.1:6081", mesh: true, rest: base},
		{name: "IPv4-mapped address of a member", base: base, from: "[::ffff:192.0.2.1]:6081", mesh: true, rest: base},
		{name: "member with an IPv4-mapped address", base: base, from: "192.0.2.2:6081", mesh: true, rest: base},
		{name: "other port at the address of a member", base: base, from: "192.0.2.1:40000", rest: base},
		{name: "address of an agent", base: base, from: "198.51.100.7:6081", rest: base},
		{name: "address of the relay itself", base: base, from: "192.0.2.9:6081", rest: base},
		{name: "member with no name", base: base, from: "192.0.2.8:6081", rest: base},
		{name: "no base config, address of a member", from: "192.0.2.1:6081", mesh: true, rest: &quic.Config{}},
		{name: "no base config, address of an agent", from: "198.51.100.7:6081"},
		{name: "base with its own choice, address of a member", base: withNext, from: "192.0.2.1:6081", mesh: true, rest: other},
		{name: "base with its own choice, address of an agent", base: withNext, from: "198.51.100.7:6081", rest: other},
		{name: "base refuses the connection", base: refuses, from: "192.0.2.1:6081", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln := m.ListenConfig(tc.base)
			require.NotNil(t, ln.GetConfigForClient)
			if tc.base != nil {
				assert.Equal(t, tc.base.MaxIdleTimeout, ln.MaxIdleTimeout, "the listener keeps the base values")
			}
			got, err := ln.GetConfigForClient(&quic.ClientInfo{RemoteAddr: net.UDPAddrFromAddrPort(netip.MustParseAddrPort(tc.from))})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if !tc.mesh {
				assert.Same(t, tc.rest, got)
				return
			}
			assert.Equal(t, time.Second, got.KeepAlivePeriod)
			assert.Equal(t, 5*time.Second, got.MaxIdleTimeout)
			assert.True(t, got.EnableDatagrams)
			assert.Equal(t, tc.rest.MaxIncomingStreams, got.MaxIncomingStreams)
			assert.NotSame(t, tc.rest, got, "the base config does not change")
		})
	}
}

// TestNewMesh checks the config that a mesh needs, and the TLS config that it
// makes from the config of the host.
func TestNewMesh(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	conf := meshTLS(ca.meshCert(t, "relay-m"))
	cases := []struct {
		name       string
		relay      string
		cfg        MeshConfig
		clientAuth tls.ClientAuthType // In the config of the host.
		wantAuth   tls.ClientAuthType
		wantErr    string
	}{
		{name: "no relay name", cfg: MeshConfig{TLS: conf, Verify: ca.verifyName}, wantErr: "mesh needs the relay name"},
		{name: "no TLS config", relay: "relay-m", cfg: MeshConfig{Verify: ca.verifyName}, wantErr: "mesh needs a TLS config"},
		{name: "no check of the other relay", relay: "relay-m", cfg: MeshConfig{TLS: conf}, wantErr: "mesh needs a check of the other relay"},
		{name: "host asks for no client cert", relay: "relay-m", cfg: MeshConfig{TLS: conf, Verify: ca.verifyName}, wantAuth: tls.RequireAnyClientCert},
		{
			name: "host checks a client cert only if it gets one", relay: "relay-m", cfg: MeshConfig{TLS: conf, Verify: ca.verifyName},
			clientAuth: tls.VerifyClientCertIfGiven, wantAuth: tls.RequireAnyClientCert,
		},
		{
			name: "host checks the client cert in the handshake", relay: "relay-m", cfg: MeshConfig{TLS: conf, Verify: ca.verifyName},
			clientAuth: tls.RequireAndVerifyClientCert, wantAuth: tls.RequireAndVerifyClientCert,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.cfg.TLS != nil {
				tc.cfg.TLS = tc.cfg.TLS.Clone()
				tc.cfg.TLS.ClientAuth = tc.clientAuth
			}
			m, err := NewMesh(tc.relay, tc.cfg)
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			got := m.TLSConfig()
			assert.Equal(t, []string{dp.ALPNMesh}, got.NextProtos)
			assert.Equal(t, uint16(tls.VersionTLS13), got.MinVersion)
			assert.Equal(t, tc.wantAuth, got.ClientAuth)
			assert.Equal(t, tc.clientAuth, tc.cfg.TLS.ClientAuth, "the config of the host does not change")
			assert.Empty(t, tc.cfg.TLS.NextProtos, "the config of the host does not change")
		})
	}
}
