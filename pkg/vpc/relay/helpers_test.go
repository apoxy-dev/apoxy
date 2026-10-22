// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	os.Exit(m.Run())
}

// testCA signs agent certs.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "agent CA"},
		NotBefore:             time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

// issue signs an agent cert with URI SAN san, or none, from notBefore.
func (ca *testCA) issue(t *testing.T, san string, notBefore time.Time) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(identity.CertLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if san != "" {
		u, err := url.Parse(san)
		require.NoError(t, err)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// agentCert issues a cert for agent name in vpc, valid since an hour ago.
func (ca *testCA) agentCert(t *testing.T, vpc VPCKey, name string) tls.Certificate {
	return ca.issue(t, agentID(vpc, name), time.Now().Add(-time.Hour))
}

// shortCert issues a cert for agent name in vpc that ends 1 to 2 seconds from
// now. A cert time has a resolution of one second.
func (ca *testCA) shortCert(t *testing.T, vpc VPCKey, name string) tls.Certificate {
	end := time.Now().Truncate(time.Second).Add(2 * time.Second)
	return ca.issue(t, agentID(vpc, name), end.Add(-identity.CertLifetime))
}

// waitExpired waits until each cert of certs is past its NotAfter.
func waitExpired(certs ...tls.Certificate) {
	for _, c := range certs {
		time.Sleep(time.Until(c.Leaf.NotAfter) + 50*time.Millisecond)
	}
}

func agentID(k VPCKey, name string) string {
	return identity.ID{Project: k.Project, VPC: k.UID, Agent: name}.String()
}

// fakeTrust is the trust data of a test relay. A project in projectCA has
// that CA, or no CA for nil. Each other project has ca.
type fakeTrust struct {
	mu        sync.Mutex
	ca        *testCA
	projectCA map[string]*testCA
	revoked   map[VPCKey][]vpcv1alpha1.RevokedAgent
	err       error
	roots     *x509.CertPool // Relay roots of all projects. Nil is the system roots.
	rootsErr  error
}

func (f *fakeTrust) AgentCA(project string) (*x509.CertPool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ca, ok := f.projectCA[project]
	if !ok {
		ca = f.ca
	}
	if ca == nil {
		return nil, errors.New("project has no agent CA")
	}
	return ca.pool(), nil
}

func (f *fakeTrust) Revoked(project, vpcUID string) ([]vpcv1alpha1.RevokedAgent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revoked[VPCKey{Project: project, UID: vpcUID}], f.err
}

func (f *fakeTrust) RelayRoots(string) (*x509.CertPool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.roots, f.rootsErr
}

func (f *fakeTrust) setCA(ca *testCA) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ca = ca
}

func (f *fakeTrust) revoke(k VPCKey, agent string, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revoked == nil {
		f.revoked = map[VPCKey][]vpcv1alpha1.RevokedAgent{}
	}
	f.revoked[k] = append(f.revoked[k], vpcv1alpha1.RevokedAgent{Name: agent, RevokedAt: metav1.NewTime(at)})
}

// fakeNetworks knows vpcA and vpcB, and fails for the VPCs in fail.
type fakeNetworks struct {
	mu   sync.Mutex
	fail map[VPCKey]bool
}

func (f *fakeNetworks) Network(project, vpcUID string) (Network, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := VPCKey{project, vpcUID}
	if f.fail[k] {
		return Network{}, errors.New("snapshot too old")
	}
	switch k {
	case vpcA:
		return Network{ID: 0x0a0b0c, Name: "net-a", DNSServers: []string{"fd00::53"}}, nil
	case vpcB:
		return Network{ID: 0x0d0e0f, MTU: 1360}, nil
	}
	return Network{}, errors.New("unknown VPC")
}

func (f *fakeNetworks) failVPC(k VPCKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = map[VPCKey]bool{k: true}
}

// fakeAddresses gives each attachment the next /96 in fd00:<n>::/96.
type fakeAddresses struct {
	mu           sync.Mutex
	next         int
	assigned     map[string]*Attachment
	attached     []attachedCall    // The Attached calls, in order.
	lost         map[string]func() // The onLost of each attachment.
	loseOnAssign bool              // Assign calls onLost before it returns.
	err          error
}

func (f *fakeAddresses) Assign(_ context.Context, a *Attachment, onLost func()) ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.next++
	if f.assigned == nil {
		f.assigned, f.lost = map[string]*Attachment{}, map[string]func(){}
	}
	f.assigned[a.ID], f.lost[a.ID] = a, onLost
	if f.loseOnAssign {
		onLost()
	}
	return []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("fd00:%x::/96", f.next))}, nil
}

// attachedCall is one Attached call: the attachment ID, and its addresses and
// its routes then.
type attachedCall struct {
	id     string
	addrs  []netip.Prefix
	routes []netip.Prefix
}

func (f *fakeAddresses) Attached(a *Attachment) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attached = append(f.attached, attachedCall{a.ID, slices.Clone(a.Addresses), slices.Clone(a.Routes)})
}

func (f *fakeAddresses) attachedCalls() []attachedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.attached)
}

func (f *fakeAddresses) Release(a *Attachment) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.assigned, a.ID)
	delete(f.lost, a.ID)
}

// onLost returns the onLost of attachment id.
func (f *fakeAddresses) onLost(id string) func() {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lost[id]
}

func (f *fakeAddresses) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeAddresses) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.assigned)
}

// harness is a relay that serves relay sessions on a loopback QUIC socket,
// with a PSP socket.
type harness struct {
	srv        *Server
	r          *Router
	trust      *fakeTrust
	nets       *fakeNetworks
	addrs      *fakeAddresses
	relayRoots *x509.CertPool // Roots of the relay cert.
	ln         *quic.Listener
	tr         *quic.Transport // QUIC socket.
	psp        *quic.Transport // PSP socket.
	pspAddr    net.Addr
	mux        *rpc.Mux
}

// relayCert issues a relay TLS cert with key for 127.0.0.1 that names id,
// from a new CA. It returns the cert and the CA pool.
func relayCert(t *testing.T, id string, key crypto.Signer) (*tls.Certificate, *x509.CertPool) {
	t.Helper()
	ca := newCA(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
		DNSNames:     []string{id},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	require.NoError(t, err)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, ca.pool()
}

// relayChain issues a *.relay.example.net cert with key from an intermediate
// CA. It returns the cert with the intermediate and the root pool.
func relayChain(t *testing.T, key crypto.Signer) (*tls.Certificate, *x509.CertPool) {
	t.Helper()
	root := newCA(t)
	ikey := newKey(t)
	itmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               pkix.Name{CommonName: "relay intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	ider, err := x509.CreateCertificate(rand.Reader, itmpl, root.cert, &ikey.PublicKey, root.key)
	require.NoError(t, err)
	inter, err := x509.ParseCertificate(ider)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(5),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
		DNSNames:     []string{"*.relay.example.net"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, inter, key.Public(), ikey)
	require.NoError(t, err)
	return &tls.Certificate{Certificate: [][]byte{der, ider}, PrivateKey: key}, root.pool()
}

// endHold lets the hold time of a new attachment end on the fake clock, so
// that the attachment can replace a live active announcer.
func endHold() {
	time.Sleep(holdTime)
	synctest.Wait()
}

// newHarness starts a relay. The options change its router before it serves.
func newHarness(t *testing.T, ca *testCA, opts ...func(*Router)) *harness {
	t.Helper()
	cert, roots := relayCert(t, "relay-1", newKey(t))
	trust := &fakeTrust{ca: ca}
	r := NewRouter(trust, Config{})
	for _, opt := range opts {
		opt(r)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	// The relay keeps the RTT of each session and sends the keep-alive of the
	// liveness check, as a relay host does.
	tr := &quic.Transport{Conn: udp, ConnContext: TraceContext, NonQUICPacketHandler: r.QUICSocketHandler()}
	pspUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	psp := &quic.Transport{Conn: pspUDP}
	psp.NonQUICPacketHandler, psp.NonQUICBatchEnd = r.PacketHandler(t.Context(), psp)
	require.NoError(t, psp.Start())
	ln, err := tr.Listen(r.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*cert}}),
		&quic.Config{EnableDatagrams: true, Tracer: TraceRTT, KeepAlivePeriod: AgentKeepAlive})
	require.NoError(t, err)
	h := &harness{
		r: r, trust: trust, nets: &fakeNetworks{}, addrs: &fakeAddresses{},
		relayRoots: roots, ln: ln, tr: tr, psp: psp, pspAddr: pspUDP.LocalAddr(), mux: rpc.NewMux(),
	}
	h.srv = &Server{
		R: r, Networks: h.nets, Addresses: h.addrs, RelayID: "relay-1",
		Cert: func() (*tls.Certificate, error) { return cert, nil },
	}
	dp.RegisterRelayServer(h.mux, h.srv)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { _ = h.srv.Serve(ctx, ln) })
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		wg.Wait()
		_ = tr.Close()
		_ = psp.Close()
	})
	return h
}

// agent is one agent connection to the relay. Its transport also carries
// PSP, as on a real agent.
type agent struct {
	c   dp.RelayClient
	qc  quic.Connection
	tr  *quic.Transport
	src netip.AddrPort // Source address as the relay sees it.
	to  net.Addr       // PSP socket of the relay.
}

// dial connects an agent with cert on ALPN alpn (the relay ALPN if empty).
func (h *harness) dial(t *testing.T, cert tls.Certificate, alpn ...string) (agent, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// On macOS, replies to a wildcard socket can go to a 127.0.0.1 socket on
	// the same port.
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udp}
	t.Cleanup(func() { _ = tr.Close() })
	// quic-go drops non-QUIC packets until the first ReadNonQUICPacket call.
	done, stop := context.WithCancel(context.Background())
	stop()
	_, _, _ = tr.ReadNonQUICPacket(done, nil)
	protos := []string{dp.ALPNRelay}
	if len(alpn) > 0 {
		protos = alpn
	}
	tc := &tls.Config{InsecureSkipVerify: true, NextProtos: protos}
	if len(cert.Certificate) > 0 {
		tc.Certificates = []tls.Certificate{cert}
	}
	qc, err := tr.Dial(ctx, h.ln.Addr(), tc, &quic.Config{EnableDatagrams: true})
	if err != nil {
		return agent{}, err
	}
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	return agent{c: dp.NewRelayClient(rpc.NewConn(qc, nil)), qc: qc, tr: tr, src: netip.MustParseAddrPort(udp.LocalAddr().String()), to: h.pspAddr}, nil
}

func (h *harness) mustDial(t *testing.T, cert tls.Certificate) agent {
	t.Helper()
	a, err := h.dial(t, cert)
	require.NoError(t, err)
	return a
}

// requireRefused checks that the relay refused the handshake. In TLS 1.3 the
// refusal can come after the dial, as a close.
func requireRefused(t *testing.T, a agent, err error) {
	t.Helper()
	if err == nil {
		select {
		case <-a.qc.Context().Done():
		case <-time.After(5 * time.Second):
			t.Fatal("relay did not refuse the connection in 5 s")
		}
		err = context.Cause(a.qc.Context())
	}
	var te *quic.TransportError
	require.ErrorAs(t, err, &te)
	require.True(t, te.ErrorCode.IsCryptoError(), "error: %v", err)
}

func (h *harness) session(t *testing.T, a agent) *Session {
	t.Helper()
	var s *Session
	require.Eventually(t, func() bool {
		h.r.mu.RLock()
		defer h.r.mu.RUnlock()
		for o := range h.r.sessions {
			if o.remote() == a.src {
				s = o
			}
		}
		return s != nil
	}, 5*time.Second, 5*time.Millisecond)
	return s
}

// testCounter gives each test probe a larger counter than the one before it.
var testCounter atomic.Uint64

// probeTo sends one path probe of a to the PSP socket at to, and waits for the
// reply. The relay then has the socket of a as the PSP address of its session.
func probeTo(t *testing.T, a agent, to net.Addr) {
	t.Helper()
	k, err := p2p.NewProbeKeys(a.qc.ConnectionState().TLS)
	require.NoError(t, err)
	_, err = a.tr.WriteTo(p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Counter: testCounter.Add(1)}, p2p.MinProbeLen, &k.Dialer), to)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buf := make([]byte, 2048)
	n, _, err := a.tr.ReadNonQUICPacket(ctx, buf)
	require.NoError(t, err, "no reply to the path probe")
	_, err = p2p.OpenProbe(buf[:n], &k.Listener)
	require.NoError(t, err)
}

// offer gives s relay SAs, as the change to PSP mode does, for a test that
// sets the mode of s itself. It returns nil if the relay has no bridge.
func (r *Router) offer(s *Session, n Network, now time.Time) (*dp.SessionResponse, error) {
	br := r.bridge.Load()
	if br == nil {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed {
		return nil, rpc.Errorf(rpc.Unauthenticated, "relay session closed")
	}
	return r.offerLocked(br, s, n, 0, now)
}

// addProbed adds s with the address of its QUIC connection as its PSP address,
// as a path probe from the socket of the connection gives it.
func (r *Router) addProbed(s *Session, now time.Time) {
	r.addSession(s, now)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setAddr(s, s.remote(), now)
}

// openIn opens the Session call of s and puts s in the data mode mode. It
// gives s no SAs.
func (r *Router) openIn(s *Session, mode dp.Mode, ref *dp.VPCRef, hello *dp.Hello) error {
	if err := r.openSync(s, mode, ref, 1280, hello); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s.sync.mode = mode
	return nil
}

// replayStream gives the messages in pending before the next ones of the stream.
type replayStream struct {
	syncStream
	pending []*dp.SessionResponse
}

func (s *replayStream) Recv() (*dp.SessionResponse, error) {
	if len(s.pending) > 0 {
		m := s.pending[0]
		s.pending = s.pending[1:]
		return m, nil
	}
	return s.syncStream.Recv()
}

// syncStream is the agent side of a Session call.
type syncStream = rpc.BidiStreamClient[dp.SessionRequest, dp.SessionResponse]

// open starts the Session call of a, changes the session to PSP mode, and
// returns the stream after Welcome, Config and the relay SAs.
func open(t *testing.T, a agent) (syncStream, *dp.Welcome, *dp.Config) {
	t.Helper()
	st, w, c, _ := openMode(t, a, dp.Mode_MODE_PSP)
	return st, w, c
}

// openMode starts the Session call of a, for PSP mode with a probe and a Rekey
// call. It returns the relay SAs; the test gives the agent SAs.
func openMode(t *testing.T, a agent, mode dp.Mode) (syncStream, *dp.Welcome, *dp.Config, *dp.KeysRequest) {
	t.Helper()
	st, err := a.c.Session(context.Background())
	require.NoError(t, err)
	require.NoError(t, st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{Mode: mode}}}))
	w, err := st.Recv()
	require.NoError(t, err)
	require.NotNil(t, w.GetWelcome(), "first message: %v", w)
	c, err := st.Recv()
	require.NoError(t, err)
	require.NotNil(t, c.GetConfig(), "second message: %v", c)
	if mode != dp.Mode_MODE_PSP {
		return st, w.GetWelcome(), c.GetConfig(), nil
	}
	probeTo(t, a, a.to)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first := newPSPReceiver(t, time.Now()).req
	_, err = a.c.Rekey(ctx, keyproto.ToProto(first))
	require.NoError(t, err)
	// The messages before the relay SAs stay for the test.
	rs := &replayStream{syncStream: st}
	var k *dp.SessionResponse
	for {
		k, err = st.Recv()
		require.NoError(t, err)
		if k.GetRekey() != nil {
			break
		}
		rs.pending = append(rs.pending, k)
	}
	spis := make([]uint32, len(first.SAs))
	for i, sa := range first.SAs {
		spis[i] = sa.SPI
	}
	_, err = a.c.Rekey(ctx, keyproto.ToProto(keys.Request{Op: keys.OpRevoke, SPIs: spis}))
	require.NoError(t, err)
	return rs, w.GetWelcome(), c.GetConfig(), k.GetRekey()
}

// sayHello starts the Session call of a in QUIC mode, for a test that needs
// only the Hello that an Attach call needs.
func sayHello(t *testing.T, a agent) {
	t.Helper()
	openMode(t, a, dp.Mode_MODE_QUIC)
}

// sayHelloAt is sayHello for an agent at the revision rev.
func sayHelloAt(t *testing.T, a agent, rev uint32) {
	t.Helper()
	st := hello(t, a, &dp.Hello{Mode: dp.Mode_MODE_QUIC, Version: &dp.Version{Revision: rev}})
	w, err := st.Recv()
	require.NoError(t, err)
	require.NotNil(t, w.GetWelcome(), "first message: %v", w)
}

// recv returns the next message of st within 5 s. It skips a RouteDelta with
// no routes, such as the first one in a VPC with no routes.
func recv(t *testing.T, st syncStream) *dp.SessionResponse {
	t.Helper()
	type res struct {
		m   *dp.SessionResponse
		err error
	}
	timeout := time.After(5 * time.Second)
	for {
		ch := make(chan res, 1)
		go func() {
			m, err := st.Recv()
			ch <- res{m, err}
		}()
		select {
		case r := <-ch:
			require.NoError(t, r.err)
			if d := r.m.GetRouteDelta(); d != nil && len(d.Add)+len(d.Remove) == 0 {
				continue
			}
			return r.m
		case <-timeout:
			t.Fatal("no Sync message in 5 s")
			return nil
		}
	}
}

// closeCode waits until qc closes and returns its application error code.
func closeCode(t *testing.T, qc quic.Connection) quic.ApplicationErrorCode {
	t.Helper()
	select {
	case <-qc.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("connection did not close in 5 s")
	}
	var ae *quic.ApplicationError
	require.ErrorAs(t, context.Cause(qc.Context()), &ae)
	return ae.ErrorCode
}

// admitMember admits s as the session of the member name, as Open does. The
// member has its PSP socket at its relay address with the PSP port of m, so
// that a test with no socket of the member knows where the trunk packets go.
func admitMember(m *Mesh, s *MeshSession, name string, v *dp.Version, ref *dp.RelayRef) error {
	at := addrPort(s.qc.RemoteAddr())
	if mem := m.member(name); mem != nil && mem.Addr.IsValid() {
		at = mem.Addr
	}
	if port := m.pspPort(); port != 0 {
		s.psp = netip.AddrPortFrom(at.Addr(), uint16(port))
	}
	return m.admit(s, name, nil, v, ref)
}
