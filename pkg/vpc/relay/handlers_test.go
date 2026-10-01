// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
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

// issue signs an agent cert with URI SAN san (none if empty), valid for one
// cert lifetime from notBefore.
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

func agentID(k VPCKey, name string) string {
	return identity.ID{Project: k.Project, VPC: k.UID, Agent: name}.String()
}

// fakeTrust is the trust data of a test relay.
type fakeTrust struct {
	mu      sync.Mutex
	ca      *testCA
	revoked map[VPCKey][]vpcv1alpha1.RevokedAgent
	err     error
}

func (f *fakeTrust) AgentCA() (*x509.CertPool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ca.pool(), nil
}

func (f *fakeTrust) Revoked(project, vpcUID string) ([]vpcv1alpha1.RevokedAgent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revoked[VPCKey{Project: project, UID: vpcUID}], f.err
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

// errAny matches any error in TestCheckCert.
var errAny = errors.New("any error")

func TestCheckCert(t *testing.T) {
	ca, other := newCA(t), newCA(t)
	laptop := agentID(vpcA, "laptop")
	issued := t0.Add(-time.Hour)
	cases := []struct {
		name  string
		cert  tls.Certificate
		trust func(*fakeTrust) // Changes the trust data. Nil keeps it.
		now   time.Time
		want  error // Nil means the check passes.
	}{
		{"good", ca.issue(t, laptop, issued), nil, t0, nil},
		{"wrong CA", other.issue(t, laptop, issued), nil, t0, errAny},
		{"expired", ca.issue(t, laptop, issued), nil, issued.Add(identity.CertLifetime + time.Second), errAny},
		{"not yet valid", ca.issue(t, laptop, issued), nil, issued.Add(-time.Second), errAny},
		{"revoked", ca.issue(t, laptop, issued), func(f *fakeTrust) { f.revoke(vpcA, "laptop", t0) }, t0, identity.ErrRevoked},
		{"revoked before the cert", ca.issue(t, laptop, issued), func(f *fakeTrust) { f.revoke(vpcA, "laptop", issued.Add(-time.Minute)) }, t0, nil},
		{"revoked in another VPC", ca.issue(t, laptop, issued), func(f *fakeTrust) { f.revoke(vpcB, "laptop", t0) }, t0, nil},
		{"other agent revoked", ca.issue(t, laptop, issued), func(f *fakeTrust) { f.revoke(vpcA, "phone", t0) }, t0, nil},
		{"no SPIFFE SAN", ca.issue(t, "", issued), nil, t0, errAny},
		{"SAN not an agent ID", ca.issue(t, "spiffe://project-a/workload/x", issued), nil, t0, errAny},
		{"trust data too old", ca.issue(t, laptop, issued), func(f *fakeTrust) { f.err = errors.New("snapshot too old") }, t0, errAny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trust := &fakeTrust{ca: ca}
			if tc.trust != nil {
				tc.trust(trust)
			}
			id, err := NewRouter(trust, Config{}).checkCert([]*x509.Certificate{tc.cert.Leaf}, tc.now)
			switch tc.want {
			case nil:
				require.NoError(t, err)
				assert.Equal(t, laptop, id.String())
			case errAny:
				assert.Error(t, err)
			default:
				assert.ErrorIs(t, err, tc.want)
			}
		})
	}

	t.Run("no cert", func(t *testing.T) {
		_, err := NewRouter(&fakeTrust{ca: ca}, Config{}).checkCert(nil, t0)
		assert.Error(t, err)
	})
	t.Run("no trust data", func(t *testing.T) {
		_, err := NewRouter(nil, Config{}).checkCert([]*x509.Certificate{ca.issue(t, laptop, issued).Leaf}, t0)
		assert.Error(t, err)
	})
}

// harness is a relay that serves the Relay service on loopback QUIC.
type harness struct {
	r     *Router
	trust *fakeTrust
	mux   *rpc.Mux
	ln    *quic.Listener
	wg    sync.WaitGroup
}

func newHarness(t *testing.T, ca *testCA) *harness {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{dp.ALPNRelay, dp.ALPNPeer},
		ClientAuth:   tls.RequireAnyClientCert,
	}, nil)
	require.NoError(t, err)
	trust := &fakeTrust{ca: ca}
	h := &harness{r: NewRouter(trust, Config{}), trust: trust, mux: rpc.NewMux(), ln: ln}
	dp.RegisterRelayServer(h.mux, Server{R: h.r})
	t.Cleanup(func() {
		_ = ln.Close()
		h.wg.Wait()
	})
	return h
}

// agent is one agent connection to the relay.
type agent struct {
	c    dp.RelayClient
	qc   quic.Connection
	sess *Session       // Nil if the relay rejected the agent cert.
	err  error          // Error of AddSession.
	src  netip.AddrPort // Source address as the relay sees it.
}

// dial connects an agent with cert. The relay serves calls also when it
// rejects the cert, so that the test sees the answer of each call.
func (h *harness) dial(t *testing.T, cert tls.Certificate) agent {
	t.Helper()
	return h.dialALPN(t, cert, dp.ALPNRelay)
}

func (h *harness) dialALPN(t *testing.T, cert tls.Certificate, alpn string) agent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accepted := make(chan quic.Connection, 1)
	go func() {
		c, _ := h.ln.Accept(ctx)
		accepted <- c
	}()
	// Dial from 127.0.0.1. On macOS the wildcard socket of DialAddr can get a
	// port that a 127.0.0.1 socket holds, and the replies then go to that socket.
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	dq, err := quic.Dial(ctx, udp, h.ln.Addr(), &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		NextProtos:         []string{alpn},
	}, nil)
	require.NoError(t, err)
	lq := <-accepted
	require.NotNil(t, lq)
	lc := rpc.NewConn(lq, h.mux)
	a := agent{c: dp.NewRelayClient(rpc.NewConn(dq, nil)), qc: dq, src: netip.MustParseAddrPort(lq.RemoteAddr().String())}
	a.sess, a.err = h.r.AddSession(lc)
	h.wg.Go(func() { _ = lc.Serve(context.Background()) })
	t.Cleanup(func() {
		_ = dq.CloseWithError(0, "")
		_ = lq.CloseWithError(0, "")
		_ = udp.Close()
	})
	return a
}

func TestOverQUIC(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	snd := h.dial(t, ca.issue(t, agentID(vpcA, "sender"), time.Now().Add(-time.Hour)))
	recv := h.dial(t, ca.issue(t, agentID(vpcA, "receiver"), time.Now().Add(-time.Hour)))
	require.NoError(t, snd.err)
	require.NoError(t, recv.err)
	// The session identity comes from the agent cert.
	assert.Equal(t, Identity{VPC: vpcA, ID: agentID(vpcA, "sender")}, snd.sess.Identity())
	require.NoError(t, h.r.AddRoute(recv.sess, netip.MustParsePrefix("fd00::2/128")))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := snd.c.ResolvePeer(ctx, &dp.ResolvePeerRequest{Vpc: ref(vpcA), Address: "fd00::2"})
	require.NoError(t, err)
	assert.Equal(t, dp.Reach_REACH_LOCAL, res.Reach)
	assert.True(t, res.P2P)

	_, err = snd.c.RegisterSPI(ctx, register(vpcA, "fd00::2", time.Minute, 7))
	require.NoError(t, err)
	// The relay takes the sender from the authenticated connection.
	dst, v := h.r.Forward(snd.src, 7, 1400, time.Now())
	require.Equal(t, Pass, v)
	assert.Equal(t, recv.src, dst)
	_, v = h.r.Forward(recv.src, 7, 1400, time.Now())
	assert.Equal(t, DropUnknownSPI, v)

	_, err = snd.c.UnregisterSPI(ctx, &dp.UnregisterSPIRequest{Vpc: ref(vpcA), Spis: []uint32{7}})
	require.NoError(t, err)
	_, v = h.r.Forward(snd.src, 7, 1400, time.Now())
	assert.Equal(t, DropUnknownSPI, v)

	// The session and its rows end when the connection closes.
	_, err = snd.c.RegisterSPI(ctx, register(vpcA, "fd00::2", time.Minute, 8))
	require.NoError(t, err)
	require.NoError(t, snd.qc.CloseWithError(0, ""))
	require.Eventually(t, func() bool {
		_, v := h.r.Forward(snd.src, 8, 1400, time.Now())
		return v == DropUnknownSource
	}, 5*time.Second, 10*time.Millisecond)
	assert.Empty(t, h.r.SenderStats(snd.sess).Lanes)
}

// relayCalls are the calls that need the caller identity, each with a VPCRef.
var relayCalls = []struct {
	method string
	json   string // Request from the JSON debug handler.
	call   func(ctx context.Context, c dp.RelayClient, vpc *dp.VPCRef) error
}{
	{dp.Relay_ResolvePeer_FullMethodName, `{"vpc":{"projectId":"project-a","vpcUid":"vpc-1"},"address":"fd00::2"}`,
		func(ctx context.Context, c dp.RelayClient, vpc *dp.VPCRef) error {
			_, err := c.ResolvePeer(ctx, &dp.ResolvePeerRequest{Vpc: vpc, Address: "fd00::2"})
			return err
		}},
	{dp.Relay_RegisterSPI_FullMethodName, `{"vpc":{"projectId":"project-a","vpcUid":"vpc-1"},"destination":"fd00::2","spis":[7],"expiresIn":"60s"}`,
		func(ctx context.Context, c dp.RelayClient, vpc *dp.VPCRef) error {
			_, err := c.RegisterSPI(ctx, &dp.RegisterSPIRequest{Vpc: vpc, Destination: "fd00::2", Spis: []uint32{7}, ExpiresIn: durationpb.New(time.Minute)})
			return err
		}},
	{dp.Relay_UnregisterSPI_FullMethodName, `{"vpc":{"projectId":"project-a","vpcUid":"vpc-1"},"spis":[7]}`,
		func(ctx context.Context, c dp.RelayClient, vpc *dp.VPCRef) error {
			_, err := c.UnregisterSPI(ctx, &dp.UnregisterSPIRequest{Vpc: vpc, Spis: []uint32{7}})
			return err
		}},
}

func shortName(method string) string { return method[strings.LastIndex(method, "/")+1:] }

// TestUnauthenticated checks that each call that needs the caller identity
// fails with Unauthenticated when there is no session: from the JSON debug
// handler (no Conn) and from a connection whose agent cert failed the check.
func TestUnauthenticated(t *testing.T) {
	h := newHarness(t, newCA(t))
	stranger := h.dial(t, newCA(t).issue(t, agentID(vpcA, "stranger"), time.Now().Add(-time.Hour)))
	require.Error(t, stranger.err)
	require.Nil(t, stranger.sess)
	// A good cert on another ALPN opens no relay session.
	ca := h.trust.ca
	assert.Error(t, h.dialALPN(t, ca.issue(t, agentID(vpcA, "peer"), time.Now().Add(-time.Hour)), dp.ALPNPeer).err)
	srv := httptest.NewServer(rpc.JSONHandler(h.mux))
	defer srv.Close()

	for _, tc := range relayCalls {
		t.Run(shortName(tc.method), func(t *testing.T) {
			resp, err := http.Post(srv.URL+tc.method, "application/json", strings.NewReader(tc.json))
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "JSON debug handler")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			assert.Equal(t, rpc.Unauthenticated, rpc.CodeOf(tc.call(ctx, stranger.c, ref(vpcA))), "cert from another CA")
		})
	}
}

// TestCertVPC checks that each call uses only the VPC in the agent cert,
// also when Permit allows all.
func TestCertVPC(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	h.r.SetPermit(func(VPCKey, string, VPCKey, netip.Addr) bool { return true })
	a := h.dial(t, ca.issue(t, agentID(vpcA, "laptop"), time.Now().Add(-time.Hour)))
	require.NoError(t, a.err)
	peer := h.dial(t, ca.issue(t, agentID(vpcA, "peer"), time.Now().Add(-time.Hour)))
	require.NoError(t, peer.err)
	require.NoError(t, h.r.AddRoute(peer.sess, netip.MustParsePrefix("fd00::2/128")))

	refs := []struct {
		name string
		vpc  *dp.VPCRef
		code rpc.Code
	}{
		{"cert VPC", ref(vpcA), rpc.OK},
		{"another project", ref(vpcB), rpc.PermissionDenied},
		{"another VPC", ref(VPCKey{Project: vpcA.Project, UID: "vpc-2"}), rpc.PermissionDenied},
	}
	for _, call := range relayCalls {
		for _, tc := range refs {
			t.Run(shortName(call.method)+"/"+tc.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				err := call.call(ctx, a.c, tc.vpc)
				assert.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
			})
		}
	}
}

// TestTrustChange checks that a change of the trust data applies to new
// sessions. Sessions that exist continue.
func TestTrustChange(t *testing.T) {
	oldCA, newCA := newCA(t), newCA(t)
	h := newHarness(t, oldCA)
	issued := time.Now().Add(-time.Hour)
	first := h.dial(t, oldCA.issue(t, agentID(vpcA, "first"), issued))
	require.NoError(t, first.err)

	h.trust.setCA(newCA)
	assert.Error(t, h.dial(t, oldCA.issue(t, agentID(vpcA, "second"), issued)).err, "cert from the old CA")
	second := h.dial(t, newCA.issue(t, agentID(vpcA, "second"), issued))
	require.NoError(t, second.err, "cert from the new CA")
	require.NoError(t, h.r.AddRoute(second.sess, netip.MustParsePrefix("fd00::2/128")))

	h.trust.revoke(vpcA, "third", time.Now())
	assert.ErrorIs(t, h.dial(t, newCA.issue(t, agentID(vpcA, "third"), issued)).err, identity.ErrRevoked)

	// The session from the old CA continues.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := first.c.ResolvePeer(ctx, &dp.ResolvePeerRequest{Vpc: ref(vpcA), Address: "fd00::2"})
	require.NoError(t, err)
	assert.Equal(t, dp.Reach_REACH_LOCAL, res.Reach)
}
