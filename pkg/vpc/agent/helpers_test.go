// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
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
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

const (
	testProject = "project-a"
	testVPC     = "vpc-1"
	testVNI     = 0x0a0b0c
)

func TestMain(m *testing.M) {
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	os.Exit(m.Run())
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// testCA signs agent certs or relay certs.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t testing.TB) *testCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
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

var serial atomic.Int64

func (ca *testCA) sign(t testing.TB, tmpl *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl.SerialNumber = big.NewInt(serial.Add(1) + 10)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	return der
}

// credential issues a credential for agent name, valid for life.
func (ca *testCA) credential(t testing.TB, project, vpc, name string, life time.Duration) *identity.Credential {
	t.Helper()
	key := newKey(t)
	id := identity.ID{Project: project, VPC: vpc, Agent: name}
	der := ca.sign(t, &x509.Certificate{
		URIs:      []*url.URL{id.URI()},
		NotBefore: time.Now().Add(-time.Second), NotAfter: time.Now().Add(life),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, key)
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	cred, err := identity.NewCredential(key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), bundle)
	require.NoError(t, err)
	return cred
}

// relayCert issues a relay cert that names only id.
func (ca *testCA) relayCert(t testing.TB, id string) *tls.Certificate {
	t.Helper()
	key := newKey(t)
	der := ca.sign(t, &x509.Certificate{
		DNSNames:  []string{id},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, key)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type fakeTrust struct {
	mu      sync.Mutex
	pool    *x509.CertPool
	revoked []vpcv1alpha1.RevokedAgent
}

func (f *fakeTrust) AgentCA() (*x509.CertPool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pool, nil
}

func (f *fakeTrust) Revoked(string, string) ([]vpcv1alpha1.RevokedAgent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revoked, nil
}

type fakeNetworks struct{}

func (fakeNetworks) Network(project, uid string) (relay.Network, error) {
	if project != testProject || uid != testVPC {
		return relay.Network{}, fmt.Errorf("unknown VPC %s/%s", project, uid)
	}
	return relay.Network{ID: testVNI}, nil
}

// fakeAddresses gives each attachment the next fd00:<n>::/96 and counts the
// live attachments of each agent.
type fakeAddresses struct {
	mu      sync.Mutex
	next    int
	live    map[string]int // Subject to live attachments.
	maxLive map[string]int
}

func (f *fakeAddresses) Assign(_ context.Context, a *relay.Attachment) ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	if f.live == nil {
		f.live, f.maxLive = map[string]int{}, map[string]int{}
	}
	f.live[a.Subject]++
	f.maxLive[a.Subject] = max(f.maxLive[a.Subject], f.live[a.Subject])
	return []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("fd00:%x::/96", f.next))}, nil
}

func (f *fakeAddresses) Release(a *relay.Attachment) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.live[a.Subject]--
}

// overlap returns the most attachments of subject that were live at once.
func (f *fakeAddresses) overlap(subject string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxLive[subject]
}

// world is the CAs and the address pool of one test.
type world struct {
	mu               sync.Mutex
	agentCA, relayCA *testCA
	trust            *fakeTrust
	addrs            *fakeAddresses
}

// rotateAgentCA makes a new agent CA for enrolls and relays.
func (w *world) rotateAgentCA(t testing.TB) {
	ca := newCA(t)
	w.mu.Lock()
	w.agentCA = ca
	w.mu.Unlock()
	w.trust.mu.Lock()
	w.trust.pool = ca.pool()
	w.trust.mu.Unlock()
}

func (w *world) enrollCA() *testCA {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.agentCA
}

func newWorld(t testing.TB) *world {
	w := &world{agentCA: newCA(t), relayCA: newCA(t), addrs: &fakeAddresses{}}
	w.trust = &fakeTrust{pool: w.agentCA.pool()}
	return w
}

// testRelay is a relay on loopback that forwards PSP packets and peer frames.
type testRelay struct {
	id   string
	srv  *relay.Server
	r    *relay.Router
	addr string
}

func (w *world) relay(t testing.TB, id string) *testRelay {
	t.Helper()
	cert := w.relayCA.relayCert(t, id)
	r := relay.NewRouter(w.trust, relay.Config{})
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udp}
	tr.NonQUICPacketHandler = r.PacketHandler(tr)
	ln, err := tr.Listen(r.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*cert}}), &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	srv := &relay.Server{
		R: r, Networks: fakeNetworks{}, Addresses: w.addrs, RelayID: id,
		Cert: func() (*tls.Certificate, error) { return cert, nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { _ = srv.Serve(ctx, ln) })
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		wg.Wait()
		_ = tr.Close()
		_ = udp.Close()
	})
	return &testRelay{id: id, srv: srv, r: r, addr: udp.LocalAddr().String()}
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
}

type agentOptions struct {
	life time.Duration // Cert life. Zero means 24 hours.
}

func (w *world) agent(t *testing.T, name string, r *testRelay, opts agentOptions) *testAgent {
	t.Helper()
	if opts.life == 0 {
		opts.life = 24 * time.Hour
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	ta := &testAgent{tr: &quic.Transport{Conn: udp}, attach: make(chan attachEvent, 16), done: make(chan struct{})}
	enroll := func(context.Context) (*identity.Credential, error) {
		ta.enrolls.Add(1)
		return w.enrollCA().credential(t, testProject, testVPC, name, opts.life), nil
	}
	ta.a = New(Config{
		Identity:   identity.NewManager(filepath.Join(t.TempDir(), "cred.json"), enroll),
		Relay:      r.addr,
		RelayID:    r.id,
		RelayRoots: w.relayCA.pool(),
		Transport:  ta.tr,
		Name:       name,
		OnAttach: func(b *psp.Binding, addr netip.Addr, prefixes []netip.Prefix) {
			ta.netstack(t, b, addr)
			ta.attach <- attachEvent{addr, prefixes}
		},
	})
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

// netstack starts a netstack on b at the first attach, and adds addr.
func (ta *testAgent) netstack(t *testing.T, b *psp.Binding, addr netip.Addr) {
	ta.stackOnce.Do(func() {
		s := stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		})
		ep := channel.New(256, psp.DefaultMTU, "")
		if err := s.CreateNIC(1, ep); err != nil {
			t.Errorf("create NIC: %v", err)
			return
		}
		s.SetRouteTable([]tcpip.Route{{Destination: header.IPv6EmptySubnet, NIC: 1}})
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
			s.Close()
		})
		ta.stack = s
	})
	pa := tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix()}
	if err := ta.stack.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		t.Errorf("add address: %v", err)
	}
}
