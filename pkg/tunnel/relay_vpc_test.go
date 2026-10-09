package tunnel_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"gvisor.dev/gvisor/pkg/tcpip"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/hasher"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	vpcrelay "github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/steer"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	vpcProject = "project-a"
	vpcUID     = "vpc-1"
	vpcNetwork = 0x0a0b0c
)

// vpcTrust trusts one CA for the agent certs. A nil relays is the system roots.
type vpcTrust struct{ pool, relays *x509.CertPool }

func (f vpcTrust) AgentCA(string) (*x509.CertPool, error)    { return f.pool, nil }
func (f vpcTrust) RelayRoots(string) (*x509.CertPool, error) { return f.relays, nil }
func (vpcTrust) Revoked(string, string) ([]vpcv1alpha1.RevokedAgent, error) {
	return nil, nil
}

type vpcNetworks struct{}

func (vpcNetworks) Network(project, uid string) (vpcrelay.Network, error) {
	if project != vpcProject || uid != vpcUID {
		return vpcrelay.Network{}, fmt.Errorf("unknown VPC %s/%s", project, uid)
	}
	return vpcrelay.Network{ID: vpcNetwork}, nil
}

// vpcAddresses gives each attachment the next fd00:<n>::/96, from next + 1.
type vpcAddresses struct {
	mu   sync.Mutex
	next int
}

func (f *vpcAddresses) Assign(context.Context, *vpcrelay.Attachment, func()) ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	return []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("fd00:%x::/96", f.next))}, nil
}

func (f *vpcAddresses) Attached(*vpcrelay.Attachment) {}

func (f *vpcAddresses) Release(*vpcrelay.Attachment) {}

// vpcAgent is an agent connection to the relay on its own socket.
type vpcAgent struct {
	tr   *quic.Transport
	qc   quic.Connection
	c    dp.RelayClient
	addr netip.Addr // Overlay address from the grant.
}

// TestRelay_VPCSharesSocket runs HTTP/3 and VPC relay sessions on the relay
// sockets, and sends PSP packets and peer frames between VPC agents.
func TestRelay_VPCSharesSocket(t *testing.T) {
	cases := []struct {
		name  string
		steer int // Sockets in a steer group. Zero uses one plain socket.
	}{
		{name: "one socket"},
		{name: "steer group of 1", steer: 1},
		{name: "steer group of 4", steer: 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.steer > 1 && runtime.GOOS != "linux" {
				t.Skip("a steer group of more than one socket needs Linux")
			}
			testRelayVPC(t, tc.steer)
		})
	}
}

// vpcRelay is a started relay with VPC sessions, and the CA of its agents.
type vpcRelay struct {
	r      *tunnel.Relay
	router *vpcrelay.Router  // Nil with no VPC relay sessions.
	roots  *x509.CertPool    // Relay roots.
	root   *x509.Certificate // CA of the relay cert.
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	ctx    context.Context
	cancel context.CancelFunc // Starts the drain.
	done   <-chan struct{}    // Closed when Start returns.
}

// relayOpts are the options of startRelayWith.
type relayOpts struct {
	name         string // Relay name. Empty is "localhost".
	relayID      string // Relay ID that a mesh gives of the relay. Empty is "localhost".
	steerSockets int
	lameDuck     time.Duration
	noVPC        bool                // The relay serves no VPC relay sessions.
	addrs        vpcrelay.Addresses  // Addresses of the attachments. Nil starts at fd00:1::/96.
	agentCA      *vpctest.CA         // CA of the agents. Nil makes a CA for this relay.
	relayRoots   *x509.CertPool      // Roots for the relay cert of a grant. Nil is the system roots.
	setup        func(*tunnel.Relay) // Runs before Start.
}

func startVPCRelay(t *testing.T, steerSockets int, lameDuck time.Duration) *vpcRelay {
	return startRelayWith(t, relayOpts{steerSockets: steerSockets, lameDuck: lameDuck})
}

func startRelayWith(t *testing.T, o relayOpts) *vpcRelay {
	steerSockets, lameDuck := o.steerSockets, o.lameDuck
	if o.name == "" {
		o.name = "localhost"
	}
	var err error
	if o.agentCA == nil {
		o.agentCA, err = vpctest.NewCA()
		require.NoError(t, err)
	}

	var conns []*net.UDPConn
	if steerSockets > 0 {
		conns, err = steer.Listen("udp", "127.0.0.1:0", steerSockets)
		require.NoError(t, err)
	} else {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		conns = []*net.UDPConn{pc.(*net.UDPConn)}
	}
	relayCA, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	require.NoError(t, err)
	root, err := x509.ParseCertificate(relayCA.Certificate[0])
	require.NoError(t, err)
	h, err := icx.NewHandler(
		icx.WithLocalAddr(netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()),
	)
	require.NoError(t, err)
	rtr := &mockRouter{}
	rtr.On("Start", mock.Anything).Return(nil)
	rtr.On("Close").Return(nil)
	r := tunnel.NewRelay(o.name, conns[0], serverCert, h, hasher.NewHasher(make([]byte, 32)), rtr)
	if steerSockets > 0 {
		require.NoError(t, r.SetSteerGroup(conns))
	}
	require.NoError(t, r.SetStatelessResetSecret([]byte("secret")))
	if o.addrs == nil {
		o.addrs = &vpcAddresses{}
	}
	var router *vpcrelay.Router
	if !o.noVPC {
		router = r.SetVPC("localhost", vpcTrust{o.agentCA.Pool(), o.relayRoots}, vpcNetworks{}, o.addrs, vpcrelay.Config{})
	}
	r.SetLameDuckPeriod(lameDuck)
	if o.setup != nil {
		o.setup(r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		assert.NoError(t, r.Start(ctx))
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return &vpcRelay{
		r: r, router: router, roots: cryptoutils.CertPoolForCertificate(relayCA), root: root,
		ca: o.agentCA.Cert, caKey: o.agentCA.Key, ctx: ctx, cancel: cancel, done: done,
	}
}

// agentTLS returns the apoxy-vpc/2 client config of agent name.
func (v *vpcRelay) agentTLS(t *testing.T, name string) *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	id := identity.ID{Project: vpcProject, VPC: vpcUID, Agent: name}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), URIs: []*url.URL{id.URI()},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, v.ca, &key.PublicKey, v.caKey)
	require.NoError(t, err)
	return &tls.Config{
		RootCAs:      v.roots,
		ServerName:   "localhost",
		NextProtos:   []string{dp.ALPNRelay},
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
}

// dial dials the relay with conf from a new socket.
func (v *vpcRelay) dial(t *testing.T, conf *tls.Config) (*quic.Transport, quic.Connection, error) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udp}
	t.Cleanup(func() { _ = tr.Close(); _ = udp.Close() })
	// quic-go drops non-QUIC packets until the first ReadNonQUICPacket call.
	stopped, stop := context.WithCancel(context.Background())
	stop()
	_, _, _ = tr.ReadNonQUICPacket(stopped, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qc, err := tr.Dial(ctx, net.UDPAddrFromAddrPort(v.r.Address()), conf, &quic.Config{EnableDatagrams: true})
	return tr, qc, err
}

func testRelayVPC(t *testing.T, steerSockets int) {
	v := startVPCRelay(t, steerSockets, 0)
	r, ctx, relayRoots := v.r, v.ctx, v.roots

	// HTTP/3 still works.
	h3 := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: relayRoots, ServerName: "localhost"}}
	t.Cleanup(func() { _ = h3.Close() })
	require.Eventually(t, func() bool {
		resp, err := (&http.Client{Transport: h3, Timeout: time.Second}).Get("https://" + r.Address().String() + "/ping")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond)

	dial := func(name string) vpcAgent {
		tr, qc, err := v.dial(t, v.agentTLS(t, name))
		require.NoError(t, err)
		dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
		defer dcancel()
		a := vpcAgent{tr: tr, qc: qc, c: dp.NewRelayClient(rpc.NewConn(qc, nil))}
		res, err := a.c.Attach(dctx, &dp.AttachRequest{Vpc: &dp.VPCRef{ProjectId: vpcProject, VpcUid: vpcUID, NetworkId: vpcNetwork}, Name: name})
		require.NoError(t, err)
		claims, err := vpcrelay.VerifyGrant(res.Grant, relayRoots, time.Now())
		require.NoError(t, err)
		assert.Equal(t, "localhost", claims.RelayId)
		a.addr = netip.MustParsePrefix(claims.Addresses[0]).Addr().Next()
		return a
	}
	// The kernel puts each new connection on a random socket of the group. The
	// later packets of a connection must reach that socket.
	agents := make([]vpcAgent, 4)
	for i := range agents {
		agents[i] = dial(fmt.Sprintf("agent-%d", i))
	}
	aead, err := pspwire.NewAEAD(make([]byte, 16))
	require.NoError(t, err)
	for i, a := range agents {
		b := agents[(i+1)%len(agents)]
		rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
		defer rcancel()

		// A peer frame from a to b.
		require.NoError(t, a.qc.SendDatagram(peerconn.EncodeToRelay(nil, b.addr, a.addr, []byte("hello"))))
		got, err := b.qc.ReceiveDatagram(rctx)
		require.NoError(t, err)
		assert.Equal(t, peerconn.EncodeFromRelay(nil, a.addr, []byte("hello")), got)

		// A PSP packet from a to b by the SPI row of a, through the packet handler.
		_, err = a.c.RegisterSPI(rctx, &dp.RegisterSPIRequest{
			Vpc:         &dp.VPCRef{ProjectId: vpcProject, VpcUid: vpcUID, NetworkId: vpcNetwork},
			Destination: b.addr.String(), Spis: []uint32{7}, ExpiresIn: durationpb.New(time.Minute),
		})
		require.NoError(t, err)
		inner := make([]byte, 40)
		inner[0] = 0x60
		pkt := make([]byte, len(inner)+pspwire.Overhead)
		n, err := pspwire.Seal(aead, pspwire.Header{SPI: 7, VNI: vpcNetwork}, pkt, inner)
		require.NoError(t, err)
		_, err = a.tr.WriteTo(pkt[:n], net.UDPAddrFromAddrPort(r.Address()))
		require.NoError(t, err)
		buf := make([]byte, 1500)
		m, _, err := b.tr.ReadNonQUICPacket(rctx, buf)
		require.NoError(t, err)
		assert.Equal(t, pkt[:n], buf[:m])
	}
}

// TestRelay_VPCDrain dials the relay during its drain. The new connection gets
// a close at once, and does not wait for the open timeout of the agent.
func TestRelay_VPCDrain(t *testing.T) {
	cases := []struct {
		name string
		alpn string
		code quic.ApplicationErrorCode
	}{
		{name: "apoxy-vpc/2", alpn: dp.ALPNRelay, code: quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN)},
		{name: "h3", alpn: http3.NextProtoH3, code: quic.ApplicationErrorCode(http3.ErrCodeNoError)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := startVPCRelay(t, 0, 2*time.Second)
			// An agent with a session sees the start of the drain.
			_, qc, err := v.dial(t, v.agentTLS(t, "stayer"))
			require.NoError(t, err)
			st, err := dp.NewRelayClient(rpc.NewConn(qc, nil)).Session(context.Background())
			require.NoError(t, err)
			hello := &dp.Hello{Mode: dp.Mode_MODE_QUIC, Version: dp.LocalVersion("test")}
			require.NoError(t, st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: hello}}))
			_, err = st.Recv()
			require.NoError(t, err)
			v.cancel()
			for {
				m, err := st.Recv()
				require.NoError(t, err)
				if d := m.GetDrain(); d != nil {
					assert.Empty(t, d.GetAlternates(), "a relay with no mesh has no relay to move to")
					break
				}
			}
			// Dial after the h3 Shutdown, which stopped the accept loop before.
			h3 := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: v.roots, ServerName: "localhost"}}
			t.Cleanup(func() { _ = h3.Close() })
			c := &http.Client{Transport: h3, Timeout: 500 * time.Millisecond}
			require.Eventually(t, func() bool {
				resp, err := c.Get("https://" + v.r.Address().String() + "/ping")
				if err == nil {
					_ = resp.Body.Close()
				}
				return err != nil
			}, 5*time.Second, 20*time.Millisecond, "h3 shuts down")

			conf := v.agentTLS(t, "late")
			conf.NextProtos = []string{tc.alpn}
			start := time.Now()
			_, late, err := v.dial(t, conf)
			if err == nil {
				select {
				case <-late.Context().Done():
				case <-time.After(time.Second):
					t.Fatal("the relay did not close the new connection in 1 s")
				}
				err = context.Cause(late.Context())
			}
			var ae *quic.ApplicationError
			require.Truef(t, errors.As(err, &ae), "close error %T", err)
			assert.True(t, ae.Remote)
			assert.Equal(t, tc.code, ae.ErrorCode)
			assert.Less(t, time.Since(start), time.Second)
		})
	}
}
