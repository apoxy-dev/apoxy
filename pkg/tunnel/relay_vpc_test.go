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
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

// vpcTrust trusts one CA for the agent certs.
type vpcTrust struct{ pool *x509.CertPool }

func (f vpcTrust) AgentCA(string) (*x509.CertPool, error) { return f.pool, nil }
func (vpcTrust) Revoked(string, string) ([]vpcv1alpha1.RevokedAgent, error) {
	return nil, nil
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

// TestRelay_VPCSharesSocket runs HTTP/3 on the tunnel sockets and VPC relay
// sessions on the QUIC socket of the VPC data plane, and sends data frames
// between VPC agents.
func TestRelay_VPCSharesSocket(t *testing.T) {
	cases := []struct {
		name  string
		steer int // Tunnel sockets in a steer group. Zero uses one plain socket.
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
	addr   netip.AddrPort // QUIC socket of the VPC relay.
	data   uint16         // Data port of the VPC data plane.
	roots  *x509.CertPool // Relay roots.
	ca     *vpctest.CA
	cancel context.CancelFunc // Starts the drain.
}

func startVPCRelay(t *testing.T, steerSockets int, lameDuck time.Duration) *vpcRelay {
	ca, err := vpctest.NewCA()
	require.NoError(t, err)
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
	h, err := icx.NewHandler(
		icx.WithLocalAddr(netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()),
	)
	require.NoError(t, err)
	rtr := &mockRouter{}
	rtr.On("Start", mock.Anything).Return(nil)
	rtr.On("Close").Return(nil)
	r := tunnel.NewRelay("localhost", conns[0], serverCert, h, hasher.NewHasher(make([]byte, 32)), rtr)
	if steerSockets > 0 {
		require.NoError(t, r.SetSteerGroup(conns))
	}
	require.NoError(t, r.SetStatelessResetSecret([]byte("secret")))

	// The VPC relay has the QUIC socket of its data plane.
	lo, err := vpctest.NewLoopback()
	require.NoError(t, err)
	go func() { _ = lo.Run() }()
	router, err := r.SetVPC(lo.QUIC, vpcrelay.Config{
		Relay:     &dp.RelayRef{Id: "localhost"},
		Trust:     vpcTrust{ca.Pool()},
		Addresses: &vpcAddresses{},
		Target:    lo.Target,
	})
	require.NoError(t, err)
	router.AddTenant(vpcProject)
	router.AddVPC(vpcrelay.VPCKey{Project: vpcProject, UID: vpcUID}, vpcrelay.Network{ID: vpcNetwork})
	r.SetLameDuckPeriod(lameDuck)

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
		_ = lo.Close()
	})
	return &vpcRelay{
		r: r, addr: lo.QUIC.LocalAddr().(*net.UDPAddr).AddrPort(), data: lo.DataPort(),
		roots: cryptoutils.CertPoolForCertificate(relayCA), ca: ca, cancel: cancel,
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, v.ca.Cert, &key.PublicKey, v.ca.Key)
	require.NoError(t, err)
	return &tls.Config{
		RootCAs:      v.roots,
		ServerName:   "localhost",
		NextProtos:   []string{dp.ALPNRelay},
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
}

// dialAt dials the relay socket at addr with conf from a new socket.
func (v *vpcRelay) dialAt(t *testing.T, conf *tls.Config, addr netip.AddrPort) (quic.Connection, error) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udp}
	t.Cleanup(func() { _ = tr.Close(); _ = udp.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return tr.Dial(ctx, net.UDPAddrFromAddrPort(addr), conf, &quic.Config{EnableDatagrams: true})
}

// openSession dials the VPC relay as agent name and runs the Session call to
// its Config message.
func (v *vpcRelay) openSession(t *testing.T, name string) (quic.Connection, dp.RelayClient, rpc.BidiStreamClient[dp.SessionRequest, dp.SessionResponse]) {
	t.Helper()
	qc, err := v.dialAt(t, v.agentTLS(t, name), v.addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	c := dp.NewRelayClient(rpc.NewConn(qc, nil))
	st, err := c.Session(context.Background())
	require.NoError(t, err)
	hello := &dp.Hello{Mode: dp.Mode_MODE_QUIC, Version: dp.LocalVersion("test"), Name: name}
	require.NoError(t, st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: hello}}))
	m, err := st.Recv()
	require.NoError(t, err)
	require.NotNil(t, m.GetWelcome(), "first message: %v", m)
	require.Empty(t, m.GetWelcome().GetPspHost())
	require.Equal(t, v.data, uint16(m.GetWelcome().GetPspPort()))
	m, err = st.Recv()
	require.NoError(t, err)
	require.NotNil(t, m.GetConfig(), "second message: %v", m)
	return qc, c, st
}

func testRelayVPC(t *testing.T, steerSockets int) {
	v := startVPCRelay(t, steerSockets, 0)
	r := v.r

	// HTTP/3 still works.
	h3 := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: v.roots, ServerName: "localhost"}}
	t.Cleanup(func() { _ = h3.Close() })
	require.Eventually(t, func() bool {
		resp, err := (&http.Client{Transport: h3, Timeout: time.Second}).Get("https://" + r.Address().String() + "/ping")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond)

	// The tunnel socket has no VPC relay sessions.
	_, err := v.dialAt(t, v.agentTLS(t, "tunnel-socket"), r.Address())
	var te *quic.TransportError
	require.ErrorAs(t, err, &te)
	assert.True(t, te.Remote, "the relay refused the handshake")

	type vpcAgent struct {
		qc   quic.Connection
		addr netip.Addr
	}
	agents := make([]vpcAgent, 4)
	for i := range agents {
		name := fmt.Sprintf("agent-%d", i)
		qc, c, _ := v.openSession(t, name)
		res, err := c.Attach(t.Context(), &dp.AttachRequest{Vpc: &dp.VPCRef{ProjectId: vpcProject, VpcUid: vpcUID}, Name: name})
		require.NoError(t, err)
		require.Len(t, res.GetAddresses(), 1)
		agents[i] = vpcAgent{qc: qc, addr: vpcrelay.OverlayAddr(netip.MustParsePrefix(res.GetAddresses()[0]))}
	}
	for i, a := range agents {
		b := agents[(i+1)%len(agents)]
		inner := make([]byte, 60)
		inner[0] = 0x60
		src, dst := a.addr.As16(), b.addr.As16()
		copy(inner[8:], src[:])
		copy(inner[24:], dst[:])
		frame := peerconn.EncodeData(nil, vpcNetwork, inner)
		require.NoError(t, a.qc.SendDatagram(frame))
		rctx, rcancel := context.WithTimeout(t.Context(), 5*time.Second)
		got, err := b.qc.ReceiveDatagram(rctx)
		rcancel()
		require.NoError(t, err)
		assert.Equal(t, frame, got)
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
			_, _, st := v.openSession(t, "stayer")
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
			// HTTP/3 has the tunnel socket, and the VPC relay its own QUIC socket.
			to := v.addr
			if tc.alpn == http3.NextProtoH3 {
				to = v.r.Address()
			}
			start := time.Now()
			late, err := v.dialAt(t, conf, to)
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
