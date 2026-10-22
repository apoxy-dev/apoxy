package tunnel_test

import (
	"cmp"
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
	router *vpcrelay.Router
	addr   netip.AddrPort // QUIC socket of the VPC relay.
	data   uint16         // Data port of the VPC data plane.
	roots  *x509.CertPool // Relay roots.
	ca     *vpctest.CA
	cancel context.CancelFunc // Starts the drain.
}

// vpcRelayOpts are the options of startVPCRelay.
type vpcRelayOpts struct {
	steer    int // Tunnel sockets in a steer group. Zero uses one plain socket.
	lameDuck time.Duration
	// mesh is the CA of the relay certs of a mesh, with id the relay ID and
	// mesh name of the relay. Nil gives the ID localhost and no mesh.
	mesh  *vpctest.CA
	id    string
	ca    *vpctest.CA   // CA of the agents. Nil makes a new one.
	addrs *vpcAddresses // Address pool. Nil makes a new one.
}

func startVPCRelay(t *testing.T, o vpcRelayOpts) *vpcRelay {
	ca, err := vpctest.NewCA()
	require.NoError(t, err)
	if o.ca != nil {
		ca = o.ca
	}
	steerSockets := o.steer
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
	// The name of the relay is its name in the mesh.
	name := "localhost"
	if o.mesh != nil {
		name = o.id
	}
	r := tunnel.NewRelay(name, conns[0], serverCert, h, hasher.NewHasher(make([]byte, 32)), rtr)
	if steerSockets > 0 {
		require.NoError(t, r.SetSteerGroup(conns))
	}
	require.NoError(t, r.SetStatelessResetSecret([]byte("secret")))

	// The VPC relay has the QUIC socket of its data plane.
	lo, err := vpctest.NewLoopback()
	require.NoError(t, err)
	go func() { _ = lo.Run() }()
	ref := &dp.RelayRef{Id: name}
	if o.mesh != nil {
		ref.Addresses = []string{lo.QUIC.LocalAddr().String()}
	}
	router, err := r.SetVPC(lo.QUIC, vpcrelay.Config{
		Relay:     ref,
		Trust:     vpcTrust{ca.Pool()},
		Addresses: cmp.Or(o.addrs, &vpcAddresses{}),
		Target:    lo.Target,
	})
	require.NoError(t, err)
	router.AddTenant(vpcProject)
	router.AddVPC(vpcrelay.VPCKey{Project: vpcProject, UID: vpcUID}, vpcrelay.Network{ID: vpcNetwork})
	if o.mesh != nil {
		cert, err := o.mesh.RelayCert(o.id)
		require.NoError(t, err)
		require.NoError(t, r.SetMesh(vpcrelay.MeshConfig{
			TLS:    &tls.Config{Certificates: []tls.Certificate{*cert}, InsecureSkipVerify: true},
			Verify: verifyMember(o.mesh),
		}))
	}
	r.SetLameDuckPeriod(o.lameDuck)

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
		r: r, router: router, addr: lo.QUIC.LocalAddr().(*net.UDPAddr).AddrPort(), data: lo.DataPort(),
		roots: cryptoutils.CertPoolForCertificate(relayCA), ca: ca, cancel: cancel,
	}
}

// verifyMember accepts a relay cert of ca that names the relay.
func verifyMember(ca *vpctest.CA) vpcrelay.MeshVerify {
	return func(chain []*x509.Certificate, name string, _ netip.AddrPort) error {
		if len(chain) == 0 {
			return errors.New("no certificate")
		}
		_, err := chain[0].Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		return err
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
	v := startVPCRelay(t, vpcRelayOpts{steer: steerSockets})
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
			v := startVPCRelay(t, vpcRelayOpts{lameDuck: 2 * time.Second})
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

// TestRelay_VPCMesh runs two relay hosts with a mesh on the QUIC sockets of
// their VPC relays. A data frame passes from an agent of relay-a to an agent of
// relay-b, and the drain of relay-a gives its agent relay-b as the alternate.
func TestRelay_VPCMesh(t *testing.T) {
	meshCA, err := vpctest.NewCA()
	require.NoError(t, err)
	agents, err := vpctest.NewCA()
	require.NoError(t, err)
	// An agent gets Drain only from a relay with a lame duck time.
	addrs := &vpcAddresses{}
	a := startVPCRelay(t, vpcRelayOpts{mesh: meshCA, id: "relay-a", ca: agents, addrs: addrs, lameDuck: 2 * time.Second})
	b := startVPCRelay(t, vpcRelayOpts{mesh: meshCA, id: "relay-b", ca: agents, addrs: addrs})
	a.router.SetMembers([]vpcrelay.MeshMember{{Name: "relay-b", Addr: b.addr}})
	b.router.SetMembers([]vpcrelay.MeshMember{{Name: "relay-a", Addr: a.addr}})
	require.Eventually(t, func() bool { return a.router.Up("relay-b") && b.router.Up("relay-a") }, 10*time.Second, 10*time.Millisecond,
		"mesh sessions")

	attach := func(v *vpcRelay, name string) (quic.Connection, netip.Addr, rpc.BidiStreamClient[dp.SessionRequest, dp.SessionResponse]) {
		qc, c, st := v.openSession(t, name)
		res, err := c.Attach(t.Context(), &dp.AttachRequest{Vpc: &dp.VPCRef{ProjectId: vpcProject, VpcUid: vpcUID}, Name: name})
		require.NoError(t, err)
		require.Len(t, res.GetAddresses(), 1)
		return qc, vpcrelay.OverlayAddr(netip.MustParsePrefix(res.GetAddresses()[0])), st
	}
	qa, addrA, st := attach(a, "agent-a")
	qb, addrB, _ := attach(b, "agent-b")
	inner := make([]byte, 60)
	inner[0] = 0x60
	src, dst := addrA.As16(), addrB.As16()
	copy(inner[8:], src[:])
	copy(inner[24:], dst[:])
	frame := peerconn.EncodeData(nil, vpcNetwork, inner)
	// The frame passes when relay-a has the route of agent-b from the mesh.
	require.Eventually(t, func() bool {
		require.NoError(t, qa.SendDatagram(frame))
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		got, err := qb.ReceiveDatagram(ctx)
		return err == nil && assert.Equal(t, frame, got)
	}, 10*time.Second, 10*time.Millisecond, "frame from agent-a to agent-b")

	a.cancel()
	for {
		m, err := st.Recv()
		require.NoError(t, err)
		if d := m.GetDrain(); d != nil {
			require.Len(t, d.GetAlternates(), 1)
			assert.Equal(t, "relay-b", d.GetAlternates()[0].GetId())
			assert.Equal(t, []string{b.addr.String()}, d.GetAlternates()[0].GetAddresses())
			break
		}
	}
}
