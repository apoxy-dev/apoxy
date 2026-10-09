package tunnel_test

import (
	"bytes"
	"context"
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
	"net/http"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/vpc/agent"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	vpcrelay "github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// meshCA issues the certs of the relays in the mesh tests. A cert names its
// relay.
type meshCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newMeshCA(t *testing.T) *meshCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &meshCA{cert: cert, key: key}
}

// tls returns the TLS config of relay name for both ends of a mesh session.
// The handshake checks nothing, so the check of the mesh makes the decision.
func (ca *meshCA) tls(t *testing.T, name string) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	return &tls.Config{
		Certificates:       []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		InsecureSkipVerify: true,
	}
}

// meshCheck is one call of the check of the other relay.
type meshCheck struct {
	name string
	from netip.AddrPort
}

// verify is the check of the other relay: its cert is from ca and names it.
// Each call goes to calls.
func (ca *meshCA) verify(calls chan<- meshCheck) vpcrelay.MeshVerify {
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	return func(chain []*x509.Certificate, name string, from netip.AddrPort) error {
		select {
		case calls <- meshCheck{name, from}:
		default:
		}
		if len(chain) == 0 {
			return errors.New("no certificate")
		}
		if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return err
		}
		if cn := chain[0].Subject.CommonName; cn != name {
			return fmt.Errorf("certificate is for %q, not for %q", cn, name)
		}
		return nil
	}
}

// meshRelay is a started relay with a mesh.
type meshRelay struct {
	*vpcRelay
	name    string
	mesh    *vpcrelay.Mesh
	ref     *dp.RelayRef // What the other relays get of this relay.
	changes chan vpcrelay.MeshChange
	checks  chan meshCheck
}

// startMeshRelay starts the relay name with a mesh. The first attachment of
// the relay gets the address fd00:<firstAddr>::/96, or fd00:1::/96 with none.
func startMeshRelay(t *testing.T, ca *meshCA, name string, steerSockets int, noVPC bool, firstAddr ...int) *meshRelay {
	t.Helper()
	opts := relayOpts{name: name, steerSockets: steerSockets, noVPC: noVPC}
	if len(firstAddr) > 0 {
		opts.addrs = &vpcAddresses{next: firstAddr[0] - 1}
	}
	return startMeshRelayWith(t, ca, opts)
}

// startMeshRelayWith starts a relay with a mesh. The relays have one ID if opts
// gives no other, and each gives the address of its socket as its agent address.
func startMeshRelayWith(t *testing.T, ca *meshCA, opts relayOpts) *meshRelay {
	t.Helper()
	m := &meshRelay{name: opts.name, changes: make(chan vpcrelay.MeshChange, 64), checks: make(chan meshCheck, 64)}
	id := opts.relayID
	if id == "" {
		id = "localhost"
	}
	opts.setup = func(r *tunnel.Relay) {
		m.ref = &dp.RelayRef{Id: id, Addresses: []string{r.Address().String()}}
		mesh, err := r.SetMesh(vpcrelay.MeshConfig{Relay: m.ref, TLS: ca.tls(t, opts.name), Verify: ca.verify(m.checks), Snapshot: opts.snapshot})
		require.NoError(t, err)
		mesh.OnChange(func(c vpcrelay.MeshChange) { m.changes <- c })
		m.mesh = mesh
	}
	m.vpcRelay = startRelayWith(t, opts)
	return m
}

func (m *meshRelay) member() vpcrelay.MeshMember {
	return vpcrelay.MeshMember{Name: m.name, Addr: m.r.Address()}
}

// change returns the next change of a member of m.
func (m *meshRelay) change(t *testing.T) vpcrelay.MeshChange {
	t.Helper()
	select {
	case c := <-m.changes:
		return c
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: no change of a member in 10 s", m.name)
		return vpcrelay.MeshChange{}
	}
}

// ping checks that the relay serves HTTP/3.
func (v *vpcRelay) ping(t *testing.T) {
	t.Helper()
	h3 := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: v.roots, ServerName: "localhost"}}
	defer h3.Close()
	require.Eventually(t, func() bool {
		resp, err := (&http.Client{Transport: h3, Timeout: time.Second}).Get("https://" + v.r.Address().String() + "/ping")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond)
}

// TestRelay_Mesh starts two relays with a mesh. They make one session between
// their listening sockets, and each relay learns at once that the other stops.
func TestRelay_Mesh(t *testing.T) {
	cases := []struct {
		name  string
		steer int    // Sockets in a steer group. Zero uses one plain socket.
		noVPC bool   // The relays serve no VPC relay sessions.
		stop  string // The relay that stops.
	}{
		{name: "the relay that accepted stops", stop: "relay-b"},
		{name: "the relay that dialed stops", stop: "relay-a"},
		{name: "no VPC relay sessions", noVPC: true, stop: "relay-b"},
		{name: "steer group of 1", steer: 1, stop: "relay-a"},
		{name: "steer group of 4", steer: 4, stop: "relay-b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.steer > 1 && runtime.GOOS != "linux" {
				t.Skip("a steer group of more than one socket needs Linux")
			}
			ca := newMeshCA(t)
			a := startMeshRelay(t, ca, "relay-a", tc.steer, tc.noVPC)
			b := startMeshRelay(t, ca, "relay-b", tc.steer, tc.noVPC)
			// relay-b gets its member first, so that it does not refuse relay-a.
			b.mesh.SetMembers([]vpcrelay.MeshMember{a.member()})
			a.mesh.SetMembers([]vpcrelay.MeshMember{b.member()})
			require.Equal(t, vpcrelay.MeshChange{Name: "relay-b", Up: true}, a.change(t))
			require.Equal(t, vpcrelay.MeshChange{Name: "relay-a", Up: true}, b.change(t))
			// relay-a dialed from its listening socket: relay-b saw that address.
			assert.Equal(t, meshCheck{"relay-b", b.r.Address()}, <-a.checks)
			assert.Equal(t, meshCheck{"relay-a", a.r.Address()}, <-b.checks)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for _, d := range []struct{ from, to *meshRelay }{{a, b}, {b, a}} {
				s := d.from.mesh.Session(d.to.name)
				require.NotNil(t, s, "%s has a session with %s", d.from.name, d.to.name)
				// The other relay answers a call. Only a relay with VPC relay
				// sessions has a trunk, and it refuses a request with no key change.
				want := rpc.InvalidArgument
				if tc.noVPC {
					want = rpc.Unimplemented
				}
				_, err := s.Client().TrunkKeys(ctx, &dp.KeysRequest{})
				assert.Equal(t, want, rpc.CodeOf(err), "call from %s: %v", d.from.name, err)
				// The relay serves HTTP/3 on the sockets of the mesh session.
				d.from.ping(t)
			}

			stops, stays := a, b
			if tc.stop == b.name {
				stops, stays = b, a
			}
			stops.cancel()
			// The reason shows that the stop came from the relay, not from the down time.
			assert.Equal(t, vpcrelay.MeshChange{Name: stops.name, Down: vpcrelay.MeshRestart}, stays.change(t))
			assert.False(t, stays.mesh.Up(stops.name))
			select {
			case <-stops.done:
			case <-time.After(10 * time.Second):
				t.Fatalf("%s did not stop in 10 s", stops.name)
			}
		})
	}
}

// TestRelay_MeshALPN dials relays with each relay protocol. A relay with no
// mesh refuses apoxy-mesh/1 in the handshake, as a relay did before the mesh.
func TestRelay_MeshALPN(t *testing.T) {
	// noProtocol is the TLS alert no_application_protocol as a QUIC error.
	const noProtocol = quic.TransportErrorCode(0x100 + 120)
	cases := []struct {
		name  string
		mesh  bool
		noVPC bool
	}{
		{name: "no mesh"},
		{name: "no mesh and no VPC relay sessions", noVPC: true},
		{name: "mesh", mesh: true},
		{name: "mesh and no VPC relay sessions", mesh: true, noVPC: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newMeshCA(t)
			var v *vpcRelay
			if tc.mesh {
				v = startMeshRelay(t, ca, "relay-b", 0, tc.noVPC).vpcRelay
			} else {
				v = startRelayWith(t, relayOpts{name: "relay-b", noVPC: tc.noVPC})
			}
			v.ping(t)

			meshConf := ca.tls(t, "relay-a")
			meshConf.NextProtos = []string{dp.ALPNMesh}
			for _, d := range []struct {
				conf *tls.Config
				ok   bool
			}{
				{conf: meshConf, ok: tc.mesh},
				{conf: v.agentTLS(t, "agent"), ok: !tc.noVPC},
			} {
				alpn := d.conf.NextProtos[0]
				_, qc, err := v.dial(t, d.conf)
				if d.ok {
					require.NoError(t, err, alpn)
					assert.Equal(t, alpn, qc.ConnectionState().TLS.NegotiatedProtocol)
					_ = qc.CloseWithError(0, "")
					continue
				}
				var te *quic.TransportError
				require.ErrorAs(t, err, &te, alpn)
				assert.Equal(t, noProtocol, te.ErrorCode, alpn)
				assert.True(t, te.Remote, "%s: the relay refused the handshake", alpn)
			}
		})
	}
}

// TestRelay_MeshKeepAlive dials a relay as another relay does. Only a dialer at
// the address of a member gets a keep-alive each second from the relay.
func TestRelay_MeshKeepAlive(t *testing.T) {
	cases := []struct {
		name   string
		member bool // The member set has the address of the dialer.
	}{
		{name: "address of a member", member: true},
		{name: "other address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ca := newMeshCA(t)
			b := startMeshRelay(t, ca, "relay-b", 0, false)
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			tr := &quic.Transport{Conn: udp}
			t.Cleanup(func() { _ = tr.Close(); _ = udp.Close() })
			addr := udp.LocalAddr().(*net.UDPAddr).AddrPort()
			if !tc.member {
				addr = netip.AddrPortFrom(addr.Addr(), addr.Port()^1)
			}
			b.mesh.SetMembers([]vpcrelay.MeshMember{{Name: "relay-a", Addr: addr}})

			var pings atomic.Int32
			tlsConf := ca.tls(t, "relay-a")
			tlsConf.NextProtos = []string{dp.ALPNMesh}
			quicConf := &quic.Config{
				// The dialer sends no keep-alive and has a long idle timeout, so
				// the timers of the relay decide.
				MaxIdleTimeout: 30 * time.Second,
				Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
					return &logging.ConnectionTracer{
						ReceivedShortHeaderPacket: func(_ *logging.ShortHeader, size logging.ByteCount, _ logging.ECN, frames []logging.Frame) {
							// A probe of the path MTU has a PING too, in a large packet.
							if size > 200 {
								return
							}
							for _, f := range frames {
								if _, ok := f.(*logging.PingFrame); ok {
									pings.Add(1)
								}
							}
						},
					}
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			qc, err := tr.Dial(ctx, net.UDPAddrFromAddrPort(b.r.Address()), tlsConf, quicConf)
			require.NoError(t, err)
			defer func() { _ = qc.CloseWithError(0, "") }()
			res, err := dp.NewMeshClient(rpc.NewConn(qc, nil)).Open(ctx, &dp.MeshOpenRequest{Version: dp.LocalVersion("test"), Name: "relay-a"})
			require.NoError(t, err)
			assert.Equal(t, "relay-b", res.GetName())
			require.Equal(t, vpcrelay.MeshChange{Name: "relay-a", Up: true}, b.change(t))

			// Count after the handshake and Open are over. The relay listener
			// sends its first keep-alive after 5 s.
			time.Sleep(300 * time.Millisecond)
			pings.Store(0)
			time.Sleep(3 * time.Second)
			if got := pings.Load(); tc.member {
				assert.GreaterOrEqual(t, got, int32(2), "keep-alives in 3 s")
			} else {
				assert.Zero(t, got, "keep-alives in 3 s")
			}
		})
	}
}

// meshSink is the Mesh service of a relay that the test plays. It keeps the
// messages of the Presence call that it gets.
type meshSink struct {
	dp.UnimplementedMeshServer
	updates chan *dp.PresenceUpdate
}

func (f *meshSink) Presence(_ context.Context, st rpc.ClientStreamServer[dp.PresenceUpdate]) (*emptypb.Empty, error) {
	for {
		u, err := st.Recv()
		if err != nil {
			return &emptypb.Empty{}, nil
		}
		f.updates <- u
	}
}

// TestRelay_MeshPresence dials a relay as another relay does. The relay sends
// the attachments of its agents on the mesh session: the full set, then changes.
func TestRelay_MeshPresence(t *testing.T) {
	ca := newMeshCA(t)
	b := startMeshRelay(t, ca, "relay-b", 0, false)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udp}
	t.Cleanup(func() { _ = tr.Close(); _ = udp.Close() })
	b.mesh.SetMembers([]vpcrelay.MeshMember{{Name: "relay-a", Addr: udp.LocalAddr().(*net.UDPAddr).AddrPort()}})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tlsConf := ca.tls(t, "relay-a")
	tlsConf.NextProtos = []string{dp.ALPNMesh}
	qc, err := tr.Dial(ctx, net.UDPAddrFromAddrPort(b.r.Address()), tlsConf, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	defer func() { _ = qc.CloseWithError(0, "") }()
	sink := &meshSink{updates: make(chan *dp.PresenceUpdate, 16)}
	mux := rpc.NewMux()
	dp.RegisterMeshServer(mux, sink)
	conn := rpc.NewConn(qc, mux)
	go func() { _ = conn.Serve(ctx) }()
	_, err = dp.NewMeshClient(conn).Open(ctx, &dp.MeshOpenRequest{Version: dp.LocalVersion("test"), Name: "relay-a"})
	require.NoError(t, err)
	next := func() *dp.PresenceUpdate {
		t.Helper()
		select {
		case u := <-sink.updates:
			return u
		case <-ctx.Done():
			t.Fatal("no presence message from the relay")
			return nil
		}
	}

	// The relay has no attachment: the full set is only its end.
	u := next()
	assert.True(t, u.GetEndOfFullSet())
	assert.Empty(t, u.GetEntries())

	// An agent sends its name in Hello and attaches.
	start := uint64(time.Now().UnixMilli())
	_, aqc, err := b.dial(t, b.agentTLS(t, "laptop"))
	require.NoError(t, err)
	agent := dp.NewRelayClient(rpc.NewConn(aqc, nil))
	st, err := agent.Session(ctx)
	require.NoError(t, err)
	require.NoError(t, st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{Mode: dp.Mode_MODE_QUIC, Name: "base"}}}))
	welcome, err := st.Recv()
	require.NoError(t, err)
	require.NotNil(t, welcome.GetWelcome())
	vpc := &dp.VPCRef{ProjectId: vpcProject, VpcUid: vpcUID, NetworkId: vpcNetwork}
	res, err := agent.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: "laptop", Routes: []string{"10.9.0.0/16"}})
	require.NoError(t, err)
	claims, err := vpcrelay.VerifyGrant(res.GetGrant(), b.roots, time.Now())
	require.NoError(t, err)

	u = next()
	assert.False(t, u.GetEndOfFullSet())
	require.Len(t, u.GetEntries(), 1)
	e := u.GetEntries()[0]
	assert.Equal(t, vpcProject, e.GetVpc().GetProjectId())
	assert.Equal(t, vpcUID, e.GetVpc().GetVpcUid())
	assert.Equal(t, uint32(vpcNetwork), e.GetVpc().GetNetworkId())
	assert.Equal(t, res.GetAttachmentId(), e.GetAttachmentId())
	assert.Equal(t, append(claims.GetAddresses(), "10.9.0.0/16"), e.GetPrefixes())
	assert.Equal(t, identity.ID{Project: vpcProject, VPC: vpcUID, Agent: "laptop"}.String(), e.GetSubject())
	assert.Equal(t, "base", e.GetAgentName())
	assert.Equal(t, uint32(1), e.GetSenderTag())
	assert.False(t, e.GetGone())
	assert.GreaterOrEqual(t, e.GetGeneration(), start)
	assert.LessOrEqual(t, e.GetGeneration(), uint64(time.Now().UnixMilli()))

	// The agent closes its session, so the attachment ends.
	require.NoError(t, aqc.CloseWithError(0, ""))
	u = next()
	require.Len(t, u.GetEntries(), 1)
	g := u.GetEntries()[0]
	assert.Equal(t, res.GetAttachmentId(), g.GetAttachmentId())
	assert.True(t, g.GetGone())
	assert.Greater(t, g.GetGeneration(), e.GetGeneration())
}

// routeAgent is an agent session on a relay that keeps the route changes, the
// Drain messages and the NoRoute messages of its Session call.
type routeAgent struct {
	tr       *quic.Transport // Socket of qc, also for PSP packets.
	qc       quic.Connection
	c        dp.RelayClient
	deltas   chan *dp.RouteDelta
	drains   chan *dp.Drain
	noRoutes chan *dp.NoRoute
}

// openRouteAgent dials v as agent name and sends hello, in QUIC mode if hello
// gives no mode. It returns after Welcome and Config.
func openRouteAgent(t *testing.T, ctx context.Context, v *vpcRelay, name string, hello *dp.Hello) *routeAgent {
	t.Helper()
	tr, qc, err := v.dial(t, v.agentTLS(t, name))
	require.NoError(t, err)
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	a := &routeAgent{
		tr: tr, qc: qc, c: dp.NewRelayClient(rpc.NewConn(qc, nil)),
		deltas: make(chan *dp.RouteDelta, 64), drains: make(chan *dp.Drain, 4), noRoutes: make(chan *dp.NoRoute, 64),
	}
	st, err := a.c.Session(ctx)
	require.NoError(t, err)
	if hello.Mode == dp.Mode_MODE_UNSPECIFIED {
		hello.Mode = dp.Mode_MODE_QUIC
	}
	require.NoError(t, st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: hello}}))
	m, err := st.Recv()
	require.NoError(t, err)
	require.NotNil(t, m.GetWelcome(), "first message: %v", m)
	m, err = st.Recv()
	require.NoError(t, err)
	require.NotNil(t, m.GetConfig(), "second message: %v", m)
	go func() {
		for {
			m, err := st.Recv()
			if err != nil {
				return
			}
			if d := m.GetRouteDelta(); d != nil {
				a.deltas <- d
			}
			if d := m.GetDrain(); d != nil {
				a.drains <- d
			}
			if n := m.GetNoRoute(); n != nil {
				a.noRoutes <- n
			}
		}
	}()
	return a
}

// drain returns the Drain message of the relay of a.
func (a *routeAgent) drain(t *testing.T) *dp.Drain {
	t.Helper()
	select {
	case d := <-a.drains:
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("no Drain from the relay in 5 s")
		return nil
	}
}

// next returns the next RouteDelta with a route, as "+origin prefix" and
// "-origin prefix". The first RouteDelta of a session can have no route.
func (a *routeAgent) next(t *testing.T, ctx context.Context) []string {
	t.Helper()
	for {
		select {
		case d := <-a.deltas:
			var out []string
			for _, rt := range d.GetRemove() {
				out = append(out, "-"+rt.GetOrigin()+" "+rt.GetPrefix())
			}
			for _, rt := range d.GetAdd() {
				assert.Equal(t, vpcProject, rt.GetVpc().GetProjectId())
				assert.Equal(t, vpcUID, rt.GetVpc().GetVpcUid())
				assert.Equal(t, uint32(vpcNetwork), rt.GetVpc().GetNetworkId())
				out = append(out, "+"+rt.GetOrigin()+" "+rt.GetPrefix())
			}
			if len(out) > 0 {
				return out
			}
		case <-ctx.Done():
			t.Fatal("no route change from the relay")
			return nil
		}
	}
}

// TestRelay_MeshRoutes checks that an agent gets and loses the route of an
// attachment on another relay, and which agents get no such route.
func TestRelay_MeshRoutes(t *testing.T) {
	ca := newMeshCA(t)
	a := startMeshRelay(t, ca, "relay-a", 0, false)
	b := startMeshRelay(t, ca, "relay-b", 0, false, 0x100)
	b.mesh.SetMembers([]vpcrelay.MeshMember{a.member()})
	a.mesh.SetMembers([]vpcrelay.MeshMember{b.member()})
	require.Equal(t, vpcrelay.MeshChange{Name: "relay-b", Up: true}, a.change(t))
	require.Equal(t, vpcrelay.MeshChange{Name: "relay-a", Up: true}, b.change(t))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	vpc := &dp.VPCRef{ProjectId: vpcProject, VpcUid: vpcUID, NetworkId: vpcNetwork}
	this := dp.LocalVersion("test")

	laptop := openRouteAgent(t, ctx, a.vpcRelay, "laptop", &dp.Hello{Version: this, Name: "base"})
	server := openRouteAgent(t, ctx, b.vpcRelay, "server", &dp.Hello{Version: this, Name: "base"})
	localOnly := openRouteAgent(t, ctx, a.vpcRelay, "vtep", &dp.Hello{Version: this, Name: "base", LocalRoutesOnly: true})
	old := openRouteAgent(t, ctx, a.vpcRelay, "old", &dp.Hello{Version: &dp.Version{Revision: 5}, Name: "base"})

	// The attachment of server on relay-b becomes a route on relay-a.
	onB, err := server.c.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: "server"})
	require.NoError(t, err)
	routeB := "+" + onB.GetAttachmentId() + " fd00:100::/96"
	assert.Equal(t, []string{routeB}, laptop.next(t, ctx))

	// An agent with no attachment cannot send to the other relay.
	_, err = laptop.c.ResolvePeer(ctx, &dp.ResolvePeerRequest{Vpc: vpc, Address: "fd00:100::1"})
	assert.Equal(t, rpc.NotFound, rpc.CodeOf(err), "ResolvePeer: %v", err)

	// The other agents of relay-a get the route of laptop as their first
	// route: they did not get the route of relay-b.
	onA, err := laptop.c.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: "laptop"})
	require.NoError(t, err)
	routeA := "+" + onA.GetAttachmentId() + " fd00:1::/96"
	assert.Equal(t, []string{routeA}, server.next(t, ctx))
	assert.Equal(t, []string{routeA}, localOnly.next(t, ctx))
	assert.Equal(t, []string{routeA}, old.next(t, ctx))

	// A new session on relay-a gets the two routes in its first RouteDelta.
	late := openRouteAgent(t, ctx, a.vpcRelay, "late", &dp.Hello{Version: this, Name: "base"})
	assert.ElementsMatch(t, []string{routeA, routeB}, late.next(t, ctx))

	// The routes go with their attachments: at the detach, and at the end of
	// the session.
	_, err = server.c.Detach(ctx, &dp.DetachRequest{AttachmentId: onB.GetAttachmentId()})
	require.NoError(t, err)
	assert.Equal(t, []string{"-" + routeB[1:]}, laptop.next(t, ctx))
	assert.Equal(t, []string{"-" + routeB[1:]}, late.next(t, ctx))
	require.NoError(t, laptop.qc.CloseWithError(0, ""))
	assert.Equal(t, []string{"-" + routeA[1:]}, server.next(t, ctx))
	assert.Equal(t, []string{"-" + routeA[1:]}, localOnly.next(t, ctx))
}

// TestRelay_MeshDrain stops relay-a of a mesh of two relays. Its agent gets
// relay-b to move to, and relay-b learns of the stop at the end of the drain.
func TestRelay_MeshDrain(t *testing.T) {
	cases := []struct {
		name     string
		lameDuck time.Duration
	}{
		// The sessions of relay-a close at once, so an agent can get no Drain.
		{name: "no lame duck"},
		{name: "lame duck of 2 s", lameDuck: 2 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newMeshCA(t)
			a := startMeshRelayWith(t, ca, relayOpts{name: "relay-a", lameDuck: tc.lameDuck})
			b := startMeshRelayWith(t, ca, relayOpts{name: "relay-b", addrs: &vpcAddresses{next: 0x100 - 1}})
			b.mesh.SetMembers([]vpcrelay.MeshMember{a.member()})
			a.mesh.SetMembers([]vpcrelay.MeshMember{b.member()})
			require.Equal(t, vpcrelay.MeshChange{Name: "relay-b", Up: true}, a.change(t))
			require.Equal(t, vpcrelay.MeshChange{Name: "relay-a", Up: true}, b.change(t))
			// Each relay has the other relay for its agents, with the socket address.
			require.Equal(t, []string{b.r.Address().String()}, b.ref.GetAddresses())
			assert.Empty(t, cmp.Diff([]*dp.RelayRef{b.ref}, a.mesh.Alternates(), protocmp.Transform()))
			assert.Empty(t, cmp.Diff([]*dp.RelayRef{a.ref}, b.mesh.Alternates(), protocmp.Transform()))

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			vpc := &dp.VPCRef{ProjectId: vpcProject, VpcUid: vpcUID, NetworkId: vpcNetwork}
			this := dp.LocalVersion("test")
			laptop := openRouteAgent(t, ctx, a.vpcRelay, "laptop", &dp.Hello{Version: this, Name: "base"})
			pinned := openRouteAgent(t, ctx, a.vpcRelay, "vtep", &dp.Hello{Version: this, Name: "base", LocalRoutesOnly: true})
			server := openRouteAgent(t, ctx, b.vpcRelay, "server", &dp.Hello{Version: this, Name: "base"})
			onA, err := laptop.c.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: "laptop"})
			require.NoError(t, err)
			onB, err := server.c.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: "server"})
			require.NoError(t, err)
			routeA := onA.GetAttachmentId() + " fd00:1::/96"
			require.Equal(t, []string{"+" + onB.GetAttachmentId() + " fd00:100::/96"}, laptop.next(t, ctx))
			require.Equal(t, []string{"+" + routeA}, server.next(t, ctx))

			// The time of the next change of relay-b is the time of the close of relay-a.
			type timedChange struct {
				c  vpcrelay.MeshChange
				at time.Time
			}
			down := make(chan timedChange, 1)
			go func() { down <- timedChange{<-b.changes, time.Now()} }()
			stopped := time.Now()
			a.cancel()
			if tc.lameDuck > 0 {
				// Only an agent that gets the routes of other relays gets relay-b.
				assert.Empty(t, cmp.Diff(&dp.Drain{Alternates: []*dp.RelayRef{b.ref}}, laptop.drain(t), protocmp.Transform()))
				assert.Empty(t, cmp.Diff(&dp.Drain{}, pinned.drain(t), protocmp.Transform()))

				// The agent did not move yet. The relays still carry its peer frames on
				// the mesh session, and its inner packets on the trunk.
				laptopAddr, serverAddr := netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("fd00:100::1")
				for _, d := range []struct {
					from, to *routeAgent
					src, dst netip.Addr
				}{{server, laptop, serverAddr, laptopAddr}, {laptop, server, laptopAddr, serverAddr}} {
					require.NoError(t, d.from.qc.SendDatagram(peerconn.EncodeToRelay(nil, d.dst, d.src, []byte("hello"))))
					rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
					got, err := d.to.qc.ReceiveDatagram(rctx)
					rcancel()
					require.NoError(t, err, "frame to %v in the lame duck", d.dst)
					assert.Equal(t, peerconn.EncodeFromRelay(nil, d.src, []byte("hello")), got)
					inner := bytes.Repeat([]byte{40}, 40)
					inner[0], inner[4], inner[5] = 0x60, 0, 0
					copy(inner[8:24], d.src.AsSlice())
					copy(inner[24:40], d.dst.AsSlice())
					assert.Equal(t, peerconn.EncodeData(nil, vpcNetwork, inner), d.from.sendData(t, ctx, d.to, inner))
				}
				// The agent opens a session on relay-b while its old session is open.
				openRouteAgent(t, ctx, b.vpcRelay, "laptop", &dp.Hello{Version: this, Name: "base"})
				assert.NoError(t, laptop.qc.Context().Err(), "the session on relay-a is open")
			}

			// relay-a tells that it stops at the end of its lame duck, not before.
			var got timedChange
			select {
			case got = <-down:
			case <-time.After(10 * time.Second):
				t.Fatal("relay-b got no change of relay-a in 10 s")
			}
			assert.Equal(t, vpcrelay.MeshChange{Name: "relay-a", Down: vpcrelay.MeshRestart}, got.c)
			assert.GreaterOrEqual(t, got.at.Sub(stopped), tc.lameDuck)
			// The agent of relay-b loses the route of the agent of relay-a.
			assert.Equal(t, []string{"-" + routeA}, server.next(t, ctx))
			assert.False(t, b.mesh.Up("relay-a"))
			assert.Empty(t, b.mesh.Alternates(), "a relay that stopped is not a relay to move to")
			select {
			case <-laptop.qc.Context().Done():
			case <-time.After(5 * time.Second):
				t.Fatal("relay-a did not close the session of its agent in 5 s")
			}
		})
	}
}

// TestRelay_MeshPeerFrames sends peer frames in the two directions between an
// agent on relay-a and an agent on relay-b. The relays carry them on the mesh.
func TestRelay_MeshPeerFrames(t *testing.T) {
	ca := newMeshCA(t)
	a := startMeshRelay(t, ca, "relay-a", 0, false)
	b := startMeshRelay(t, ca, "relay-b", 0, false, 0x100)
	b.mesh.SetMembers([]vpcrelay.MeshMember{a.member()})
	a.mesh.SetMembers([]vpcrelay.MeshMember{b.member()})
	require.Equal(t, vpcrelay.MeshChange{Name: "relay-b", Up: true}, a.change(t))
	require.Equal(t, vpcrelay.MeshChange{Name: "relay-a", Up: true}, b.change(t))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	vpc := &dp.VPCRef{ProjectId: vpcProject, VpcUid: vpcUID, NetworkId: vpcNetwork}
	this := dp.LocalVersion("test")
	laptop := openRouteAgent(t, ctx, a.vpcRelay, "laptop", &dp.Hello{Version: this, Name: "base"})
	server := openRouteAgent(t, ctx, b.vpcRelay, "server", &dp.Hello{Version: this, Name: "base"})

	// When an agent has the route of the other agent, its relay has the
	// attachment of the other relay, which it needs for the two directions.
	onA, err := laptop.c.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: "laptop"})
	require.NoError(t, err)
	onB, err := server.c.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: "server"})
	require.NoError(t, err)
	require.Equal(t, []string{"+" + onB.GetAttachmentId() + " fd00:100::/96"}, laptop.next(t, ctx))
	require.Equal(t, []string{"+" + onA.GetAttachmentId() + " fd00:1::/96"}, server.next(t, ctx))

	laptopAddr, serverAddr := netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("fd00:100::1")
	cases := []struct {
		name     string
		from, to *routeAgent
		src, dst netip.Addr
	}{
		{"relay-a to relay-b", laptop, server, laptopAddr, serverAddr},
		{"relay-b to relay-a", server, laptop, serverAddr, laptopAddr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A peer session uses QUIC packets of 1200 B.
			for _, pkt := range [][]byte{[]byte("hello"), bytes.Repeat([]byte{0x40}, 1200)} {
				require.NoError(t, tc.from.qc.SendDatagram(peerconn.EncodeToRelay(nil, tc.dst, tc.src, pkt)))
				got, err := tc.to.qc.ReceiveDatagram(ctx)
				require.NoError(t, err)
				assert.Equal(t, peerconn.EncodeFromRelay(nil, tc.src, pkt), got)
			}
		})
	}

	// When the trunk has keys, relay-a names the agent of relay-b as a peer.
	var res *dp.ResolvePeerResponse
	require.Eventually(t, func() bool {
		res, err = laptop.c.ResolvePeer(ctx, &dp.ResolvePeerRequest{Vpc: vpc, Address: serverAddr.String()})
		return err == nil
	}, 10*time.Second, 20*time.Millisecond, "answer of relay-a for the agent of relay-b")
	assert.Equal(t, dp.Reach_REACH_TRUNK, res.GetReach())
	assert.Equal(t, identity.ID{Project: vpcProject, VPC: vpcUID, Agent: "server"}.String(), res.GetSubject())
	assert.Equal(t, []string{onB.GetAttachmentId()}, res.GetAttachmentIds())
}

// sendPSP sends pkt from a to its relay v each 200 ms, until the socket of to
// gets a packet of that size. RegisterSPI waits for no trunk keys and no row.
func (a *routeAgent) sendPSP(t *testing.T, ctx context.Context, v *vpcRelay, to *routeAgent, pkt []byte) ([]byte, netip.AddrPort) {
	t.Helper()
	buf := make([]byte, 1500)
	for {
		_, err := a.tr.WriteTo(pkt, net.UDPAddrFromAddrPort(v.r.Address()))
		require.NoError(t, err)
		rctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		for {
			n, from, err := to.tr.ReadNonQUICPacket(rctx, buf)
			if err != nil {
				break
			}
			// A packet of another size is a late copy of the packet before.
			if n == len(pkt) {
				cancel()
				src := from.(*net.UDPAddr).AddrPort()
				return buf[:n], netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
			}
		}
		cancel()
		require.NoError(t, ctx.Err(), "no PSP packet from the other relay")
	}
}

// TestRelay_MeshPSP sends PSP packets in the two directions between an agent
// on relay-a and an agent on relay-b. The receiver gets the bytes of the sender.
func TestRelay_MeshPSP(t *testing.T) {
	cases := []struct {
		name  string
		steer int // Sockets in a steer group. Zero uses one plain socket.
	}{
		{name: "plain socket"},
		{name: "steer group of 4", steer: 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.steer > 1 && runtime.GOOS != "linux" {
				t.Skip("a steer group of more than one socket needs Linux")
			}
			testMeshPSP(t, tc.steer)
		})
	}
}

func testMeshPSP(t *testing.T, steerSockets int) {
	ca := newMeshCA(t)
	a := startMeshRelay(t, ca, "relay-a", steerSockets, false)
	b := startMeshRelay(t, ca, "relay-b", steerSockets, false, 0x100)
	b.mesh.SetMembers([]vpcrelay.MeshMember{a.member()})
	a.mesh.SetMembers([]vpcrelay.MeshMember{b.member()})
	require.Equal(t, vpcrelay.MeshChange{Name: "relay-b", Up: true}, a.change(t))
	require.Equal(t, vpcrelay.MeshChange{Name: "relay-a", Up: true}, b.change(t))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	vpc := &dp.VPCRef{ProjectId: vpcProject, VpcUid: vpcUID, NetworkId: vpcNetwork}
	this := dp.LocalVersion("test")
	laptop := openRouteAgent(t, ctx, a.vpcRelay, "laptop", &dp.Hello{Version: this, Name: "base"})
	server := openRouteAgent(t, ctx, b.vpcRelay, "server", &dp.Hello{Version: this, Name: "base"})

	// When an agent has the route of the other agent, its relay has the
	// attachment of the other relay, which names the sender of a row.
	onA, err := laptop.c.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: "laptop"})
	require.NoError(t, err)
	onB, err := server.c.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: "server"})
	require.NoError(t, err)
	require.Equal(t, []string{"+" + onB.GetAttachmentId() + " fd00:100::/96"}, laptop.next(t, ctx))
	require.Equal(t, []string{"+" + onA.GetAttachmentId() + " fd00:1::/96"}, server.next(t, ctx))

	// The relays do not open the packet, so the key is one that no relay has.
	aead, err := pspwire.NewAEAD(bytes.Repeat([]byte{7}, 16))
	require.NoError(t, err)
	dirs := []struct {
		name     string
		from, to *routeAgent
		first    *meshRelay // Relay of the sender.
		last     *meshRelay // Relay of the receiver.
		dst      string
		spi      uint32
	}{
		{"relay-a to relay-b", laptop, server, a, b, "fd00:100::1", 0x700},
		{"relay-b to relay-a", server, laptop, b, a, "fd00:1::1", 0x900},
	}
	for _, d := range dirs {
		_, err := d.from.c.RegisterSPI(ctx, &dp.RegisterSPIRequest{
			Vpc: vpc, Destination: d.dst, Spis: []uint32{d.spi}, ExpiresIn: durationpb.New(time.Minute),
		})
		require.NoError(t, err, d.name)
		// A trunk carries an inner MTU of 1280 at once, and of 1412 after its
		// full-size probe passes.
		for _, size := range []int{40, 1280, 1412} {
			inner := bytes.Repeat([]byte{byte(size)}, size)
			inner[0] = 0x60
			pkt := make([]byte, size+pspwire.Overhead)
			n, err := pspwire.Seal(aead, pspwire.Header{SPI: d.spi, VNI: vpcNetwork}, pkt, inner)
			require.NoError(t, err)
			got, src := d.from.sendPSP(t, ctx, d.first.vpcRelay, d.to, pkt[:n])
			assert.Equal(t, pkt[:n], got, "%s, inner size %d", d.name, size)
			assert.Equal(t, d.last.r.Address(), src, "%s, inner size %d", d.name, size)
		}
	}
	// Each relay host counts the packets for the other relay, and has the RTT of
	// the mesh session: the host that dialed it and the host that accepted it.
	for _, d := range dirs {
		sent, got := memberSeries(t, d.first, d.last.name), memberSeries(t, d.last, d.first.name)
		assert.GreaterOrEqual(t, sent["apoxy_vpc_relay_trunk_packets_total tx"], 3.0, d.name)
		assert.GreaterOrEqual(t, got["apoxy_vpc_relay_trunk_packets_total rx"], 3.0, d.name)
		assert.Positive(t, sent["apoxy_vpc_relay_mesh_rtt_seconds"], d.name)
	}
}

// TestRelay_MeshNoRoute ends the mesh session of two relays. The PSP-mode agent on
// relay-a then gets a NoRoute with the home relay for the PSP packet of its SPI row.
func TestRelay_MeshNoRoute(t *testing.T) {
	ca := newMeshCA(t)
	a := startMeshRelayWith(t, ca, relayOpts{name: "relay-a"})
	// An agent visits only a relay with an ID that no other relay of the mesh has.
	b := startMeshRelayWith(t, ca, relayOpts{name: "relay-b", relayID: "relay-b.example", addrs: &vpcAddresses{next: 0x100 - 1}})
	b.mesh.SetMembers([]vpcrelay.MeshMember{a.member()})
	a.mesh.SetMembers([]vpcrelay.MeshMember{b.member()})
	require.Equal(t, vpcrelay.MeshChange{Name: "relay-b", Up: true}, a.change(t))
	require.Equal(t, vpcrelay.MeshChange{Name: "relay-a", Up: true}, b.change(t))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	vpc := &dp.VPCRef{ProjectId: vpcProject, VpcUid: vpcUID, NetworkId: vpcNetwork}
	this := dp.LocalVersion("test")
	laptop := openRouteAgent(t, ctx, a.vpcRelay, "laptop", &dp.Hello{Version: this, Name: "base", Mode: dp.Mode_MODE_PSP})
	server := openRouteAgent(t, ctx, b.vpcRelay, "server", &dp.Hello{Version: this, Name: "base"})
	onA, err := laptop.c.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: "laptop"})
	require.NoError(t, err)
	onB, err := server.c.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: "server"})
	require.NoError(t, err)
	require.Equal(t, []string{"+" + onB.GetAttachmentId() + " fd00:100::/96"}, laptop.next(t, ctx))
	require.Equal(t, []string{"+" + onA.GetAttachmentId() + " fd00:1::/96"}, server.next(t, ctx))

	// The relays do not open the packet: its inner destination is not the address of the row.
	const dst = "fd00:100::1"
	_, err = laptop.c.RegisterSPI(ctx, &dp.RegisterSPIRequest{
		Vpc: vpc, Destination: dst, Spis: []uint32{0x700}, ExpiresIn: durationpb.New(time.Minute),
	})
	require.NoError(t, err)
	aead, err := pspwire.NewAEAD(bytes.Repeat([]byte{7}, 16))
	require.NoError(t, err)
	inner := bytes.Repeat([]byte{40}, 40)
	inner[0] = 0x60
	pkt := make([]byte, len(inner)+pspwire.Overhead)
	n, err := pspwire.Seal(aead, pspwire.Header{SPI: 0x700, VNI: vpcNetwork}, pkt, inner)
	require.NoError(t, err)
	pkt = pkt[:n]
	got, _ := laptop.sendPSP(t, ctx, a.vpcRelay, server, pkt)
	require.Equal(t, pkt, got)
	require.Empty(t, laptop.noRoutes, "NoRoute while relay-b is up")

	// relay-b only removes relay-a: a relay that stops closes with RESTART, and relay-a names no home relay then.
	start := time.Now()
	b.mesh.SetMembers(nil)
	sent := time.Now()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		_, err := laptop.tr.WriteTo(pkt, net.UDPAddrFromAddrPort(a.r.Address()))
		require.NoError(t, err)
		select {
		case m := <-laptop.noRoutes:
			assert.LessOrEqual(t, time.Since(sent), 4*time.Second, "time from the first packet with no session")
			assert.GreaterOrEqual(t, time.Since(start), 3*time.Second, "relay-a waits for a new session of relay-b first")
			assert.Empty(t, cmp.Diff(&dp.NoRoute{Vpc: vpc, Address: dst, HomeRelay: b.ref}, m, protocmp.Transform()))
			return
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("no NoRoute from relay-a")
		}
	}
}

// TestRelay_MeshSnapshot starts relay-a with a host snapshot and relay-b with none.
// relay-b gets the bytes of relay-a over the mesh session, and an agent session gets none.
func TestRelay_MeshSnapshot(t *testing.T) {
	ca := newMeshCA(t)
	// The snapshot is more than three parts of 1 MiB, and the relays do not read it.
	want := make([]byte, 3<<20+7)
	_, err := rand.Read(want)
	require.NoError(t, err)
	var served atomic.Int32
	a := startMeshRelayWith(t, ca, relayOpts{name: "relay-a", snapshot: func() []byte {
		served.Add(1)
		return want
	}})
	b := startMeshRelayWith(t, ca, relayOpts{name: "relay-b", addrs: &vpcAddresses{next: 0x100 - 1}})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Before the session opens, relay-b has no member to ask.
	_, _, err = b.mesh.FetchSnapshot(ctx)
	require.Equal(t, rpc.NotFound, rpc.CodeOf(err), "error: %v", err)
	b.mesh.SetMembers([]vpcrelay.MeshMember{a.member()})
	a.mesh.SetMembers([]vpcrelay.MeshMember{b.member()})
	require.Equal(t, vpcrelay.MeshChange{Name: "relay-b", Up: true}, a.change(t))
	require.Equal(t, vpcrelay.MeshChange{Name: "relay-a", Up: true}, b.change(t))

	got, from, err := b.mesh.FetchSnapshot(ctx)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(want, got), "relay-b gets the bytes that relay-a serves")
	assert.Equal(t, "relay-a", from)
	assert.EqualValues(t, 1, served.Load())
	// The host of relay-b has no snapshot, so relay-a gets none.
	_, _, err = a.mesh.FetchSnapshot(ctx)
	assert.Equal(t, rpc.NotFound, rpc.CodeOf(err), "error: %v", err)

	// The agent listener of relay-a does not have the Mesh service.
	laptop := openRouteAgent(t, ctx, a.vpcRelay, "laptop", &dp.Hello{Version: dp.LocalVersion("test"), Name: "base"})
	st, err := dp.NewMeshClient(rpc.NewConn(laptop.qc, nil)).Snapshot(ctx, &dp.SnapshotRequest{})
	require.NoError(t, err)
	part, err := st.Recv()
	assert.Equal(t, rpc.Unimplemented, rpc.CodeOf(err), "error: %v", err)
	assert.Nil(t, part)
	assert.EqualValues(t, 1, served.Load(), "the call of an agent does not reach the hook")
}

// memberSeries returns the series of member peer in the metrics of m that have no
// reason label and are not zero, as "<metric name> <direction>" or "<metric name>".
func memberSeries(t *testing.T, m *meshRelay, peer string) map[string]float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(m.router))
	families, err := reg.Gather()
	require.NoError(t, err)
	out := map[string]float64{}
	for _, f := range families {
		for _, c := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range c.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			v := c.GetCounter().GetValue() + c.GetGauge().GetValue()
			if labels["peer_relay"] == peer && labels["reason"] == "" && v != 0 {
				out[strings.TrimSpace(f.GetName()+" "+labels["direction"])] = v
			}
		}
	}
	return out
}

// sendData sends the data frame of inner on the session of a each 200 ms, until to
// gets a frame of that size. The relays keep no packet for a trunk with no keys.
func (a *routeAgent) sendData(t *testing.T, ctx context.Context, to *routeAgent, inner []byte) []byte {
	t.Helper()
	frame := peerconn.EncodeData(nil, vpcNetwork, inner)
	for {
		require.NoError(t, a.qc.SendDatagram(frame))
		rctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		for {
			got, err := to.qc.ReceiveDatagram(rctx)
			if err != nil {
				break
			}
			// A frame of another size is a late copy of the frame before.
			if len(got) == len(frame) {
				cancel()
				return got
			}
		}
		cancel()
		require.NoError(t, ctx.Err(), "no data frame from the other relay")
	}
}

// TestRelay_MeshData sends data frames in the two directions between QUIC-mode
// agents on two relays. The receiver gets a data frame with the same inner packet.
func TestRelay_MeshData(t *testing.T) {
	cases := []struct {
		name  string
		steer int // Sockets in a steer group. Zero uses one plain socket.
	}{
		{name: "plain socket"},
		{name: "steer group of 4", steer: 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.steer > 1 && runtime.GOOS != "linux" {
				t.Skip("a steer group of more than one socket needs Linux")
			}
			testMeshData(t, tc.steer)
		})
	}
}

func testMeshData(t *testing.T, steerSockets int) {
	ca := newMeshCA(t)
	a := startMeshRelay(t, ca, "relay-a", steerSockets, false)
	b := startMeshRelay(t, ca, "relay-b", steerSockets, false, 0x100)
	b.mesh.SetMembers([]vpcrelay.MeshMember{a.member()})
	a.mesh.SetMembers([]vpcrelay.MeshMember{b.member()})
	require.Equal(t, vpcrelay.MeshChange{Name: "relay-b", Up: true}, a.change(t))
	require.Equal(t, vpcrelay.MeshChange{Name: "relay-a", Up: true}, b.change(t))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	vpc := &dp.VPCRef{ProjectId: vpcProject, VpcUid: vpcUID, NetworkId: vpcNetwork}
	this := dp.LocalVersion("test")
	laptop := openRouteAgent(t, ctx, a.vpcRelay, "laptop", &dp.Hello{Version: this, Name: "base"})
	server := openRouteAgent(t, ctx, b.vpcRelay, "server", &dp.Hello{Version: this, Name: "base"})

	// When an agent has the route of the other agent, its relay has the
	// attachment of the other relay, which names the sender of an inner packet.
	onA, err := laptop.c.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: "laptop"})
	require.NoError(t, err)
	onB, err := server.c.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: "server"})
	require.NoError(t, err)
	require.Equal(t, []string{"+" + onB.GetAttachmentId() + " fd00:100::/96"}, laptop.next(t, ctx))
	require.Equal(t, []string{"+" + onA.GetAttachmentId() + " fd00:1::/96"}, server.next(t, ctx))

	laptopAddr, serverAddr := netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("fd00:100::1")
	dirs := []struct {
		name     string
		from, to *routeAgent
		src, dst netip.Addr
	}{
		{"relay-a to relay-b", laptop, server, laptopAddr, serverAddr},
		{"relay-b to relay-a", server, laptop, serverAddr, laptopAddr},
	}
	for _, d := range dirs {
		// A test agent sends a datagram of up to 1243 B before its path MTU discovery.
		for _, size := range []int{40, 1200} {
			inner := bytes.Repeat([]byte{byte(size)}, size)
			inner[0], inner[4], inner[5] = 0x60, byte((size-40)>>8), byte(size-40)
			copy(inner[8:24], d.src.AsSlice())
			copy(inner[24:40], d.dst.AsSlice())
			got := d.from.sendData(t, ctx, d.to, inner)
			// The frame has the network ID of the VPC, and its flags are zero.
			assert.Equal(t, peerconn.EncodeData(nil, vpcNetwork, inner), got, "%s, inner size %d", d.name, size)
		}
	}
}

// sendFrame sends the peer frame of pkt from a each 200 ms, until to gets it.
func (a *routeAgent) sendFrame(t *testing.T, ctx context.Context, to *routeAgent, src, dst netip.Addr, pkt []byte) {
	t.Helper()
	want := peerconn.EncodeFromRelay(nil, src, pkt)
	for {
		require.NoError(t, a.qc.SendDatagram(peerconn.EncodeToRelay(nil, dst, src, pkt)))
		rctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		for {
			got, err := to.qc.ReceiveDatagram(rctx)
			if err != nil {
				break
			}
			if bytes.Equal(got, want) {
				cancel()
				return
			}
		}
		cancel()
		require.NoError(t, ctx.Err(), "no peer frame %q for %v", pkt, dst)
	}
}

// TestRelay_MeshVisit attaches an agent on relay-a. A second connection of the
// agent visits relay-b with the grant of relay-a, and talks to an agent of relay-b.
func TestRelay_MeshVisit(t *testing.T) {
	ca := newMeshCA(t)
	agents, err := vpctest.NewCA()
	require.NoError(t, err)
	a := startMeshRelayWith(t, ca, relayOpts{name: "relay-a", agentCA: agents})
	// relay-b accepts the grants of relay-a. relay-a accepts no grant of the test.
	b := startMeshRelayWith(t, ca, relayOpts{
		name: "relay-b", agentCA: agents, addrs: &vpcAddresses{next: 0x100 - 1}, relayRoots: a.roots,
	})
	b.mesh.SetMembers([]vpcrelay.MeshMember{a.member()})
	a.mesh.SetMembers([]vpcrelay.MeshMember{b.member()})
	require.Equal(t, vpcrelay.MeshChange{Name: "relay-b", Up: true}, a.change(t))
	require.Equal(t, vpcrelay.MeshChange{Name: "relay-a", Up: true}, b.change(t))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	vpc := &dp.VPCRef{ProjectId: vpcProject, VpcUid: vpcUID, NetworkId: vpcNetwork}
	this := dp.LocalVersion("test")
	attach := func(e *routeAgent, name string) *dp.AttachResponse {
		res, err := e.c.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: name})
		require.NoError(t, err)
		return res
	}

	home := openRouteAgent(t, ctx, a.vpcRelay, "laptop", &dp.Hello{Version: this, Name: "base"})
	phone := openRouteAgent(t, ctx, a.vpcRelay, "phone", &dp.Hello{Version: this, Name: "base"})
	server := openRouteAgent(t, ctx, b.vpcRelay, "server", &dp.Hello{Version: this, Name: "base"})
	onLaptop, onPhone, onServer := attach(home, "laptop"), attach(phone, "phone"), attach(server, "server")
	laptopAddr, serverAddr := netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("fd00:100::1")
	// Each relay has the attachments of the other relay when its agent has their routes.
	var routes []string
	for len(routes) < 2 {
		routes = append(routes, server.next(t, ctx)...)
	}
	require.ElementsMatch(t, []string{"+" + onLaptop.GetAttachmentId() + " fd00:1::/96", "+" + onPhone.GetAttachmentId() + " fd00:2::/96"}, routes)
	for routes = nil; len(routes) < 2; {
		routes = append(routes, home.next(t, ctx)...)
	}
	require.Contains(t, routes, "+"+onServer.GetAttachmentId()+" fd00:100::/96")

	// Before the visit, the mesh carries a frame for the agent to relay-a.
	server.sendFrame(t, ctx, home, serverAddr, laptopAddr, []byte("before"))

	visitor := openRouteAgent(t, ctx, b.vpcRelay, "laptop", &dp.Hello{Version: this, Name: "base", LocalRoutesOnly: true})
	wide := openRouteAgent(t, ctx, b.vpcRelay, "laptop", &dp.Hello{Version: this, Name: "base"})
	guest := openRouteAgent(t, ctx, a.vpcRelay, "server", &dp.Hello{Version: this, Name: "base", LocalRoutesOnly: true})
	refused := []struct {
		name  string
		on    *routeAgent
		addr  string
		grant *dp.AttachmentGrant
		code  rpc.Code
	}{
		{"grant of another agent", visitor, "fd00:2::1", onPhone.GetGrant(), rpc.PermissionDenied},
		{"address of another agent", visitor, "fd00:2::1", onLaptop.GetGrant(), rpc.PermissionDenied},
		{"session with the routes of other relays", wide, "fd00:1::1", onLaptop.GetGrant(), rpc.FailedPrecondition},
		{"grant from a relay cert that is not in the relay roots", visitor, "fd00:100::1", onServer.GetGrant(), rpc.PermissionDenied},
		{"relay with the system roots", guest, "fd00:100::1", onServer.GetGrant(), rpc.PermissionDenied},
	}
	for _, tc := range refused {
		_, err := tc.on.c.Visit(ctx, &dp.VisitRequest{Vpc: vpc, Address: tc.addr, Grant: tc.grant})
		assert.Equal(t, tc.code, rpc.CodeOf(err), "%s: %v", tc.name, err)
	}
	_, err = visitor.c.Visit(ctx, &dp.VisitRequest{Vpc: vpc, Address: laptopAddr.String(), Grant: onLaptop.GetGrant()})
	require.NoError(t, err)

	// The visitor and the agent of relay-b send to each other on relay-b only.
	aead, err := pspwire.NewAEAD(bytes.Repeat([]byte{7}, 16))
	require.NoError(t, err)
	dirs := []struct {
		name     string
		from, to *routeAgent
		src, dst netip.Addr
		spi      uint32
	}{
		{"agent of relay-b to the visitor", server, visitor, serverAddr, laptopAddr, 0x700},
		{"visitor to the agent of relay-b", visitor, server, laptopAddr, serverAddr, 0x900},
	}
	for _, d := range dirs {
		require.NoError(t, d.from.qc.SendDatagram(peerconn.EncodeToRelay(nil, d.dst, d.src, []byte("hello"))), d.name)
		got, err := d.to.qc.ReceiveDatagram(ctx)
		require.NoError(t, err, d.name)
		assert.Equal(t, peerconn.EncodeFromRelay(nil, d.src, []byte("hello")), got, d.name)

		inner := bytes.Repeat([]byte{40}, 40)
		inner[0], inner[4], inner[5] = 0x60, 0, 0
		copy(inner[8:24], d.src.AsSlice())
		copy(inner[24:40], d.dst.AsSlice())
		assert.Equal(t, peerconn.EncodeData(nil, vpcNetwork, inner), d.from.sendData(t, ctx, d.to, inner), d.name)

		_, err = d.from.c.RegisterSPI(ctx, &dp.RegisterSPIRequest{
			Vpc: vpc, Destination: d.dst.String(), Spis: []uint32{d.spi}, ExpiresIn: durationpb.New(time.Minute),
		})
		require.NoError(t, err, d.name)
		pkt := make([]byte, len(inner)+pspwire.Overhead)
		n, err := pspwire.Seal(aead, pspwire.Header{SPI: d.spi, VNI: vpcNetwork}, pkt, inner)
		require.NoError(t, err)
		sealed, from := d.from.sendPSP(t, ctx, b.vpcRelay, d.to, pkt[:n])
		assert.Equal(t, pkt[:n], sealed, d.name)
		assert.Equal(t, b.r.Address(), from, d.name)
	}
	// The visitor reaches no address of another relay.
	_, err = visitor.c.RegisterSPI(ctx, &dp.RegisterSPIRequest{
		Vpc: vpc, Destination: "fd00:2::1", Spis: []uint32{0x901}, ExpiresIn: durationpb.New(time.Minute),
	})
	assert.Equal(t, rpc.NotFound, rpc.CodeOf(err), "row of the visitor to relay-a: %v", err)

	// After the visit, the mesh carries the frames for the agent to relay-a again.
	require.NoError(t, visitor.qc.CloseWithError(0, ""))
	server.sendFrame(t, ctx, home, serverAddr, laptopAddr, []byte("after"))
	assert.Empty(t, server.deltas, "a visit changes no route")
}

// hostAttach is one attachment of a hostAgent.
type hostAttach struct {
	addr   netip.Addr
	prefix netip.Prefix
}

// hostAgent is an agent of this build on a relay host, with a UDP netstack on
// its binding.
type hostAgent struct {
	a          *agent.Agent
	once       sync.Once
	stack      *stack.Stack
	hostAttach // The last attachment that attached took.
	attaches   chan hostAttach
	stop       func() // Ends the agent and waits for it.

	mu     sync.Mutex
	routes map[netip.Prefix]bool
}

// startHostAgent runs agent name on the relay v and waits for its attachment.
// roots must have the CA of each relay of the mesh.
func startHostAgent(t *testing.T, ca *vpctest.CA, roots *x509.CertPool, v *vpcRelay, name string, mode agent.TransportMode) *hostAgent {
	t.Helper()
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: sock}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	h := &hostAgent{
		routes: map[netip.Prefix]bool{}, attaches: make(chan hostAttach, 8),
		stop: sync.OnceFunc(func() { cancel(); <-done }),
	}
	h.a = agent.New(agent.Config{
		Identity: identity.NewManager(filepath.Join(t.TempDir(), "cred.json"), func(context.Context) (*identity.Credential, error) {
			return ca.Credential(vpcProject, vpcUID, name, time.Hour)
		}),
		Relays:        []identity.Relay{{ID: "localhost", Addresses: []string{v.r.Address().String()}}},
		RelayRoots:    roots,
		Sessions:      1,
		Transport:     tr,
		TransportMode: mode,
		Name:          name,
		OnAttach: func(b *psp.Binding, addr netip.Addr, prefixes []netip.Prefix) {
			h.netstack(t, b, addr)
			h.attaches <- hostAttach{addr, prefixes[0]}
		},
		OnRoutes: func(add, remove []netip.Prefix) {
			h.mu.Lock()
			defer h.mu.Unlock()
			for _, p := range remove {
				delete(h.routes, p)
			}
			for _, p := range add {
				h.routes[p] = true
			}
		},
	})
	go func() {
		defer close(done)
		assert.NoError(t, h.a.Run(ctx), "agent %s", name)
	}()
	t.Cleanup(func() {
		h.stop()
		_ = tr.Close()
		_ = sock.Close()
	})
	h.attached(t)
	return h
}

// attached waits for the next attachment of h and takes its address.
func (h *hostAgent) attached(t *testing.T) {
	t.Helper()
	select {
	case h.hostAttach = <-h.attaches:
	case <-time.After(10 * time.Second):
		t.Fatal("the agent did not attach in 10 s")
	}
}

// netstack adds addr to the netstack of h. The first call makes the netstack on
// the binding b.
func (h *hostAgent) netstack(t *testing.T, b *psp.Binding, addr netip.Addr) {
	h.once.Do(func() {
		s := stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		})
		ep := channel.New(256, uint32(b.DeviceMTU()), "")
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
			_ = d.Run(ctx)
		}()
		t.Cleanup(func() {
			// The driver ends when the agent closes the binding.
			h.stop()
			cancel()
			<-done
			s.Close()
		})
		h.stack = s
	})
	if h.stack == nil {
		return
	}
	pa := tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix()}
	if err := h.stack.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		t.Errorf("add address: %v", err)
	}
}

func (h *hostAgent) hasRoute(p netip.Prefix) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.routes[p]
}

// echo answers each UDP packet to port on the address of h with the same bytes.
func (h *hostAgent) echo(t *testing.T, port uint16) {
	t.Helper()
	local := &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(h.addr.AsSlice()), Port: port}
	c, err := gonet.DialUDP(h.stack, local, nil, ipv6.ProtocolNumber)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = c.WriteTo(buf[:n], from)
		}
	}()
}

// ping sends msg from h to port on the address of to each 500 ms, until the
// echo comes. A first packet from before the trunk keys costs 5 s.
func (h *hostAgent) ping(t *testing.T, to *hostAgent, port uint16, msg []byte) {
	t.Helper()
	local := &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(h.addr.AsSlice())}
	remote := &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(to.addr.AsSlice()), Port: port}
	c, err := gonet.DialUDP(h.stack, local, remote, ipv6.ProtocolNumber)
	require.NoError(t, err)
	defer c.Close()
	buf := make([]byte, 1500)
	for range 30 {
		_, err := c.Write(msg)
		require.NoError(t, err)
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(buf)
		if err == nil {
			assert.Equal(t, msg, buf[:n])
			return
		}
	}
	t.Fatalf("no echo of %d B from %s", len(msg), to.addr)
}

// pathDrops returns the packets that the relays dropped on the paths between
// them. It leaves out trunk_no_row: a first packet can come before its row.
func pathDrops(t *testing.T, relays ...*meshRelay) []string {
	t.Helper()
	var out []string
	for _, m := range relays {
		reg := prometheus.NewRegistry()
		require.NoError(t, reg.Register(m.router))
		families, err := reg.Gather()
		require.NoError(t, err)
		for _, f := range families {
			if f.GetName() != "apoxy_vpc_relay_dropped_packets_total" {
				continue
			}
			for _, c := range f.GetMetric() {
				reason, n := c.GetLabel()[0].GetValue(), c.GetCounter().GetValue()
				if n > 0 && reason != "trunk_no_row" && (strings.HasPrefix(reason, "trunk_") || strings.HasPrefix(reason, "mesh_")) {
					out = append(out, fmt.Sprintf("%s %s %v", m.name, reason, n))
				}
			}
		}
	}
	return out
}

// TestRelay_MeshAgents runs an agent of this build on each of two relay hosts of
// a mesh. UDP passes both ways between the agents, in each pair of modes.
func TestRelay_MeshAgents(t *testing.T) {
	const quicMode = agent.TransportQUIC
	cases := []struct {
		name  string
		a, b  agent.TransportMode // The zero value is auto, which gives PSP here.
		steer int                 // Sockets in a steer group. Zero uses one plain socket.
	}{
		{name: "PSP to PSP"},
		{name: "QUIC to QUIC", a: quicMode, b: quicMode},
		{name: "PSP to QUIC", b: quicMode},
		{name: "QUIC to PSP", a: quicMode},
		{name: "PSP to PSP, steer group of 4", steer: 4},
		{name: "QUIC to QUIC, steer group of 4", a: quicMode, b: quicMode, steer: 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.steer > 1 && runtime.GOOS != "linux" {
				t.Skip("a steer group of more than one socket needs Linux")
			}
			ca := newMeshCA(t)
			agents, err := vpctest.NewCA()
			require.NoError(t, err)
			// The two relays give addresses of one VPC network.
			addrs := &vpctest.Addresses{}
			a := startMeshRelayWith(t, ca, relayOpts{name: "relay-a", steerSockets: tc.steer, agentCA: agents, addrs: addrs})
			b := startMeshRelayWith(t, ca, relayOpts{name: "relay-b", steerSockets: tc.steer, agentCA: agents, addrs: addrs})
			b.mesh.SetMembers([]vpcrelay.MeshMember{a.member()})
			a.mesh.SetMembers([]vpcrelay.MeshMember{b.member()})
			require.Equal(t, vpcrelay.MeshChange{Name: "relay-b", Up: true}, a.change(t))
			require.Equal(t, vpcrelay.MeshChange{Name: "relay-a", Up: true}, b.change(t))

			// An agent checks the grant of its peer, which the other relay signed.
			roots := x509.NewCertPool()
			roots.AddCert(a.root)
			roots.AddCert(b.root)
			laptop := startHostAgent(t, agents, roots, a.vpcRelay, "laptop", tc.a)
			server := startHostAgent(t, agents, roots, b.vpcRelay, "server", tc.b)
			for _, h := range []struct {
				h    *hostAgent
				mode agent.TransportMode
			}{{laptop, tc.a}, {server, tc.b}} {
				want := dp.Mode_MODE_PSP
				if h.mode == quicMode {
					want = dp.Mode_MODE_QUIC
				}
				assert.Equal(t, want, h.h.a.Status().Mode)
			}
			laptop.echo(t, 9000)
			server.echo(t, 9000)
			require.Eventually(t, func() bool { return laptop.hasRoute(server.prefix) && server.hasRoute(laptop.prefix) },
				10*time.Second, 10*time.Millisecond, "each agent has the route of the other")

			// The first packet opens the peer session through the two relays.
			for _, size := range []int{5, 1200} {
				msg := bytes.Repeat([]byte{byte(size)}, size)
				laptop.ping(t, server, 9000, msg)
				server.ping(t, laptop, 9000, msg)
			}
			assert.Equal(t, 1, laptop.a.Status().Peers, "peer sessions of laptop")
			assert.Equal(t, 1, server.a.Status().Peers, "peer sessions of server")
			assert.Empty(t, pathDrops(t, a, b), "drops between the relays")

			// When server stops, laptop loses its route and closes the session.
			server.stop()
			require.Eventually(t, func() bool { return !laptop.hasRoute(server.prefix) && laptop.a.Status().Peers == 0 },
				10*time.Second, 10*time.Millisecond, "laptop has no route and no session")
		})
	}
}

// TestRelay_MeshAgentsDrain stops relay-a of a mesh of two relay hosts. Its agent
// moves to relay-b, and UDP passes both ways with the agent of relay-b again.
func TestRelay_MeshAgentsDrain(t *testing.T) {
	cases := []struct {
		name string
		mode agent.TransportMode // The zero value is auto, which gives PSP here.
	}{{name: "PSP"}, {name: "QUIC", mode: agent.TransportQUIC}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newMeshCA(t)
			agents, err := vpctest.NewCA()
			require.NoError(t, err)
			addrs := &vpctest.Addresses{}
			// An agent gets Drain only from a relay with a lame duck time.
			a := startMeshRelayWith(t, ca, relayOpts{name: "relay-a", lameDuck: 2 * time.Second, agentCA: agents, addrs: addrs})
			b := startMeshRelayWith(t, ca, relayOpts{name: "relay-b", agentCA: agents, addrs: addrs})
			b.mesh.SetMembers([]vpcrelay.MeshMember{a.member()})
			a.mesh.SetMembers([]vpcrelay.MeshMember{b.member()})
			require.Equal(t, vpcrelay.MeshChange{Name: "relay-b", Up: true}, a.change(t))
			require.Equal(t, vpcrelay.MeshChange{Name: "relay-a", Up: true}, b.change(t))
			roots := x509.NewCertPool()
			roots.AddCert(a.root)
			roots.AddCert(b.root)
			laptop := startHostAgent(t, agents, roots, a.vpcRelay, "laptop", tc.mode)
			server := startHostAgent(t, agents, roots, b.vpcRelay, "server", tc.mode)
			mode := laptop.a.Status().Mode
			laptop.echo(t, 9000)
			server.echo(t, 9000)
			require.Eventually(t, func() bool { return laptop.hasRoute(server.prefix) && server.hasRoute(laptop.prefix) },
				10*time.Second, 10*time.Millisecond, "each agent has the route of the other")
			msg := []byte("hello")
			laptop.ping(t, server, 9000, msg)
			server.ping(t, laptop, 9000, msg)

			// laptop knows only relay-a, and gets relay-b in the Drain of relay-a.
			old, start := laptop.prefix, time.Now()
			a.cancel()
			laptop.attached(t)
			moved := time.Since(start)
			require.NotEqual(t, old, laptop.prefix)
			laptop.echo(t, 9000)
			require.Eventually(t, func() bool { return server.hasRoute(laptop.prefix) && !server.hasRoute(old) },
				10*time.Second, 10*time.Millisecond, "server has only the new route of laptop")
			assert.Len(t, b.router.AttachmentStats(), 2, "attachments on relay-b")
			assert.Equal(t, mode, laptop.a.Status().Mode)

			// The peer session through relay-a ended. The new one is on relay-b.
			laptop.ping(t, server, 9000, msg)
			server.ping(t, laptop, 9000, msg)
			t.Logf("laptop attached on relay-b %d ms after the stop of relay-a, and UDP passed both ways after %d ms",
				moved.Milliseconds(), time.Since(start).Milliseconds())
			require.Eventually(t, func() bool { return laptop.a.Status().Peers == 1 && server.a.Status().Peers == 1 },
				10*time.Second, 10*time.Millisecond, "one peer session for each agent")
		})
	}
}
