package tunnel_test

import (
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
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	vpcrelay "github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
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
	changes chan vpcrelay.MeshChange
	checks  chan meshCheck
}

func startMeshRelay(t *testing.T, ca *meshCA, name string, steerSockets int, noVPC bool) *meshRelay {
	t.Helper()
	m := &meshRelay{name: name, changes: make(chan vpcrelay.MeshChange, 64), checks: make(chan meshCheck, 64)}
	m.vpcRelay = startRelayWith(t, relayOpts{name: name, steerSockets: steerSockets, noVPC: noVPC, setup: func(r *tunnel.Relay) {
		mesh, err := r.SetMesh(vpcrelay.MeshConfig{
			Relay:  &dp.RelayRef{Id: "localhost"},
			TLS:    ca.tls(t, name),
			Verify: ca.verify(m.checks),
		})
		require.NoError(t, err)
		mesh.OnChange(func(c vpcrelay.MeshChange) { m.changes <- c })
		m.mesh = mesh
	}})
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
				// The other relay answers a call. This method has no handler yet.
				_, err := s.Client().TrunkKeys(ctx, &dp.KeysRequest{})
				assert.Equal(t, rpc.Unimplemented, rpc.CodeOf(err), "call from %s: %v", d.from.name, err)
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
