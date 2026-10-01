package tunnel_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	vpcProject = "project-a"
	vpcUID     = "vpc-1"
	vpcNetwork = 0x0a0b0c
)

type vpcTrust struct{ pool *x509.CertPool }

func (f vpcTrust) AgentCA() (*x509.CertPool, error) { return f.pool, nil }
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

// vpcAddresses gives each attachment the next fd00:<n>::/96.
type vpcAddresses struct {
	mu   sync.Mutex
	next int
}

func (f *vpcAddresses) Assign(context.Context, *vpcrelay.Attachment) ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	return []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("fd00:%x::/96", f.next))}, nil
}

func (f *vpcAddresses) Release(*vpcrelay.Attachment) {}

// vpcAgent is an agent connection to the relay on its own socket.
type vpcAgent struct {
	tr   *quic.Transport
	qc   quic.Connection
	c    dp.RelayClient
	addr netip.Addr // Overlay address from the grant.
}

// TestRelay_VPCSharesSocket runs HTTP/3 and VPC relay sessions on one relay
// socket, and sends PSP packets and peer frames between two VPC agents.
func TestRelay_VPCSharesSocket(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	agentCA, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	agentPool := x509.NewCertPool()
	agentPool.AddCert(agentCA)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	relayCA, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	require.NoError(t, err)
	relayRoots := cryptoutils.CertPoolForCertificate(relayCA)
	h, err := icx.NewHandler(
		icx.WithLocalAddr(netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()),
	)
	require.NoError(t, err)
	rtr := &mockRouter{}
	rtr.On("Start", mock.Anything).Return(nil)
	rtr.On("Close").Return(nil)
	r := tunnel.NewRelay("localhost", pc, serverCert, h, hasher.NewHasher(make([]byte, 32)), rtr)
	r.SetVPC("localhost", vpcTrust{agentPool}, vpcNetworks{}, &vpcAddresses{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		assert.NoError(t, r.Start(ctx))
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = pc.Close()
	})

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
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		id := identity.ID{Project: vpcProject, VPC: vpcUID, Agent: name}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2), URIs: []*url.URL{id.URI()},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, agentCA, &key.PublicKey, caKey)
		require.NoError(t, err)
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		tr := &quic.Transport{Conn: udp}
		t.Cleanup(func() { _ = tr.Close(); _ = udp.Close() })
		dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
		defer dcancel()
		qc, err := tr.Dial(dctx, net.UDPAddrFromAddrPort(r.Address()), &tls.Config{
			RootCAs:      relayRoots,
			ServerName:   "localhost",
			NextProtos:   []string{dp.ALPNRelay},
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		}, &quic.Config{EnableDatagrams: true})
		require.NoError(t, err)
		a := vpcAgent{tr: tr, qc: qc, c: dp.NewRelayClient(rpc.NewConn(qc, nil))}
		res, err := a.c.Attach(dctx, &dp.AttachRequest{Vpc: &dp.VPCRef{ProjectId: vpcProject, VpcUid: vpcUID, NetworkId: vpcNetwork}, Name: name})
		require.NoError(t, err)
		claims, err := vpcrelay.VerifyGrant(res.Grant, relayRoots, time.Now())
		require.NoError(t, err)
		assert.Equal(t, "localhost", claims.RelayId)
		a.addr = netip.MustParsePrefix(claims.Addresses[0]).Addr().Next()
		return a
	}
	a, b := dial("a"), dial("b")

	// A peer frame from a to b.
	require.NoError(t, a.qc.SendDatagram(peerconn.EncodeToRelay(nil, b.addr, a.addr, []byte("hello"))))
	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	defer rcancel()
	got, err := b.qc.ReceiveDatagram(rctx)
	require.NoError(t, err)
	assert.Equal(t, peerconn.EncodeFromRelay(nil, a.addr, []byte("hello")), got)

	// A PSP packet from a to b by the SPI row of a, through the packet handler.
	_, err = a.c.RegisterSPI(rctx, &dp.RegisterSPIRequest{
		Vpc:         &dp.VPCRef{ProjectId: vpcProject, VpcUid: vpcUID, NetworkId: vpcNetwork},
		Destination: b.addr.String(), Spis: []uint32{7}, ExpiresIn: durationpb.New(time.Minute),
	})
	require.NoError(t, err)
	aead, err := pspwire.NewAEAD(make([]byte, 16))
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
