package tunnel_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/hasher"
)

func TestRelay_Connect_UpdateKeys_Disconnect(t *testing.T) {
	const goodToken = "secret-token"

	// onConnect assigns VNI and overlay address so handleConnect can proceed.
	onConnect := func(ctx context.Context, agent string, conn controllers.Connection) error {
		// Choose a deterministic VNI for the test.
		conn.SetVNI(101)
		conn.SetOverlayAddress("10.0.0.2/32")
		return nil
	}

	var disc api.Request

	onDisconnect := func(ctx context.Context, agent, id string) error {
		disc.Agent = agent
		disc.ID = id
		return nil
	}

	r, caCert, stop := startRelay(t, goodToken, onConnect, onDisconnect)
	t.Cleanup(stop)

	c := clientForRelay(t, r, caCert, goodToken)
	t.Cleanup(func() {
		require.NoError(t, c.Close())
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)

	// Connect
	connectResp, err := c.Connect(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, connectResp.ID)
	require.Equal(t, uint(101), connectResp.VNI)
	require.Equal(t, 1392, connectResp.MTU)
	require.Len(t, connectResp.Addresses, 1)
	require.Equal(t, "10.0.0.2/32", connectResp.Addresses[0])
	require.WithinDuration(t, time.Now().Add(24*time.Hour), connectResp.Keys.ExpiresAt, time.Minute)

	firstEpoch := connectResp.Keys.Epoch
	require.EqualValues(t, 0, firstEpoch, "initial key epoch should start at 0")

	// UpdateKeys
	upd, err := c.UpdateKeys(ctx, connectResp.ID)
	require.NoError(t, err)
	require.Equal(t, connectResp.ID, connectResp.ID)
	require.GreaterOrEqual(t, int(upd.Keys.Epoch), int(firstEpoch+1), "epoch must increment")
	require.WithinDuration(t, time.Now().Add(24*time.Hour), upd.Keys.ExpiresAt, time.Minute)

	// Disconnect
	err = c.Disconnect(ctx, connectResp.ID)
	require.NoError(t, err)

	// Verify callback observed the same info
	require.Equal(t, "it-agent", disc.Agent)
	require.Equal(t, connectResp.ID, disc.ID)
}

func startRelay(t *testing.T, token string, onConnect func(context.Context, string, controllers.Connection) error, onDisconnect func(context.Context, string, string) error) (*tunnel.Relay, tls.Certificate, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	caCert, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	require.NoError(t, err)

	h, err := icx.NewHandler(icx.WithLocalAddr(toFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()))
	require.NoError(t, err)

	idKey := make([]byte, 32)
	_, err = rand.Read(idKey)
	require.NoError(t, err)

	idHasher := hasher.NewHasher(idKey)

	r := tunnel.NewRelay("relay-it", pc, serverCert, h, idHasher)
	r.SetCredentials("test-tunnel", token)
	r.SetOnConnect(onConnect)
	r.SetOnDisconnect(onDisconnect)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		_ = r.Start(ctx) // on shutdown we don't assert the error path
		close(done)
	}()

	// Give the server a brief moment to bind and start serving.
	time.Sleep(150 * time.Millisecond)

	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			// if shutdown hangs, tests will fail below anyway
		}
		_ = pc.Close()
	}

	return r, caCert, stop
}

func clientForRelay(t *testing.T, r *tunnel.Relay, caCert tls.Certificate, token string) *api.Client {
	t.Helper()

	baseURL := "https://" + r.Address()
	tlsCfg := &tls.Config{
		RootCAs:    cryptoutils.CertPoolForCertificate(caCert),
		ServerName: "localhost",
	}

	c, err := api.NewClient(api.ClientOptions{
		BaseURL:    baseURL,
		Agent:      "it-agent",
		TunnelName: "test-tunnel",
		Token:      token,
		TLSConfig:  tlsCfg,
		Timeout:    5 * time.Second,
	})
	require.NoError(t, err)
	return c
}

func toFullAddress(addrPort netip.AddrPort) *tcpip.FullAddress {
	if addrPort.Addr().Is4() {
		addrv4 := addrPort.Addr().As4()
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4Slice(addrv4[:]),
			Port: uint16(addrPort.Port()),
		}
	} else {
		addrv6 := addrPort.Addr().As16()
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom16Slice(addrv6[:]),
			Port: uint16(addrPort.Port()),
		}
	}
}
