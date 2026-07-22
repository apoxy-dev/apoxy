package tunnel_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/hasher"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"
)

func TestRelay_Connect_UpdateKeys_Disconnect(t *testing.T) {
	const goodToken = "secret-token"

	onConnect := func(ctx context.Context, tunnelName, agentName string, conn controllers.Connection) error {
		conn.SetVNI(ctx, 101)
		conn.SetOverlayAddress("10.0.0.2/32")
		return nil
	}

	discCh := make(chan api.Request, 1)

	onDisconnect := func(ctx context.Context, agent, id string) error {
		discCh <- api.Request{Agent: agent, ID: id}
		return nil
	}

	r, caCert, stop, _ := startRelay(t, goodToken, onConnect, onDisconnect)
	t.Cleanup(stop)

	c := clientForRelay(t, r, caCert, goodToken)
	t.Cleanup(func() {
		require.NoError(t, c.Close())
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)

	connectResp, err := c.Connect(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, connectResp.ID)
	require.Equal(t, uint(101), connectResp.VNI)
	// Pin the wire value explicitly (not icx.MTU(api.TunnelPathMTU), which would
	// track any icx encap-overhead regression instead of catching it). Must stay
	// >= 1280 so the IPv6 overlay works on the agent's TUN device.
	require.Equal(t, 1392, connectResp.MTU)
	require.GreaterOrEqual(t, connectResp.MTU, 1280)
	require.Len(t, connectResp.Addresses, 1)
	require.Equal(t, "10.0.0.2/32", connectResp.Addresses[0])
	require.WithinDuration(t, time.Now().Add(24*time.Hour), connectResp.Keys.ExpiresAt, time.Minute)

	firstEpoch := connectResp.Keys.Epoch
	require.EqualValues(t, 1, firstEpoch)
	require.NotEqual(t, api.MasterSecret{}, connectResp.Keys.MasterSecret)

	upd, err := c.UpdateKeys(ctx, connectResp.ID)
	require.NoError(t, err)
	require.Equal(t, connectResp.ID, connectResp.ID)
	require.GreaterOrEqual(t, int(upd.Keys.Epoch), int(firstEpoch+1))
	require.Equal(t, connectResp.Keys.MasterSecret, upd.Keys.MasterSecret)
	require.WithinDuration(t, time.Now().Add(24*time.Hour), upd.Keys.ExpiresAt, time.Minute)

	err = c.Disconnect(ctx, connectResp.ID)
	require.NoError(t, err)

	select {
	case disc := <-discCh:
		require.Equal(t, "it-agent", disc.Agent)
		require.Equal(t, connectResp.ID, disc.ID)
	case <-time.After(3 * time.Second):
		t.Fatal("expected onDisconnect callback to fire")
	}
}

func TestRelay_CredentialBounds(t *testing.T) {
	const goodToken = "bounded-token"

	onConnect := func(ctx context.Context, tunnelName, agentName string, conn controllers.Connection) error {
		conn.SetVNI(ctx, 303)
		conn.SetOverlayAddress("10.0.0.4/32")
		return nil
	}
	onDisconnect := func(ctx context.Context, agent, id string) error { return nil }

	r, caCert, stop, _ := startRelay(t, goodToken, onConnect, onDisconnect)
	t.Cleanup(stop)

	r.SetTokenValidator(&boundedValidator{
		token: goodToken,
		authz: &token.AuthzResult{
			Network:          "test-tunnel",
			AllowedLabelSets: []map[string]string{{"app": "payments", "env": "prod"}},
			AllowedRoutes:    []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16")},
		},
	})

	cases := []struct {
		name    string
		labels  map[string]string
		routes  []string
		wantErr string
	}{
		{
			name:   "in bounds",
			labels: map[string]string{"app": "payments"},
			routes: []string{"10.10.5.0/24"},
		},
		{
			name:    "out of bounds route",
			routes:  []string{"192.168.0.0/24"},
			wantErr: "403",
		},
		{
			name:    "garbage route",
			routes:  []string{"not-a-cidr"},
			wantErr: "400",
		},
		{
			name:    "labels outside allowed set",
			labels:  map[string]string{"app": "payments", "team": "x"},
			wantErr: "403",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseURL := "https://" + r.Address().String()
			tlsCfg := &tls.Config{
				RootCAs:    cryptoutils.CertPoolForCertificate(caCert),
				ServerName: "localhost",
			}

			c, err := api.NewClient(api.ClientOptions{
				BaseURL:          baseURL,
				Agent:            "it-agent",
				TunnelName:       "test-tunnel",
				Token:            goodToken,
				TLSConfig:        tlsCfg,
				Timeout:          5 * time.Second,
				Labels:           tc.labels,
				AdvertisedRoutes: tc.routes,
				AgentInstance:    "b3b937f2-9e39-4b6f-9a4e-05dd5e2f2f26",
			})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, c.Close()) })

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			t.Cleanup(cancel)

			connectResp, err := c.Connect(ctx)
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.NoError(t, c.Disconnect(ctx, connectResp.ID))
		})
	}
}

// boundedValidator is a test TokenValidator returning a fixed authorization.
type boundedValidator struct {
	token string
	authz *token.AuthzResult
}

func (v *boundedValidator) Validate(_ context.Context, network, tokenStr string) (*token.AuthzResult, error) {
	if tokenStr != v.token || network != v.authz.Network {
		return nil, token.ErrUnauthorized
	}
	return v.authz, nil
}

// TestRelay_NilAuthzFailsClosed guards against a validator that authenticates
// (nil error) but returns no authorization: the relay must reject rather than
// treat the connection as unbounded.
func TestRelay_NilAuthzFailsClosed(t *testing.T) {
	const goodToken = "nil-authz-token"

	onConnect := func(ctx context.Context, tunnelName, agentName string, conn controllers.Connection) error {
		conn.SetVNI(ctx, 404)
		conn.SetOverlayAddress("10.0.0.5/32")
		return nil
	}
	onDisconnect := func(ctx context.Context, agent, id string) error { return nil }

	r, caCert, stop, _ := startRelay(t, goodToken, onConnect, onDisconnect)
	t.Cleanup(stop)

	r.SetTokenValidator(nilAuthzValidator{})

	c := clientForRelay(t, r, caCert, goodToken)
	t.Cleanup(func() { require.NoError(t, c.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)

	// Before the fix this connected successfully (enforcement skipped); now the
	// relay rejects the nil authorization at the auth layer.
	_, err := c.Connect(ctx)
	require.Error(t, err)
}

// nilAuthzValidator authenticates every request but returns no authorization,
// simulating a buggy external validator.
type nilAuthzValidator struct{}

func (nilAuthzValidator) Validate(_ context.Context, _, _ string) (*token.AuthzResult, error) {
	return nil, nil
}

func TestRelay_InvalidAuthClosesQUIC(t *testing.T) {
	const goodToken = "correct-token"
	const badToken = "wrong-token"

	onConnect := func(ctx context.Context, tunnelName, agentName string, conn controllers.Connection) error { return nil }
	onDisconnect := func(ctx context.Context, agentName, id string) error { return nil }

	r, caCert, stop, _ := startRelay(t, goodToken, onConnect, onDisconnect)
	t.Cleanup(stop)

	tlsCfg := &tls.Config{
		RootCAs:    cryptoutils.CertPoolForCertificate(caCert),
		ServerName: "localhost",
	}

	var captured quic.EarlyConnection
	rt := &http3.Transport{
		TLSClientConfig: tlsCfg,
		Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			c, err := quic.DialAddrEarly(ctx, addr, tlsConf, cfg)
			if err == nil {
				captured = c
			}
			return c, err
		},
	}
	t.Cleanup(func() { _ = rt.Close() })

	h3Client := &http.Client{
		Transport: rt,
		Timeout:   3 * time.Second,
	}

	url := "https://" + r.Address().String() + "/v1/tunnel/test-tunnel"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+badToken)
	req.Header.Set("Content-Type", "application/json")

	_, err = h3Client.Do(req)
	require.True(t, err != nil && strings.Contains(err.Error(), "H3_REQUEST_REJECTED"), "expected request to be rejected, got: %v", err)

	require.NotNil(t, captured, "should have captured the QUIC connection")

	select {
	case <-captured.Context().Done():
	case <-time.After(750 * time.Millisecond):
		t.Fatalf("expected QUIC connection to be closed after unauthorized response, but it remained open")
	}
}

func TestRelay_GarbageCollector_DropsIdleConnections(t *testing.T) {
	const token = "gc-token"

	discCh := make(chan api.Request, 1)
	onDisconnect := func(ctx context.Context, agent, id string) error {
		discCh <- api.Request{Agent: agent, ID: id}
		return nil
	}
	onConnect := func(ctx context.Context, tunnelName, agentName string, conn controllers.Connection) error {
		conn.SetVNI(ctx, 202)
		conn.SetOverlayAddress("10.0.0.3/32")
		return nil
	}

	r, caCert, stop, h := startRelay(t, token, onConnect, onDisconnect)
	t.Cleanup(stop)

	c := clientForRelay(t, r, caCert, token)
	t.Cleanup(func() { require.NoError(t, c.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	connResp, err := c.Connect(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, connResp.ID)
	require.Equal(t, uint(202), connResp.VNI)

	vnet, ok := h.GetVirtualNetwork(connResp.VNI)
	require.True(t, ok, "virtual network should exist")

	old := time.Now().Add(-10 * time.Minute).UnixNano()
	vnet.Stats.LastRXUnixNano.Store(old)

	select {
	case got := <-discCh:
		require.Equal(t, connResp.ID, got.ID)
		require.Equal(t, "it-agent", got.Agent)
	default:
		select {
		case got := <-discCh:
			require.Equal(t, connResp.ID, got.ID)
			require.Equal(t, "it-agent", got.Agent)
		case <-time.After(8 * time.Second):
			t.Fatalf("expected GC to drop idle connection within a GC interval")
		}
	}

	err = c.Disconnect(ctx, connResp.ID)
	require.Error(t, err) // should error as connection already dropped by GC
}

func startRelay(
	t *testing.T,
	token string,
	onConnect func(context.Context, string, string, controllers.Connection) error,
	onDisconnect func(context.Context, string, string) error,
) (*tunnel.Relay, tls.Certificate, func(), *icx.Handler) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	caCert, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	require.NoError(t, err)

	h, err := icx.NewHandler(
		icx.WithLocalAddr(netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()),
	)
	require.NoError(t, err)

	idKey := make([]byte, 32)
	_, err = rand.Read(idKey)
	require.NoError(t, err)

	idHasher := hasher.NewHasher(idKey)

	rtr := &mockRouter{}
	rtr.On("Start", mock.Anything).Return(nil)
	rtr.On("Close").Return(nil)
	rtr.On("AddAddr", mock.Anything, mock.Anything).Return(nil)
	rtr.On("DelAddr", mock.Anything).Return(nil)
	rtr.On("AddRoute", mock.Anything).Return(nil)
	rtr.On("DelRoute", mock.Anything).Return(nil)

	r := tunnel.NewRelay("relay-it", pc, serverCert, h, idHasher, rtr)
	r.SetCredentials("test-tunnel", token)
	r.SetOnConnect(onConnect)
	r.SetOnDisconnect(onDisconnect)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		if err := r.Start(ctx); err != nil {
			t.Errorf("Relay stopped with error: %v", err)
		}
		close(done)
	}()

	time.Sleep(150 * time.Millisecond)

	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		_ = pc.Close()
	}

	return r, caCert, stop, h
}

func clientForRelay(t *testing.T, r *tunnel.Relay, caCert tls.Certificate, token string) *api.Client {
	t.Helper()

	baseURL := "https://" + r.Address().String()
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

type mockRouter struct {
	mock.Mock
}

func (m *mockRouter) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockRouter) AddAddr(addr netip.Prefix, tun connection.Connection) error {
	args := m.Called(addr, tun)
	return args.Error(0)
}

func (m *mockRouter) DelAddr(addr netip.Prefix) error {
	args := m.Called(addr)
	return args.Error(0)
}

func (m *mockRouter) AddRoute(dst netip.Prefix) error {
	args := m.Called(dst)
	return args.Error(0)
}

func (m *mockRouter) DelRoute(dst netip.Prefix) error {
	args := m.Called(dst)
	return args.Error(0)
}

func (m *mockRouter) Close() error {
	args := m.Called()
	return args.Error(0)
}
