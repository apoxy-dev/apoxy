package alpha_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/apoxy/pkg/cmd"
	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/hasher"
)

func TestTunnelRun(t *testing.T) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	var connected bool

	// onConnect assigns VNI and overlay address so handleConnect can proceed.
	onConnect := func(ctx context.Context, tunnelName, agentName string, conn controllers.Connection) error {
		// Choose a deterministic VNI for the test.
		conn.SetVNI(ctx, 101)
		conn.SetOverlayAddress("10.0.0.2/32")
		t.Logf("onConnect called, agent=%s", agentName)
		if agentName == "test-agent" {
			connected = true
		}
		return nil
	}

	onDisconnect := func(ctx context.Context, agent, id string) error {
		t.Logf("onDisconnect called, agent=%s id=%s", agent, id)
		return nil
	}

	r, _, stop := startRelay(t, "letmein", onConnect, onDisconnect)
	t.Cleanup(stop)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)

	cmd := cmd.RootCmd
	cmd.SetArgs([]string{
		"alpha", "tunnel", "run",
		"--agent", "test-agent",
		"--name", "test-tunnel",
		"--relay-addr", r.Address().String(),
		"--token", "letmein",
		"--insecure-skip-verify",
	})
	cmd.SilenceUsage = true
	err := cmd.ExecuteContext(ctx)
	if err != nil && errors.Is(err, context.DeadlineExceeded) {
		err = nil // expected on timeout
	}
	require.NoError(t, err)

	require.True(t, connected, "expected to be connected")

	// TODO: verify traffic routing through the tunnel
}

func startRelay(t *testing.T, token string, onConnect func(context.Context, string, string, controllers.Connection) error, onDisconnect func(context.Context, string, string) error) (*tunnel.Relay, tls.Certificate, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	caCert, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	require.NoError(t, err)

	h, err := icx.NewHandler(icx.WithLocalAddr(netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()))
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

	// Give the server a brief moment to bind and start serving.
	time.Sleep(150 * time.Millisecond)

	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			// if shutdown hangs, tests will fail below anyway
		}
		_ = pc.Close()
	}

	return r, caCert, stop
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
