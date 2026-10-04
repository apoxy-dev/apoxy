package agent

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/hasher"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/randalloc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
)

// noopRelayRouter is a router.Router that does nothing. The agent tests do not
// use the overlay routes of the relay.
type noopRelayRouter struct{}

func (noopRelayRouter) Start(context.Context) error                       { return nil }
func (noopRelayRouter) AddAddr(netip.Prefix, connection.Connection) error { return nil }
func (noopRelayRouter) DelAddr(netip.Prefix) error                        { return nil }
func (noopRelayRouter) AddRoute(netip.Prefix) error                       { return nil }
func (noopRelayRouter) DelRoute(netip.Prefix) error                       { return nil }
func (noopRelayRouter) Close() error                                      { return nil }

// startRelayHarness starts an in-process QUIC relay on pc and returns it with a
// stop func. The test cleanup also calls stop.
func startRelayHarness(t *testing.T, token string, pc net.PacketConn, rtr router.Router, h *icx.Handler, onConnect func(context.Context, string, string, controllers.Connection) error, onDisconnect func(context.Context, string, string) error, configure ...func(*tunnel.Relay)) (*tunnel.Relay, func()) {
	t.Helper()

	_, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	require.NoError(t, err)

	idKey := make([]byte, 32)
	_, err = rand.Read(idKey)
	require.NoError(t, err)

	r := tunnel.NewRelay("relay-test", pc, serverCert, h, hasher.NewHasher(idKey), rtr)
	r.SetCredentials("test-tunnel", token)
	r.SetOnConnect(onConnect)
	r.SetOnDisconnect(onDisconnect)
	for _, c := range configure {
		c(r)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- r.Start(ctx) }()

	time.Sleep(150 * time.Millisecond) // Let the server bind and serve.

	stop := sync.OnceFunc(func() {
		cancel()
		select {
		case err := <-errc:
			if err != nil {
				t.Logf("Relay stopped: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("relay did not stop in 15 s")
		}
		_ = pc.Close()
	})
	t.Cleanup(stop)
	return r, stop
}

// startLoopbackRelay is startRelayHarness on a new loopback UDP socket with a
// router that does nothing.
func startLoopbackRelay(t *testing.T, token string, onConnect func(context.Context, string, string, controllers.Connection) error, onDisconnect func(context.Context, string, string) error) (*tunnel.Relay, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	return startRelayHarness(t, token, pc, noopRelayRouter{}, newTestHandler(t), onConnect, onDisconnect)
}

// assignVNIOnConnect gives the connection a known VNI and overlay address, so
// handleConnect completes.
func assignVNIOnConnect(vni uint, overlay string) func(context.Context, string, string, controllers.Connection) error {
	return func(ctx context.Context, _, _ string, conn controllers.Connection) error {
		conn.SetVNI(ctx, vni)
		conn.SetOverlayAddress(overlay)
		return nil
	}
}

func loopbackConfig() Config {
	return Config{
		Agent:             "loopback-agent",
		Network:           "test-tunnel",
		Token:             "letmein",
		Instance:          "3f6d9c2a-0000-4000-8000-000000000000",
		ConnectionTracker: NewConnectionTracker(1),
	}
}

func TestBootstrapSession(t *testing.T) {
	discCh := make(chan struct{}, 1)
	onDisconnect := func(context.Context, string, string) error {
		select {
		case discCh <- struct{}{}:
		default:
		}
		return nil
	}

	r, stop := startLoopbackRelay(t, "letmein", assignVNIOnConnect(707, "10.0.0.7/32"), onDisconnect)
	t.Cleanup(stop)

	pp, err := newPacketPlane()
	require.NoError(t, err)
	t.Cleanup(pp.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	tlsConf := &tls.Config{InsecureSkipVerify: true}
	boot, err := bootstrapSession(ctx, loopbackConfig(), r.Address().String(), pp.QuicMux, tlsConf)
	require.NoError(t, err)
	require.NotNil(t, boot.Connect)
	require.Equal(t, uint(707), boot.Connect.VNI)
	require.Equal(t, []string{"10.0.0.7/32"}, boot.Connect.Addresses)

	// Bootstrap disconnects its temporary session.
	select {
	case <-discCh:
	case <-time.After(2 * time.Second):
		t.Fatal("expected bootstrap session to disconnect")
	}
}

// newAgentRouter makes the agent netstack router and handler from a bootstrap
// response, as Run does, without SOCKS or pcap.
func newAgentRouter(t *testing.T, ctx context.Context, g *errgroup.Group, boot *bootstrapInfo, pp *packetPlane) (router.Router, *icx.Handler, *routeReconciler) {
	t.Helper()
	return newAgentRouterWithSocks(t, ctx, g, boot, pp, "")
}

// newAgentRouterWithSocks is newAgentRouter with a SOCKS listen address, so two
// agents in one test use different addresses.
func newAgentRouterWithSocks(t *testing.T, ctx context.Context, g *errgroup.Group, boot *bootstrapInfo, pp *packetPlane, socksAddr string) (router.Router, *icx.Handler, *routeReconciler) {
	t.Helper()
	r, handler, routes, err := initRouter(ctx, g, boot.Connect, routerInitOpts{pcGeneve: pp.Geneve, socksListenAddr: socksAddr})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	return r, handler, routes
}

func TestManageConnectionSlot_EstablishesAndReleases(t *testing.T) {
	r, stop := startLoopbackRelay(t, "letmein", assignVNIOnConnect(808, "10.0.0.8/32"), func(context.Context, string, string) error { return nil })
	t.Cleanup(stop)

	pp, err := newPacketPlane()
	require.NoError(t, err)
	t.Cleanup(pp.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	g, gctx := errgroup.WithContext(ctx)

	cfg := loopbackConfig()
	statusCh := make(chan ConnectionStatus, 16)
	cfg.ConnectionObserver = func(status ConnectionStatus) { statusCh <- status }
	tlsConf := &tls.Config{InsecureSkipVerify: true}

	boot, err := bootstrapSession(gctx, cfg, r.Address().String(), pp.QuicMux, tlsConf)
	require.NoError(t, err)

	ar, handler, routes := newAgentRouter(t, gctx, g, boot, pp)
	pool := randalloc.NewRandAllocator(sets.New[string](r.Address().String()))

	slotErr := make(chan error, 1)
	go func() { slotErr <- manageConnectionSlot(gctx, cfg, pp.QuicMux, handler, ar, routes, pool, tlsConf) }()

	// The slot connects and marks itself healthy.
	require.Eventually(t, func() bool {
		return cfg.ConnectionTracker.ActiveConnections() == 1
	}, 5*time.Second, 20*time.Millisecond, "slot should establish one live session")
	require.Eventually(t, func() bool {
		for {
			select {
			case status := <-statusCh:
				if status.Slot == 0 && status.State == ConnectionStateConnected && status.Relay == r.Address().String() {
					return true
				}
			default:
				return false
			}
		}
	}, 5*time.Second, 20*time.Millisecond, "slot should publish its connected state")

	// A cancel ends the session. The slot releases the relay and returns ctx.Err.
	cancel()
	select {
	case err := <-slotErr:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("manageConnectionSlot did not return after cancel")
	}
	require.Eventually(t, func() bool {
		return cfg.ConnectionTracker.ActiveConnections() == 0
	}, 3*time.Second, 20*time.Millisecond, "connection count should return to zero after release")
}

func TestManageConnectionSlot_ExclusiveAcquireCapsAtPoolSize(t *testing.T) {
	r, stop := startLoopbackRelay(t, "letmein", assignVNIOnConnect(909, "10.0.0.9/32"), func(context.Context, string, string) error { return nil })
	t.Cleanup(stop)

	pp, err := newPacketPlane()
	require.NoError(t, err)
	t.Cleanup(pp.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	g, gctx := errgroup.WithContext(ctx)

	cfg := loopbackConfig()
	tlsConf := &tls.Config{InsecureSkipVerify: true}

	boot, err := bootstrapSession(gctx, cfg, r.Address().String(), pp.QuicMux, tlsConf)
	require.NoError(t, err)
	ar, handler, routes := newAgentRouter(t, gctx, g, boot, pp)

	// One relay and two slots. A slot holds its relay alone, so the second slot
	// waits in Acquire.
	pool := randalloc.NewRandAllocator(sets.New[string](r.Address().String()))
	for i := 0; i < 2; i++ {
		go func() { _ = manageConnectionSlot(gctx, cfg, pp.QuicMux, handler, ar, routes, pool, tlsConf) }()
	}

	require.Eventually(t, func() bool {
		return cfg.ConnectionTracker.ActiveConnections() == 1
	}, 5*time.Second, 20*time.Millisecond, "exactly one slot should connect")

	// Give the second slot time to connect, then make sure that it did not.
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, 1, cfg.ConnectionTracker.ActiveConnections(), "second slot must stay blocked on the exclusive pool")
}
