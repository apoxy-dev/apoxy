package agent

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

// noopRelayRouter is a no-op router.Router for the relay side of the loopback
// harness — the relay's overlay routing is irrelevant to agent-side tests.
type noopRelayRouter struct{}

func (noopRelayRouter) Start(context.Context) error                      { return nil }
func (noopRelayRouter) AddAddr(netip.Prefix, connection.Connection) error { return nil }
func (noopRelayRouter) DelAddr(netip.Prefix) error                       { return nil }
func (noopRelayRouter) AddRoute(netip.Prefix) error                      { return nil }
func (noopRelayRouter) DelRoute(netip.Prefix) error                      { return nil }
func (noopRelayRouter) Close() error                                     { return nil }

// startRelayHarness starts a real in-process QUIC relay on pc with the given
// router and icx handler, and returns it plus a stop func. It is the single
// relay bring-up used by the loopback and data-plane tests.
func startRelayHarness(t *testing.T, token string, pc net.PacketConn, rtr router.Router, h *icx.Handler, onConnect func(context.Context, string, string, controllers.Connection) error, onDisconnect func(context.Context, string, string) error) (*tunnel.Relay, func()) {
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

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		if err := r.Start(ctx); err != nil {
			t.Logf("Relay stopped: %v", err)
		}
		close(done)
	}()

	time.Sleep(150 * time.Millisecond) // let the server bind and serve

	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		_ = pc.Close()
	}
	return r, stop
}

// startLoopbackRelay is startRelayHarness on a fresh loopback UDP socket with
// a no-op router — the control-plane-only variant.
func startLoopbackRelay(t *testing.T, token string, onConnect func(context.Context, string, string, controllers.Connection) error, onDisconnect func(context.Context, string, string) error) (*tunnel.Relay, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	return startRelayHarness(t, token, pc, noopRelayRouter{}, newTestHandler(t), onConnect, onDisconnect)
}

// assignVNIOnConnect is the standard onConnect for these tests: it hands the
// connection a deterministic VNI and overlay address so handleConnect completes.
func assignVNIOnConnect(vni uint, overlay string) func(context.Context, string, string, controllers.Connection) error {
	return func(ctx context.Context, _, _ string, conn controllers.Connection) error {
		conn.SetVNI(ctx, vni)
		conn.SetOverlayAddress(overlay)
		return nil
	}
}

func loopbackConfig() Config {
	return Config{
		Agent:    "loopback-agent",
		Network:  "test-tunnel",
		Token:    "letmein",
		Instance: "3f6d9c2a-0000-4000-8000-000000000000",
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

	// Bootstrap disconnects its throwaway session gracefully.
	select {
	case <-discCh:
	case <-time.After(2 * time.Second):
		t.Fatal("expected bootstrap session to disconnect")
	}
}

// newAgentRouter builds the agent-side netstack router + handler from a bootstrap
// response, mirroring the Run wiring (no SOCKS listener, no pcap).
func newAgentRouter(t *testing.T, ctx context.Context, g *errgroup.Group, boot *bootstrapInfo, pp *packetPlane) (router.Router, *icx.Handler) {
	t.Helper()
	return newAgentRouterWithSocks(t, ctx, g, boot, pp, "")
}

// newAgentRouterWithSocks is newAgentRouter with an explicit SOCKS listen address,
// so two agents in one test don't collide on the default localhost:1080.
func newAgentRouterWithSocks(t *testing.T, ctx context.Context, g *errgroup.Group, boot *bootstrapInfo, pp *packetPlane, socksAddr string) (router.Router, *icx.Handler) {
	t.Helper()
	r, handler, err := initRouter(ctx, g, boot.Connect, routerInitOpts{pcGeneve: pp.Geneve, socksListenAddr: socksAddr})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	return r, handler
}


func TestManageConnectionSlot_EstablishesAndReleases(t *testing.T) {
	orig := connectionHealthCounter.Load()
	t.Cleanup(func() { connectionHealthCounter.Store(orig) })
	connectionHealthCounter.Store(0)

	r, stop := startLoopbackRelay(t, "letmein", assignVNIOnConnect(808, "10.0.0.8/32"), func(context.Context, string, string) error { return nil })
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

	ar, handler := newAgentRouter(t, gctx, g, boot, pp)
	pool := randalloc.NewRandAllocator(sets.New[string](r.Address().String()))

	slotErr := make(chan error, 1)
	go func() { slotErr <- manageConnectionSlot(gctx, cfg, pp.QuicMux, handler, ar, pool, tlsConf) }()

	// The slot connects and marks itself healthy.
	require.Eventually(t, func() bool {
		return connectionHealthCounter.Load() == 1
	}, 5*time.Second, 20*time.Millisecond, "slot should establish one live session")

	// Cancelling ends the session; the slot releases and returns ctx.Err.
	cancel()
	select {
	case err := <-slotErr:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("manageConnectionSlot did not return after cancel")
	}
	require.Eventually(t, func() bool {
		return connectionHealthCounter.Load() == 0
	}, 3*time.Second, 20*time.Millisecond, "health counter should return to zero after release")
}

func TestManageConnectionSlot_ExclusiveAcquireCapsAtPoolSize(t *testing.T) {
	orig := connectionHealthCounter.Load()
	t.Cleanup(func() { connectionHealthCounter.Store(orig) })
	connectionHealthCounter.Store(0)

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
	ar, handler := newAgentRouter(t, gctx, g, boot, pp)

	// One relay in the pool, two slots. Because a slot holds a relay exclusively,
	// only one slot can be connected at a time; the surplus blocks in Acquire.
	pool := randalloc.NewRandAllocator(sets.New[string](r.Address().String()))
	for i := 0; i < 2; i++ {
		go func() { _ = manageConnectionSlot(gctx, cfg, pp.QuicMux, handler, ar, pool, tlsConf) }()
	}

	require.Eventually(t, func() bool {
		return connectionHealthCounter.Load() == 1
	}, 5*time.Second, 20*time.Millisecond, "exactly one slot should connect")

	// Give the second slot ample time to (wrongly) connect, then assert it did not.
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, int32(1), connectionHealthCounter.Load(), "second slot must stay blocked on the exclusive pool")
}
