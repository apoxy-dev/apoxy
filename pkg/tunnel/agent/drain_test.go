package agent

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/randalloc"
)

// startDrainableRelay is startLoopbackRelay with a lame-duck period and a
// recorded onDraining callback, for exercising the graceful drain path.
func startDrainableRelay(t *testing.T, lameDuck time.Duration, onDraining func(context.Context), vni uint, overlay string, onConnect func(context.Context, string, string, controllers.Connection) error) (*tunnel.Relay, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	connect := assignVNIOnConnect(vni, overlay)
	if onConnect != nil {
		wrapped := connect
		connect = func(ctx context.Context, tn, an string, conn controllers.Connection) error {
			if err := wrapped(ctx, tn, an, conn); err != nil {
				return err
			}
			return onConnect(ctx, tn, an, conn)
		}
	}

	return startRelayHarness(t, "letmein", pc, noopRelayRouter{}, newTestHandler(t), connect,
		func(context.Context, string, string) error { return nil },
		func(r *tunnel.Relay) {
			r.SetLameDuckPeriod(lameDuck)
			r.SetOnDraining(onDraining)
		})
}

// TestClientDrainingOnGoaway pins the drain announcement wire: shutting a
// relay down must surface on the api.Client's Draining channel (the GOAWAY
// closes the idle control connection with H3_NO_ERROR), while a
// client-initiated Close must not.
func TestClientDrainingOnGoaway(t *testing.T) {
	var drained atomic.Bool
	r, stop := startDrainableRelay(t, 2*time.Second, func(context.Context) { drained.Store(true) }, 707, "10.0.0.7/32", nil)
	t.Cleanup(stop)

	pp, err := newPacketPlane()
	require.NoError(t, err)
	t.Cleanup(pp.Close)

	relayAddr := r.Address().String()
	pcQuic, err := pp.QuicMux.Open(&net.UDPAddr{IP: r.Address().Addr().AsSlice(), Port: int(r.Address().Port())})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pcQuic.Close() })

	client, err := api.NewClient(api.ClientOptions{
		BaseURL:    (&url.URL{Scheme: "https", Host: relayAddr}).String(),
		Agent:      "drain-agent",
		TunnelName: "test-tunnel",
		Token:      "letmein",
		TLSConfig:  &tls.Config{InsecureSkipVerify: true},
		PacketConn: pcQuic,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	_, err = client.Connect(ctx)
	require.NoError(t, err)

	select {
	case <-client.Draining():
		t.Fatal("Draining must not fire before the relay drains")
	default:
	}

	// Trigger the drain. stop blocks through the lame duck, so run it async.
	go stop()

	select {
	case <-client.Draining():
	case <-time.After(5 * time.Second):
		t.Fatal("client did not observe the relay's drain announcement")
	}
	require.True(t, drained.Load(), "onDraining must run at drain start")
}

// TestManageConnectionSlot_DrainMakeBeforeBreak is the agent half of the
// graceful drain: when the current relay announces a drain, the slot must
// bring up a session to a replacement relay BEFORE hanging up the draining
// one, so the slot never drops below one live connection.
func TestManageConnectionSlot_DrainMakeBeforeBreak(t *testing.T) {
	relay2Connected := make(chan struct{}, 4)
	r1, stop1 := startDrainableRelay(t, 3*time.Second, nil, 808, "10.0.0.8/32", nil)
	t.Cleanup(stop1)
	r2, stop2 := startDrainableRelay(t, 0, nil, 809, "10.0.0.9/32",
		func(context.Context, string, string, controllers.Connection) error {
			select {
			case relay2Connected <- struct{}{}:
			default:
			}
			return nil
		})
	t.Cleanup(stop2)

	pp, err := newPacketPlane()
	require.NoError(t, err)
	t.Cleanup(pp.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	g, gctx := errgroup.WithContext(ctx)

	cfg := loopbackConfig()
	tlsConf := &tls.Config{InsecureSkipVerify: true}

	boot, err := bootstrapSession(gctx, cfg, r1.Address().String(), pp.QuicMux, tlsConf)
	require.NoError(t, err)

	ar, handler, routes := newAgentRouter(t, gctx, g, boot, pp)
	pool := randalloc.NewRandAllocator(sets.New[string](r1.Address().String()))

	slotErr := make(chan error, 1)
	go func() { slotErr <- manageConnectionSlot(gctx, cfg, pp.QuicMux, handler, ar, routes, pool, tlsConf) }()

	require.Eventually(t, func() bool {
		return cfg.ConnectionTracker.ActiveConnections() == 1
	}, 10*time.Second, 20*time.Millisecond, "slot should establish a session to relay 1")

	// From here on the slot must never drop to zero live sessions: the whole
	// point of the lame duck is that the break happens after the make.
	var sawZero atomic.Bool
	sampleDone := make(chan struct{})
	sampleStop := make(chan struct{})
	go func() {
		defer close(sampleDone)
		for {
			select {
			case <-sampleStop:
				return
			default:
			}
			if cfg.ConnectionTracker.ActiveConnections() == 0 {
				sawZero.Store(true)
			}
			time.Sleep(time.Millisecond)
		}
	}()

	// The replacement becomes available and the draining relay leaves the
	// pool — the discovery-driven flow — then relay 1 announces its drain.
	pool.Replace(sets.New[string](r2.Address().String()))
	go stop1()

	// The slot connects to relay 2 while relay 1 is still draining...
	select {
	case <-relay2Connected:
	case <-time.After(10 * time.Second):
		t.Fatal("slot did not establish a replacement session during the drain")
	}

	// ...and settles back to exactly one live session (the old one released).
	require.Eventually(t, func() bool {
		return cfg.ConnectionTracker.ActiveConnections() == 1
	}, 10*time.Second, 20*time.Millisecond, "slot should settle on the replacement session")

	close(sampleStop)
	<-sampleDone
	require.False(t, sawZero.Load(), "live session count must never touch zero during a drain")

	// The slot is still running and owns relay 2's slot exclusively.
	select {
	case err := <-slotErr:
		t.Fatalf("connection slot exited unexpectedly: %v", err)
	default:
	}
}

// TestManageConnectionSlot_SingleRelayDrainReconnect is the degenerate — and
// common — case where the pool holds exactly one relay (dev, or a network
// served by a single relay): there is no replacement to make-before-break
// onto, and a restarted relay comes back at the SAME address (a hostNetwork
// pod's node IP). The slot must not deadlock waiting for a replacement while
// its own draining session holds the pool's only address; once the draining
// session dies, the slot must release the address and reconnect to it.
func TestManageConnectionSlot_SingleRelayDrainReconnect(t *testing.T) {
	origGrace := drainGracePeriod
	// Keep the grace well outside the assertion window. The same-address
	// replacement must be detected by the draining-session check, not by waiting
	// for the old session's grace period to expire.
	drainGracePeriod = time.Minute
	t.Cleanup(func() { drainGracePeriod = origGrace })

	r1, stop1 := startDrainableRelay(t, 500*time.Millisecond, nil, 810, "10.0.0.10/32", nil)
	relayAddr := r1.Address()

	pp, err := newPacketPlane()
	require.NoError(t, err)
	t.Cleanup(pp.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	g, gctx := errgroup.WithContext(ctx)

	cfg := loopbackConfig()
	tlsConf := &tls.Config{InsecureSkipVerify: true}

	boot, err := bootstrapSession(gctx, cfg, relayAddr.String(), pp.QuicMux, tlsConf)
	require.NoError(t, err)

	ar, handler, routes := newAgentRouter(t, gctx, g, boot, pp)
	pool := randalloc.NewRandAllocator(sets.New[string](relayAddr.String()))

	slotErr := make(chan error, 1)
	go func() { slotErr <- manageConnectionSlot(gctx, cfg, pp.QuicMux, handler, ar, routes, pool, tlsConf) }()

	require.Eventually(t, func() bool {
		return cfg.ConnectionTracker.ActiveConnections() == 1
	}, 10*time.Second, 20*time.Millisecond, "slot should establish a session to the relay")

	// Drain and stop the only relay. stop1 blocks through the lame duck and
	// then tears the relay down, freeing its address.
	stopDone := make(chan struct{})
	go func() {
		stop1()
		close(stopDone)
	}()
	select {
	case <-stopDone:
	case <-time.After(10 * time.Second):
		t.Fatal("relay did not stop")
	}

	// Bring a replacement up at the SAME address, like a restarted
	// hostNetwork pod rebinding its node IP.
	pc, err := net.ListenPacket("udp", relayAddr.String())
	require.NoError(t, err)
	relay2Connected := make(chan struct{}, 4)
	onConnect := func(context.Context, string, string, controllers.Connection) error {
		select {
		case relay2Connected <- struct{}{}:
		default:
		}
		return nil
	}
	connect := assignVNIOnConnect(811, "10.0.0.11/32")
	_, stop2 := startRelayHarness(t, "letmein", pc, noopRelayRouter{}, newTestHandler(t),
		func(ctx context.Context, tn, an string, conn controllers.Connection) error {
			if err := connect(ctx, tn, an, conn); err != nil {
				return err
			}
			return onConnect(ctx, tn, an, conn)
		},
		func(context.Context, string, string) error { return nil })
	t.Cleanup(stop2)

	// The slot must shed the dead session (releasing the pool's only
	// address), re-acquire it, and reconnect — instead of deadlocking in the
	// replacement acquire while the draining session still holds the address.
	select {
	case <-relay2Connected:
	case err := <-slotErr:
		t.Fatalf("connection slot exited instead of reconnecting: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("slot never reconnected to the restarted relay at the same address")
	}

	require.Eventually(t, func() bool {
		return cfg.ConnectionTracker.ActiveConnections() == 1
	}, 10*time.Second, 20*time.Millisecond, "slot should settle on the new session")

	// Tear the slot down synchronously and verify that the live session exits.
	cancel()
	select {
	case <-slotErr:
	case <-time.After(10 * time.Second):
		t.Fatal("connection slot did not exit after cancel")
	}
}
