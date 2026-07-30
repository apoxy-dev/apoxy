package agent

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
)

// TestRunConnectAll_SessionPerRelay is the consumer connection policy:
// relays do not federate routes, so a consumer (backplane VTEP) must hold a
// live session to EVERY relay in the pool, not MinConns randomly-picked
// ones.
func TestRunConnectAll_SessionPerRelay(t *testing.T) {
	origGrace := drainGracePeriod
	drainGracePeriod = time.Second
	origRedial := connectAllRedialInterval
	origRefresh := relayRefreshInterval
	connectAllRedialInterval = 100 * time.Millisecond
	relayRefreshInterval = 200 * time.Millisecond
	t.Cleanup(func() {
		drainGracePeriod = origGrace
		connectAllRedialInterval = origRedial
		relayRefreshInterval = origRefresh
	})

	orig := connectionHealthCounter.Load()
	t.Cleanup(func() { connectionHealthCounter.Store(orig) })
	connectionHealthCounter.Store(0)

	r1, stop1 := startDrainableRelay(t, 0, nil, 820, "10.0.0.20/32", nil)
	t.Cleanup(stop1)
	r2, stop2 := startDrainableRelay(t, 500*time.Millisecond, nil, 821, "10.0.0.21/32", nil)
	addr1, addr2 := r1.Address().String(), r2.Address().String()

	// Mutable "registered relays" view, standing in for the Endpoint-backed
	// lister the backplane uses.
	var mu sync.Mutex
	registered := sets.New[string](addr1, addr2)
	setRegistered := func(addrs ...string) {
		mu.Lock()
		defer mu.Unlock()
		registered = sets.New[string](addrs...)
	}
	cfg := loopbackConfig()
	cfg.ConnectAll = true
	cfg.RelayLister = func(context.Context) (sets.Set[string], error) {
		mu.Lock()
		defer mu.Unlock()
		return registered.Clone(), nil
	}

	pp, err := newPacketPlane()
	require.NoError(t, err)
	t.Cleanup(pp.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	g, gctx := errgroup.WithContext(ctx)

	tlsConf := &tls.Config{InsecureSkipVerify: true}
	boot, err := bootstrapSession(gctx, cfg, addr1, pp.QuicMux, tlsConf)
	require.NoError(t, err)
	ar, handler, routes := newAgentRouter(t, gctx, g, boot, pp)

	runErr := make(chan error, 1)
	go func() {
		runErr <- runConnectAll(gctx, cfg, pp.QuicMux, handler, ar, routes, registered.Clone(), tlsConf)
	}()

	// One live session per relay.
	require.Eventually(t, func() bool {
		return connectionHealthCounter.Load() == 2
	}, 10*time.Second, 20*time.Millisecond, "consumer should hold a session to every relay")

	// A relay deregisters and goes away: its runner must stop re-dialing,
	// the other session must stay.
	setRegistered(addr1)
	stop2()
	require.Eventually(t, func() bool {
		return connectionHealthCounter.Load() == 1
	}, 30*time.Second, 20*time.Millisecond, "session to the departed relay should end")

	// A replacement registers at the SAME address (restarted hostNetwork pod
	// keeps its node IP): the sync loop must dial it back.
	pc, err := net.ListenPacket("udp", addr2)
	require.NoError(t, err)
	reconnected := make(chan struct{}, 4)
	connect := assignVNIOnConnect(822, "10.0.0.22/32")
	_, stop3 := startRelayHarness(t, "letmein", pc, noopRelayRouter{}, newTestHandler(t),
		func(ctx context.Context, tn, an string, conn controllers.Connection) error {
			if err := connect(ctx, tn, an, conn); err != nil {
				return err
			}
			select {
			case reconnected <- struct{}{}:
			default:
			}
			return nil
		},
		func(context.Context, string, string) error { return nil })
	t.Cleanup(stop3)
	setRegistered(addr1, addr2)

	select {
	case <-reconnected:
	case err := <-runErr:
		t.Fatalf("runConnectAll exited unexpectedly: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("consumer never reconnected to the re-registered relay")
	}
	require.Eventually(t, func() bool {
		return connectionHealthCounter.Load() == 2
	}, 10*time.Second, 20*time.Millisecond, "consumer should be back to a session per relay")

	// Tear down synchronously so the health-counter unwinding cannot leak
	// into the next test.
	cancel()
	select {
	case <-runErr:
	case <-time.After(10 * time.Second):
		t.Fatal("runConnectAll did not exit after cancel")
	}
}
