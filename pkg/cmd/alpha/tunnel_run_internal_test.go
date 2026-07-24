package alpha

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/randalloc"
)

func relaySet(items ...string) sets.Set[string] { return sets.New[string](items...) }

// acquireOnce Acquires from the pool with a short deadline, releases immediately,
// and reports what it got. Used to observe pool membership without blocking a
// test forever if the pool is unexpectedly empty.
func acquireOnce(t *testing.T, pool *randalloc.RandAllocator[string]) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got, err := pool.Acquire(ctx)
	if err != nil {
		return "", false
	}
	pool.Release(got)
	return got, true
}

func TestRefreshRelayPool(t *testing.T) {
	t.Run("replaces pool membership on tick", func(t *testing.T) {
		pool := randalloc.NewRandAllocator(relaySet("a"))
		lister := func(context.Context) (sets.Set[string], error) { return relaySet("b", "c"), nil }

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errCh := make(chan error, 1)
		go func() { errCh <- refreshRelayPool(ctx, lister, pool, 5*time.Millisecond) }()

		// Once a tick has fired, the pool holds only {b,c} and never hands out "a".
		require.Eventually(t, func() bool {
			got, ok := acquireOnce(t, pool)
			return ok && (got == "b" || got == "c")
		}, 2*time.Second, 5*time.Millisecond)

		cancel()
		require.ErrorIs(t, <-errCh, context.Canceled)
	})

	t.Run("keeps current pool when the lister errors", func(t *testing.T) {
		pool := randalloc.NewRandAllocator(relaySet("a"))
		lister := func(context.Context) (sets.Set[string], error) { return nil, errors.New("apiserver down") }

		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		require.ErrorIs(t, refreshRelayPool(ctx, lister, pool, 5*time.Millisecond), context.DeadlineExceeded)

		got, ok := acquireOnce(t, pool)
		require.True(t, ok)
		require.Equal(t, "a", got, "a transient lister error must not strand the agent")
	})

	t.Run("keeps current pool when the refresh is empty", func(t *testing.T) {
		pool := randalloc.NewRandAllocator(relaySet("a"))
		lister := func(context.Context) (sets.Set[string], error) { return relaySet(), nil }

		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		require.ErrorIs(t, refreshRelayPool(ctx, lister, pool, 5*time.Millisecond), context.DeadlineExceeded)

		got, ok := acquireOnce(t, pool)
		require.True(t, ok)
		require.Equal(t, "a", got, "an empty relay list must not empty the pool")
	})

	t.Run("returns promptly on context cancel", func(t *testing.T) {
		pool := randalloc.NewRandAllocator(relaySet("a"))
		lister := func(context.Context) (sets.Set[string], error) { return relaySet("b"), nil }

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		require.ErrorIs(t, refreshRelayPool(ctx, lister, pool, time.Hour), context.Canceled)
	})
}

// newTestHandler builds a standalone icx.Handler suitable for VNI bookkeeping
// tests (AddVirtualNetwork / GetVirtualNetwork / RX stats). It drives no real
// traffic.
func newTestHandler(t *testing.T) *icx.Handler {
	t.Helper()
	h, err := icx.NewHandler(
		icx.WithLocalAddr(netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()),
	)
	require.NoError(t, err)
	return h
}

func TestRelayWatchdog(t *testing.T) {
	const vni = uint(4242)
	remote := netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:7000"))

	withVNI := func(t *testing.T) *icx.Handler {
		t.Helper()
		h := newTestHandler(t)
		require.NoError(t, h.AddVirtualNetwork(vni, remote, nil))
		return h
	}

	t.Run("trips on RX silence past maxSilence", func(t *testing.T) {
		h := withVNI(t)
		vnet, ok := h.GetVirtualNetwork(vni)
		require.True(t, ok)
		vnet.Stats.LastRXUnixNano.Store(time.Now().Add(-time.Hour).UnixNano())

		err := relayWatchdog(context.Background(), h, vni, 20*time.Millisecond, 5*time.Millisecond)
		require.Error(t, err)
		require.Contains(t, err.Error(), "rx silence")
	})

	t.Run("fresh session (never received) survives until context ends", func(t *testing.T) {
		h := withVNI(t)
		// LastRXUnixNano stays 0 → "never received" is treated as connect time, so
		// the watchdog must not trip before maxSilence actually elapses.
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		err := relayWatchdog(ctx, h, vni, time.Hour, 5*time.Millisecond)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("returns when the VNI disappears", func(t *testing.T) {
		h := withVNI(t)
		require.NoError(t, h.RemoveVirtualNetwork(vni))
		err := relayWatchdog(context.Background(), h, vni, time.Hour, 5*time.Millisecond)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no longer present")
	})
}

func TestParsePrefixes(t *testing.T) {
	t.Run("parses a mixed v4/v6 list", func(t *testing.T) {
		got, err := parsePrefixes([]string{"10.0.0.1/32", "fd00::1/128"})
		require.NoError(t, err)
		require.Len(t, got, 2)
		require.Equal(t, "10.0.0.1/32", got[0].String())
		require.Equal(t, "fd00::1/128", got[1].String())
	})

	t.Run("rejects a garbage entry", func(t *testing.T) {
		_, err := parsePrefixes([]string{"10.0.0.1/32", "not-a-cidr"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not-a-cidr")
	})

	t.Run("empty input yields no prefixes", func(t *testing.T) {
		got, err := parsePrefixes(nil)
		require.NoError(t, err)
		require.Empty(t, got)
	})
}

// TestTunnelRunValidation drives RunE directly with the package flag globals set
// so the up-front validation (which returns before any network I/O) is covered
// without cobra reparsing or contaminating other tests. Globals are restored.
func TestTunnelRunValidation(t *testing.T) {
	origMin, origRoutes, origSeed, origTok := minConns, advertisedRoutes, seedRelayAddr, token
	t.Cleanup(func() {
		minConns, advertisedRoutes, seedRelayAddr, token = origMin, origRoutes, origSeed, origTok
	})

	t.Run("rejects --min-conns below 1", func(t *testing.T) {
		// Seed relay+token set so a passing validation would never reach discovery.
		minConns, advertisedRoutes = 0, nil
		seedRelayAddr, token = "127.0.0.1:6081", "tok"
		err := tunnelRunCmd.RunE(tunnelRunCmd, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "min-conns")
	})

	t.Run("rejects an invalid --route CIDR up front", func(t *testing.T) {
		minConns, advertisedRoutes = 1, []string{"10.0.0.0/24", "not-a-cidr"}
		seedRelayAddr, token = "127.0.0.1:6081", "tok"
		err := tunnelRunCmd.RunE(tunnelRunCmd, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid --route")
		require.Contains(t, err.Error(), "not-a-cidr")
	})
}

func TestHealthHandler(t *testing.T) {
	orig := connectionHealthCounter.Load()
	t.Cleanup(func() { connectionHealthCounter.Store(orig) })

	cases := []struct {
		name       string
		active     int32
		wantStatus int
		wantBody   string
	}{
		{name: "no active connections is unhealthy", active: 0, wantStatus: http.StatusServiceUnavailable, wantBody: "UNHEALTHY"},
		{name: "one active connection is healthy", active: 1, wantStatus: http.StatusOK, wantBody: "1 active"},
		{name: "multiple active connections are healthy", active: 3, wantStatus: http.StatusOK, wantBody: "3 active"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			connectionHealthCounter.Store(tc.active)
			rec := httptest.NewRecorder()
			healthHandler(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
			require.Equal(t, tc.wantStatus, rec.Code)
			require.Contains(t, rec.Body.String(), tc.wantBody)
		})
	}
}
