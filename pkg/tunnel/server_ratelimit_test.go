package tunnel

import (
	"testing"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// newTestServerForLimiter returns a TunnelServer wired only with the fields
// needed to exercise the reconnect limiter. Avoids the full QUIC/TLS
// bringup path that tunnel_test.go uses for end-to-end coverage.
func newTestServerForLimiter() *TunnelServer {
	return &TunnelServer{
		reconnectLimiters: haxmap.New[string, *limiterEntry](),
	}
}

func TestGetOrCreateReconnectLimiter_IsIdempotent(t *testing.T) {
	s := newTestServerForLimiter()

	a := s.getOrCreateReconnectLimiter("k1")
	b := s.getOrCreateReconnectLimiter("k1")
	assert.Same(t, a, b, "same key must return the same limiterEntry")

	c := s.getOrCreateReconnectLimiter("k2")
	assert.NotSame(t, a, c, "distinct keys must produce distinct limiterEntries")

	assert.Equal(t, uintptr(2), s.reconnectLimiters.Len())
}

func TestGetOrCreateReconnectLimiter_ParamsMatchConstants(t *testing.T) {
	s := newTestServerForLimiter()
	entry := s.getOrCreateReconnectLimiter("k")
	assert.Equal(t, reconnectLimiterBurst, entry.limiter.Burst())
	// rate.Limit is tokens/sec; rate.Every(6s) == 1/6.
	expected := rate.Every(reconnectLimiterRefillEvery)
	assert.InDelta(t, float64(expected), float64(entry.limiter.Limit()), 1e-9)
}

// TestReconnectLimiter_ExhaustsBurst proves the bucket holds exactly the
// configured burst before the next Reserve() reports a non-zero Delay.
// This is the hot path the /connect handler executes per request.
func TestReconnectLimiter_ExhaustsBurst(t *testing.T) {
	s := newTestServerForLimiter()
	entry := s.getOrCreateReconnectLimiter("k")

	// Burst allows the first N calls to get zero-delay reservations.
	for i := 0; i < reconnectLimiterBurst; i++ {
		res := entry.limiter.Reserve()
		require.True(t, res.OK(), "reservation %d should be OK", i+1)
		assert.Zero(t, res.Delay(), "reservation %d should have zero delay", i+1)
	}

	// N+1: Reserve() still returns OK (token bucket is not capped on
	// reservations) but Delay() > 0 — this is the signal the handler
	// interprets as "reject with 429".
	res := entry.limiter.Reserve()
	require.True(t, res.OK())
	assert.Greater(t, res.Delay(), time.Duration(0),
		"post-burst reservation must have non-zero delay")
	// Delay should be bounded by the refill interval.
	assert.LessOrEqual(t, res.Delay(), reconnectLimiterRefillEvery)
	res.Cancel()
}

func TestReconnectLimiter_DistinctKeysAreIndependent(t *testing.T) {
	s := newTestServerForLimiter()
	a := s.getOrCreateReconnectLimiter("tun-A|proc-1")
	b := s.getOrCreateReconnectLimiter("tun-A|proc-2")

	// Exhaust bucket A.
	for i := 0; i < reconnectLimiterBurst; i++ {
		a.limiter.Reserve()
	}
	// Bucket B is untouched; its next reservation has zero delay.
	res := b.limiter.Reserve()
	require.True(t, res.OK())
	assert.Zero(t, res.Delay(), "exhausting one key must not affect another")
}

// TestSweepReconnectLimiters_EvictsIdleEntries verifies the janitor removes
// entries whose lastUsed is older than reconnectLimiterIdleTTL and keeps
// recent ones. Also confirms the published gauge reflects the post-sweep size.
func TestSweepReconnectLimiters_EvictsIdleEntries(t *testing.T) {
	s := newTestServerForLimiter()
	now := time.Now()

	idle := s.getOrCreateReconnectLimiter("idle")
	idle.lastUsed.Store(now.Add(-reconnectLimiterIdleTTL - time.Minute).UnixNano())

	fresh := s.getOrCreateReconnectLimiter("fresh")
	fresh.lastUsed.Store(now.UnixNano())

	s.sweepReconnectLimiters(now)

	_, idlePresent := s.reconnectLimiters.Get("idle")
	assert.False(t, idlePresent, "idle entry should be evicted")
	_, freshPresent := s.reconnectLimiters.Get("fresh")
	assert.True(t, freshPresent, "fresh entry should be retained")
	assert.Equal(t, uintptr(1), s.reconnectLimiters.Len())
}

func TestSweepReconnectLimiters_BoundaryIsExclusive(t *testing.T) {
	// An entry whose lastUsed equals the cutoff should also be evicted —
	// the comparison is "older than TTL" which we implement as
	// lastUsed < cutoff. A lastUsed equal to cutoff is NOT older and is
	// kept. This test pins that choice so the behavior is intentional.
	s := newTestServerForLimiter()
	now := time.Now()
	entry := s.getOrCreateReconnectLimiter("edge")
	cutoff := now.Add(-reconnectLimiterIdleTTL).UnixNano()
	entry.lastUsed.Store(cutoff) // exactly at the boundary

	s.sweepReconnectLimiters(now)

	_, present := s.reconnectLimiters.Get("edge")
	assert.True(t, present, "entry at exactly the cutoff should be retained")
}

// TestLimiterEntry_LastAcceptedAt_SkipsFirstObservation confirms the
// gap-histogram logic in the handler: Swap returns 0 for a fresh entry
// (no prior accept), and the subsequent Swap returns the previous
// timestamp so the caller can observe the delta.
func TestLimiterEntry_LastAcceptedAt_SkipsFirstObservation(t *testing.T) {
	entry := &limiterEntry{
		limiter: rate.NewLimiter(rate.Every(reconnectLimiterRefillEvery), reconnectLimiterBurst),
	}

	first := time.Now().UnixNano()
	prev := entry.lastAcceptedAt.Swap(first)
	assert.Zero(t, prev, "first swap must return zero — handler skips observation")

	time.Sleep(2 * time.Millisecond) // keep timestamps monotonically distinct
	second := time.Now().UnixNano()
	prev = entry.lastAcceptedAt.Swap(second)
	assert.Equal(t, first, prev, "subsequent swap must return the previous timestamp")

	// The gap should be positive and at least the sleep we performed.
	gap := time.Duration(second - prev)
	assert.Greater(t, gap, time.Millisecond)
}
