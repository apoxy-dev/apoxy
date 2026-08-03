package agent

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestLatencyTracker pins the sharing contract between the probe loop and
// live sessions: updates merge (a relay missing from one probe round keeps
// its last measurement), and a nil tracker reads as zero so probe-less paths
// need no wiring.
func TestLatencyTracker(t *testing.T) {
	tracker := newLatencyTracker()
	require.Zero(t, tracker.Get("a"), "unknown relay must read as unmeasured")

	tracker.Update(map[string]time.Duration{"a": 10 * time.Millisecond, "b": 20 * time.Millisecond})
	require.Equal(t, 10*time.Millisecond, tracker.Get("a"))

	// A round that only measured "b" must not erase "a".
	tracker.Update(map[string]time.Duration{"b": 25 * time.Millisecond})
	require.Equal(t, 10*time.Millisecond, tracker.Get("a"))
	require.Equal(t, 25*time.Millisecond, tracker.Get("b"))

	var nilTracker *latencyTracker
	require.Zero(t, nilTracker.Get("a"))
	nilTracker.Update(map[string]time.Duration{"a": time.Millisecond}) // must not panic
}

// TestProbeRelays_RanksAndSkipsDraining pins the probe contract: reachable
// relays come back ranked, and a draining relay (503 on /ping) drops out of
// the ranking so future acquisitions steer away from it.
func TestProbeRelays_RanksAndSkipsDraining(t *testing.T) {
	r1, stop1 := startDrainableRelay(t, 3*time.Second, nil, 830, "10.0.0.30/32", nil)
	r2, stop2 := startDrainableRelay(t, 0, nil, 831, "10.0.0.31/32", nil)
	t.Cleanup(stop2)
	addr1, addr2 := r1.Address().String(), r2.Address().String()

	tlsConf := &tls.Config{InsecureSkipVerify: true}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	order, latencies := probeRelaysWithLatency(ctx, tlsConf, []string{addr1, addr2})
	require.ElementsMatch(t, []string{addr1, addr2}, order,
		"both live relays must be ranked")
	require.Positive(t, latencies[addr1])
	require.Positive(t, latencies[addr2])

	// Drain relay 1; its /ping answers 503 through the lame duck, so probes
	// must exclude it while sessions on it are still being carried.
	stopDone := make(chan struct{})
	go func() { stop1(); close(stopDone) }()
	require.Eventually(t, func() bool {
		return len(probeRelays(ctx, tlsConf, []string{addr1, addr2})) == 1
	}, 10*time.Second, 200*time.Millisecond, "draining relay must drop out of the ranking")
	order = probeRelays(ctx, tlsConf, []string{addr1, addr2})
	require.Equal(t, []string{addr2}, order)
	<-stopDone
}
