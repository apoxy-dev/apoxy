package agent

import (
	"context"
	"crypto/tls"
	"log/slog"
	"sort"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/endpointselect"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/randalloc"
)

// latencyTracker shares relay latency measurements between the periodic probe
// loop (writer) and live sessions (readers), so a session's status snapshots
// track the freshest probe instead of freezing the acquire-time value.
type latencyTracker struct {
	mu        sync.Mutex
	latencies map[string]time.Duration
}

func newLatencyTracker() *latencyTracker {
	return &latencyTracker{latencies: make(map[string]time.Duration)}
}

// Update merges the given measurements. Relays absent from the map keep their
// previous value: a failed probe is not evidence the relay got slower.
func (t *latencyTracker) Update(latencies map[string]time.Duration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for addr, latency := range latencies {
		t.latencies[addr] = latency
	}
}

// Get returns the last measurement for addr, or 0 when unknown. Nil-safe so
// paths without probing (static single relay, consumer mode) can skip the
// tracker entirely.
func (t *latencyTracker) Get(addr string) time.Duration {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.latencies[addr]
}

// relayProbeInterval is how often the agent re-probes relay latency to keep
// the pool's preference order current. Deliberately slow: the ranking only
// influences FUTURE acquisitions (a healthy session is never migrated), so
// staleness costs at most a suboptimal pick on the next rotation.
var relayProbeInterval = 5 * time.Minute

// probeRelays measures latency to each candidate relay over its H3 /ping
// endpoint and returns the addresses ordered best-first. Unreachable relays
// (including draining ones, which answer 503) are omitted — the allocator
// treats unranked items as last-resort fallbacks rather than excluding them,
// so a probe blip cannot empty the pool.
func probeRelays(ctx context.Context, tlsConf *tls.Config, addrs []string) []string {
	order, _ := probeRelaysWithLatency(ctx, tlsConf, addrs)
	return order
}

// probeRelaysWithLatency is probeRelays plus the successful measurement for
// each ranked address. The command UI uses the measurements while the
// allocator consumes only the order.
func probeRelaysWithLatency(ctx context.Context, tlsConf *tls.Config, addrs []string) ([]string, map[string]time.Duration) {
	sel := endpointselect.NewLatencySelector(
		endpointselect.WithInsecureSkipVerify(tlsConf != nil && tlsConf.InsecureSkipVerify),
	)
	_, results, err := sel.SelectWithResults(ctx, addrs)
	if err != nil {
		slog.Warn("Relay latency probe failed; keeping current preference", slog.Any("error", err))
		return nil, nil
	}
	ok := results[:0]
	for _, res := range results {
		if res.Error == nil {
			ok = append(ok, res)
		}
	}
	sort.Slice(ok, func(i, j int) bool { return ok[i].Latency < ok[j].Latency })
	order := make([]string, 0, len(ok))
	latencies := make(map[string]time.Duration, len(ok))
	for _, res := range ok {
		order = append(order, res.Addr)
		latencies[res.Addr] = res.Latency
	}
	return order, latencies
}

// probeRelayPreference keeps the pool's preference order current: one probe
// every relayProbeInterval over the current candidate set (re-listed when
// discovery is configured). The initial probe is the caller's job (Run does
// it synchronously before spawning slots). Fresh measurements also flow into
// the shared tracker so live sessions report current latency. Errors are
// non-fatal — the pool just stays randomly ordered.
func probeRelayPreference(
	ctx context.Context,
	cfg Config,
	pool *randalloc.RandAllocator[string],
	tlsConf *tls.Config,
	static sets.Set[string],
	tracker *latencyTracker,
) error {
	probe := func() {
		addrs := static
		if cfg.RelayLister != nil {
			listCtx, cancel := context.WithTimeout(ctx, relayRefreshInterval)
			listed, err := cfg.RelayLister(listCtx)
			cancel()
			if err == nil && listed.Len() > 0 {
				addrs = listed
			}
		}
		if addrs.Len() <= 1 {
			return
		}
		if order, latencies := probeRelaysWithLatency(ctx, tlsConf, addrs.UnsortedList()); len(order) > 0 {
			slog.Debug("Updating relay preference order", slog.Any("order", order))
			pool.SetPreference(order)
			tracker.Update(latencies)
		}
	}

	ticker := time.NewTicker(relayProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			probe()
		}
	}
}
