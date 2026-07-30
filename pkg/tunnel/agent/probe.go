package agent

import (
	"context"
	"crypto/tls"
	"log/slog"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/endpointselect"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/randalloc"
)

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
	sel := endpointselect.NewLatencySelector(
		endpointselect.WithInsecureSkipVerify(tlsConf != nil && tlsConf.InsecureSkipVerify),
	)
	_, results, err := sel.SelectWithResults(ctx, addrs)
	if err != nil {
		slog.Warn("Relay latency probe failed; keeping current preference", slog.Any("error", err))
		return nil
	}
	ok := results[:0]
	for _, res := range results {
		if res.Error == nil {
			ok = append(ok, res)
		}
	}
	sort.Slice(ok, func(i, j int) bool { return ok[i].Latency < ok[j].Latency })
	order := make([]string, 0, len(ok))
	for _, res := range ok {
		order = append(order, res.Addr)
	}
	return order
}

// probeRelayPreference keeps the pool's preference order current: one probe
// every relayProbeInterval over the current candidate set (re-listed when
// discovery is configured). The initial probe is the caller's job (Run does
// it synchronously before spawning slots). Errors are non-fatal — the pool
// just stays randomly ordered.
func probeRelayPreference(
	ctx context.Context,
	cfg Config,
	pool *randalloc.RandAllocator[string],
	tlsConf *tls.Config,
	static sets.Set[string],
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
		if order := probeRelays(ctx, tlsConf, addrs.UnsortedList()); len(order) > 0 {
			slog.Debug("Updating relay preference order", slog.Any("order", order))
			pool.SetPreference(order)
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
