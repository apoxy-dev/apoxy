package metrics

import (
	"context"
	"log/slog"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
)

// StoreTarget describes an agent whose metrics are stored.
type StoreTarget struct {
	ConnID     string
	TunnelNode string
	AgentName  string
	ProjectID  string
}

// StoreResult holds the parsed metric families from a single agent push.
type StoreResult struct {
	Target   StoreTarget
	Families map[string]*dto.MetricFamily
	PushedAt time.Time
}

// MetricsStore accepts pushed metrics from tunnel agents and makes them
// available for re-export via Prometheus. It replaces the old pull-based
// AgentScraper: instead of scraping agents over the overlay network, agents
// POST their metrics to the tunnelproxy over the existing HTTP/3 connection.
type MetricsStore struct {
	resultsMu sync.RWMutex
	results   map[string]*StoreResult
}

// NewMetricsStore creates a new MetricsStore.
func NewMetricsStore() *MetricsStore {
	return &MetricsStore{
		results: make(map[string]*StoreResult),
	}
}

// Start blocks until ctx is cancelled. It exists for compatibility with
// callers that run the store in an errgroup alongside other long-running
// goroutines.
func (s *MetricsStore) Start(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// Register records a new agent connection. Metadata from the target is
// attached to every metric when re-exported. The result starts with empty
// Families until the first push arrives.
func (s *MetricsStore) Register(target StoreTarget) {
	slog.Info("Registering agent for metrics push",
		slog.String("conn_id", target.ConnID),
		slog.String("tunnel_node", target.TunnelNode),
	)

	s.resultsMu.Lock()
	defer s.resultsMu.Unlock()

	s.results[target.ConnID] = &StoreResult{
		Target:   target,
		Families: make(map[string]*dto.MetricFamily),
	}
}

// Unregister removes an agent connection and its cached metrics.
func (s *MetricsStore) Unregister(connID string) {
	slog.Info("Unregistering agent from metrics store", slog.String("conn_id", connID))

	s.resultsMu.Lock()
	defer s.resultsMu.Unlock()

	delete(s.results, connID)
}

// Push stores a new set of metric families for the given connection,
// replacing any previously pushed data. Unknown connection IDs are silently
// ignored (the push may arrive between Unregister and the next push tick).
func (s *MetricsStore) Push(connID string, families map[string]*dto.MetricFamily) {
	s.resultsMu.Lock()
	defer s.resultsMu.Unlock()

	result, ok := s.results[connID]
	if !ok {
		return
	}
	result.Families = families
	result.PushedAt = time.Now()
}

// Results returns a snapshot of all current results.
func (s *MetricsStore) Results() map[string]*StoreResult {
	s.resultsMu.RLock()
	defer s.resultsMu.RUnlock()

	out := make(map[string]*StoreResult, len(s.results))
	for k, v := range s.results {
		out[k] = v
	}
	return out
}

// ForEachResult iterates over results under a read lock. The callback must
// not call other MetricsStore methods (deadlock). Keep callbacks short.
func (s *MetricsStore) ForEachResult(fn func(connID string, result *StoreResult) bool) {
	s.resultsMu.RLock()
	defer s.resultsMu.RUnlock()

	for k, v := range s.results {
		if !fn(k, v) {
			return
		}
	}
}
