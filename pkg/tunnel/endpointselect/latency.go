package endpointselect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	// DefaultProbeTimeout is the default timeout for each endpoint probe.
	DefaultProbeTimeout = 3 * time.Second
	// DefaultMaxConcurrent is the default maximum number of concurrent probes.
	DefaultMaxConcurrent = 10
	// DefaultPingsPerEndpoint is the default number of ping requests per endpoint.
	DefaultPingsPerEndpoint = 3
)

// Option configures a LatencySelector.
type Option func(*latencyOptions)

type latencyOptions struct {
	probeTimeout     time.Duration
	maxConcurrent    int
	insecureSkip     bool
	pingsPerEndpoint int
}

// WithProbeTimeout sets the timeout for each endpoint probe.
func WithProbeTimeout(timeout time.Duration) Option {
	return func(o *latencyOptions) {
		o.probeTimeout = timeout
	}
}

// WithMaxConcurrent sets the maximum number of concurrent probes.
func WithMaxConcurrent(max int) Option {
	return func(o *latencyOptions) {
		o.maxConcurrent = max
	}
}

// WithInsecureSkipVerify sets whether to skip TLS certificate verification.
func WithInsecureSkipVerify(skip bool) Option {
	return func(o *latencyOptions) {
		o.insecureSkip = skip
	}
}

// WithPingsPerEndpoint sets the number of ping requests per endpoint.
// The latencies are aggregated using a trimmed mean (removing outliers).
func WithPingsPerEndpoint(n int) Option {
	return func(o *latencyOptions) {
		if n < 1 {
			n = 1
		}
		o.pingsPerEndpoint = n
	}
}

// LatencySelector selects endpoints based on QUIC handshake latency.
type LatencySelector struct {
	opts latencyOptions
}

// NewLatencySelector creates a new LatencySelector.
func NewLatencySelector(opts ...Option) *LatencySelector {
	options := latencyOptions{
		probeTimeout:     DefaultProbeTimeout,
		maxConcurrent:    DefaultMaxConcurrent,
		pingsPerEndpoint: DefaultPingsPerEndpoint,
	}
	for _, opt := range opts {
		opt(&options)
	}
	return &LatencySelector{opts: options}
}

// Select returns the endpoint with the lowest latency.
func (s *LatencySelector) Select(ctx context.Context, endpoints []string) (string, error) {
	addr, _, err := s.SelectWithResults(ctx, endpoints)
	return addr, err
}

// SelectWithResults returns the endpoint with the lowest latency along with all probe results.
func (s *LatencySelector) SelectWithResults(ctx context.Context, endpoints []string) (string, []ProbeResult, error) {
	if len(endpoints) == 0 {
		return "", nil, errors.New("no endpoints provided")
	}
	if len(endpoints) == 1 {
		return endpoints[0], []ProbeResult{{
			Addr:     endpoints[0],
			ProbedAt: time.Now(),
		}}, nil
	}

	results := s.probeAll(ctx, endpoints)

	// Sort by latency (errors go to the end).
	sort.Slice(results, func(i, j int) bool {
		// Errors go to the end.
		if results[i].Error != nil && results[j].Error != nil {
			return false
		}
		if results[i].Error != nil {
			return false
		}
		if results[j].Error != nil {
			return true
		}
		return results[i].Latency < results[j].Latency
	})

	// Find the first successful result.
	for _, r := range results {
		if r.Error == nil {
			slog.Info("Selected endpoint based on latency",
				slog.String("addr", r.Addr),
				slog.Duration("latency", r.Latency))
			return r.Addr, results, nil
		}
	}

	// All probes failed - return error with details.
	return "", results, errors.New("all endpoint probes failed")
}

// probeAll probes all endpoints concurrently and returns the results.
func (s *LatencySelector) probeAll(ctx context.Context, endpoints []string) []ProbeResult {
	results := make([]ProbeResult, len(endpoints))
	var wg sync.WaitGroup

	// Semaphore to limit concurrent probes.
	sem := make(chan struct{}, s.opts.maxConcurrent)

	for i, endpoint := range endpoints {
		wg.Add(1)
		go func(idx int, addr string) {
			defer wg.Done()

			// Acquire semaphore.
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[idx] = ProbeResult{
					Addr:     addr,
					Error:    ctx.Err(),
					ProbedAt: time.Now(),
				}
				return
			}

			results[idx] = s.probe(ctx, addr)
		}(i, endpoint)
	}

	wg.Wait()
	return results
}

// dialEndpoint establishes a QUIC connection and creates an HTTP/3 client connection.
// Returns the QUIC connection, HTTP/3 client connection, and any error.
func (s *LatencySelector) dialEndpoint(ctx context.Context, addr string) (quic.Connection, *http3.ClientConn, error) {
	// Extract hostname from address for TLS ServerName.
	serverName := "proxy"
	if host, _, err := net.SplitHostPort(addr); err == nil && net.ParseIP(host) == nil {
		serverName = host
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		NextProtos:         []string{http3.NextProtoH3},
		InsecureSkipVerify: s.opts.insecureSkip,
	}

	quicConfig := &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: 1350,
	}

	// Dial QUIC connection.
	qConn, err := quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, nil, err
	}

	// Create HTTP/3 client connection.
	tr := &http3.Transport{EnableDatagrams: true}
	hConn := tr.NewClientConn(qConn)

	return qConn, hConn, nil
}

// pingSingle performs a single HTTP/3 GET /ping request over an existing connection.
// Returns the round-trip latency or an error.
func (s *LatencySelector) pingSingle(ctx context.Context, hConn *http3.ClientConn) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://proxy/ping", nil)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	resp, err := hConn.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("ping returned status %d", resp.StatusCode)
	}

	return time.Since(start), nil
}

// aggregateLatencies computes the trimmed mean of latencies by discarding
// the highest and lowest values (if there are enough samples) and averaging the rest.
// For 1-2 samples, returns the median. For 3+ samples, discards extremes.
func aggregateLatencies(pings []time.Duration) time.Duration {
	if len(pings) == 0 {
		return 0
	}
	if len(pings) == 1 {
		return pings[0]
	}

	// Sort the pings.
	sorted := make([]time.Duration, len(pings))
	copy(sorted, pings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	if len(sorted) == 2 {
		// Return median (average of two).
		return (sorted[0] + sorted[1]) / 2
	}

	// Discard highest and lowest, average the rest.
	trimmed := sorted[1 : len(sorted)-1]
	var sum time.Duration
	for _, d := range trimmed {
		sum += d
	}
	return sum / time.Duration(len(trimmed))
}

// probe measures the round-trip latency to a single endpoint by making
// multiple HTTP/3 requests to the /ping endpoint and aggregating the results.
func (s *LatencySelector) probe(ctx context.Context, addr string) ProbeResult {
	result := ProbeResult{
		Addr:     addr,
		ProbedAt: time.Now(),
	}

	probeCtx, cancel := context.WithTimeout(ctx, s.opts.probeTimeout)
	defer cancel()

	// Establish connection.
	qConn, hConn, err := s.dialEndpoint(probeCtx, addr)
	if err != nil {
		result.Error = err
		slog.Debug("Endpoint probe failed (QUIC dial)",
			slog.String("addr", addr),
			slog.Any("error", err))
		return result
	}
	defer qConn.CloseWithError(0, "probe complete")

	// Perform multiple pings and collect latencies.
	var pings []time.Duration
	for i := 0; i < s.opts.pingsPerEndpoint; i++ {
		latency, err := s.pingSingle(probeCtx, hConn)
		if err != nil {
			slog.Debug("Endpoint ping failed",
				slog.String("addr", addr),
				slog.Int("ping", i+1),
				slog.Any("error", err))
			// Continue to collect as many pings as possible.
			continue
		}
		pings = append(pings, latency)
		slog.Debug("Endpoint ping succeeded",
			slog.String("addr", addr),
			slog.Int("ping", i+1),
			slog.Duration("latency", latency))
	}

	// If no pings succeeded, return an error.
	if len(pings) == 0 {
		result.Error = fmt.Errorf("all %d pings failed", s.opts.pingsPerEndpoint)
		slog.Debug("Endpoint probe failed (all pings failed)",
			slog.String("addr", addr))
		return result
	}

	// Aggregate latencies using trimmed mean.
	result.Latency = aggregateLatencies(pings)

	slog.Debug("Endpoint probe succeeded",
		slog.String("addr", addr),
		slog.Int("successful_pings", len(pings)),
		slog.Int("total_pings", s.opts.pingsPerEndpoint),
		slog.Duration("aggregated_latency", result.Latency))

	return result
}
