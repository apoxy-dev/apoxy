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
)

// Option configures a LatencySelector.
type Option func(*latencyOptions)

type latencyOptions struct {
	probeTimeout  time.Duration
	maxConcurrent int
	insecureSkip  bool
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

// LatencySelector selects endpoints based on QUIC handshake latency.
type LatencySelector struct {
	opts latencyOptions
}

// NewLatencySelector creates a new LatencySelector.
func NewLatencySelector(opts ...Option) *LatencySelector {
	options := latencyOptions{
		probeTimeout:  DefaultProbeTimeout,
		maxConcurrent: DefaultMaxConcurrent,
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

// probe measures the round-trip latency to a single endpoint by making
// an HTTP/3 request to the /ping endpoint.
func (s *LatencySelector) probe(ctx context.Context, addr string) ProbeResult {
	result := ProbeResult{
		Addr:     addr,
		ProbedAt: time.Now(),
	}

	probeCtx, cancel := context.WithTimeout(ctx, s.opts.probeTimeout)
	defer cancel()

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

	start := time.Now()

	// Dial QUIC connection.
	qConn, err := quic.DialAddr(probeCtx, addr, tlsConfig, quicConfig)
	if err != nil {
		result.Error = err
		slog.Debug("Endpoint probe failed (QUIC dial)",
			slog.String("addr", addr),
			slog.Any("error", err))
		return result
	}
	defer qConn.CloseWithError(0, "probe complete")

	// Make HTTP/3 request to /ping endpoint.
	tr := &http3.Transport{EnableDatagrams: true}
	hConn := tr.NewClientConn(qConn)

	req, err := http.NewRequestWithContext(probeCtx, "GET", "https://proxy/ping", nil)
	if err != nil {
		result.Error = err
		slog.Debug("Endpoint probe failed (request creation)",
			slog.String("addr", addr),
			slog.Any("error", err))
		return result
	}

	resp, err := hConn.RoundTrip(req)
	if err != nil {
		result.Error = err
		slog.Debug("Endpoint probe failed (HTTP/3 request)",
			slog.String("addr", addr),
			slog.Any("error", err))
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Errorf("ping returned status %d", resp.StatusCode)
		slog.Debug("Endpoint probe failed (bad status)",
			slog.String("addr", addr),
			slog.Int("status", resp.StatusCode))
		return result
	}

	result.Latency = time.Since(start)

	slog.Debug("Endpoint probe succeeded",
		slog.String("addr", addr),
		slog.Duration("latency", result.Latency))

	return result
}
