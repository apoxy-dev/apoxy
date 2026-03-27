package metrics

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// DefaultScrapeInterval is the default interval between agent metric scrapes.
const DefaultScrapeInterval = 15 * time.Second

// DefaultScrapeTimeout is the default HTTP timeout for each scrape request.
const DefaultScrapeTimeout = 5 * time.Second

// DefaultMetricsPort is the well-known port agents expose /metrics on.
const DefaultMetricsPort = 8081

// LabelMetricsPort is the connection label key used to advertise the agent's
// metrics port to the server for overlay scraping.
const LabelMetricsPort = "metrics_port"

// ScrapeTarget describes an agent to scrape metrics from.
type ScrapeTarget struct {
	ConnID      string
	TunnelNode  string
	AgentName   string
	ProjectID   string
	OverlayAddr string // Host part only, e.g. "fd00::abcd:1234".
	MetricsPort int    // Port the agent's metrics server listens on. 0 means use scraper default.
}

// ScrapeResult holds the parsed metric families from a single agent scrape.
type ScrapeResult struct {
	Target    ScrapeTarget
	Families  map[string]*dto.MetricFamily
	ScrapedAt time.Time
}

// AgentScraper manages per-connection scrape goroutines that independently
// poll each agent's /metrics endpoint through the overlay network. Each
// goroutine sends results to a central channel; a single aggregator goroutine
// owns the results map, eliminating concurrent map writes.
type AgentScraper struct {
	resultsMu sync.RWMutex
	results   map[string]*ScrapeResult

	// resultsCh receives scrape results from per-connection goroutines.
	resultsCh chan *ScrapeResult

	// cancels tracks per-connection cancel funcs so Unregister can stop them.
	cancelsMu sync.Mutex
	cancels   map[string]context.CancelFunc

	// ctxMu guards ctx which is set by Start() and read by Register().
	ctxMu sync.Mutex
	ctx   context.Context

	interval time.Duration
	timeout  time.Duration
	port     int
	client   *http.Client
}

// AgentScraperOption configures an AgentScraper.
type AgentScraperOption func(*AgentScraper)

// WithScrapeInterval sets the scrape interval.
func WithScrapeInterval(d time.Duration) AgentScraperOption {
	return func(s *AgentScraper) { s.interval = d }
}

// WithScrapeTimeout sets the per-scrape HTTP timeout.
func WithScrapeTimeout(d time.Duration) AgentScraperOption {
	return func(s *AgentScraper) { s.timeout = d }
}

// WithMetricsPort sets the default port to scrape on each agent.
func WithMetricsPort(port int) AgentScraperOption {
	return func(s *AgentScraper) { s.port = port }
}

// NewAgentScraper creates a new AgentScraper.
func NewAgentScraper(opts ...AgentScraperOption) *AgentScraper {
	s := &AgentScraper{
		results:   make(map[string]*ScrapeResult),
		resultsCh: make(chan *ScrapeResult, 1024),
		cancels:   make(map[string]context.CancelFunc),
		interval:  DefaultScrapeInterval,
		timeout:   DefaultScrapeTimeout,
		port:      DefaultMetricsPort,
	}
	for _, o := range opts {
		o(s)
	}
	s.client = &http.Client{}
	return s
}

// Start runs the aggregator loop that receives scrape results from
// per-connection goroutines and maintains the results map. Blocks until ctx
// is cancelled.
func (s *AgentScraper) Start(ctx context.Context) error {
	s.ctxMu.Lock()
	s.ctx = ctx
	s.ctxMu.Unlock()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result := <-s.resultsCh:
			s.drainAndStore(result)
		}
	}
}

// drainAndStore stores the given result and drains any additional buffered
// results in a single lock acquisition to reduce contention with Collect.
func (s *AgentScraper) drainAndStore(first *ScrapeResult) {
	s.resultsMu.Lock()
	s.results[first.Target.ConnID] = first
	for {
		select {
		case r := <-s.resultsCh:
			s.results[r.Target.ConnID] = r
		default:
			s.resultsMu.Unlock()
			return
		}
	}
}

// Register adds a scrape target and spawns a dedicated goroutine that
// periodically scrapes metrics from the agent.
func (s *AgentScraper) Register(target ScrapeTarget) {
	slog.Info("Registering agent for metrics scraping",
		slog.String("conn_id", target.ConnID),
		slog.String("tunnel_node", target.TunnelNode),
		slog.String("overlay_addr", target.OverlayAddr),
		slog.Int("metrics_port", target.MetricsPort),
	)

	s.cancelsMu.Lock()
	if cancel, ok := s.cancels[target.ConnID]; ok {
		cancel()
	}
	s.ctxMu.Lock()
	parentCtx := s.ctx
	s.ctxMu.Unlock()
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithCancel(parentCtx)
	s.cancels[target.ConnID] = cancel
	s.cancelsMu.Unlock()

	go s.scrapeLoop(ctx, target)
}

// Unregister stops the scrape goroutine for the given connection and removes
// its cached result.
func (s *AgentScraper) Unregister(connID string) {
	slog.Info("Unregistering agent from metrics scraping", slog.String("conn_id", connID))

	s.cancelsMu.Lock()
	if cancel, ok := s.cancels[connID]; ok {
		cancel()
		delete(s.cancels, connID)
	}
	s.cancelsMu.Unlock()

	s.resultsMu.Lock()
	delete(s.results, connID)
	s.resultsMu.Unlock()
}

// Results returns a snapshot of all current scrape results.
func (s *AgentScraper) Results() map[string]*ScrapeResult {
	s.resultsMu.RLock()
	defer s.resultsMu.RUnlock()
	out := make(map[string]*ScrapeResult, len(s.results))
	for k, v := range s.results {
		out[k] = v
	}
	return out
}

// ForEachResult iterates over a snapshot of scrape results. The snapshot is
// taken under a read lock, but the callback runs without holding any lock.
func (s *AgentScraper) ForEachResult(fn func(connID string, result *ScrapeResult) bool) {
	snap := s.Results()
	for k, v := range snap {
		if !fn(k, v) {
			return
		}
	}
}

// ScrapeOnce performs a synchronous scrape of all registered connections.
// Intended for testing — in production each connection has its own loop.
func (s *AgentScraper) ScrapeOnce(ctx context.Context) {
	s.resultsMu.RLock()
	targets := make([]ScrapeTarget, 0, len(s.results))
	for _, r := range s.results {
		targets = append(targets, r.Target)
	}
	s.resultsMu.RUnlock()

	for _, target := range targets {
		result, err := s.scrapeOne(ctx, &target)
		if err != nil {
			continue
		}
		s.resultsMu.Lock()
		s.results[target.ConnID] = result
		s.resultsMu.Unlock()
	}
}

// scrapeLoop runs in its own goroutine per connection. It immediately performs
// an initial scrape, then ticks at the configured interval.
func (s *AgentScraper) scrapeLoop(ctx context.Context, target ScrapeTarget) {
	log := slog.With(
		slog.String("conn_id", target.ConnID),
		slog.String("tunnel_node", target.TunnelNode),
		slog.String("overlay_addr", target.OverlayAddr),
	)

	s.doScrape(ctx, log, target)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.doScrape(ctx, log, target)
		}
	}
}

func (s *AgentScraper) doScrape(ctx context.Context, log *slog.Logger, target ScrapeTarget) {
	if target.OverlayAddr == "" {
		return
	}
	result, err := s.scrapeOne(ctx, &target)
	if err != nil {
		log.Warn("Failed to scrape agent metrics", slog.Any("error", err))
		return
	}
	select {
	case s.resultsCh <- result:
	default:
		log.Debug("Results channel full, dropping scrape result")
	}
}

func (s *AgentScraper) scrapeOne(ctx context.Context, target *ScrapeTarget) (*ScrapeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	port := s.port
	if target.MetricsPort > 0 {
		port = target.MetricsPort
	}
	url := fmt.Sprintf("http://[%s]:%d/metrics", target.OverlayAddr, port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP GET %s: status %d", url, resp.StatusCode)
	}

	families := make(map[string]*dto.MetricFamily)
	dec := expfmt.NewDecoder(resp.Body, expfmt.NewFormat(expfmt.TypeTextPlain))
	for {
		var mf dto.MetricFamily
		if err := dec.Decode(&mf); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("parsing metrics: %w", err)
		}
		families[mf.GetName()] = &mf
	}

	return &ScrapeResult{
		Target:    *target,
		Families:  families,
		ScrapedAt: time.Now(),
	}, nil
}
