package envoy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// samplerIntervals are the timings of the admin sampler.
type samplerIntervals struct {
	// Sample is how often the runtime reads the admin stats.
	Sample time.Duration
	// CacheRetry is how often the runtime reads the DNS cache limits until it
	// finds a cache.
	CacheRetry time.Duration
	// CacheSettleTime is how long the runtime retries before it falls back to
	// the slow refresh, also when it finds no cache.
	CacheSettleTime time.Duration
	// CacheRefresh is how often the runtime reads the DNS cache limits after
	// they settled.
	CacheRefresh time.Duration
}

// defaultSamplerIntervals returns the timings the backplane runs with. The
// dynamic forward proxy clusters arrive over xDS seconds after Envoy starts,
// so the first reads of the DNS cache limits are close together.
func defaultSamplerIntervals() samplerIntervals {
	return samplerIntervals{
		Sample:          5 * time.Second,
		CacheRetry:      5 * time.Second,
		CacheSettleTime: 60 * time.Second,
		CacheRefresh:    60 * time.Second,
	}
}

const (
	// adminRequestTimeout bounds one read of the Envoy admin interface.
	adminRequestTimeout = 3 * time.Second

	// adminStatsFilter selects the stats the sampler reads. Envoy matches the
	// filter against the name of every stat.
	adminStatsFilter = `^(server\.total_connections|http\..*\.downstream_(rq|cx)_active)$`
)

// adminSample is one read of the Envoy admin stats. The admin interface is
// gone once the process exits, so the exit record keeps the last sample.
type adminSample struct {
	// At is when the sample was taken.
	At time.Time
	// TotalConnections is server.total_connections.
	TotalConnections int64
	// RequestsInFlight is the sum of the active downstream requests of every
	// HTTP connection manager.
	RequestsInFlight int64
	// Connections is the sum of the active downstream connections of every
	// HTTP connection manager.
	Connections int64
}

// startSampler reads the Envoy admin stats until the returned function is
// called. That function waits for the sampler to return, so that a sample of
// the old process never lands in the record of the next one.
func (r *Runtime) startSampler(ctx context.Context) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.sampleLoop(ctx)
	}()

	return func() {
		cancel()
		<-done
	}
}

// sampleLoop reads the Envoy admin stats until ctx ends. The caller ends ctx
// when the Envoy process exits.
func (r *Runtime) sampleLoop(ctx context.Context) {
	if r.adminHost == "" {
		return
	}

	iv := r.tel.samplerIntervals()
	client := &http.Client{Timeout: adminRequestTimeout}
	stats := time.NewTicker(iv.Sample)
	defer stats.Stop()
	caches := time.NewTicker(iv.CacheRetry)
	defer caches.Stop()

	r.sampleOnce(ctx, client)

	startedAt := time.Now()
	settled := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-stats.C:
			r.sampleOnce(ctx, client)
		case <-caches.C:
			found := r.refreshDNSCacheLimits(ctx, client)
			// The caches arrive over xDS after the process starts. Read them
			// often until one shows up, then slow down.
			if !settled && (found || time.Since(startedAt) >= iv.CacheSettleTime) {
				settled = true
				caches.Reset(iv.CacheRefresh)
			}
		}
	}
}

// sampleOnce reads the admin stats and the kernel TCP counters, and stores
// both. The counters are kept also when the admin interface does not answer,
// because the exit record counts the connections from the last read.
func (r *Runtime) sampleOnce(ctx context.Context, client *http.Client) {
	var tcp *tcpCounters
	if _, nr := systemReaders(); nr != nil {
		if c, err := nr.TCPCounters(); err == nil {
			tcp = &c
		}
	}

	s, err := r.readAdminStats(ctx, client)
	if err != nil {
		r.tel.adminScrapeErrors.Add(1)
		slog.Debug("Failed to read the Envoy admin stats", "error", err)
	}

	if !r.tel.storeSample(tcp, s) {
		return
	}

	version, err := r.readEnvoyVersion(ctx, client)
	if err != nil {
		slog.Debug("Failed to read the Envoy version", "error", err)
		return
	}
	r.tel.setEnvoyVersion(version)
}

// readAdminStats reads every stat the sampler needs in one request.
func (r *Runtime) readAdminStats(ctx context.Context, client *http.Client) (*adminSample, error) {
	q := url.Values{}
	q.Set("format", "json")
	q.Set("filter", adminStatsFilter)
	body, err := r.getAdmin(ctx, client, "/stats?"+q.Encode())
	if err != nil {
		return nil, err
	}

	var payload struct {
		Stats []struct {
			Name  string `json:"name"`
			Value int64  `json:"value"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("failed to decode the admin stats: %w", err)
	}

	s := &adminSample{At: time.Now().UTC()}
	for _, stat := range payload.Stats {
		switch {
		case stat.Name == "server.total_connections":
			s.TotalConnections = stat.Value
		case strings.HasSuffix(stat.Name, ".downstream_rq_active"):
			s.RequestsInFlight += stat.Value
		case strings.HasSuffix(stat.Name, ".downstream_cx_active"):
			s.Connections += stat.Value
		}
	}

	return s, nil
}

// readEnvoyVersion reads the Envoy version from the admin interface.
func (r *Runtime) readEnvoyVersion(ctx context.Context, client *http.Client) (string, error) {
	body, err := r.getAdmin(ctx, client, "/server_info")
	if err != nil {
		return "", err
	}

	var payload struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("failed to decode the server info: %w", err)
	}

	return envoyVersionFromServerInfo(payload.Version), nil
}

// envoyVersionFromServerInfo reads the release out of the version string the
// admin interface reports, for example "<hash>/1.35.13/Clean/RELEASE/BoringSSL".
func envoyVersionFromServerInfo(version string) string {
	parts := strings.Split(version, "/")
	if len(parts) >= 2 && parts[1] != "" {
		return parts[1]
	}

	return version
}

// refreshDNSCacheLimits reads the configured host limit of every dynamic
// forward proxy DNS cache. The read is best effort. It reports whether the
// dump holds at least one cache.
func (r *Runtime) refreshDNSCacheLimits(ctx context.Context, client *http.Client) bool {
	body, err := r.getAdmin(ctx, client, "/config_dump?resource=dynamic_active_clusters")
	if err != nil {
		slog.Debug("Failed to read the Envoy config dump", "error", err)
		return false
	}

	var dump any
	if err := json.Unmarshal(body, &dump); err != nil {
		slog.Debug("Failed to decode the Envoy config dump", "error", err)
		return false
	}

	limits := make(map[string]uint64)
	collectDNSCacheLimits(dump, limits)

	r.tel.setDNSCacheLimits(limits)

	return len(limits) > 0
}

// sanitizeStatName writes a name the way Envoy writes it inside a stat name.
// Envoy replaces every character outside [A-Za-z0-9_] with an underscore, so a
// Backend named "dynamic-proxy" appears as "dynamic_proxy".
func sanitizeStatName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			return r
		default:
			return '_'
		}
	}, name)
}

// collectDNSCacheLimits walks the config dump and reads the host limit of
// every dns_cache_config it finds. The cache is keyed the way Envoy names it
// in its own stats, so that the limit joins with envoy_dns_cache_<name>_*.
func collectDNSCacheLimits(node any, out map[string]uint64) {
	switch v := node.(type) {
	case map[string]any:
		if cfg, ok := v["dns_cache_config"].(map[string]any); ok {
			name, _ := cfg["name"].(string)
			if hosts, ok := jsonUint(cfg["max_hosts"]); ok && name != "" {
				out[sanitizeStatName(name)] = hosts
			}
		}
		for _, child := range v {
			collectDNSCacheLimits(child, out)
		}
	case []any:
		for _, child := range v {
			collectDNSCacheLimits(child, out)
		}
	}
}

// jsonUint reads a JSON number that protojson writes either as a number or as
// a string.
func jsonUint(v any) (uint64, bool) {
	switch n := v.(type) {
	case float64:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	case string:
		u, err := strconv.ParseUint(n, 10, 64)
		if err != nil {
			return 0, false
		}
		return u, true
	}

	return 0, false
}

// getAdmin reads path from the Envoy admin interface.
func (r *Runtime) getAdmin(ctx context.Context, client *http.Client, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+r.adminHost+path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}
