package envoy

import (
	"sync"
	"sync/atomic"

	"github.com/apoxy-dev/apoxy/pkg/backplane/logs"
	"github.com/apoxy-dev/apoxy/pkg/backplane/otel"
)

// telemetry holds what the backplane observes about the Envoy process: the
// identity and the limits, the sampler state, the restart window and the
// metric instruments.
type telemetry struct {
	// Log and trace collection. The lifecycle sets these once before Start and
	// reads them only while it starts and stops the process, so they need no
	// lock.
	logs          logs.LogsCollector
	otelCollector *otel.Collector

	identity     Identity
	limits       Limits
	otlpSinkAddr string
	// intervals are the timings of the admin sampler. A zero value selects the
	// defaults.
	intervals samplerIntervals

	// adminScrapeErrors counts the failed reads of the Envoy admin interface.
	adminScrapeErrors atomic.Int64

	metricsOnce sync.Once
	metrics     atomic.Pointer[Metrics]

	// mu guards the fields below. It is not the process lock, so a scrape
	// never waits on a start or an exit.
	mu sync.RWMutex
	// lastSample is the newest read of the Envoy admin stats.
	lastSample *adminSample
	// lastTCP is the newest read of the kernel TCP counters. The sampler takes
	// it next to lastSample, so that the exit record holds the counters from
	// before the kernel tore the connections of the process down.
	lastTCP *tcpCounters
	// envoyVersion is the version the Envoy admin interface reports.
	envoyVersion string
	// dnsCacheMaxHosts holds the host limit of each dynamic forward proxy cache.
	dnsCacheMaxHosts map[string]uint64
	// window holds the kernel TCP counters that bound the time Envoy was gone.
	// It is nil once the counters of the next start are recorded.
	window *restartWindow
	// oomKills is the cgroup OOM kill count read when Envoy started.
	oomKills int64
	// oomKillsKnown reports whether the cgroup publishes an OOM kill count.
	oomKillsKnown bool
}

// samplerIntervals returns the timings of the sampler. Tests set their own.
func (t *telemetry) samplerIntervals() samplerIntervals {
	if t.intervals.Sample > 0 {
		return t.intervals
	}

	return defaultSamplerIntervals()
}

// startProcess drops the reads of the process that ended and keeps the OOM
// kill count the next exit compares against.
func (t *telemetry) startProcess(kills int64, killsKnown bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastSample = nil
	t.lastTCP = nil
	t.oomKills, t.oomKillsKnown = kills, killsKnown
}

// storeSample keeps the newest reads. Either read may be absent. It reports
// whether the Envoy version is still unknown.
func (t *telemetry) storeSample(tcp *tcpCounters, s *adminSample) (needVersion bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if tcp != nil {
		t.lastTCP = tcp
	}
	if s != nil {
		t.lastSample = s
	}

	return s != nil && t.envoyVersion == ""
}

// setEnvoyVersion keeps the version the admin interface reports.
func (t *telemetry) setEnvoyVersion(version string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.envoyVersion = version
}

// setDNSCacheLimits replaces the host limits of the dynamic forward proxy
// caches.
func (t *telemetry) setDNSCacheLimits(limits map[string]uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dnsCacheMaxHosts = limits
}

// exitState returns the newest reads taken while the process ran, and whether
// the cgroup OOM killer ended it. kills is the OOM kill count read after the
// exit.
func (t *telemetry) exitState(kills int64, killsKnown bool) (*adminSample, *tcpCounters, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.lastSample, t.lastTCP, killsKnown && t.oomKillsKnown && kills > t.oomKills
}

// setWindow keeps the counters that bound the time Envoy is gone.
func (t *telemetry) setWindow(w *restartWindow) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.window = w
}

// restartWindow returns the open window, or nil when none is open.
func (t *telemetry) restartWindow() *restartWindow {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.window
}

// clearWindow closes the window.
func (t *telemetry) clearWindow() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.window = nil
}

// observe fills the values the backplane reads from the telemetry state.
func (t *telemetry) observe(s *runtimeSample) {
	s.Identity = t.identity
	s.Limits = t.limits
	s.AdminScrapeErrors = t.adminScrapeErrors.Load()

	t.mu.RLock()
	defer t.mu.RUnlock()
	s.EnvoyVersion = t.envoyVersion
	s.DNSCacheMaxHosts = make(map[string]uint64, len(t.dnsCacheMaxHosts))
	for k, v := range t.dnsCacheMaxHosts {
		s.DNSCacheMaxHosts[k] = v
	}
}
