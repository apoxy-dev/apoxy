package envoy

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/otlptranslator"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

const (
	// meterName names the instrumentation scope of the runtime metrics.
	meterName = "github.com/apoxy-dev/apoxy/pkg/backplane/envoy"

	// otlpExportInterval is how often the runtime pushes metrics to the
	// OpenTelemetry collector.
	otlpExportInterval = 30 * time.Second

	// serviceName identifies the backplane in the OTLP resource.
	serviceName = "apoxy-backplane"
)

// Limits are the configured ceilings of the Envoy process. Dashboards draw the
// ceiling next to the value Envoy reports.
type Limits struct {
	// MaxActiveDownstreamConnections is the connection cap of the overload
	// manager.
	MaxActiveDownstreamConnections *uint64
	// MaxHeapBytes is the fixed heap size of the overload manager.
	MaxHeapBytes *uint64
}

// runtimeSample holds every value the metrics report in one collection cycle.
type runtimeSample struct {
	Identity          Identity
	Running           bool
	StartedAt         time.Time
	Restarts          int
	ExitCounts        map[ExitKey]int64
	LastExit          *ExitInfo
	Release           string
	EnvoyVersion      string
	Limits            Limits
	MemoryLimitBytes  int64
	MemoryLimitKnown  bool
	DNSCacheMaxHosts  map[string]uint64
	AdminScrapeErrors int64
	Process           *processStats
	TCP               *tcpCounters
}

// metricsSource provides the values the observable instruments report.
type metricsSource interface {
	sample() runtimeSample
}

// Metrics exports the state of the Envoy runtime to Prometheus and, when a
// sink is configured, to an OpenTelemetry collector.
type Metrics struct {
	src      metricsSource
	registry *prometheus.Registry
	provider *sdkmetric.MeterProvider
}

// NewMetrics defines the runtime metrics and registers the exporters. An empty
// otlpAddr leaves the OTLP export off, which is the default outside the hosted
// platform.
func NewMetrics(src metricsSource, id Identity, otlpAddr string) (*Metrics, error) {
	reg := prometheus.NewRegistry()
	promReader, err := promexporter.New(
		promexporter.WithRegisterer(reg),
		promexporter.WithoutScopeInfo(),
		promexporter.WithoutTargetInfo(),
		// The rendered names must match the documented ones exactly.
		promexporter.WithTranslationStrategy(otlptranslator.UnderscoreEscapingWithSuffixes),
		promexporter.WithoutUnits(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create prometheus exporter: %w", err)
	}

	opts := []sdkmetric.Option{
		sdkmetric.WithResource(otlpResource(id)),
		sdkmetric.WithReader(promReader),
	}
	if otlpAddr != "" {
		exp, err := otlpmetricgrpc.New(context.Background(),
			otlpmetricgrpc.WithEndpoint(otlpAddr),
			otlpmetricgrpc.WithInsecure(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create otlp metric exporter: %w", err)
		}
		opts = append(opts, sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(otlpExportInterval)),
		))
	}

	m := &Metrics{
		src:      src,
		registry: reg,
		provider: sdkmetric.NewMeterProvider(opts...),
	}
	if err := m.register(); err != nil {
		return nil, err
	}

	return m, nil
}

// otlpResource describes the backplane process to the collector.
func otlpResource(id Identity) *resource.Resource {
	attrs := []attribute.KeyValue{
		attribute.String("service.name", serviceName),
		attribute.String("apoxy.proxy", id.Proxy),
		attribute.String("apoxy.replica", id.Replica),
	}
	if id.ProjectID != "" {
		attrs = append(attrs, attribute.String("apoxy.project_id", id.ProjectID))
	}

	return resource.NewSchemaless(attrs...)
}

// Registry returns the Prometheus registry the metrics are registered on.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// Gatherer returns the Prometheus gatherer of the runtime metrics.
func (m *Metrics) Gatherer() prometheus.Gatherer {
	return m.registry
}

// Shutdown flushes and stops the exporters.
func (m *Metrics) Shutdown(ctx context.Context) error {
	return m.provider.Shutdown(ctx)
}

// register defines the instruments and the callback that reads the runtime.
func (m *Metrics) register() error {
	meter := m.provider.Meter(meterName)

	gauge := func(name, desc string) (metric.Int64ObservableGauge, error) {
		return meter.Int64ObservableGauge(name, metric.WithDescription(desc))
	}
	secondsGauge := func(name, desc string) (metric.Float64ObservableGauge, error) {
		return meter.Float64ObservableGauge(name, metric.WithDescription(desc))
	}
	counter := func(name, desc string) (metric.Int64ObservableCounter, error) {
		return meter.Int64ObservableCounter(name, metric.WithDescription(desc))
	}

	var err error
	add := func(e error) {
		if err == nil {
			err = e
		}
	}

	up, e := gauge("apoxy.backplane.envoy.up", "One while the Envoy process runs.")
	add(e)
	startTime, e := secondsGauge("apoxy.backplane.envoy.start_time_seconds", "Start time of the Envoy process in seconds since the epoch.")
	add(e)
	restarts, e := counter("apoxy.backplane.envoy.restarts", "Starts of the Envoy process after an exit.")
	add(e)
	exits, e := counter("apoxy.backplane.envoy.exits", "Exits of the Envoy process by reason and code.")
	add(e)
	lastExitTime, e := secondsGauge("apoxy.backplane.envoy.last_exit_timestamp_seconds", "Time of the last Envoy exit in seconds since the epoch.")
	add(e)
	info, e := gauge("apoxy.backplane.envoy.info", "One, labelled with the Envoy release and version.")
	add(e)
	openFDs, e := gauge("apoxy.backplane.envoy.open_fds", "Open file descriptors of the Envoy process.")
	add(e)
	maxFDs, e := gauge("apoxy.backplane.envoy.max_fds", "File descriptor limit of the Envoy process.")
	add(e)
	rssBytes, e := gauge("apoxy.backplane.envoy.rss_bytes", "Resident memory of the Envoy process in bytes.")
	add(e)
	limitMaxConns, e := gauge("apoxy.backplane.envoy.limit.max_active_downstream_connections", "Configured cap on active downstream connections.")
	add(e)
	limitMaxHeap, e := gauge("apoxy.backplane.envoy.limit.max_heap_bytes", "Configured fixed heap size in bytes.")
	add(e)
	limitMemory, e := gauge("apoxy.backplane.envoy.limit.memory_bytes", "Memory limit of the container in bytes.")
	add(e)
	limitDNSHosts, e := gauge("apoxy.backplane.envoy.limit.dns_cache_max_hosts", "Configured host limit of a dynamic forward proxy DNS cache.")
	add(e)
	lastExitRequests, e := gauge("apoxy.backplane.envoy.last_exit_requests_in_flight", "Downstream requests active at the last sample before the last exit.")
	add(e)
	lastExitConns, e := gauge("apoxy.backplane.envoy.last_exit_connections", "Downstream connections active at the last sample before the last exit.")
	add(e)
	lastExitAborted, e := gauge("apoxy.backplane.envoy.last_exit_connections_aborted", "Connections the kernel tore down when Envoy died. The value becomes final when the next process starts.")
	add(e)
	lastExitRefused, e := gauge("apoxy.backplane.envoy.last_exit_connections_refused", "Connection attempts the kernel reset while Envoy was gone. The value becomes final when the next process starts.")
	add(e)
	scrapeErrors, e := counter("apoxy.backplane.envoy.admin_scrape_errors", "Failed reads of the Envoy admin interface.")
	add(e)
	outRsts, e := counter("apoxy.backplane.net.tcp.out_rsts", "TCP resets the kernel sent.")
	add(e)
	estabResets, e := counter("apoxy.backplane.net.tcp.estab_resets", "Established TCP connections the kernel reset.")
	add(e)
	abortOnClose, e := counter("apoxy.backplane.net.tcp.abort_on_close", "TCP connections aborted on close with unread data.")
	add(e)
	abortOnData, e := counter("apoxy.backplane.net.tcp.abort_on_data", "TCP connections aborted because data arrived after close.")
	add(e)
	listenOverflows, e := counter("apoxy.backplane.net.tcp.listen_overflows", "Connections dropped because the accept queue was full.")
	add(e)
	listenDrops, e := counter("apoxy.backplane.net.tcp.listen_drops", "Connections the listening socket dropped.")
	add(e)
	if err != nil {
		return fmt.Errorf("failed to define runtime metrics: %w", err)
	}

	observe := func(_ context.Context, o metric.Observer) error {
		s := m.src.sample()
		base := identityAttributes(s.Identity)
		set := metric.WithAttributes(base...)

		running := int64(0)
		if s.Running {
			running = 1
		}
		o.ObserveInt64(up, running, set)
		if !s.StartedAt.IsZero() {
			o.ObserveFloat64(startTime, epochSeconds(s.StartedAt), set)
		}
		o.ObserveInt64(restarts, int64(s.Restarts), set)
		for k, v := range s.ExitCounts {
			o.ObserveInt64(exits, v, metric.WithAttributes(append(append([]attribute.KeyValue{}, base...),
				attribute.String("reason", k.Reason),
				attribute.String("code", k.Code),
			)...))
		}
		if s.LastExit != nil {
			o.ObserveFloat64(lastExitTime, epochSeconds(s.LastExit.At), set)
			if s.LastExit.RequestsInFlight != nil {
				o.ObserveInt64(lastExitRequests, *s.LastExit.RequestsInFlight, set)
			}
			if s.LastExit.Connections != nil {
				o.ObserveInt64(lastExitConns, *s.LastExit.Connections, set)
			}
			o.ObserveInt64(lastExitAborted, s.LastExit.ConnectionsAborted, set)
			o.ObserveInt64(lastExitRefused, s.LastExit.ConnectionsRefused, set)
		}

		o.ObserveInt64(info, 1, metric.WithAttributes(append(append([]attribute.KeyValue{}, base...),
			attribute.String("release", s.Release),
			attribute.String("envoy_version", s.EnvoyVersion),
		)...))

		if s.Process != nil {
			o.ObserveInt64(openFDs, s.Process.OpenFDs, set)
			if s.Process.MaxFDs > 0 {
				o.ObserveInt64(maxFDs, s.Process.MaxFDs, set)
			}
			o.ObserveInt64(rssBytes, s.Process.RSSBytes, set)
		}

		if s.Limits.MaxActiveDownstreamConnections != nil {
			o.ObserveInt64(limitMaxConns, int64(*s.Limits.MaxActiveDownstreamConnections), set)
		}
		if s.Limits.MaxHeapBytes != nil {
			o.ObserveInt64(limitMaxHeap, int64(*s.Limits.MaxHeapBytes), set)
		}
		if s.MemoryLimitKnown {
			o.ObserveInt64(limitMemory, s.MemoryLimitBytes, set)
		}
		for cache, hosts := range s.DNSCacheMaxHosts {
			o.ObserveInt64(limitDNSHosts, int64(hosts), metric.WithAttributes(append(append([]attribute.KeyValue{}, base...),
				attribute.String("cache", cache),
			)...))
		}

		o.ObserveInt64(scrapeErrors, s.AdminScrapeErrors, set)

		if s.TCP != nil {
			o.ObserveInt64(outRsts, s.TCP.OutRsts, set)
			o.ObserveInt64(estabResets, s.TCP.EstabResets, set)
			o.ObserveInt64(abortOnClose, s.TCP.AbortOnClose, set)
			o.ObserveInt64(abortOnData, s.TCP.AbortOnData, set)
			o.ObserveInt64(listenOverflows, s.TCP.ListenOverflows, set)
			o.ObserveInt64(listenDrops, s.TCP.ListenDrops, set)
		}

		return nil
	}

	_, err = meter.RegisterCallback(observe,
		up, startTime, restarts, exits, lastExitTime, info,
		openFDs, maxFDs, rssBytes,
		limitMaxConns, limitMaxHeap, limitMemory, limitDNSHosts,
		lastExitRequests, lastExitConns, lastExitAborted, lastExitRefused,
		scrapeErrors,
		outRsts, estabResets, abortOnClose, abortOnData, listenOverflows, listenDrops,
	)
	if err != nil {
		return fmt.Errorf("failed to register the runtime metric callback: %w", err)
	}

	return nil
}

// identityAttributes returns the attributes every datapoint carries. The
// Prometheus exporter writes resource attributes to target_info only, and the
// collector filters on datapoint attributes.
func identityAttributes(id Identity) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("proxy", id.Proxy),
		attribute.String("replica", id.Replica),
	}
	if id.ProjectID != "" {
		attrs = append(attrs, attribute.String("project_id", id.ProjectID))
	}

	return attrs
}

// epochSeconds returns t in seconds since the epoch.
func epochSeconds(t time.Time) float64 {
	return float64(t.UnixNano()) / float64(time.Second)
}

// Metrics returns the runtime metrics and defines them on first use.
func (r *Runtime) Metrics() *Metrics {
	r.tel.metricsOnce.Do(func() {
		m, err := NewMetrics(r, r.tel.identity, r.tel.otlpSinkAddr)
		if err != nil {
			slog.Error("Failed to define the Envoy runtime metrics", "error", err)
			return
		}
		r.tel.metrics.Store(m)
	})

	return r.tel.metrics.Load()
}

// metricsIfStarted returns the runtime metrics, or nil when they were never
// defined.
func (r *Runtime) metricsIfStarted() *Metrics {
	return r.tel.metrics.Load()
}

// Gatherer returns the Prometheus gatherer of the runtime metrics. The metrics
// server appends the families to the Envoy stats.
func (r *Runtime) Gatherer() prometheus.Gatherer {
	m := r.Metrics()
	if m == nil {
		return prometheus.NewRegistry()
	}

	return m.Gatherer()
}

// sample reads the runtime state and the process counters once.
func (r *Runtime) sample() runtimeSample {
	var s runtimeSample
	r.tel.observe(&s)
	if r.Release != nil {
		s.Release = r.Release.String()
	}

	r.mu.RLock()
	s.Running = r.status.Running
	s.StartedAt = r.status.StartedAt
	s.Restarts = r.status.Restarts
	s.LastExit = r.status.LastExit
	pid := r.pid
	s.ExitCounts = make(map[ExitKey]int64, len(r.status.ExitCounts))
	for k, v := range r.status.ExitCounts {
		s.ExitCounts[k] = v
	}
	r.mu.RUnlock()

	s.MemoryLimitBytes, s.MemoryLimitKnown = defaultCgroupReader().memoryLimit()

	pr, nr := systemReaders()
	if pr != nil && s.Running && pid > 0 {
		if ps, err := pr.ProcessStats(pid); err == nil {
			s.Process = &ps
		}
	}
	if nr != nil {
		if tc, err := nr.TCPCounters(); err == nil {
			s.TCP = &tc
		}
	}

	return s
}
