// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package bootstrap

import (
	// Register embed
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"text/template"
	"time"
)

const (
	// envoyCfgFileName is the name of the Envoy configuration file.
	envoyCfgFileName = "bootstrap.yaml"
	// envoyGatewayXdsServerHost is the DNS name of the Xds Server within Envoy Gateway.
	// It defaults to the Envoy Gateway Kubernetes service.
	envoyGatewayXdsServerHost = "envoy-gateway"
	// EnvoyAdminAddress is the listening address of the envoy admin interface.
	EnvoyAdminAddress = "127.0.0.1"
	// EnvoyAdminPort is the port used to expose admin interface.
	EnvoyAdminPort = 19000
	// envoyAdminAccessLogPath is the path used to expose admin access log.
	envoyAdminAccessLogPath = "/dev/null"

	// DefaultXdsServerPort is the default listening port of the xds-server.
	DefaultXdsServerPort = 18000

	// DefaultTLSCAPath is the default path to system CA certificates.
	DefaultTLSCAPath = "/etc/ssl/certs/ca-certificates.crt"

	envoyReadinessAddress = "0.0.0.0"
	EnvoyReadinessPort    = 19001
	EnvoyReadinessPath    = "/ready"
)

// defaultEnvoyMaxActiveDownstreamConnections is the default maximum number of active downstream connections.
var defaultEnvoyMaxActiveDownstreamConnections uint64 = 50000

const (
	// defaultWatchdogMissTimeout is how long a thread may stay unresponsive
	// before Envoy counts a watchdog miss. It is Envoy's own default.
	defaultWatchdogMissTimeout = 200 * time.Millisecond
	// defaultWatchdogMegamissTimeout is how long a thread may stay unresponsive
	// before Envoy counts a watchdog megamiss. It is Envoy's own default.
	defaultWatchdogMegamissTimeout = time.Second
)

//go:embed bootstrap.yaml.tpl
var bootstrapTmplStr string

var bootstrapTmpl = template.Must(template.New(envoyCfgFileName).Parse(bootstrapTmplStr))

// envoyBootstrap defines the envoy Bootstrap configuration.
type bootstrapConfig struct {
	// parameters defines configurable bootstrap configuration parameters.
	parameters bootstrapParameters
	// rendered is the rendered bootstrap configuration.
	rendered string
}

// envoyBootstrap defines the envoy Bootstrap configuration.
type bootstrapParameters struct {
	// XdsServer defines the configuration of the XDS server.
	XdsServer xdsServerParameters
	// AdminServer defines the configuration of the Envoy admin interface.
	AdminServer adminServerParameters
	// ReadyServer defines the configuration for health check ready listener
	ReadyServer readyServerParameters
	// EnablePrometheus defines whether to enable metrics endpoint for prometheus.
	EnablePrometheus bool
	// OtelMetricSinks defines the configuration of the OpenTelemetry sinks.
	OtelMetricSinks []metricSink
	// MetricSinkTags are the fixed tags Envoy adds to every stat. An empty list
	// adds none.
	MetricSinkTags []metricSinkTag
	// StatsFlushInterval is how often Envoy flushes stats to the sinks, already
	// rendered as a proto duration literal. It is empty when the caller sets
	// none, which leaves Envoy on its own default.
	StatsFlushInterval string
	// EnableStatConfig defines whether to to customize the Envoy proxy stats.
	EnableStatConfig bool
	// StatsMatcher is to control creation of custom Envoy stats with prefix,
	// suffix, and regex expressions match on the name of the stats.
	StatsMatcher *StatsMatcherParameters
	// OverloadManager defines the configuration of the Envoy overload manager.
	OverloadManager OverloadManagerParameters
	// Watchdog defines the timeouts of the Envoy thread watchdogs.
	Watchdog WatchdogParameters
	// XdsTLSCAPath is the path to the CA certificate for xDS TLS. Empty disables TLS.
	XdsTLSCAPath string
}

// WatchdogParameters holds the watchdog timeouts, already rendered as proto
// duration literals.
type WatchdogParameters struct {
	// MissTimeout is the time after which a stalled thread counts as a miss.
	MissTimeout string
	// MegamissTimeout is the time after which a stalled thread counts as a megamiss.
	MegamissTimeout string
}

type OverloadManagerParameters struct {
	// MaxHeapSizeBytes defines the maximum heap size in bytes.
	MaxHeapSizeBytes *uint64
	// MaxActiveDownstreamConnections defines the maximum number of active downstream connections.
	MaxActiveDownstreamConnections *uint64
}

type xdsServerParameters struct {
	// Address is the address of the XDS Server that Envoy is managed by.
	Address string
	// Port is the port of the XDS Server that Envoy is managed by.
	Port int32
}

type metricSink struct {
	// Address is the address of the XDS Server that Envoy is managed by.
	Address string
	// Port is the port of the XDS Server that Envoy is managed by.
	Port uint32
}

// metricSinkTag is one fixed tag Envoy adds to every stat.
type metricSinkTag struct {
	// Name is the tag name.
	Name string
	// Value is the tag value.
	Value string
}

type adminServerParameters struct {
	// Address is the address of the Envoy admin interface.
	Address string
	// Port is the port of the Envoy admin interface.
	Port int32
	// AccessLogPath is the path of the Envoy admin access log.
	AccessLogPath string
}

type readyServerParameters struct {
	// Address is the address of the Envoy readiness probe
	Address string
	// Port is the port of envoy readiness probe
	Port int32
	// ReadinessPath is the path for the envoy readiness probe
	ReadinessPath string
}

type StatsMatcherParameters struct {
	Exacts             []string
	Prefixs            []string
	Suffixs            []string
	RegularExpressions []string
}

// render the stringified bootstrap config in yaml format.
func (b *bootstrapConfig) render() error {
	buf := new(strings.Builder)
	if err := bootstrapTmpl.Execute(buf, b.parameters); err != nil {
		return fmt.Errorf("failed to render bootstrap config: %w", err)
	}
	b.rendered = buf.String()

	return nil
}

type BootstrapConfig struct {
	// XdsServerHost is the DNS name of the Xds Server within Envoy Gateway.
	XdsServerHost string
	// XdsServerPort is the port of the Xds Server within Envoy Gateway.
	XdsServerPort int32
	// XdsTLSCAPath enables TLS for the xDS server connection using the CA certificate at this path.
	// Empty string disables TLS.
	XdsTLSCAPath string
	// OverloadMaxHeapSizeBytes defines the maximum heap size in bytes for the Envoy overload manager.
	OverloadMaxHeapSizeBytes *uint64
	// OverloadMaxActiveDownstreamConnections defines the maximum number of active downstream connections for the Envoy overload manager.
	OverloadMaxActiveDownstreamConnections *uint64
	// OtelMetricSinks are the OpenTelemetry metric sinks Envoy reports stats to.
	// An empty list leaves the stats sink section out of the bootstrap.
	OtelMetricSinks []metricSink
	// MetricSinkIdentity names the proxy the stats come from. A nil value adds
	// no identity tags.
	MetricSinkIdentity *MetricSinkIdentity
	// StatsFlushInterval is how often Envoy flushes stats to the sinks. A zero
	// value leaves Envoy on its own default.
	StatsFlushInterval time.Duration
	// WatchdogMissTimeout is the time after which a stalled Envoy thread counts
	// as a watchdog miss.
	WatchdogMissTimeout time.Duration
	// WatchdogMegamissTimeout is the time after which a stalled Envoy thread
	// counts as a watchdog megamiss.
	WatchdogMegamissTimeout time.Duration
}

func defaultBootstrapConfig() *BootstrapConfig {
	// Create a variable from the constant so we can take its address
	defaultConnections := defaultEnvoyMaxActiveDownstreamConnections

	// Get the default max heap size from the detector
	maxHeapSize := GetDefaultMaxHeapSizeBytes()

	return &BootstrapConfig{
		XdsServerHost:                          envoyGatewayXdsServerHost,
		XdsServerPort:                          DefaultXdsServerPort,
		OverloadMaxHeapSizeBytes:               maxHeapSize,
		OverloadMaxActiveDownstreamConnections: &defaultConnections,
		WatchdogMissTimeout:                    defaultWatchdogMissTimeout,
		WatchdogMegamissTimeout:                defaultWatchdogMegamissTimeout,
	}
}

// BootstrapOption defines the functional option to configure the bootstrap configuration.
type BootstrapOption func(*BootstrapConfig)

// WithXdsServerHost sets the Xds Server host.
func WithXdsServerHost(host string) BootstrapOption {
	return func(cfg *BootstrapConfig) {
		cfg.XdsServerHost = host
	}
}

// WithXdsServerPort sets the Xds Server port.
// The default port is 18000.
func WithXdsServerPort(port int32) BootstrapOption {
	return func(cfg *BootstrapConfig) {
		cfg.XdsServerPort = port
	}
}

// WithXdsTLS enables TLS for the xDS server connection using system CA certificates.
func WithXdsTLS() BootstrapOption {
	return WithXdsTLSCAPath(DefaultTLSCAPath)
}

// WithXdsTLSCAPath enables TLS for the xDS server connection using the CA certificate at the given path.
func WithXdsTLSCAPath(caPath string) BootstrapOption {
	return func(cfg *BootstrapConfig) {
		cfg.XdsTLSCAPath = caPath
	}
}

// WithOverloadMaxHeapSizeBytes sets the maximum heap size in bytes for the Envoy overload manager.
func WithOverloadMaxHeapSizeBytes(size uint64) BootstrapOption {
	return func(cfg *BootstrapConfig) {
		cfg.OverloadMaxHeapSizeBytes = &size
	}
}

// WithOverloadMaxActiveConnections sets the maximum number of active downstream connections for the Envoy overload manager.
func WithOverloadMaxActiveConnections(count uint64) BootstrapOption {
	return func(cfg *BootstrapConfig) {
		cfg.OverloadMaxActiveDownstreamConnections = &count
	}
}

// WithOtelMetricSink adds an OpenTelemetry metric sink at host:port. Envoy
// reports its stats to every sink added, each through its own cluster, so
// calling this more than once fans the stats out rather than replacing a sink.
func WithOtelMetricSink(host string, port uint32) BootstrapOption {
	return func(cfg *BootstrapConfig) {
		cfg.OtelMetricSinks = append(cfg.OtelMetricSinks, metricSink{Address: host, Port: port})
	}
}

// MetricSinkIdentity names the proxy the Envoy stats come from. Envoy reports
// it as a fixed tag on every stat.
type MetricSinkIdentity struct {
	// Proxy is the name of the Proxy the replica belongs to.
	Proxy string
	// Replica is the name of this replica.
	Replica string
	// ProjectID is the Apoxy project, which is empty on a self-hosted install.
	ProjectID string
}

// WithMetricSinkIdentity names the proxy Envoy reports its stats for.
func WithMetricSinkIdentity(proxy, replica, projectID string) BootstrapOption {
	return func(cfg *BootstrapConfig) {
		cfg.MetricSinkIdentity = &MetricSinkIdentity{
			Proxy:     proxy,
			Replica:   replica,
			ProjectID: projectID,
		}
	}
}

// metricSinkTags renders the identity as fixed stats tags. A self-hosted
// install has no project, which leaves that tag out.
func metricSinkTags(id *MetricSinkIdentity) []metricSinkTag {
	if id == nil {
		return nil
	}

	tags := []metricSinkTag{
		{Name: "apoxy.proxy", Value: id.Proxy},
		{Name: "apoxy.replica", Value: id.Replica},
	}
	if id.ProjectID != "" {
		tags = append(tags, metricSinkTag{Name: "apoxy.project_id", Value: id.ProjectID})
	}

	return tags
}

// WithStatsFlushInterval sets how often Envoy flushes stats to the sinks. A
// value of zero or less leaves Envoy on its own default.
func WithStatsFlushInterval(d time.Duration) BootstrapOption {
	return func(cfg *BootstrapConfig) {
		if d > 0 {
			cfg.StatsFlushInterval = d
		}
	}
}

// WithWatchdogTimeouts sets the Envoy watchdog miss and megamiss timeouts. A
// value of zero or less keeps the default for that timeout. The watchdog never
// kills the process, so these timeouts only change when Envoy counts a stalled
// thread.
func WithWatchdogTimeouts(miss, megamiss time.Duration) BootstrapOption {
	return func(cfg *BootstrapConfig) {
		if miss > 0 {
			cfg.WatchdogMissTimeout = miss
		}
		if megamiss > 0 {
			cfg.WatchdogMegamissTimeout = megamiss
		}
	}
}

// protoDuration renders d the way a proto duration field is written in YAML:
// whole seconds with a fractional part, never a Go duration string. Go prints
// a minute as "1m0s", which Envoy rejects.
func protoDuration(d time.Duration) string {
	return strconv.FormatFloat(d.Seconds(), 'f', -1, 64) + "s"
}

// GetRenderedBootstrapConfig renders the bootstrap YAML string.
func GetRenderedBootstrapConfig(opts ...BootstrapOption) (string, error) {
	sOpts := defaultBootstrapConfig()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(sOpts)
	}
	cfg := &bootstrapConfig{
		parameters: bootstrapParameters{
			XdsServer: xdsServerParameters{
				Address: sOpts.XdsServerHost,
				Port:    sOpts.XdsServerPort,
			},
			AdminServer: adminServerParameters{
				Address:       EnvoyAdminAddress,
				Port:          EnvoyAdminPort,
				AccessLogPath: envoyAdminAccessLogPath,
			},
			ReadyServer: readyServerParameters{
				Address:       envoyReadinessAddress,
				Port:          EnvoyReadinessPort,
				ReadinessPath: EnvoyReadinessPath,
			},
			OverloadManager: OverloadManagerParameters{
				MaxHeapSizeBytes:               sOpts.OverloadMaxHeapSizeBytes,
				MaxActiveDownstreamConnections: sOpts.OverloadMaxActiveDownstreamConnections,
			},
			Watchdog: WatchdogParameters{
				MissTimeout:     protoDuration(sOpts.WatchdogMissTimeout),
				MegamissTimeout: protoDuration(sOpts.WatchdogMegamissTimeout),
			},
			OtelMetricSinks: sOpts.OtelMetricSinks,
			MetricSinkTags:  metricSinkTags(sOpts.MetricSinkIdentity),
			XdsTLSCAPath:    sOpts.XdsTLSCAPath,
		},
	}

	if sOpts.StatsFlushInterval > 0 {
		cfg.parameters.StatsFlushInterval = protoDuration(sOpts.StatsFlushInterval)
	}

	if err := cfg.render(); err != nil {
		return "", err
	}

	return cfg.rendered, nil
}

// Resolve returns the effective bootstrap values without rendering the
// configuration. The backplane publishes the overload manager ceilings as
// gauges, so a dashboard can draw the limit next to the value Envoy reports.
func Resolve(opts ...BootstrapOption) *BootstrapConfig {
	cfg := defaultBootstrapConfig()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(cfg)
	}

	return cfg
}
