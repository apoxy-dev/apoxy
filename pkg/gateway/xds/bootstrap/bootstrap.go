// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package bootstrap

import (
	// Register embed
	_ "embed"
	"fmt"
	"strings"
	"text/template"
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

	envoyReadinessAddress = "0.0.0.0"
	EnvoyReadinessPort    = 19001
	EnvoyReadinessPath    = "/ready"
)

// defaultEnvoyMaxActiveDownstreamConnections is the default maximum number of active downstream connections.
var defaultEnvoyMaxActiveDownstreamConnections uint64 = 50000

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
	// EnableStatConfig defines whether to to customize the Envoy proxy stats.
	EnableStatConfig bool
	// StatsMatcher is to control creation of custom Envoy stats with prefix,
	// suffix, and regex expressions match on the name of the stats.
	StatsMatcher *StatsMatcherParameters
	// OverloadManager defines the configuration of the Envoy overload manager.
	OverloadManager OverloadManagerParameters
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
	// OverloadMaxHeapSizeBytes defines the maximum heap size in bytes for the Envoy overload manager.
	OverloadMaxHeapSizeBytes *uint64
	// OverloadMaxActiveDownstreamConnections defines the maximum number of active downstream connections for the Envoy overload manager.
	OverloadMaxActiveDownstreamConnections *uint64
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

// GetRenderedBootstrapConfig renders the bootstrap YAML string.
func GetRenderedBootstrapConfig(opts ...BootstrapOption) (string, error) {
	sOpts := defaultBootstrapConfig()
	for _, opt := range opts {
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
		},
	}

	if err := cfg.render(); err != nil {
		return "", err
	}

	return cfg.rendered, nil
}
