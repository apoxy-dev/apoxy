package socksproxy

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// SOCKS proxy connection metrics.
	SocksConnectionRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "socks_connection_requests_total",
			Help: "Total number of connection requests to the SOCKS proxy server.",
		},
	)
	SocksConnectionsActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "socks_connections_active",
			Help: "Number of currently active SOCKS connections.",
		},
	)
	SocksConnectionFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "socks_connection_failures_total",
			Help: "Total number of failed SOCKS connection attempts.",
		},
		[]string{"reason"},
	)
	SocksConnectionDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "socks_connection_duration_seconds",
			Help:    "Duration of SOCKS connections in seconds.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15), // 1ms to ~32s
		},
		[]string{"destination_type"}, // "upstream", "fallback", "loopback"
	)

	// SOCKS proxy data transfer metrics.
	SocksBytesTransferred = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "socks_bytes_transferred_total",
			Help: "Total number of bytes transferred through the SOCKS proxy.",
		},
		[]string{"direction", "destination_type"}, // direction: "sent", "received"; destination_type: "upstream", "fallback", "loopback"
	)

	// SOCKS proxy DNS metrics.
	SocksDNSRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "socks_dns_requests_total",
			Help: "Total number of DNS requests made by the SOCKS proxy.",
		},
		[]string{"result"}, // "success", "failure", "no_addresses"
	)
	SocksDNSLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "socks_dns_latency_seconds",
			Help:    "Latency of DNS resolution in seconds.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms to ~1s
		},
	)

	// SOCKS proxy authentication metrics.
	SocksAuthAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "socks_auth_attempts_total",
			Help: "Total number of authentication attempts.",
		},
		[]string{"method", "result"}, // method: "none", "password", etc.; result: "success", "failure"
	)

	// SOCKS command metrics.
	SocksCommands = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "socks_commands_total",
			Help: "Total number of SOCKS commands received.",
		},
		[]string{"command", "result"}, // command: "connect", "bind", "udp"; result: "success", "failure"
	)

	// SOCKS proxy error metrics.
	SocksErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "socks_errors_total",
			Help: "Total number of SOCKS proxy errors.",
		},
		[]string{"error_type"}, // "parse_error", "dial_error", "resolve_error", etc.
	)
)

func init() {
	// Register metrics with the controller-runtime metrics registry.
	metrics.Registry.MustRegister(SocksConnectionRequests)
	metrics.Registry.MustRegister(SocksConnectionsActive)
	metrics.Registry.MustRegister(SocksConnectionFailures)
	metrics.Registry.MustRegister(SocksConnectionDuration)
	metrics.Registry.MustRegister(SocksBytesTransferred)
	metrics.Registry.MustRegister(SocksDNSRequests)
	metrics.Registry.MustRegister(SocksDNSLatency)
	metrics.Registry.MustRegister(SocksAuthAttempts)
	metrics.Registry.MustRegister(SocksCommands)
	metrics.Registry.MustRegister(SocksErrors)
}
