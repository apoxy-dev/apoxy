package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// TunnelServer metrics.
	TunnelPingRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tunnel_ping_requests_total",
			Help: "Total number of ping requests for latency probing.",
		},
	)
	TunnelConnectionRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tunnel_connection_requests_total",
			Help: "Total number of connection requests to the tunnel server.",
		},
	)
	TunnelConnectionsActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "tunnel_connections_active",
			Help: "Number of currently active tunnel connections.",
		},
	)
	TunnelConnectionFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_connection_failures_total",
			Help: "Total number of failed connection attempts.",
		},
		[]string{"reason"},
	)
	TunnelNodesManaged = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "tunnel_nodes_managed_total",
			Help: "Number of currently managed tunnel nodes.",
		},
	)
	// MuxedConn metrics.
	TunnelPacketsSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tunnel_packets_sent_total",
			Help: "Total number of packets sent through the tunnel.",
		},
	)
	TunnelBytesSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tunnel_bytes_sent_total",
			Help: "Total number of bytes sent through the tunnel.",
		},
	)
	// TunnelPacketsSentErrors tracks packet send errors with labels.
	// Common error_type values: "invalid_ip", "no_tunnel", "invalid_connection_type", "write_error"
	TunnelPacketsSentErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_packets_sent_errors_total",
			Help: "Total number of packets sent through the tunnel with errors.",
		},
		[]string{"error_type"},
	)
	TunnelPacketsReceived = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tunnel_packets_received_total",
			Help: "Total number of packets received from the tunnel.",
		},
	)
	TunnelBytesReceived = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tunnel_bytes_received_total",
			Help: "Total number of bytes received from the tunnel.",
		},
	)
	// TunnelPacketsReceivedErrors tracks packet receive errors with labels.
	// Common error_type values: "read_error", "connection_closed"
	TunnelPacketsReceivedErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_packets_received_errors_total",
			Help: "Total number of packets received from the tunnel with errors.",
		},
		[]string{"error_type"},
	)
	// TunnelPacketsDropped tracks packets that were dropped.
	// Common reason values: "channel_full", "channel_closed"
	TunnelPacketsDropped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_packets_dropped_total",
			Help: "Total number of packets dropped by the tunnel.",
		},
		[]string{"reason"},
	)
)

func init() {
	// Register metrics with the controller-runtime metrics registry.
	metrics.Registry.MustRegister(TunnelPingRequests)
	metrics.Registry.MustRegister(TunnelConnectionRequests)
	metrics.Registry.MustRegister(TunnelConnectionsActive)
	metrics.Registry.MustRegister(TunnelConnectionFailures)
	metrics.Registry.MustRegister(TunnelNodesManaged)
	metrics.Registry.MustRegister(TunnelPacketsSent)
	metrics.Registry.MustRegister(TunnelBytesSent)
	metrics.Registry.MustRegister(TunnelPacketsSentErrors)
	metrics.Registry.MustRegister(TunnelPacketsReceived)
	metrics.Registry.MustRegister(TunnelBytesReceived)
	metrics.Registry.MustRegister(TunnelPacketsReceivedErrors)
	metrics.Registry.MustRegister(TunnelPacketsDropped)
}
