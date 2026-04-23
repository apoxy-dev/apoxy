package metrics

import (
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/apoxy-dev/apoxy/build"
)

// startTime is the time the process started. Used for uptime calculation.
var startTime = time.Now()

// QueryParamAgentProcessID is the CONNECT-IP query-string key the agent uses
// to tell the server its stable per-process ID. Referenced by both the client
// and the server handler so a rename can't silently break the wire.
const QueryParamAgentProcessID = "agent_process_id"

// processID is stable for the process lifetime so callers can distinguish
// "same process with multiple conns" from "multiple processes each with one
// conn". Prefers a CRI container ID (cross-refs kubelet/containerd metadata)
// and falls back to a UUID when none is detectable.
var processID = initProcessID()

// containerIDRegex matches the 64-char hex token that CRI runtimes
// (containerd, cri-o, docker, podman) embed in cgroup paths. Covers both
// cgroup v1 and v2 layouts and the common systemd-slice wrappers
// (`cri-containerd-<id>.scope`, `docker-<id>.scope`, etc).
var containerIDRegex = regexp.MustCompile(`[0-9a-f]{64}`)

func initProcessID() string {
	// Linux-only: on macOS/Windows the read fails and we fall back to a UUID.
	// Both paths rotate on container/process restart, so cardinality is bounded
	// by the same restart rate either way.
	if id := detectContainerID("/proc/self/cgroup"); id != "" {
		return id
	}
	return uuid.NewString()
}

func detectContainerID(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return parseCgroupForContainerID(data)
}

func parseCgroupForContainerID(data []byte) string {
	return containerIDRegex.FindString(string(data))
}

// AgentProcessID returns the stable per-process ID for this agent.
func AgentProcessID() string { return processID }

var (
	// Agent info and lifecycle metrics.

	// TunnelAgentInfo is an info metric that exports version labels. Always set to 1.
	TunnelAgentInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tunnel_agent_info",
			Help: "Agent build information. Always 1.",
		},
		[]string{"version", "build_date", "commit"},
	)
	// TunnelAgentUptimeSeconds reports agent process uptime.
	TunnelAgentUptimeSeconds = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "tunnel_agent_uptime_seconds",
			Help: "Seconds since the agent process started.",
		},
		func() float64 { return time.Since(startTime).Seconds() },
	)
	// TunnelConnectionReconnects counts reconnection attempts across all connections.
	TunnelConnectionReconnects = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tunnel_connection_reconnects_total",
			Help: "Total number of tunnel reconnection attempts.",
		},
	)

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

	// Per-protocol packet and byte counters.
	// Protocol values: "tcp", "udp", "icmp", "other".
	// Direction values: "tx", "rx".
	TunnelPacketsByProtocol = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_packets_by_protocol_total",
			Help: "Total packets broken down by IP protocol and direction.",
		},
		[]string{"protocol", "direction"},
	)
	TunnelBytesByProtocol = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_bytes_by_protocol_total",
			Help: "Total bytes broken down by IP protocol and direction.",
		},
		[]string{"protocol", "direction"},
	)

	// TunnelConnectIPICMPReturned counts ICMP packets that CONNECT-IP
	// synthesized in response to an outbound-write failure (notably the QUIC
	// DatagramTooLargeError path that emits an ICMPv6 Packet-Too-Big back at
	// the sender for PMTUD). Cross-reference with tunnel_icmp6_packet_too_big_*
	// to detect PTB generation vs. propagation issues.
	// TODO(APO-543): remove once PMTUD-over-tunnel is verified healthy.
	TunnelConnectIPICMPReturned = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tunnel_connect_ip_icmp_returned_total",
			Help: "ICMP packets synthesized by connect-ip-go on WritePacket failure (e.g. QUIC DatagramTooLargeError → ICMPv6 PTB).",
		},
	)
)

func init() {
	// Register shared metrics used by both agent and server processes.
	metrics.Registry.MustRegister(TunnelConnectionReconnects)
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
	metrics.Registry.MustRegister(TunnelPacketsByProtocol)
	metrics.Registry.MustRegister(TunnelBytesByProtocol)
	metrics.Registry.MustRegister(TunnelConnectIPICMPReturned)
}

var registerAgentOnce sync.Once

// RegisterAgentMetrics registers agent-only metrics (info and uptime) with the
// controller-runtime metrics registry. This must be called explicitly by agent
// processes — server processes (tunnelproxy) should NOT call this, as they
// re-export agent metrics via the AgentScraper/ReexportCollector path instead.
func RegisterAgentMetrics() {
	registerAgentOnce.Do(func() {
		TunnelAgentInfo.WithLabelValues(build.BuildVersion, build.BuildDate, build.CommitHash).Set(1)
		metrics.Registry.MustRegister(TunnelAgentInfo)
		metrics.Registry.MustRegister(TunnelAgentUptimeSeconds)
	})
}

// ProtocolFromIPHeader returns a protocol label from the IP next-header/protocol byte.
func ProtocolFromIPHeader(proto byte) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1, 58:
		return "icmp"
	default:
		return "other"
	}
}

// ProtocolCounters holds pre-resolved counters for a (protocol, direction) pair
// to avoid per-packet WithLabelValues lookups on the hot path.
type ProtocolCounters struct {
	Packets prometheus.Counter
	Bytes   prometheus.Counter
}

// Pre-resolved counters keyed by "proto:direction".
var protocolCounters map[string]*ProtocolCounters

func init() {
	protocolCounters = make(map[string]*ProtocolCounters)
	for _, proto := range []string{"tcp", "udp", "icmp", "other"} {
		for _, dir := range []string{"tx", "rx"} {
			protocolCounters[proto+":"+dir] = &ProtocolCounters{
				Packets: TunnelPacketsByProtocol.WithLabelValues(proto, dir),
				Bytes:   TunnelBytesByProtocol.WithLabelValues(proto, dir),
			}
		}
	}
}

// GetProtocolCounters returns pre-resolved counters for the given protocol and direction.
// Returns nil if the protocol string is empty.
func GetProtocolCounters(proto, direction string) *ProtocolCounters {
	if proto == "" {
		return nil
	}
	return protocolCounters[proto+":"+direction]
}
