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

// QueryParamAgentProcessID is the CONNECT-IP query key for the agent process ID.
const QueryParamAgentProcessID = "agent_process_id"

// RelayRTTMetric is the family name of TunnelRelayRTTSeconds.
const RelayRTTMetric = "tunnel_relay_rtt_seconds"

// processID is stable for the process lifetime: a CRI container ID, else a
// UUID.
var processID = initProcessID()

// containerIDRegex matches the 64-hex CRI container ID in cgroup paths.
var containerIDRegex = regexp.MustCompile(`[0-9a-f]{64}`)

func initProcessID() string {
	// Linux only; elsewhere the read fails and a UUID is used. The ID is cut to 32
	// chars so it is also a valid label value.
	if id := detectContainerID("/proc/self/cgroup"); id != "" {
		return id[:32]
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
	// TunnelRelayRTTSeconds is the smoothed QUIC RTT to each relay with a live
	// session. The series goes when the session ends.
	TunnelRelayRTTSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: RelayRTTMetric,
			Help: "Smoothed round-trip time to the connected relay, as measured by QUIC.",
		},
		[]string{"relay"},
	)
	// TunnelRelayPacketsLost counts packets QUIC declared lost on the control
	// connection, by relay and reason.
	TunnelRelayPacketsLost = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_relay_packets_lost_total",
			Help: "Packets declared lost by QUIC on the relay control connection.",
		},
		[]string{"relay", "reason"},
	)
	// TunnelRelayPTOs counts QUIC probe timeouts on the control connection. A
	// rising rate means the path to that relay is failing.
	TunnelRelayPTOs = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_relay_ptos_total",
			Help: "QUIC probe timeouts (PTO) on the relay control connection.",
		},
		[]string{"relay"},
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
	// TunnelSessionClosures counts connections removed after their QUIC control
	// session closed. This is the primary per-connection liveness signal.
	TunnelSessionClosures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tunnel_session_closures_total",
			Help: "Tunnel connections removed after their QUIC control session closed.",
		},
	)
	// TunnelCleanupPending is the number of connection allocations held until
	// their Tunnel deletion is confirmed.
	TunnelCleanupPending = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "tunnel_cleanup_pending",
			Help: "Connection allocations waiting for Tunnel deletion confirmation.",
		},
	)
	// TunnelCleanupRetries counts Tunnel deletion attempts after a failure.
	TunnelCleanupRetries = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tunnel_cleanup_retries_total",
			Help: "Tunnel deletion attempts that failed and were scheduled for retry.",
		},
	)
	// TunnelCreatesPending is the number of live connections with no Tunnel yet.
	TunnelCreatesPending = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "tunnel_creates_pending",
			Help: "Live connections whose Tunnel object is not written yet.",
		},
		func() float64 { creates, _ := backlogs.totals(time.Now()); return float64(creates) },
	)
	// TunnelOldestPendingWrite is the age of the oldest waiting Tunnel write.
	TunnelOldestPendingWrite = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "tunnel_oldest_pending_write_seconds",
			Help: "Age of the oldest Tunnel create or delete that waits. 0 when none waits.",
		},
		func() float64 { _, age := backlogs.totals(time.Now()); return age.Seconds() },
	)
	// TunnelSlotLosses counts leased slots that lost their backing authority.
	TunnelSlotLosses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tunnel_slot_losses_total",
			Help: "Leased relay slots that lost their backing lease authority.",
		},
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

	// Per-protocol packet and byte counters. Protocol is tcp, udp, icmp or other;
	// direction is tx or rx.
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

	// TunnelConnectIPICMPReturned counts ICMP packets that CONNECT-IP made after a
	// failed write, such as Packet-Too-Big. TODO: remove when PMTUD is verified.
	TunnelConnectIPICMPReturned = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tunnel_connect_ip_icmp_returned_total",
			Help: "ICMP packets synthesized by connect-ip-go on WritePacket failure (e.g. QUIC DatagramTooLargeError → ICMPv6 PTB).",
		},
	)
)

func init() {
	// Register shared metrics used by both agent and server processes.
	metrics.Registry.MustRegister(TunnelRelayRTTSeconds)
	metrics.Registry.MustRegister(TunnelRelayPacketsLost)
	metrics.Registry.MustRegister(TunnelRelayPTOs)
	metrics.Registry.MustRegister(TunnelConnectionReconnects)
	metrics.Registry.MustRegister(TunnelPingRequests)
	metrics.Registry.MustRegister(TunnelConnectionRequests)
	metrics.Registry.MustRegister(TunnelConnectionsActive)
	metrics.Registry.MustRegister(TunnelConnectionFailures)
	metrics.Registry.MustRegister(TunnelSessionClosures)
	metrics.Registry.MustRegister(TunnelCleanupPending)
	metrics.Registry.MustRegister(TunnelCleanupRetries)
	metrics.Registry.MustRegister(TunnelSlotLosses)
	metrics.Registry.MustRegister(TunnelCreatesPending)
	metrics.Registry.MustRegister(TunnelOldestPendingWrite)
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

// RegisterAgentMetrics registers the agent-only metrics. Agents call it; the
// servers re-export agent metrics instead.
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

// tunnelBacklog holds the Tunnel write backlog of each publisher.
type tunnelBacklog struct {
	mu      sync.Mutex
	byOwner map[any]backlog
}

type backlog struct {
	creates int
	oldest  time.Time
}

var backlogs = &tunnelBacklog{byOwner: make(map[any]backlog)}

// SetTunnelBacklog records the waiting creates of owner and when its oldest
// waiting write became due. A zero oldest means nothing waits.
func SetTunnelBacklog(owner any, creates int, oldest time.Time) {
	backlogs.mu.Lock()
	defer backlogs.mu.Unlock()
	backlogs.byOwner[owner] = backlog{creates: creates, oldest: oldest}
}

func DeleteTunnelBacklog(owner any) {
	backlogs.mu.Lock()
	defer backlogs.mu.Unlock()
	delete(backlogs.byOwner, owner)
}

// totals returns the waiting creates and the age of the oldest waiting write.
func (b *tunnelBacklog) totals(now time.Time) (int, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	creates := 0
	var age time.Duration
	for _, l := range b.byOwner {
		creates += l.creates
		if !l.oldest.IsZero() {
			age = max(age, now.Sub(l.oldest))
		}
	}
	return creates, age
}
