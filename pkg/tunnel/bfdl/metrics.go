package bfdl

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// BFD session metrics.

	// BFDSessionsActive tracks the number of BFD sessions currently in each state.
	// Labels: "role" (server|client), "state" (Down|Init|Up).
	BFDSessionsActive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tunnel_bfd_sessions_active",
			Help: "Number of active BFD sessions by role and state.",
		},
		[]string{"role", "state"},
	)

	// BFDPacketsTx counts BFD control packets transmitted.
	// Labels: "role" (server|client).
	BFDPacketsTx = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_bfd_packets_tx_total",
			Help: "Total BFD control packets transmitted.",
		},
		[]string{"role"},
	)

	// BFDPacketsRx counts BFD control packets received.
	// Labels: "role" (server|client).
	BFDPacketsRx = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_bfd_packets_rx_total",
			Help: "Total BFD control packets received.",
		},
		[]string{"role"},
	)

	// BFDStateTransitions counts BFD state transitions.
	// Labels: "role" (server|client), "from" (Down|Init|Up), "to" (Down|Init|Up).
	BFDStateTransitions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_bfd_state_transitions_total",
			Help: "Total BFD session state transitions.",
		},
		[]string{"role", "from", "to"},
	)

	// BFDDetectTimeouts counts detect-timer expirations (session went Down due to missed packets).
	// Labels: "role" (server|client).
	BFDDetectTimeouts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_bfd_detect_timeouts_total",
			Help: "Total BFD detect-timer expirations (session timed out).",
		},
		[]string{"role"},
	)

	// BFDPacketErrors counts BFD packet errors (unmarshal, write).
	// Labels: "role" (server|client), "direction" (tx|rx).
	BFDPacketErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_bfd_packet_errors_total",
			Help: "Total BFD packet errors.",
		},
		[]string{"role", "direction"},
	)

	// BFDHeartbeatsReceived counts valid BFD heartbeat packets received.
	// Labels: "role" (server|client).
	BFDHeartbeatsReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_bfd_heartbeats_received_total",
			Help: "Total valid BFD heartbeat packets received.",
		},
		[]string{"role"},
	)
)

func init() {
	metrics.Registry.MustRegister(
		BFDSessionsActive,
		BFDPacketsTx,
		BFDPacketsRx,
		BFDStateTransitions,
		BFDDetectTimeouts,
		BFDPacketErrors,
		BFDHeartbeatsReceived,
	)
}
