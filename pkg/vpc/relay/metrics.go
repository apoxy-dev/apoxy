// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

var (
	sessionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "apoxy_vpc_relay_sessions_total",
		Help: "Agent Session calls, by data mode and the reason for QUIC mode.",
	}, []string{"mode", "reason"})
	connectSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "apoxy_vpc_relay_connect_seconds",
		Help:    "Time to connect: from the start of the dial to the first Config, as the agent reports it.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"mode"})
)

func init() {
	metrics.Registry.MustRegister(sessionsTotal, connectSeconds)
}

// dropReason is a reason that the relay drops a packet.
type dropReason int

const (
	dropMalformed dropReason = iota
	dropUnknownSource
	dropUnknownSPI
	dropLaneMeter
	dropTunnelLimit
	numDropReasons
)

// dropLabels are the reason labels of the drop metric.
var dropLabels = [numDropReasons]string{"malformed", "unknown_source", "unknown_spi", "lane_meter", "tunnel_limit"}

var dropsDesc = prometheus.NewDesc("apoxy_vpc_relay_dropped_packets_total",
	"Packets that the relay dropped before it forwarded them, by reason.", []string{"reason"}, nil)

var _ prometheus.Collector = (*Router)(nil)

// Describe implements prometheus.Collector.
func (r *Router) Describe(ch chan<- *prometheus.Desc) { ch <- dropsDesc }

// Collect implements prometheus.Collector. It gives the drop counters.
func (r *Router) Collect(ch chan<- prometheus.Metric) {
	for i := range r.drops {
		ch <- prometheus.MustNewConstMetric(dropsDesc, prometheus.CounterValue, float64(r.drops[i].Load()), dropLabels[i])
	}
}

func modeLabel(m dp.Mode) string {
	switch m {
	case dp.Mode_MODE_PSP:
		return "psp"
	case dp.Mode_MODE_QUIC:
		return "quic"
	}
	return "unknown"
}

func reasonLabel(r dp.FallbackReason) string {
	switch r {
	case dp.FallbackReason_FALLBACK_REASON_UNSPECIFIED:
		return "none"
	case dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT:
		return "probe_timeout"
	case dp.FallbackReason_FALLBACK_REASON_CONFIG:
		return "config"
	}
	return "unknown"
}
