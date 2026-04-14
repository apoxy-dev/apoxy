package metrics

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const (
	// StaleResultTimeout is how long a pushed result remains valid.
	// Results older than this are skipped during collection.
	StaleResultTimeout = 60 * time.Second

	labelTunnelNode     = "tunnel_node"
	labelAgent          = "agent" // Deprecated alias for conn_id; retained for dashboard compatibility.
	labelConnID         = "conn_id"
	labelAgentProcessID = "agent_process_id"
	labelProjectID      = "project_id"

	// connUptimeMetric is the first-party per-connection uptime metric emitted
	// by the ReexportCollector (computed from StoreResult.RegisteredAt). Unlike
	// tunnel_agent_uptime_seconds — which is re-exported from the agent and
	// reports the agent *process* uptime duplicated across every conn_id — this
	// metric reflects the lifetime of a single CONNECT-IP session.
	connUptimeMetric = "tunnel_connection_uptime_seconds"
)

// targetLabelNames is the canonical order of the labels we inject on every
// metric emitted by this collector (both re-exported agent metrics and the
// first-party conn uptime gauge). Single source of truth so the connUptimeDesc
// and per-result label-value slice stay in lock-step.
var targetLabelNames = []string{
	labelTunnelNode,
	labelAgent,
	labelConnID,
	labelAgentProcessID,
	labelProjectID,
}

func targetLabelValues(t StoreTarget) []string {
	return []string{
		t.TunnelNode,
		t.AgentName, // legacy "agent" value; today always equal to ConnID on the server side
		t.ConnID,
		t.AgentProcessID,
		t.ProjectID,
	}
}

// ReexportCollector implements prometheus.Collector by iterating over pushed
// agent metrics and re-emitting them with tunnel_node, agent, conn_id,
// agent_process_id, and project_id labels injected. It should be registered
// with the tunnelproxy's Prometheus registry so agent metrics appear on the
// tunnelproxy's /metrics endpoint.
type ReexportCollector struct {
	store          *MetricsStore
	prefix         string
	connUptimeDesc *prometheus.Desc
}

// ReexportOption configures a ReexportCollector.
type ReexportOption func(*ReexportCollector)

// WithReexportPrefix sets a prefix added to all re-exported metric names.
// Defaults to "apoxy_".
func WithReexportPrefix(prefix string) ReexportOption {
	return func(c *ReexportCollector) { c.prefix = prefix }
}

// NewReexportCollector creates a new ReexportCollector backed by the given store.
func NewReexportCollector(store *MetricsStore, opts ...ReexportOption) *ReexportCollector {
	c := &ReexportCollector{
		store:  store,
		prefix: "apoxy_",
	}
	for _, o := range opts {
		o(c)
	}
	c.connUptimeDesc = prometheus.NewDesc(
		c.prefix+connUptimeMetric,
		"Seconds since this tunnel connection was registered with the tunnelproxy.",
		targetLabelNames,
		nil,
	)
	return c
}

// Describe implements prometheus.Collector. Because the set of metrics is
// dynamic (depends on what the agents export), we emit no fixed descriptors
// and mark this as an unchecked collector.
func (c *ReexportCollector) Describe(ch chan<- *prometheus.Desc) {}

// Collect implements prometheus.Collector. It takes a snapshot of the store
// results (briefly holding RLock), then iterates the snapshot without any lock.
func (c *ReexportCollector) Collect(ch chan<- prometheus.Metric) {
	now := time.Now()
	c.store.ForEachResult(func(connID string, result *StoreResult) bool {
		values := targetLabelValues(result.Target)
		// Guard tolerates tests that populate store.results directly, bypassing
		// Register. In production Register always stamps RegisteredAt.
		if !result.RegisteredAt.IsZero() {
			ch <- prometheus.MustNewConstMetric(
				c.connUptimeDesc,
				prometheus.GaugeValue,
				now.Sub(result.RegisteredAt).Seconds(),
				values...,
			)
		}
		if now.Sub(result.PushedAt) > StaleResultTimeout {
			return true
		}
		c.collectResult(ch, result, values)
		return true
	})
}

func (c *ReexportCollector) collectResult(
	ch chan<- prometheus.Metric,
	result *StoreResult,
	targetValues []string,
) {
	for name, family := range result.Families {
		prefixedName := c.prefix + name
		for _, m := range family.Metric {
			pm, err := c.toPrometheusMetric(prefixedName, family.GetType(), m, targetValues)
			if err != nil {
				slog.Debug("Skipping metric",
					slog.String("name", prefixedName),
					slog.Any("error", err),
				)
				continue
			}
			ch <- pm
		}
	}
}

func (c *ReexportCollector) toPrometheusMetric(
	name string,
	mtype dto.MetricType,
	m *dto.Metric,
	targetValues []string,
) (prometheus.Metric, error) {
	existing := m.GetLabel()
	labelNames := make([]string, 0, len(existing)+len(targetLabelNames))
	labelValues := make([]string, 0, len(existing)+len(targetLabelNames))
	for _, lp := range existing {
		labelNames = append(labelNames, lp.GetName())
		labelValues = append(labelValues, lp.GetValue())
	}
	labelNames = append(labelNames, targetLabelNames...)
	labelValues = append(labelValues, targetValues...)

	desc := prometheus.NewDesc(name, "Re-exported agent metric.", labelNames, nil)

	switch mtype {
	case dto.MetricType_COUNTER:
		return prometheus.NewConstMetric(desc, prometheus.CounterValue,
			m.GetCounter().GetValue(), labelValues...)
	case dto.MetricType_GAUGE:
		return prometheus.NewConstMetric(desc, prometheus.GaugeValue,
			m.GetGauge().GetValue(), labelValues...)
	case dto.MetricType_UNTYPED:
		return prometheus.NewConstMetric(desc, prometheus.UntypedValue,
			m.GetUntyped().GetValue(), labelValues...)
	case dto.MetricType_SUMMARY:
		quantiles := make(map[float64]float64)
		for _, q := range m.GetSummary().GetQuantile() {
			quantiles[q.GetQuantile()] = q.GetValue()
		}
		return prometheus.NewConstSummary(desc,
			m.GetSummary().GetSampleCount(),
			m.GetSummary().GetSampleSum(),
			quantiles, labelValues...)
	case dto.MetricType_HISTOGRAM:
		buckets := make(map[float64]uint64)
		for _, b := range m.GetHistogram().GetBucket() {
			buckets[b.GetUpperBound()] = b.GetCumulativeCount()
		}
		return prometheus.NewConstHistogram(desc,
			m.GetHistogram().GetSampleCount(),
			m.GetHistogram().GetSampleSum(),
			buckets, labelValues...)
	default:
		return nil, fmt.Errorf("unsupported metric type: %v", mtype)
	}
}
