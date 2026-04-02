package metrics

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
)

const (
	// StaleResultTimeout is how long a pushed result remains valid.
	// Results older than this are skipped during collection.
	StaleResultTimeout = 60 * time.Second

	labelTunnelNode = "tunnel_node"
	labelAgent      = "agent"
	labelProjectID  = "project_id"
)

// ReexportCollector implements prometheus.Collector by iterating over pushed
// agent metrics and re-emitting them with tunnel_node, agent, and project_id
// labels injected. It should be registered with the tunnelproxy's Prometheus
// registry so agent metrics appear on the tunnelproxy's /metrics endpoint.
type ReexportCollector struct {
	store  *MetricsStore
	prefix string
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
		if now.Sub(result.PushedAt) > StaleResultTimeout {
			return true
		}
		c.collectResult(ch, result)
		return true
	})
}

func (c *ReexportCollector) collectResult(ch chan<- prometheus.Metric, result *StoreResult) {
	extraLabels := []*dto.LabelPair{
		{Name: proto.String(labelTunnelNode), Value: proto.String(result.Target.TunnelNode)},
		{Name: proto.String(labelAgent), Value: proto.String(result.Target.AgentName)},
		{Name: proto.String(labelProjectID), Value: proto.String(result.Target.ProjectID)},
	}

	for name, family := range result.Families {
		prefixedName := c.prefix + name
		for _, m := range family.Metric {
			pm, err := c.toPrometheusMetric(prefixedName, family.GetType(), m, extraLabels)
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
	extraLabels []*dto.LabelPair,
) (prometheus.Metric, error) {
	// Copy labels to avoid mutating the protobuf message's backing array.
	existing := m.GetLabel()
	allLabels := make([]*dto.LabelPair, 0, len(existing)+len(extraLabels))
	allLabels = append(allLabels, existing...)
	allLabels = append(allLabels, extraLabels...)

	labelNames := make([]string, len(allLabels))
	labelValues := make([]string, len(allLabels))
	for i, lp := range allLabels {
		labelNames[i] = lp.GetName()
		labelValues[i] = lp.GetValue()
	}

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
