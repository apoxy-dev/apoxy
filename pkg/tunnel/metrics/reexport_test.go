package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

func fakeFamily(name string, mtype dto.MetricType, value float64, labels ...[2]string) *dto.MetricFamily {
	lps := make([]*dto.LabelPair, 0, len(labels))
	for _, kv := range labels {
		lps = append(lps, &dto.LabelPair{
			Name:  proto.String(kv[0]),
			Value: proto.String(kv[1]),
		})
	}
	m := &dto.Metric{Label: lps}
	switch mtype {
	case dto.MetricType_GAUGE:
		m.Gauge = &dto.Gauge{Value: proto.Float64(value)}
	case dto.MetricType_COUNTER:
		m.Counter = &dto.Counter{Value: proto.Float64(value)}
	}
	return &dto.MetricFamily{
		Name:   proto.String(name),
		Type:   mtype.Enum(),
		Metric: []*dto.Metric{m},
	}
}

func TestReexportCollector_InjectsLabels(t *testing.T) {
	scraper := NewAgentScraper()

	// Inject a fake result directly.
	scraper.results["conn-1"] = &ScrapeResult{
		Target: ScrapeTarget{
			ConnID:      "conn-1",
			TunnelNode:  "my-laptop",
			AgentName:   "agent-1",
			ProjectID:   "proj-abc",
			OverlayAddr: "fd00::1",
		},
		Families: map[string]*dto.MetricFamily{
			"tunnel_connections_active": fakeFamily("tunnel_connections_active", dto.MetricType_GAUGE, 1),
			"tunnel_bytes_sent_total":   fakeFamily("tunnel_bytes_sent_total", dto.MetricType_COUNTER, 4096),
		},
		ScrapedAt: time.Now(),
	}

	collector := NewReexportCollector(scraper)

	// Collect into a channel.
	ch := make(chan prometheus.Metric, 100)
	collector.Collect(ch)
	close(ch)

	var collected []prometheus.Metric
	for m := range ch {
		collected = append(collected, m)
	}

	require.Len(t, collected, 2, "expected 2 metrics re-exported")

	// Verify labels are injected on each metric.
	for _, m := range collected {
		d := &dto.Metric{}
		require.NoError(t, m.Write(d))

		labelMap := make(map[string]string)
		for _, lp := range d.GetLabel() {
			labelMap[lp.GetName()] = lp.GetValue()
		}

		assert.Equal(t, "my-laptop", labelMap["tunnel_node"], "expected tunnel_node label")
		assert.Equal(t, "agent-1", labelMap["agent"], "expected agent label")
		assert.Equal(t, "proj-abc", labelMap["project_id"], "expected project_id label")
	}
}

func TestReexportCollector_SkipsStaleResults(t *testing.T) {
	scraper := NewAgentScraper()

	// Inject a stale result.
	scraper.results["conn-stale"] = &ScrapeResult{
		Target: ScrapeTarget{
			ConnID:     "conn-stale",
			TunnelNode: "stale-node",
		},
		Families: map[string]*dto.MetricFamily{
			"tunnel_connections_active": fakeFamily("tunnel_connections_active", dto.MetricType_GAUGE, 1),
		},
		ScrapedAt: time.Now().Add(-2 * StaleResultTimeout),
	}

	// Inject a fresh result.
	scraper.results["conn-fresh"] = &ScrapeResult{
		Target: ScrapeTarget{
			ConnID:     "conn-fresh",
			TunnelNode: "fresh-node",
		},
		Families: map[string]*dto.MetricFamily{
			"tunnel_connections_active": fakeFamily("tunnel_connections_active", dto.MetricType_GAUGE, 1),
		},
		ScrapedAt: time.Now(),
	}

	collector := NewReexportCollector(scraper)

	ch := make(chan prometheus.Metric, 100)
	collector.Collect(ch)
	close(ch)

	var collected []prometheus.Metric
	for m := range ch {
		collected = append(collected, m)
	}

	require.Len(t, collected, 1, "should only have fresh result")

	d := &dto.Metric{}
	require.NoError(t, collected[0].Write(d))
	labelMap := make(map[string]string)
	for _, lp := range d.GetLabel() {
		labelMap[lp.GetName()] = lp.GetValue()
	}
	assert.Equal(t, "fresh-node", labelMap["tunnel_node"])
}

func TestReexportCollector_PrefixesMetricNames(t *testing.T) {
	scraper := NewAgentScraper()

	scraper.results["conn-1"] = &ScrapeResult{
		Target: ScrapeTarget{
			ConnID:     "conn-1",
			TunnelNode: "node-1",
		},
		Families: map[string]*dto.MetricFamily{
			"test_metric": fakeFamily("test_metric", dto.MetricType_GAUGE, 42),
		},
		ScrapedAt: time.Now(),
	}

	collector := NewReexportCollector(scraper)

	ch := make(chan prometheus.Metric, 100)
	collector.Collect(ch)
	close(ch)

	m := <-ch
	desc := m.Desc().String()
	assert.Contains(t, desc, "apoxy_test_metric", "metric name should be prefixed with apoxy_")
}

// TestAgentMetricsNotRegisteredByInit verifies that init() does not register
// the agent-only metrics (tunnel_agent_info, tunnel_agent_uptime_seconds) with
// the controller-runtime metrics registry. These must only be registered via
// the explicit RegisterAgentMetrics() call from agent processes.
func TestAgentMetricsNotRegisteredByInit(t *testing.T) {
	// Gather all metrics from the controller-runtime registry (where init() registers).
	gatherer, ok := crmetrics.Registry.(prometheus.Gatherer)
	require.True(t, ok, "crmetrics.Registry must implement prometheus.Gatherer")

	families, err := gatherer.Gather()
	require.NoError(t, err)

	registered := make(map[string]bool)
	for _, f := range families {
		registered[f.GetName()] = true
	}

	// Agent-only metrics must NOT be present from init() alone.
	assert.False(t, registered["tunnel_agent_info"],
		"tunnel_agent_info should not be registered by init()")
	assert.False(t, registered["tunnel_agent_uptime_seconds"],
		"tunnel_agent_uptime_seconds should not be registered by init()")

	// Shared metrics should be present.
	assert.True(t, registered["tunnel_connections_active"],
		"tunnel_connections_active should be registered by init()")
	assert.True(t, registered["tunnel_packets_sent_total"],
		"tunnel_packets_sent_total should be registered by init()")
}

func TestReexportCollector_NoMetricsAfterUnregister(t *testing.T) {
	scraper := NewAgentScraper()

	scraper.results["conn-1"] = &ScrapeResult{
		Target: ScrapeTarget{
			ConnID:     "conn-1",
			TunnelNode: "node-1",
		},
		Families: map[string]*dto.MetricFamily{
			"tunnel_connections_active": fakeFamily("tunnel_connections_active", dto.MetricType_GAUGE, 1),
		},
		ScrapedAt: time.Now(),
	}

	// Unregister should remove the result.
	scraper.Unregister("conn-1")

	collector := NewReexportCollector(scraper)

	ch := make(chan prometheus.Metric, 100)
	collector.Collect(ch)
	close(ch)

	var collected []prometheus.Metric
	for m := range ch {
		collected = append(collected, m)
	}
	assert.Empty(t, collected, "no metrics should be emitted after unregister")
}
