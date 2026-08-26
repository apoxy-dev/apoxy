package metrics

import (
	"fmt"
	"strings"
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
	store := NewMetricsStore()

	// Inject a fake result directly.
	store.results["conn-1"] = &StoreResult{
		Target: StoreTarget{
			ConnID:         "conn-1",
			TunnelNode:     "my-laptop",
			AgentName:      "conn-1",
			AgentProcessID: "proc-xyz",
			ProjectID:      "proj-abc",
		},
		RegisteredAt: time.Now(),
		Families: map[string]*dto.MetricFamily{
			"tunnel_connections_active": fakeFamily("tunnel_connections_active", dto.MetricType_GAUGE, 1),
			"tunnel_bytes_sent_total":   fakeFamily("tunnel_bytes_sent_total", dto.MetricType_COUNTER, 4096),
		},
		PushedAt: time.Now(),
	}

	collector := NewReexportCollector(store)

	// Collect into a channel.
	ch := make(chan prometheus.Metric, 100)
	collector.Collect(ch)
	close(ch)

	var collected []prometheus.Metric
	for m := range ch {
		collected = append(collected, m)
	}

	// 2 re-exported agent metrics + 1 first-party connection uptime metric.
	require.Len(t, collected, 3, "expected 2 re-exported metrics + 1 conn uptime")

	// Verify labels are injected on each metric.
	for _, m := range collected {
		d := &dto.Metric{}
		require.NoError(t, m.Write(d))

		labelMap := make(map[string]string)
		for _, lp := range d.GetLabel() {
			labelMap[lp.GetName()] = lp.GetValue()
		}

		assert.Equal(t, "my-laptop", labelMap["tunnel_node"], "expected tunnel_node label")
		assert.Equal(t, "conn-1", labelMap["agent"], "expected legacy agent label (=conn_id)")
		assert.Equal(t, "conn-1", labelMap["conn_id"], "expected conn_id label")
		assert.Equal(t, "proc-xyz", labelMap["agent_process_id"], "expected agent_process_id label")
		assert.Equal(t, "proj-abc", labelMap["project_id"], "expected project_id label")
	}
}

func TestReexportCollector_SkipsStaleResults(t *testing.T) {
	store := NewMetricsStore()

	// Inject a stale result.
	store.results["conn-stale"] = &StoreResult{
		Target: StoreTarget{
			ConnID:     "conn-stale",
			TunnelNode: "stale-node",
		},
		RegisteredAt: time.Now().Add(-2 * StaleResultTimeout),
		Families: map[string]*dto.MetricFamily{
			"tunnel_connections_active": fakeFamily("tunnel_connections_active", dto.MetricType_GAUGE, 1),
		},
		PushedAt: time.Now().Add(-2 * StaleResultTimeout),
	}

	// Inject a fresh result.
	store.results["conn-fresh"] = &StoreResult{
		Target: StoreTarget{
			ConnID:     "conn-fresh",
			TunnelNode: "fresh-node",
		},
		RegisteredAt: time.Now(),
		Families: map[string]*dto.MetricFamily{
			"tunnel_connections_active": fakeFamily("tunnel_connections_active", dto.MetricType_GAUGE, 1),
		},
		PushedAt: time.Now(),
	}

	collector := NewReexportCollector(store)

	ch := make(chan prometheus.Metric, 100)
	collector.Collect(ch)
	close(ch)

	// Re-exported agent metrics are skipped when the push is stale, but
	// conn-uptime is still emitted for every registered connection.
	reexported := 0
	uptimes := map[string]float64{}
	for m := range ch {
		d := &dto.Metric{}
		require.NoError(t, m.Write(d))
		labels := map[string]string{}
		for _, lp := range d.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if strings.Contains(m.Desc().String(), connUptimeMetric) {
			uptimes[labels["tunnel_node"]] = d.GetGauge().GetValue()
			continue
		}
		reexported++
		assert.Equal(t, "fresh-node", labels["tunnel_node"],
			"only the fresh result should be re-exported")
	}
	assert.Equal(t, 1, reexported, "exactly one re-exported metric expected")
	assert.Len(t, uptimes, 2, "uptime should be emitted for both conns")
	assert.InDelta(t, (2 * StaleResultTimeout).Seconds(), uptimes["stale-node"], 1.0)
}

func TestReexportCollector_PrefixesMetricNames(t *testing.T) {
	store := NewMetricsStore()

	store.results["conn-1"] = &StoreResult{
		Target: StoreTarget{
			ConnID:     "conn-1",
			TunnelNode: "node-1",
		},
		RegisteredAt: time.Now(),
		Families: map[string]*dto.MetricFamily{
			"tunnel_test_metric": fakeFamily("tunnel_test_metric", dto.MetricType_GAUGE, 42),
		},
		PushedAt: time.Now(),
	}

	collector := NewReexportCollector(store)

	ch := make(chan prometheus.Metric, 100)
	collector.Collect(ch)
	close(ch)

	sawReexport := false
	for m := range ch {
		if strings.Contains(m.Desc().String(), "apoxy_tunnel_test_metric") {
			sawReexport = true
		}
	}
	assert.True(t, sawReexport, "re-exported metric should be prefixed with apoxy_")
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
	store := NewMetricsStore()

	store.results["conn-1"] = &StoreResult{
		Target: StoreTarget{
			ConnID:     "conn-1",
			TunnelNode: "node-1",
		},
		RegisteredAt: time.Now(),
		Families: map[string]*dto.MetricFamily{
			"tunnel_connections_active": fakeFamily("tunnel_connections_active", dto.MetricType_GAUGE, 1),
		},
		PushedAt: time.Now(),
	}

	// Unregister should remove the result.
	store.Unregister("conn-1")

	collector := NewReexportCollector(store)

	ch := make(chan prometheus.Metric, 100)
	collector.Collect(ch)
	close(ch)

	var collected []prometheus.Metric
	for m := range ch {
		collected = append(collected, m)
	}
	assert.Empty(t, collected, "no metrics should be emitted after unregister")
}

func TestMetricsStore_PushAndResults(t *testing.T) {
	store := NewMetricsStore()

	store.Register(StoreTarget{
		ConnID:     "conn-1",
		TunnelNode: "node-1",
		AgentName:  "agent-1",
		ProjectID:  "proj-1",
	})

	// Push metrics.
	families := map[string]*dto.MetricFamily{
		"test_gauge": fakeFamily("test_gauge", dto.MetricType_GAUGE, 42),
	}
	store.Push("conn-1", families)

	// Verify.
	results := store.Results()
	require.Len(t, results, 1)
	require.Contains(t, results, "conn-1")
	assert.Equal(t, "node-1", results["conn-1"].Target.TunnelNode)
	assert.Contains(t, results["conn-1"].Families, "test_gauge")
	assert.False(t, results["conn-1"].PushedAt.IsZero())
	assert.False(t, results["conn-1"].RegisteredAt.IsZero(),
		"Register must populate RegisteredAt for per-conn uptime")
}

// TestReexportCollector_ConnUptime verifies the first-party
// tunnel_connection_uptime_seconds metric reflects time since Register,
// independent of agent push state.
func TestReexportCollector_ConnUptime(t *testing.T) {
	store := NewMetricsStore()

	start := time.Now().Add(-42 * time.Second)
	store.results["conn-1"] = &StoreResult{
		Target: StoreTarget{
			ConnID:         "conn-1",
			TunnelNode:     "node-1",
			AgentName:      "conn-1",
			AgentProcessID: "proc-xyz",
			ProjectID:      "proj-1",
		},
		RegisteredAt: start,
		// No Push yet — conn just registered.
	}

	collector := NewReexportCollector(store)

	ch := make(chan prometheus.Metric, 100)
	collector.Collect(ch)
	close(ch)

	var found *dto.Metric
	var foundDesc string
	for m := range ch {
		if !strings.Contains(m.Desc().String(), connUptimeMetric) {
			continue
		}
		d := &dto.Metric{}
		require.NoError(t, m.Write(d))
		found = d
		foundDesc = m.Desc().String()
	}
	require.NotNil(t, found, "conn-uptime metric must be emitted even without a push")
	assert.Contains(t, foundDesc, "apoxy_"+connUptimeMetric)

	labels := map[string]string{}
	for _, lp := range found.GetLabel() {
		labels[lp.GetName()] = lp.GetValue()
	}
	assert.Equal(t, "node-1", labels[labelTunnelNode])
	assert.Equal(t, "conn-1", labels[labelAgent], "legacy label equals conn_id")
	assert.Equal(t, "conn-1", labels[labelConnID])
	assert.Equal(t, "proc-xyz", labels[labelAgentProcessID])
	assert.Equal(t, "proj-1", labels[labelProjectID])
	assert.InDelta(t, 42.0, found.GetGauge().GetValue(), 2.0,
		"uptime should reflect seconds since RegisteredAt")
}

// TestReexportCollector_DistinguishesProcesses verifies that two conns from
// the same agent process share agent_process_id, and the label is present
// on both re-exported metrics and the per-conn uptime metric.
func TestReexportCollector_DistinguishesProcesses(t *testing.T) {
	store := NewMetricsStore()

	// Two conns, same agent process.
	for _, cid := range []string{"conn-a", "conn-b"} {
		store.results[cid] = &StoreResult{
			Target: StoreTarget{
				ConnID:         cid,
				TunnelNode:     "laptop-1",
				AgentName:      cid,
				AgentProcessID: "same-proc-uuid",
				ProjectID:      "proj-1",
			},
			RegisteredAt: time.Now(),
			Families: map[string]*dto.MetricFamily{
				"tunnel_agent_uptime_seconds": fakeFamily(
					"tunnel_agent_uptime_seconds", dto.MetricType_GAUGE, 99),
			},
			PushedAt: time.Now(),
		}
	}

	collector := NewReexportCollector(store)
	ch := make(chan prometheus.Metric, 100)
	collector.Collect(ch)
	close(ch)

	procIDs := map[string]struct{}{}
	connIDs := map[string]struct{}{}
	for m := range ch {
		d := &dto.Metric{}
		require.NoError(t, m.Write(d))
		for _, lp := range d.GetLabel() {
			if lp.GetName() == labelAgentProcessID {
				procIDs[lp.GetValue()] = struct{}{}
			}
			if lp.GetName() == labelConnID {
				connIDs[lp.GetValue()] = struct{}{}
			}
		}
	}
	assert.Equal(t, map[string]struct{}{"same-proc-uuid": {}}, procIDs,
		"both conns must share the same agent_process_id")
	assert.Equal(t, map[string]struct{}{"conn-a": {}, "conn-b": {}}, connIDs,
		"conn_id must differ per connection")
}

func TestMetricsStore_PushUnknownConnID(t *testing.T) {
	store := NewMetricsStore()

	// Push to unknown connection — should be a no-op.
	store.Push("unknown", map[string]*dto.MetricFamily{
		"test": fakeFamily("test", dto.MetricType_GAUGE, 1),
	})

	assert.Empty(t, store.Results())
}

// TestReexportCollector_FiltersToTunnelFamilies pins which pushed families
// reach the scrape. An agent gathers its whole registry, so the push carries
// the Go runtime, process, client-go, and workqueue families as well; every
// one of them would be multiplied by the number of connections the relay
// holds, and nothing reads them.
func TestReexportCollector_FiltersToTunnelFamilies(t *testing.T) {
	cases := []struct {
		name string
		// family is the family name the agent pushed.
		family string
		// wantReexported is whether the scrape carries it.
		wantReexported bool
	}{
		{
			name:           "a tunnel family is re-exported",
			family:         "tunnel_connections_active",
			wantReexported: true,
		},
		{
			name:           "the agent info family is re-exported",
			family:         "tunnel_agent_info",
			wantReexported: true,
		},
		{
			name:   "the Go runtime families are dropped",
			family: "go_goroutines",
		},
		{
			name:   "the process families are dropped",
			family: "process_resident_memory_bytes",
		},
		{
			name:   "the client-go families are dropped",
			family: "rest_client_requests_total",
		},
		{
			name:   "the workqueue families are dropped",
			family: "workqueue_depth",
		},
		{
			name:   "the controller-runtime families are dropped",
			family: "controller_runtime_reconcile_total",
		},
		{
			name:   "a name that only begins with tunnel is dropped",
			family: "tunnelish_metric",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := NewMetricsStore()
			store.Register(StoreTarget{ConnID: "conn-1", TunnelNode: "node-1"})
			store.Push("conn-1", map[string]*dto.MetricFamily{
				tc.family: fakeFamily(tc.family, dto.MetricType_GAUGE, 1),
			})

			ch := make(chan prometheus.Metric, 100)
			NewReexportCollector(store).Collect(ch)
			close(ch)

			sawFamily, sawUptime := false, false
			for m := range ch {
				desc := m.Desc().String()
				switch {
				case strings.Contains(desc, "apoxy_"+connUptimeMetric):
					sawUptime = true
				case strings.Contains(desc, "apoxy_"+tc.family):
					sawFamily = true
				}
			}

			assert.Equal(t, tc.wantReexported, sawFamily,
				"re-export of %q", tc.family)
			assert.True(t, sawUptime,
				"the first-party conn uptime metric is emitted whatever the agent pushed")
			assert.Equal(t, tc.wantReexported, ReexportsFamily(tc.family))
		})
	}
}

// TestReexportCollector_PushIsNotBlockedByCollect pins that a scrape does not
// hold agent pushes off. The collector copies the results out and converts the
// copy with no lock held, so a consumer that reads the channel slowly stalls
// only itself. Converting under the read lock made every push on the relay
// wait for the whole scrape.
func TestReexportCollector_PushIsNotBlockedByCollect(t *testing.T) {
	store := NewMetricsStore()
	store.Register(StoreTarget{ConnID: "conn-1", TunnelNode: "node-1"})

	// Many families, so the collector is still mid-iteration when the push
	// arrives.
	families := make(map[string]*dto.MetricFamily, 200)
	for i := 0; i < 200; i++ {
		name := fmt.Sprintf("tunnel_family_%d", i)
		families[name] = fakeFamily(name, dto.MetricType_GAUGE, float64(i))
	}
	store.Push("conn-1", families)

	// Unbuffered: every send waits for this test to read.
	ch := make(chan prometheus.Metric)
	collectDone := make(chan struct{})
	go func() {
		defer close(collectDone)
		collector := NewReexportCollector(store)
		collector.Collect(ch)
		close(ch)
	}()
	// Unblock the collector even if an assertion below ends the test early.
	t.Cleanup(func() {
		for range ch {
		}
		<-collectDone
	})

	// Take one metric: the collector now waits to send the next one.
	first := <-ch
	require.NotNil(t, first)

	pushDone := make(chan struct{})
	go func() {
		defer close(pushDone)
		store.Push("conn-1", map[string]*dto.MetricFamily{
			"tunnel_late_push": fakeFamily("tunnel_late_push", dto.MetricType_GAUGE, 1),
		})
	}()

	select {
	case <-pushDone:
	case <-time.After(5 * time.Second):
		t.Fatal("an agent push waited on a scrape that is still mid-iteration")
	}

	// Draining the rest walks the copy the collector took, so the late push is
	// not part of this scrape and the collector never reads a map another
	// goroutine is replacing.
	sawLatePush := false
	drained := 1
	for m := range ch {
		drained++
		if strings.Contains(m.Desc().String(), "apoxy_tunnel_late_push") {
			sawLatePush = true
		}
	}
	<-collectDone

	assert.False(t, sawLatePush, "a push during a scrape must not change the scrape")
	assert.Equal(t, len(families)+1, drained,
		"every family in the copy plus the conn uptime metric")
}

// TestMetricsStore_SnapshotIsNotChangedByPush pins the property the collector
// depends on: a push replaces the whole family map, so a copy taken earlier
// keeps reading the map it was given.
func TestMetricsStore_SnapshotIsNotChangedByPush(t *testing.T) {
	store := NewMetricsStore()
	store.Register(StoreTarget{ConnID: "conn-1", TunnelNode: "node-1"})
	store.Push("conn-1", map[string]*dto.MetricFamily{
		"tunnel_first": fakeFamily("tunnel_first", dto.MetricType_GAUGE, 1),
	})

	snapshot := store.Snapshot()
	require.Len(t, snapshot, 1)
	require.Equal(t, "conn-1", snapshot[0].Target.ConnID)

	store.Push("conn-1", map[string]*dto.MetricFamily{
		"tunnel_second": fakeFamily("tunnel_second", dto.MetricType_GAUGE, 2),
	})

	assert.Contains(t, snapshot[0].Families, "tunnel_first",
		"a push must replace the map, not write into the one a reader holds")
	assert.NotContains(t, snapshot[0].Families, "tunnel_second")
	assert.Contains(t, store.Snapshot()[0].Families, "tunnel_second",
		"a later copy sees the newer push")
}
