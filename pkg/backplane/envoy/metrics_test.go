package envoy

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gatherNames returns the names of the families the runtime exports.
func gatherNames(t *testing.T, r *Runtime) ([]string, map[string]*dto.MetricFamily) {
	t.Helper()

	families, err := r.Gatherer().Gather()
	require.NoError(t, err)

	byName := make(map[string]*dto.MetricFamily, len(families))
	names := make([]string, 0, len(families))
	for _, mf := range families {
		byName[mf.GetName()] = mf
		names = append(names, mf.GetName())
	}
	sort.Strings(names)

	return names, byName
}

// familyValue returns the value of the first metric of the family.
func familyValue(t *testing.T, mf *dto.MetricFamily) float64 {
	t.Helper()

	require.NotNil(t, mf)
	require.NotEmpty(t, mf.GetMetric())
	m := mf.GetMetric()[0]
	if m.GetGauge() != nil {
		return m.GetGauge().GetValue()
	}
	require.NotNil(t, m.GetCounter())

	return m.GetCounter().GetValue()
}

// labelValue returns the value of label on the first metric of the family.
func labelValue(mf *dto.MetricFamily, label string) string {
	if mf == nil || len(mf.GetMetric()) == 0 {
		return ""
	}
	for _, l := range mf.GetMetric()[0].GetLabel() {
		if l.GetName() == label {
			return l.GetValue()
		}
	}

	return ""
}

func TestMetricsRenderedNames(t *testing.T) {
	startedAt := time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)
	exitedAt := startedAt.Add(time.Hour)
	requests := int64(7)
	connections := int64(11)
	maxConns := uint64(50000)
	maxHeap := uint64(1 << 30)

	// The names every state exports.
	always := []string{
		"apoxy_backplane_envoy_up",
		"apoxy_backplane_envoy_restarts_total",
		"apoxy_backplane_envoy_info",
		"apoxy_backplane_envoy_admin_scrape_errors_total",
	}

	cases := []struct {
		name      string
		setup     func(r *Runtime)
		wantNames []string
		missing   []string
	}{
		{
			name:      "envoy never started",
			setup:     func(r *Runtime) {},
			wantNames: always,
			missing: []string{
				"apoxy_backplane_envoy_start_time_seconds",
				"apoxy_backplane_envoy_last_exit_timestamp_seconds",
				"apoxy_backplane_envoy_exits_total",
				"apoxy_backplane_envoy_last_exit_connections",
			},
		},
		{
			name: "envoy runs",
			setup: func(r *Runtime) {
				r.status.Running = true
				r.status.StartedAt = startedAt
				r.tel.limits = Limits{
					MaxActiveDownstreamConnections: &maxConns,
					MaxHeapBytes:                   &maxHeap,
				}
				r.tel.dnsCacheMaxHosts = map[string]uint64{"dynamic_proxy": 1024}
			},
			wantNames: append([]string{
				"apoxy_backplane_envoy_start_time_seconds",
				"apoxy_backplane_envoy_limit_max_active_downstream_connections",
				"apoxy_backplane_envoy_limit_max_heap_bytes",
				"apoxy_backplane_envoy_limit_dns_cache_max_hosts",
			}, always...),
			missing: []string{"apoxy_backplane_envoy_last_exit_timestamp_seconds"},
		},
		{
			name: "envoy exited twice",
			setup: func(r *Runtime) {
				r.status.StartedAt = startedAt
				r.status.Restarts = 2
				r.status.ExitCounts = map[ExitKey]int64{
					{Reason: ExitReasonSignal, Code: "SIGSEGV"}: 1,
					{Reason: ExitReasonExit, Code: "1"}:         1,
				}
				r.status.LastExit = &ExitInfo{
					At:                 exitedAt,
					Reason:             ExitReasonSignal,
					Code:               "SIGSEGV",
					RequestsInFlight:   &requests,
					Connections:        &connections,
					ConnectionsAborted: 3,
					ConnectionsRefused: 5,
				}
			},
			wantNames: append([]string{
				"apoxy_backplane_envoy_exits_total",
				"apoxy_backplane_envoy_last_exit_timestamp_seconds",
				"apoxy_backplane_envoy_last_exit_requests_in_flight",
				"apoxy_backplane_envoy_last_exit_connections",
				"apoxy_backplane_envoy_last_exit_connections_aborted",
				"apoxy_backplane_envoy_last_exit_connections_refused",
			}, always...),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runtime{}
			r.Configure(WithIdentity("gw", "gw-0", ""))
			tc.setup(r)

			names, byName := gatherNames(t, r)

			for _, want := range tc.wantNames {
				assert.Contains(t, names, want)
			}
			for _, missing := range tc.missing {
				assert.NotContains(t, names, missing)
			}

			// Every datapoint carries the proxy and the replica.
			for _, mf := range byName {
				assert.Equal(t, "gw", labelValue(mf, "proxy"), mf.GetName())
				assert.Equal(t, "gw-0", labelValue(mf, "replica"), mf.GetName())
			}

			lints, err := testutil.GatherAndLint(r.Gatherer())
			require.NoError(t, err)
			assert.Empty(t, lints)
		})
	}
}

// fixedSource reports the same sample on every collection.
type fixedSource struct {
	s runtimeSample
}

// sample implements the metricsSource interface.
func (f *fixedSource) sample() runtimeSample { return f.s }

func TestMetricsNamesOnLinux(t *testing.T) {
	requests := int64(7)
	connections := int64(11)
	maxConns := uint64(50000)
	maxHeap := uint64(1 << 30)

	src := &fixedSource{s: runtimeSample{
		Identity:   Identity{Proxy: "gw", Replica: "gw-0"},
		Running:    true,
		StartedAt:  time.Now(),
		Restarts:   1,
		ExitCounts: map[ExitKey]int64{{Reason: ExitReasonExit, Code: "1"}: 1},
		LastExit: &ExitInfo{
			At:                 time.Now(),
			Reason:             ExitReasonExit,
			Code:               "1",
			RequestsInFlight:   &requests,
			Connections:        &connections,
			ConnectionsAborted: 2,
			ConnectionsRefused: 3,
		},
		Release:          "v1.35.13",
		EnvoyVersion:     "1.35.13",
		Limits:           Limits{MaxActiveDownstreamConnections: &maxConns, MaxHeapBytes: &maxHeap},
		MemoryLimitBytes: 2 << 30,
		MemoryLimitKnown: true,
		DNSCacheMaxHosts: map[string]uint64{"dynamic_proxy": 1024},
		Process:          &processStats{OpenFDs: 120, MaxFDs: 1024, RSSBytes: 4096},
		TCP: &tcpCounters{
			OutRsts: 1, EstabResets: 2, AbortOnClose: 3,
			AbortOnData: 4, ListenOverflows: 5, ListenDrops: 6,
		},
	}}

	m, err := NewMetrics(src, src.s.Identity, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })

	families, err := m.Gatherer().Gather()
	require.NoError(t, err)
	names := make([]string, 0, len(families))
	for _, mf := range families {
		names = append(names, mf.GetName())
	}
	sort.Strings(names)

	assert.Equal(t, []string{
		"apoxy_backplane_envoy_admin_scrape_errors_total",
		"apoxy_backplane_envoy_exits_total",
		"apoxy_backplane_envoy_info",
		"apoxy_backplane_envoy_last_exit_connections",
		"apoxy_backplane_envoy_last_exit_connections_aborted",
		"apoxy_backplane_envoy_last_exit_connections_refused",
		"apoxy_backplane_envoy_last_exit_requests_in_flight",
		"apoxy_backplane_envoy_last_exit_timestamp_seconds",
		"apoxy_backplane_envoy_limit_dns_cache_max_hosts",
		"apoxy_backplane_envoy_limit_max_active_downstream_connections",
		"apoxy_backplane_envoy_limit_max_heap_bytes",
		"apoxy_backplane_envoy_limit_memory_bytes",
		"apoxy_backplane_envoy_max_fds",
		"apoxy_backplane_envoy_open_fds",
		"apoxy_backplane_envoy_restarts_total",
		"apoxy_backplane_envoy_rss_bytes",
		"apoxy_backplane_envoy_start_time_seconds",
		"apoxy_backplane_envoy_up",
		"apoxy_backplane_net_tcp_abort_on_close_total",
		"apoxy_backplane_net_tcp_abort_on_data_total",
		"apoxy_backplane_net_tcp_estab_resets_total",
		"apoxy_backplane_net_tcp_listen_drops_total",
		"apoxy_backplane_net_tcp_listen_overflows_total",
		"apoxy_backplane_net_tcp_out_rsts_total",
	}, names)
}

func TestMetricsValues(t *testing.T) {
	requests := int64(7)
	connections := int64(11)

	r := &Runtime{}
	r.Configure(WithIdentity("gw", "gw-0", "proj-1"))
	r.status.Running = true
	r.status.Restarts = 3
	r.status.ExitCounts = map[ExitKey]int64{{Reason: ExitReasonOOMKill, Code: "SIGKILL"}: 2}
	r.status.LastExit = &ExitInfo{
		At:                 time.Now(),
		Reason:             ExitReasonOOMKill,
		Code:               "SIGKILL",
		RequestsInFlight:   &requests,
		Connections:        &connections,
		ConnectionsAborted: 3,
		ConnectionsRefused: 5,
	}
	r.tel.envoyVersion = "1.35.13"
	r.tel.adminScrapeErrors.Store(4)

	_, byName := gatherNames(t, r)

	assert.Equal(t, 1.0, familyValue(t, byName["apoxy_backplane_envoy_up"]))
	assert.Equal(t, 3.0, familyValue(t, byName["apoxy_backplane_envoy_restarts_total"]))
	assert.Equal(t, 2.0, familyValue(t, byName["apoxy_backplane_envoy_exits_total"]))
	assert.Equal(t, 4.0, familyValue(t, byName["apoxy_backplane_envoy_admin_scrape_errors_total"]))
	assert.Equal(t, 7.0, familyValue(t, byName["apoxy_backplane_envoy_last_exit_requests_in_flight"]))
	assert.Equal(t, 11.0, familyValue(t, byName["apoxy_backplane_envoy_last_exit_connections"]))
	assert.Equal(t, 3.0, familyValue(t, byName["apoxy_backplane_envoy_last_exit_connections_aborted"]))
	assert.Equal(t, 5.0, familyValue(t, byName["apoxy_backplane_envoy_last_exit_connections_refused"]))

	assert.Equal(t, ExitReasonOOMKill, labelValue(byName["apoxy_backplane_envoy_exits_total"], "reason"))
	assert.Equal(t, "SIGKILL", labelValue(byName["apoxy_backplane_envoy_exits_total"], "code"))
	assert.Equal(t, "1.35.13", labelValue(byName["apoxy_backplane_envoy_info"], "envoy_version"))
	assert.Equal(t, "proj-1", labelValue(byName["apoxy_backplane_envoy_up"], "project_id"))
}
