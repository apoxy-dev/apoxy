package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func result(key string, gbps, clientCPG, serverCPG float64) Result {
	var r Result
	r.Key = key
	r.Throughput.Gbps = gbps
	r.CPU.Client.CoresPerGbps = clientCPG
	r.CPU.Server.CoresPerGbps = serverCPG
	return r
}

func infraResult(key, why string) Result {
	r := result(key, 0, 0, 0)
	r.InfraError = why
	return r
}

func pps(r Result, v float64) Result {
	r.Throughput.PacketsPerSecond = v
	return r
}

func TestCompare(t *testing.T) {
	base := Baseline{Tolerance: 0.10, Entries: map[string]BaselineEntry{
		"k":     {Gbps: 10, ClientCoresPerGbps: 0.2, ServerCoresPerGbps: 0.4},
		"gbps":  {Gbps: 10},
		"pps":   {PacketsPerSecond: 500000},
		"loose": {Gbps: 10, ClientCoresPerGbps: 0.2, ServerCoresPerGbps: 0.4, Tolerance: 0.25},
		"floor": {MinGbps: 2},
		"both":  {Gbps: 2.2, MinGbps: 2},
	}}
	cases := []struct {
		name          string
		baseline      Baseline
		res           Result
		wantOK        bool
		wantRegressed []string
	}{
		{name: "no entry", baseline: base, res: result("other", 1, 1, 1), wantOK: false},
		{name: "same", baseline: base, res: result("k", 10, 0.2, 0.4), wantOK: true},
		{name: "better", baseline: base, res: result("k", 12, 0.1, 0.3), wantOK: true},
		{name: "small drop", baseline: base, res: result("k", 9.1, 0.21, 0.43), wantOK: true},
		{name: "throughput drop", baseline: base, res: result("k", 8.9, 0.2, 0.4), wantOK: true, wantRegressed: []string{"gbps"}},
		{
			name: "client cpu rise", baseline: base, res: result("k", 10, 0.23, 0.4),
			wantOK: true, wantRegressed: []string{"client_cores_per_gbps"},
		},
		{
			name: "all worse", baseline: base, res: result("k", 5, 0.4, 0.8),
			wantOK: true, wantRegressed: []string{"gbps", "client_cores_per_gbps", "server_cores_per_gbps"},
		},
		{name: "zero fields not checked", baseline: base, res: result("gbps", 10, 9, 9), wantOK: true},
		{name: "packet rate same", baseline: base, res: pps(result("pps", 0, 0, 0), 480000), wantOK: true},
		{
			name: "packet rate drop", baseline: base, res: pps(result("pps", 0, 0, 0), 250000),
			wantOK: true, wantRegressed: []string{"packets_per_second"},
		},
		{name: "entry tolerance", baseline: base, res: result("loose", 8, 0.24, 0.48), wantOK: true},
		{name: "above the floor", baseline: base, res: result("floor", 2.1, 0, 0), wantOK: true},
		{name: "at the floor", baseline: base, res: result("floor", 2, 0, 0), wantOK: true},
		{name: "below the floor", baseline: base, res: result("floor", 1.99, 0, 0), wantOK: true, wantRegressed: []string{"min_gbps"}},
		{name: "floor and baseline ok", baseline: base, res: result("both", 2.05, 0, 0), wantOK: true},
		{
			name: "below the floor and the baseline", baseline: base, res: result("both", 1.95, 0, 0),
			wantOK: true, wantRegressed: []string{"min_gbps", "gbps"},
		},
		{
			name:     "default tolerance",
			baseline: Baseline{Entries: map[string]BaselineEntry{"k": {Gbps: 10}}},
			res:      result("k", 8.95, 0, 0), wantOK: true, wantRegressed: []string{"gbps"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checks, ok := compare(tc.baseline, tc.res)
			require.Equal(t, tc.wantOK, ok)
			var regressed []string
			for _, c := range checks {
				if c.Regressed {
					regressed = append(regressed, c.Metric)
				}
			}
			assert.Equal(t, tc.wantRegressed, regressed)
		})
	}
}

func TestCompareResults(t *testing.T) {
	base := Baseline{Tolerance: 0.10, Entries: map[string]BaselineEntry{
		"k":          {Gbps: 10, ClientCoresPerGbps: 0.2},
		"pps":        {PacketsPerSecond: 500000},
		"empty":      {Source: "no numbers"},
		"floor":      {MinGbps: 2},
		"info":       {Gbps: 1, Info: true},
		"info-empty": {Info: true},
	}}
	cases := []struct {
		name     string
		results  []Result
		wantErr  error
		wantText []string
	}{
		{
			name:     "no baseline passes",
			results:  []Result{result("new", 3, 0.3, 0.3)},
			wantText: []string{"NO BASELINE new", "gbps=3", "packets_per_second=0"},
		},
		{
			name:     "pass",
			results:  []Result{result("k", 9.5, 0.2, 0.3)},
			wantText: []string{"PASS k", "-5.0%"},
		},
		{
			name:     "regression fails",
			results:  []Result{result("new", 3, 0.3, 0.3), result("k", 5, 0.2, 0.3)},
			wantErr:  errRegression,
			wantText: []string{"NO BASELINE new", "FAIL k", "REGRESSION"},
		},
		{
			name:     "packet rate drop fails",
			results:  []Result{pps(result("pps", 0, 0.3, 0.3), 250000)},
			wantErr:  errRegression,
			wantText: []string{"FAIL pps", "packets_per_second", "-50.0%", "REGRESSION"},
		},
		{
			name:     "entry with no metric fails",
			results:  []Result{result("empty", 3, 0.3, 0.3)},
			wantErr:  errRegression,
			wantText: []string{"FAIL empty", "checks no metric"},
		},
		{
			name:     "below the floor fails",
			results:  []Result{result("floor", 1.5, 0.3, 0.3)},
			wantErr:  errRegression,
			wantText: []string{"FAIL floor", "min_gbps", "-25.0%", "REGRESSION"},
		},
		{
			name:     "infra error",
			results:  []Result{result("k", 10, 0.2, 0.3), infraResult("k", "too much CPU steal: 7.10% in rep 2")},
			wantErr:  errInfra,
			wantText: []string{"PASS k", "INFRA k", "too much CPU steal"},
		},
		{
			name:     "regression and infra error",
			results:  []Result{result("k", 5, 0.2, 0.3), infraResult("pps", "rig setup: no netem")},
			wantErr:  errRegression,
			wantText: []string{"FAIL k", "INFRA pps", "rig setup: no netem"},
		},
		{
			name:     "info entry regression passes",
			results:  []Result{result("info", 0.5, 0.3, 0.3), result("info-empty", 1, 0.3, 0.3)},
			wantText: []string{"WARN info", "-50.0%", "REGRESSION", "WARN info-empty", "checks no metric"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			outcomes, err := compareResults(&out, base, tc.results)
			assert.Len(t, outcomes, len(tc.results))
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Equal(t, tc.wantErr == errInfra, errors.Is(err, errInfra))
			} else {
				require.NoError(t, err)
			}
			for _, s := range tc.wantText {
				assert.Contains(t, out.String(), s)
			}
		})
	}
}

func TestBaselineFiles(t *testing.T) {
	dir := t.TempDir()
	r := result("x86_64 iperf3-tcp streams=4", 9.5, 0.2, 0.3)
	data, err := json.Marshal(r)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.json"), data, 0o644))

	results, err := loadResults([]string{dir})
	require.NoError(t, err)
	require.Len(t, results, 1)

	path := filepath.Join(t.TempDir(), "baseline.json")
	_, err = loadBaseline(path, false)
	require.Error(t, err)
	b, err := loadBaseline(path, true)
	require.NoError(t, err)
	b.Entries[r.Key] = entryFor(results[0])
	require.NoError(t, saveBaseline(path, b))

	b, err = loadBaseline(path, false)
	require.NoError(t, err)
	assert.Equal(t, 9.5, b.Entries[r.Key].Gbps)
	assert.Equal(t, defaultTolerance, b.Tolerance)
	checks, ok := compare(b, r)
	require.True(t, ok)
	assert.Len(t, checks, 3)

	_, err = loadResults([]string{t.TempDir()})
	require.ErrorContains(t, err, "no result files")
}

func TestUpdateEntry(t *testing.T) {
	r := result("k", 2.4, 0.5, 0.6)
	cases := []struct {
		name string
		old  BaselineEntry
		want BaselineEntry
	}{
		{
			name: "new entry",
			want: BaselineEntry{Gbps: 2.4, ClientCoresPerGbps: 0.5, ServerCoresPerGbps: 0.6},
		},
		{
			name: "keeps the floor, the tolerance and the info flag",
			old:  BaselineEntry{Gbps: 2.1, MinGbps: 2, Tolerance: 0.2, Info: true, Source: "old"},
			want: BaselineEntry{Gbps: 2.4, ClientCoresPerGbps: 0.5, ServerCoresPerGbps: 0.6, MinGbps: 2, Tolerance: 0.2, Info: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := updateEntry(tc.old, r)
			tc.want.Source = got.Source
			assert.Equal(t, tc.want, got)
			assert.NotEqual(t, "old", got.Source)
		})
	}
}

func TestNeedsRetry(t *testing.T) {
	base := Baseline{Tolerance: 0.10, Entries: map[string]BaselineEntry{
		"floor": {Gbps: 2.2, MinGbps: 2, ClientCoresPerGbps: 0.5},
		"info":  {Gbps: 1, Info: true},
		"empty": {},
	}}
	cases := []struct {
		name string
		res  Result
		want bool
	}{
		{name: "pass", res: result("floor", 2.3, 0.5, 0), want: false},
		{name: "below the floor", res: result("floor", 1.9, 0.5, 0), want: true},
		{name: "cpu rise", res: result("floor", 2.3, 0.6, 0), want: true},
		{name: "info entry", res: result("info", 0.5, 0, 0), want: false},
		{name: "entry with no metric", res: result("empty", 1, 0, 0), want: false},
		{name: "no entry", res: result("other", 0.1, 0, 0), want: false},
		{name: "infra error", res: infraResult("floor", "too much CPU steal"), want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, needsRetry(base, tc.res))
		})
	}
}

func TestUpdateBaseline(t *testing.T) {
	b := Baseline{Entries: map[string]BaselineEntry{"k": {Gbps: 1, MinGbps: 2}}}
	var out bytes.Buffer
	updateBaseline(&out, b, []Result{result("k", 2.5, 0.1, 0.2), infraResult("bad", "rig setup: no netem")})
	assert.Equal(t, "SET k\nSKIP bad: rig setup: no netem\n", out.String())
	assert.Equal(t, 2.5, b.Entries["k"].Gbps)
	assert.Equal(t, 2.0, b.Entries["k"].MinGbps)
	assert.NotContains(t, b.Entries, "bad")
}
