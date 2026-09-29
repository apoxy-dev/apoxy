package main

import (
	"bytes"
	"encoding/json"
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

func TestCompare(t *testing.T) {
	base := Baseline{Tolerance: 0.10, Entries: map[string]BaselineEntry{
		"k":     {Gbps: 10, ClientCoresPerGbps: 0.2, ServerCoresPerGbps: 0.4},
		"gbps":  {Gbps: 10},
		"loose": {Gbps: 10, ClientCoresPerGbps: 0.2, ServerCoresPerGbps: 0.4, Tolerance: 0.25},
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
		{name: "entry tolerance", baseline: base, res: result("loose", 8, 0.24, 0.48), wantOK: true},
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
	base := Baseline{Tolerance: 0.10, Entries: map[string]BaselineEntry{"k": {Gbps: 10, ClientCoresPerGbps: 0.2}}}
	cases := []struct {
		name     string
		results  []Result
		wantErr  bool
		wantText []string
	}{
		{
			name:     "no baseline passes",
			results:  []Result{result("new", 3, 0.3, 0.3)},
			wantText: []string{"NO BASELINE new", "gbps=3"},
		},
		{
			name:     "pass",
			results:  []Result{result("k", 9.5, 0.2, 0.3)},
			wantText: []string{"PASS k", "-5.0%"},
		},
		{
			name:     "regression fails",
			results:  []Result{result("new", 3, 0.3, 0.3), result("k", 5, 0.2, 0.3)},
			wantErr:  true,
			wantText: []string{"NO BASELINE new", "FAIL k", "REGRESSION"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := compareResults(&out, base, tc.results)
			if tc.wantErr {
				require.ErrorIs(t, err, errRegression)
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
