package main

import (
	"encoding/json"
	"math"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMedian(t *testing.T) {
	cases := []struct {
		name string
		in   []float64
		want float64
	}{
		{name: "empty", want: 0},
		{name: "one", in: []float64{3}, want: 3},
		{name: "odd", in: []float64{5, 1, 3}, want: 3},
		{name: "even", in: []float64{4, 1, 3, 2}, want: 2.5},
		{name: "six", in: []float64{1.9, 2.2, 1.7, 2.1, 2.0, 1.8}, want: 1.95},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := append([]float64(nil), tc.in...)
			assert.InDelta(t, tc.want, median(tc.in), 1e-9)
			assert.Equal(t, in, tc.in, "median must not sort its input")
		})
	}
}

// testRun returns a run with a rate, the client and server CPU per Gbps and an optional workload result.
func testRun(gbps, clientCPG, serverCPG float64, line string) Run {
	r := Run{Throughput: Throughput{Seconds: 30, BitsPerSecond: gbps * 1e9, Gbps: gbps, Retransmits: int64(math.Round(gbps * 10))}}
	r.CPU.WallS = 36
	r.CPU.Client = ProcCPU{Cores: clientCPG * gbps, CoresPerGbps: clientCPG}
	r.CPU.Server = ProcCPU{Cores: serverCPG * gbps, CoresPerGbps: serverCPG}
	if line != "" {
		r.WorkloadResult = json.RawMessage(line)
		r.CPU.Relay = markCPU(r.WorkloadResult, "relay")
	}
	return r
}

func TestSummarize(t *testing.T) {
	cases := []struct {
		name          string
		runs          []Run
		wantGbps      float64
		wantRetrans   int64
		wantClientCPG float64
		wantServerCPG float64
		wantRelay     *RelayCPU
		wantInfo      map[string]float64
	}{
		{
			name:     "one run",
			runs:     []Run{testRun(2, 0.5, 0.7, "")},
			wantGbps: 2, wantRetrans: 20, wantClientCPG: 0.5, wantServerCPG: 0.7,
		},
		{
			name: "three runs, each field on its own",
			runs: []Run{
				testRun(1.8, 0.6, 0.8, `{"relay_cores": 1.0, "relay_cores_per_gbps": 0.55, "load_rtt_ms": {"p99": 60}}`),
				testRun(2.2, 0.4, 0.9, `{"relay_cores": 1.2, "relay_cores_per_gbps": 0.5, "load_rtt_ms": {"p99": 40}}`),
				testRun(2.0, 0.5, 0.7, `{"relay_cores": 1.1, "relay_cores_per_gbps": 0.6, "load_rtt_ms": {"p99": 50}}`),
			},
			wantGbps: 2, wantRetrans: 20, wantClientCPG: 0.5, wantServerCPG: 0.8,
			wantRelay: &RelayCPU{Cores: 1.1, CoresPerGbps: 0.55},
			wantInfo:  map[string]float64{"relay_cores": 1.1, "relay_cores_per_gbps": 0.55, "load_rtt_ms.p99": 50},
		},
		{
			name: "after a retry, the median of 4 runs",
			runs: []Run{
				testRun(1.5, 0.6, 0.8, `{"relay_drops": 10}`),
				testRun(1.7, 0.5, 0.8, `{"relay_drops": 0}`),
				testRun(2.1, 0.5, 0.7, ""),
				testRun(2.3, 0.4, 0.7, `{"relay_drops": 4}`),
			},
			wantGbps: 1.9, wantRetrans: 19, wantClientCPG: 0.5, wantServerCPG: 0.75,
			wantInfo: map[string]float64{"relay_drops": 4},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := &Result{Runs: tc.runs}
			res.summarize()
			assert.Equal(t, len(tc.runs), res.Reps)
			assert.InDelta(t, tc.wantGbps, res.Throughput.Gbps, 1e-9)
			assert.InDelta(t, tc.wantGbps*1e9, res.Throughput.BitsPerSecond, 1)
			assert.Equal(t, tc.wantRetrans, res.Throughput.Retransmits)
			assert.InDelta(t, tc.wantClientCPG, res.CPU.Client.CoresPerGbps, 1e-9)
			assert.InDelta(t, tc.wantServerCPG, res.CPU.Server.CoresPerGbps, 1e-9)
			assert.Equal(t, 36.0, res.CPU.WallS)
			assert.Equal(t, tc.wantRelay, res.CPU.Relay)
			assert.Equal(t, tc.wantInfo, res.Info)
		})
	}
}

func TestWorkloadNumbers(t *testing.T) {
	line, err := os.ReadFile("testdata/vpcbench.json")
	require.NoError(t, err)
	got := workloadNumbers(json.RawMessage(line))
	for _, k := range []string{
		"retrans_percent", "load_rtt_ms.p50", "load_rtt_ms.p99", "idle_rtt_ms.p50",
		"client_cores_per_gbps", "relay_cores_per_gbps", "relay_drops", "server_rcvbuf_errors",
		"relay_rcvbuf_drops", "server_sock_drops", "omit.server_sock_drops",
		"omit.bits_per_second", "omit.retransmits", "omit.relay_drops", "omit.rtt_ms.p90", "omit.rtt_ms.max",
	} {
		assert.Contains(t, got, k)
	}
	for _, k := range []string{
		"seconds", "bits_per_second", "packets_per_second", "retransmits", // In Throughput.
		"flow_start_unix_ms", "window_start_unix_ms", "window_end_unix_ms", // Wall clock times.
		"driver", "cc", // Not numbers.
	} {
		assert.NotContains(t, got, k)
	}

	assert.Nil(t, workloadNumbers(nil))
	assert.Nil(t, workloadNumbers(json.RawMessage("[1, 2]")))
}

func TestMarkCPU(t *testing.T) {
	cases := []struct {
		name string
		line string
		role string
		want *RelayCPU
	}{
		{name: "relay", line: `{"relay_cores": 1.23456, "relay_cores_per_gbps": 0.6172839}`, role: "relay", want: &RelayCPU{Cores: 1.2346, CoresPerGbps: 0.617284}},
		{name: "server", line: `{"server_cores": 0.5, "server_cores_per_gbps": 0.25, "relay_cores": 0}`, role: "server", want: &RelayCPU{Cores: 0.5, CoresPerGbps: 0.25}},
		{
			name: "vpcbench line with text and objects", role: "client", want: &RelayCPU{Cores: 1.5, CoresPerGbps: 0.3},
			line: `{"driver": "netstack", "load_rtt_ms": {"p50": 1}, "client_cores": 1.5, "client_cores_per_gbps": 0.3}`,
		},
		{name: "direct has no relay", line: `{"relay_cores": 0, "relay_cores_per_gbps": 0}`, role: "relay"},
		{name: "no relay fields", line: `{"bits_per_second": 1e9}`, role: "relay"},
		{name: "no line", role: "relay"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, markCPU(json.RawMessage(tc.line), tc.role))
		})
	}
}

func TestJSONObjectLine(t *testing.T) {
	iperf3, err := os.ReadFile("testdata/iperf3-tcp.json")
	require.NoError(t, err)
	cases := []struct {
		name string
		out  string
		want string
	}{
		{name: "last line", out: "starting\n{\"seconds\": 30, \"bits_per_second\": 2e9}\n\n", want: `{"seconds": 30, "bits_per_second": 2e9}`},
		{name: "iperf3 JSON on many lines", out: string(iperf3)},
		{name: "text", out: "done: 2 Gbps\n"},
		{name: "array", out: "[1, 2]\n"},
		{name: "cut line", out: `{"seconds": 30,`},
		{name: "empty", out: "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := jsonObjectLine([]byte(tc.out))
			if tc.want == "" {
				assert.Nil(t, got)
				return
			}
			assert.Equal(t, tc.want, string(got))
		})
	}
}

func TestResultJSON(t *testing.T) {
	line, err := os.ReadFile("testdata/vpcbench.json")
	require.NoError(t, err)
	res := &Result{Key: "k", Runs: []Run{testRun(2, 0.5, 0.7, string(line))}}
	res.summarize()
	data, err := json.Marshal(res)
	require.NoError(t, err)

	var back Result
	require.NoError(t, json.Unmarshal(data, &back))
	assert.Equal(t, 1, back.Reps)
	require.Len(t, back.Runs, 1)
	assert.JSONEq(t, string(line), string(back.Runs[0].WorkloadResult))
	assert.NotNil(t, back.CPU.Relay)
	assert.Contains(t, back.Info, "load_rtt_ms.p99")
}
