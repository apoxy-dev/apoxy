package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteSummary(t *testing.T) {
	line, err := os.ReadFile("testdata/vpcbench.json")
	require.NoError(t, err)

	gate := &Result{Key: "aarch64 vpc-netstack-psp-relay streams=4", Workload: "vpc-netstack-psp-relay", Retried: true,
		Runs: []Run{testRun(1.9, 0.8, 1.1, string(line)), testRun(2.1, 0.8, 1.1, string(line))}}
	gate.Settings.Streams = 4
	gate.summarize()
	loss := &Result{Key: "aarch64 vpc-netstack-psp-relay-loss streams=4", Workload: "vpc-netstack-psp-relay-loss",
		Runs: []Run{testRun(0.8, 0.9, 1.2, "")}}
	loss.Settings.Streams, loss.Settings.LossPercent, loss.Settings.Rate = 4, 0.1, "1000mbit"
	loss.summarize()
	base := Baseline{Tolerance: 0.10, Entries: map[string]BaselineEntry{
		gate.Key: {Gbps: 2.3, MinGbps: 2.0},
		"info":   {Gbps: 1, Info: true},
	}}

	var buf bytes.Buffer
	bad := infraResult("aarch64 vpc-tun-psp-relay streams=4", "too much CPU steal: 7.10% in rep 2, -max-steal is 5%")
	writeSummary(&buf, []outcome{evaluate(base, *gate), evaluate(base, *loss), evaluate(base, bad)})
	out := buf.String()

	rows := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Split(l, " | "); len(f) > 2 && strings.HasPrefix(l, "| ") {
			rows[strings.TrimPrefix(f[0], "| ")] = l
		}
	}
	assert.Equal(t, "| FAIL | vpc-netstack-psp-relay, 4 flows | 2.00 (retried) | 1.90 2.10 | 2.00 | 2.30 (-13.0%) | 0.80, 1.10, 2.25 | 0.00 | 20.8, 39.7 | 25.6, 30.7 | 15, 2310 |",
		rows["FAIL"], "2.00 is more than 10 percent below the 2.30 baseline")
	assert.Equal(t, "| NO BASELINE | vpc-netstack-psp-relay-loss, 4 flows, loss 0.1%, rate 1000mbit | 0.80 | 0.80 | - | - | 0.90, 1.20, - | - | - | - | - |",
		rows["NO BASELINE"])
	assert.Contains(t, out, "| Status | Workload | Gbps |")
	assert.Contains(t, out, "- FAIL `aarch64 vpc-netstack-psp-relay streams=4`; min_gbps 2.0000 (baseline 2.0000, +0.0%, ok); gbps 2.0000 (baseline 2.3000, -13.0%, REGRESSION)"+
		"; drops omit/window: client link 15/2310, client tx 0/0, relay 0/0, server rcvbuf 0/0, server rx 0/0, server link 0/0"+
		"; server retx omit/window: 0/0\n")
	assert.Contains(t, out, "- NO BASELINE `aarch64 vpc-netstack-psp-relay-loss streams=4`\n")
	assert.Contains(t, rows, "INFRA")
	assert.Contains(t, out, "- INFRA `aarch64 vpc-tun-psp-relay streams=4`; too much CPU steal: 7.10% in rep 2, -max-steal is 5%\n")
}

func TestInfoCells(t *testing.T) {
	info := map[string]float64{
		"load_rtt_ms.p50": 20.04, "load_rtt_ms.p99": 58.66,
		"client_tx_drops": 0, "server_rx_drops": 2, "relay_drops": 10, "server_rcvbuf_errors": -1,
		"omit.client_tx_drops": 0, "omit.server_rx_drops": 0, "omit.relay_drops": 2462, "omit.server_rcvbuf_errors": 5,
		"client_link_drops": 7, "omit.client_link_drops": 3, "server_link_drops": -1,
		"server_retransmits": 1, "omit.server_retransmits": 0,
	}
	cases := []struct {
		name string
		got  string
		want string
	}{
		{name: "two values", got: infoCell(info, "%.1f", "load_rtt_ms.p50", "load_rtt_ms.p99"), want: "20.0, 58.7"},
		{name: "missing key", got: infoCell(info, "%.1f", "load_rtt_ms.p50", "omit.rtt_ms.p90"), want: "-"},
		{name: "no info", got: infoCell(nil, "%.2f", "retrans_percent"), want: "-"},
		{name: "drops with no rcvbuf and server link counters", got: dropsCell(info), want: "2470, 19"},
		{name: "no drops", got: dropsCell(map[string]float64{"relay_drops": 1}), want: "-"},
		{
			name: "drops of each place",
			got:  dropsDetail(info),
			want: "drops omit/window: client link 3/7, client tx 0/0, relay 2462/10, server rcvbuf 5/-, server rx 0/2, server link -/-" +
				"; server retx omit/window: 0/1",
		},
		{name: "no drop counters", got: dropsDetail(map[string]float64{"server_retransmits": 1}), want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.got)
		})
	}
}

func TestAppendSummary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.md")
	require.NoError(t, os.WriteFile(path, []byte("# Job\n"), 0o644))
	o := []outcome{evaluate(Baseline{}, result("k", 1, 0.1, 0.1))}
	require.NoError(t, appendSummary(path, o))
	require.NoError(t, appendSummary(path, o))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(data), "# Job\n"))
	assert.Equal(t, 2, strings.Count(string(data), "### perfrig results"))
}
