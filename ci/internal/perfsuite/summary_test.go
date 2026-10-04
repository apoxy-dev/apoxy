package perfsuite

import (
	"slices"
	"strings"
	"testing"
)

func TestFloorExit(t *testing.T) {
	cases := []struct {
		name  string
		rep   Report
		floor Compare
		want  int
	}{
		{name: "pass", floor: Compare{Ran: true, Code: 0}, want: 0},
		{name: "regression", floor: Compare{Ran: true, Code: 1}, want: 1},
		{name: "result infra error", floor: Compare{Ran: true, Code: 3}, want: 3},
		{name: "other code", floor: Compare{Ran: true, Code: 2}, want: 1},
		{name: "no floor result", floor: Compare{}, want: 1},
		{name: "no floor row selected", floor: Compare{Unselected: true}, want: 0},
		{name: "infra error with no floor row selected", rep: Report{InfraError: "no capacity"}, floor: Compare{Unselected: true}, want: 3},
		{name: "agent infra error", rep: Report{InfraError: "no capacity"}, floor: Compare{Ran: true}, want: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FloorExit(tc.rep, tc.floor); got != tc.want {
				t.Fatalf("FloorExit = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSummary(t *testing.T) {
	rep := Report{Rows: []RowResult{
		{ID: "netstack-psp-relay", Group: "floor", ExitCode: 0},
		{ID: "tun-psp-relay-cubic", Group: "info", ExitCode: 3},
		{ID: "late", Group: "info", ExitCode: -1, Error: "not run: context deadline exceeded"},
	}}
	rep.Host.Kernel = "6.14.0-1012-aws"
	cases := []struct {
		name     string
		rep      Report
		compares []Compare
		console  string
		want     []string
		notWant  []string
	}{
		{
			name: "results",
			rep:  rep,
			compares: []Compare{
				{Group: "floor", Ran: true, Markdown: "### perfrig results\n\n| PASS | floor |\n"},
				{Group: "info", Ran: true, Markdown: "### perfrig results\n\n| NO BASELINE | info |\n"},
			},
			want: []string{
				"## VPC perf", "kernel 6.14.0-1012-aws", "| PASS | floor |", "### Rows: info", "These rows have no floor.",
				"- tun-psp-relay-cubic: perfrig exit 3, see logs/tun-psp-relay-cubic.log",
				"- late: not run: context deadline exceeded (exit -1)",
			},
			notWant: []string{"Infra error", "- netstack-psp-relay:"},
		},
		{
			name:     "infra",
			rep:      Report{InfraError: "the instance is terminated and perfagent put no agent.json"},
			compares: []Compare{{Group: "floor"}, {Group: "info"}},
			console:  "boot\ncloud-init: failed\n",
			want:     []string{"**Infra error:** the instance is terminated", "cloud-init: failed", "No floor result.", "No info results."},
		},
		{
			name: "no floor row selected",
			rep:  Report{Rows: []RowResult{{ID: "netstack-psp-relay-cubic", Group: "info"}}},
			compares: []Compare{
				{Group: "floor", Unselected: true},
				{Group: "info", Ran: true, Markdown: "### perfrig results\n\n| NO BASELINE | info |\n"},
			},
			want:    []string{"No floor row ran: the selected rows have no floor.", "| NO BASELINE | info |"},
			notWant: []string{"No floor result."},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Summary(VPC, tc.rep, tc.compares, tc.console)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("summary has no %q:\n%s", w, got)
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(got, nw) {
					t.Errorf("summary has %q:\n%s", nw, got)
				}
			}
		})
	}
}

const compareFail = `FAIL c7a.8xlarge vpc-netstack-psp-relay streams=4 duration=30s omit=5s delay=10ms jitter=0ms loss=0% rate=none queue=100000 mtu=1500 bitrate=none window=none
  min_gbps                   2.1000  baseline     2.0000    +5.0%  ok
  gbps                       2.1000  baseline     2.5000   -16.0%  REGRESSION
NO BASELINE c7a.8xlarge iperf3-tcp streams=1 duration=30s omit=2s delay=10ms jitter=0ms loss=0% rate=none queue=100000 mtu=1500 bitrate=none window=none
  gbps=30 packets_per_second=0 client_cores_per_gbps=0 server_cores_per_gbps=0
`

func TestSlackText(t *testing.T) {
	fail := Result{
		Workload: "vpc-netstack-psp-relay", Retried: true, Throughput: Throughput{Gbps: 2.1},
		Runs: []Run{{Throughput: Throughput{Gbps: 2}}, {Throughput: Throughput{Gbps: 2.2}}},
	}
	cases := []struct {
		name      string
		floorExit int
		rep       Report
		floor     []Result
		want      string
	}{
		{
			name: "fail", floorExit: 1, floor: []Result{fail},
			want: "VPC perf FAIL on apoxy@abc1234: vpc-netstack-psp-relay median 2.1 Gbps, runs 2 2.2, retried; " +
				"vpc-netstack-psp-relay gbps 2.1000 (baseline 2.5000, -16.0%). <https://run|Run>",
		},
		{name: "agent infra", floorExit: 3, rep: Report{InfraError: "no subnet has capacity."}, want: "VPC perf INFRA on apoxy@abc1234: no subnet has capacity. <https://run|Run>"},
		{name: "result infra", floorExit: 3, floor: []Result{{InfraError: "steal 9%"}}, want: "VPC perf INFRA on apoxy@abc1234: steal 9%. <https://run|Run>"},
		{name: "no result", floorExit: 1, want: "VPC perf ERROR on apoxy@abc1234: no floor result. <https://run|Run>"},
		{name: "later step", floorExit: 0, floor: []Result{fail}, want: "VPC perf ERROR on apoxy@abc1234: the floor check passed, but a later step failed. <https://run|Run>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SlackText(VPC, tc.floorExit, tc.rep, tc.floor, compareFail, "apoxy@abc1234", "https://run")
			if got != tc.want {
				t.Fatalf("SlackText =\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}

func TestNodes(t *testing.T) {
	client := `{"workload": "vpc-netstack-psp-relay-3node", "role": "client", "host": {"class": "c7a.8xlarge", "cpus": 32, "kernel": "7.0.0-aws",
		"nic": {"dev": "ens5", "driver": "ena", "version": "7.0.0-aws", "mtu": 9001, "rx_queues": 8, "xdp_features": ["basic", "redirect"]}},
		"rtt_ms": {"avg": 0.061}, "relay_rtt_ms": {"avg": 0.058},
		"throughput": {"gbps": 4}, "info": {"client_cores_per_gbps": 0.25, "client_host_cores": 2, "server_cores_per_gbps": 0.5, "server_host_cores": 3, "relay_host_cores": -1},
		"nic_counters": {"bw_in_allowance_exceeded": 0, "pps_allowance_exceeded": 12, "rx_dropped": 1, "tx_dropped": 0, "rx_top_queue_pct": 99}}`
	server := `{"workload": "vpc-netstack-psp-relay-3node", "role": "server", "host": {"class": "c7a.8xlarge", "cpus": 32, "kernel": "7.0.0-aws"}}`
	relay := `{"workload": "vpc-netstack-psp-relay-3node", "role": "relay", "host": {"class": "c7a.8xlarge", "cpus": 32, "kernel": "7.0.0-aws"}}`
	rig := `{"workload": "vpc-netstack-psp-relay", "host": {"class": "c7a.8xlarge"}}`
	cases := []struct {
		name    string
		results []string
		want    []string
		empty   bool
	}{
		{name: "netns rig results", results: []string{rig, "not json"}, empty: true},
		{
			name: "hosts in role order", results: []string{relay, server, rig, client},
			want: []string{
				"### Hosts of the node rows",
				"| vpc-netstack-psp-relay-3node | client | c7a.8xlarge, 32 CPUs, 7.0.0-aws | ens5 ena 7.0.0-aws, mtu 9001 | 8 | basic redirect | 0.061, 0.058 | 0.250 | 2.00 | 0.500 | 0 | - | 12 | - | 1 | 0 | 99 |",
				"| vpc-netstack-psp-relay-3node | server | c7a.8xlarge, 32 CPUs, 7.0.0-aws | - | - | - | - | 0.500 | 3.00 | 0.750 | - | - | - | - | - | - | - |",
				"| vpc-netstack-psp-relay-3node | relay | c7a.8xlarge, 32 CPUs, 7.0.0-aws | - | - | - | - | - | - | - | - | - | - | - | - | - | - |",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Nodes(tc.results)
			if tc.empty {
				if got != "" {
					t.Fatalf("Nodes = %q, want empty", got)
				}
				return
			}
			lines := strings.Split(got, "\n")
			last := -1
			for i, w := range tc.want {
				at := slices.Index(lines, w)
				if at < 0 {
					t.Errorf("line %d missing: %s\n%s", i, w, got)
				} else if at < last {
					t.Errorf("line %d is not in role order:\n%s", i, got)
				}
				last = max(last, at)
			}
		})
	}
}
