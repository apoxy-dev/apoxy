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

// tcpKey is the key of an iperf3-tcp case with the given streams and loss.
func tcpKey(streams, loss string) string {
	return "c7a.8xlarge iperf3-tcp streams=" + streams + " duration=30s omit=2s delay=10ms jitter=0ms loss=" + loss +
		" rate=none queue=100000 mtu=1500 bitrate=none window=none"
}

var udpKey = "c7a.8xlarge iperf3-udp streams=1 duration=30s omit=2s delay=10ms jitter=0ms loss=0% rate=none queue=100000 mtu=1500 bitrate=2G window=none"

// compareToday is the "perfrig compare" report of Perf run 41680058069, job netns-rig.
var compareToday = "PASS " + tcpKey("1", "0%") + `
  gbps                      11.5490  baseline    12.8970   -10.5%  ok
  client_cores_per_gbps      0.0401  baseline     0.0410    -2.2%  ok
WARN ` + tcpKey("4", "0.1%") + `
  gbps                       0.4500  baseline     0.4700    -4.3%  ok
  client_cores_per_gbps      0.0597  baseline     0.0408   +46.5%  REGRESSION
  server_cores_per_gbps      0.0574  baseline     0.0414   +38.6%  REGRESSION
FAIL ` + tcpKey("4", "0%") + `
  gbps                      67.2900  baseline    84.4790   -20.3%  REGRESSION
  client_cores_per_gbps      0.0585  baseline     0.0465   +25.7%  REGRESSION
PASS ` + udpKey + `
  gbps                       1.7740  baseline     1.8000    -1.4%  ok
`

// floorToday are the floor results of compareToday.
var floorToday = []Result{
	{Key: tcpKey("1", "0%"), Workload: "iperf3-tcp", Runs: runs(11.167, 11.586, 11.549)},
	{Key: tcpKey("4", "0.1%"), Workload: "iperf3-tcp", Runs: runs(0.45, 0.44, 0.46)},
	{Key: tcpKey("4", "0%"), Workload: "iperf3-tcp", Retried: true, Runs: runs(70.59, 63.99, 57.12, 70.81, 63.56, 77.17)},
	{Key: udpKey, Workload: "iperf3-udp", Runs: runs(1.774, 1.77, 1.78)},
}

func runs(gbps ...float64) []Run {
	got := make([]Run, len(gbps))
	for i, g := range gbps {
		got[i].Throughput.Gbps = g
	}
	return got
}

func TestSlackText(t *testing.T) {
	const todayFail = "netns rig FAIL on apoxy@3cd750e (c7a.8xlarge) <https://run|Run>\n" +
		"• iperf3-tcp streams=4 loss=0%: 67.29 Gbps vs 84.48 (-20.3%), client cores/Gbps 0.0585 vs 0.0465 (+25.7%); " +
		"runs 70.59 63.99 57.12 70.81 63.56 77.17, retried\n" +
		"Warnings: 1 case(s), see run."
	ec2 := Report{}
	ec2.Host.EC2 = &struct {
		InstanceID   string `json:"instance_id"`
		InstanceType string `json:"instance_type"`
		AZ           string `json:"az"`
		AMI          string `json:"ami"`
	}{InstanceType: "c7a.8xlarge"}
	cases := []struct {
		name      string
		floorExit int
		rep       Report
		floor     []Result
		compare   string
		want      string
	}{
		{name: "one fail and one warn", floorExit: 1, floor: floorToday, compare: compareToday, want: todayFail},
		{
			name: "duplicated blocks", floorExit: 1, floor: floorToday,
			// A failed perfrig compare writes the report to stdout and to stderr.
			compare: compareToday + compareToday +
				`time=2026-11-03T06:41:02Z level=ERROR msg="Perf rig failed" error="regression: 1 of 4 results failed" exit_code=1` + "\n",
			want: todayFail,
		},
		{
			name: "two fails that differ only by loss", floorExit: 1,
			floor: []Result{
				{Key: tcpKey("4", "0%"), Workload: "iperf3-tcp", Runs: runs(60, 61.5)},
				{Key: tcpKey("4", "1%"), Workload: "iperf3-tcp", Runs: runs(0.3, 0.31)},
			},
			compare: "FAIL " + tcpKey("4", "0%") + `
  gbps                      61.0000  baseline    84.4790   -27.8%  REGRESSION
FAIL ` + tcpKey("4", "1%") + `
  gbps                       0.3100  baseline     0.4000   -22.5%  REGRESSION
  server_cores_per_gbps      0.0600  baseline     0.0414   +44.9%  REGRESSION
`,
			want: "netns rig FAIL on apoxy@3cd750e (c7a.8xlarge) <https://run|Run>\n" +
				"• iperf3-tcp loss=0%: 61 Gbps vs 84.48 (-27.8%); runs 60 61.5\n" +
				"• iperf3-tcp loss=1%: 0.31 Gbps vs 0.4 (-22.5%), server cores/Gbps 0.06 vs 0.0414 (+44.9%); runs 0.3 0.31",
		},
		{
			name: "agent infra", floorExit: 3, rep: Report{InfraError: "no subnet has capacity."},
			want: "netns rig INFRA on apoxy@3cd750e <https://run|Run>\nno subnet has capacity.",
		},
		{
			name: "result infra", floorExit: 3, floor: []Result{{Key: tcpKey("1", "0%"), InfraError: "steal 9%"}},
			compare: "INFRA " + tcpKey("1", "0%") + "\n  steal 9%\n",
			want:    "netns rig INFRA on apoxy@3cd750e (c7a.8xlarge) <https://run|Run>\nsteal 9%.",
		},
		{
			name: "no floor result", floorExit: 1, rep: ec2,
			want: "netns rig ERROR on apoxy@3cd750e (c7a.8xlarge) <https://run|Run>\nNo floor result.",
		},
		{
			name: "later step", floorExit: 0, floor: floorToday, compare: compareToday,
			want: "netns rig ERROR on apoxy@3cd750e (c7a.8xlarge) <https://run|Run>\nThe floor check passed, but a later step failed.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SlackText(Netns, tc.floorExit, tc.rep, tc.floor, tc.compare, "apoxy@3cd750e", "https://run")
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
