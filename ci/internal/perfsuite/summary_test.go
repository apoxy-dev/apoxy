package perfsuite

import (
	"strings"
	"testing"
)

func TestGateExit(t *testing.T) {
	cases := []struct {
		name string
		rep  Report
		gate Compare
		want int
	}{
		{name: "pass", gate: Compare{Ran: true, Code: 0}, want: 0},
		{name: "regression", gate: Compare{Ran: true, Code: 1}, want: 1},
		{name: "result infra error", gate: Compare{Ran: true, Code: 3}, want: 3},
		{name: "other code", gate: Compare{Ran: true, Code: 2}, want: 1},
		{name: "no gate result", gate: Compare{}, want: 1},
		{name: "no gated row selected", gate: Compare{Unselected: true}, want: 0},
		{name: "infra error with no gated row selected", rep: Report{InfraError: "no capacity"}, gate: Compare{Unselected: true}, want: 3},
		{name: "agent infra error", rep: Report{InfraError: "no capacity"}, gate: Compare{Ran: true}, want: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := GateExit(tc.rep, tc.gate); got != tc.want {
				t.Fatalf("GateExit = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSummary(t *testing.T) {
	rep := Report{Rows: []RowResult{
		{ID: "gate", Group: "gate", ExitCode: 0},
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
				{Group: "gate", Ran: true, Markdown: "### perfrig results\n\n| PASS | gate |\n"},
				{Group: "info", Ran: true, Markdown: "### perfrig results\n\n| NO BASELINE | info |\n"},
			},
			want: []string{
				"## VPC gate", "kernel 6.14.0-1012-aws", "| PASS | gate |", "### Rows: info", "These rows do not gate.",
				"- tun-psp-relay-cubic: perfrig exit 3, see logs/tun-psp-relay-cubic.log",
				"- late: not run: context deadline exceeded (exit -1)",
			},
			notWant: []string{"Infra error", "- gate:"},
		},
		{
			name:     "infra",
			rep:      Report{InfraError: "the instance is terminated and perfagent put no agent.json"},
			compares: []Compare{{Group: "gate"}, {Group: "info"}},
			console:  "boot\ncloud-init: failed\n",
			want:     []string{"**Infra error:** the instance is terminated", "cloud-init: failed", "No gate result.", "No info results."},
		},
		{
			name: "no gated row selected",
			rep:  Report{Rows: []RowResult{{ID: "netstack-psp-relay-cubic", Group: "info"}}},
			compares: []Compare{
				{Group: "gate", Unselected: true},
				{Group: "info", Ran: true, Markdown: "### perfrig results\n\n| NO BASELINE | info |\n"},
			},
			want:    []string{"No gated row ran: the selected rows do not gate.", "| NO BASELINE | info |"},
			notWant: []string{"No gate result."},
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
		name     string
		gateExit int
		rep      Report
		gate     []Result
		want     string
	}{
		{
			name: "fail", gateExit: 1, gate: []Result{fail},
			want: "VPC gate FAIL on apoxy@abc1234: vpc-netstack-psp-relay median 2.1 Gbps, runs 2 2.2, retried; " +
				"vpc-netstack-psp-relay gbps 2.1000 (baseline 2.5000, -16.0%). <https://run|Run>",
		},
		{name: "agent infra", gateExit: 3, rep: Report{InfraError: "no subnet has capacity."}, want: "VPC gate INFRA on apoxy@abc1234: no subnet has capacity. <https://run|Run>"},
		{name: "result infra", gateExit: 3, gate: []Result{{InfraError: "steal 9%"}}, want: "VPC gate INFRA on apoxy@abc1234: steal 9%. <https://run|Run>"},
		{name: "no result", gateExit: 1, want: "VPC gate ERROR on apoxy@abc1234: no gate result. <https://run|Run>"},
		{name: "later step", gateExit: 0, gate: []Result{fail}, want: "VPC gate ERROR on apoxy@abc1234: the gate passed, but a later step failed. <https://run|Run>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SlackText(VPC, tc.gateExit, tc.rep, tc.gate, compareFail, "apoxy@abc1234", "https://run")
			if got != tc.want {
				t.Fatalf("SlackText =\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}
