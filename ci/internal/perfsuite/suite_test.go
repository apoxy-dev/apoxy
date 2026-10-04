package perfsuite

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func parsePlan(t *testing.T, s Suite, o Options) Plan {
	t.Helper()
	data, err := s.Plan(o)
	if err != nil {
		t.Fatal(err)
	}
	var p Plan
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func rowByID(t *testing.T, p Plan, id string) Row {
	t.Helper()
	i := slices.IndexFunc(p.Rows, func(r Row) bool { return r.ID == id })
	if i < 0 {
		t.Fatalf("no row %s", id)
	}
	return p.Rows[i]
}

func TestPlan(t *testing.T) {
	o := Options{Duration: "30s", Reps: 3, MinCPUs: 16}
	cases := []struct {
		name      string
		suite     Suite
		opts      Options
		wantIDs   []string
		wantHost  bool
		wantTun   bool
		wantError string
	}{
		{
			name: "netns", suite: Netns, opts: o,
			wantIDs: []string{"iperf3-tcp-p1", "iperf3-tcp-p4", "iperf3-tcp-p4-loss0.1", "iperf3-udp-p1"},
		},
		{
			name: "vpc on a host", suite: VPC, opts: Options{Duration: "30s", Reps: 3, MinCPUs: 16, Host: true},
			wantIDs: []string{"netstack-psp-relay", "netstack-quic-relay", "tun-psp-relay-cubic", "netstack-psp-relay-loss0.1",
				"netstack-psp-direct", "netstack-psp-relay-cubic", "netstack-psp-relay-rate1000mbit",
				"netstack-psp-relay-netns", "netstack-psp-relay-xdp"},
			wantHost: true, wantTun: true,
		},
		{
			name: "vpc rows", suite: VPC, opts: Options{Duration: "10s", Only: []string{"netstack-psp-direct", "netstack-psp-relay"}},
			wantIDs: []string{"netstack-psp-direct", "netstack-psp-relay"}, wantTun: true,
		},
		{
			name: "empty row ID", suite: Netns, opts: Options{Duration: "10s", Only: []string{""}},
			wantIDs: []string{"iperf3-tcp-p1", "iperf3-tcp-p4", "iperf3-tcp-p4-loss0.1", "iperf3-udp-p1"},
		},
		{name: "unknown row", suite: VPC, opts: Options{Duration: "10s", Only: []string{"nope"}}, wantError: `unknown vpc row "nope"`},
		{
			name: "node rows and a rig row", suite: VPC, opts: Options{Duration: "10s", Only: []string{"netstack-psp-direct-2node", "netstack-psp-direct"}},
			wantIDs: []string{"netstack-psp-direct"}, wantTun: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.suite.Plan(tc.opts)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("err = %v, want %q", err, tc.wantError)
				}
				return
			}
			var p Plan
			if err := json.Unmarshal([]byte(data), &p); err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, r := range p.Rows {
				ids = append(ids, r.ID)
			}
			if !slices.Equal(ids, tc.wantIDs) {
				t.Errorf("rows = %v, want %v", ids, tc.wantIDs)
			}
			if (p.Sysctls != nil) != tc.wantHost || slices.Contains(p.Modules, "sch_netem") != tc.wantHost {
				t.Errorf("sysctls = %v, modules = %v, want host setup %v", p.Sysctls, p.Modules, tc.wantHost)
			}
			if p.Tun != tc.wantTun {
				t.Errorf("tun = %v, want %v", p.Tun, tc.wantTun)
			}
		})
	}
}

func TestVPCRowArgs(t *testing.T) {
	p := parsePlan(t, VPC, Options{Duration: "30s", Reps: 3, MinCPUs: 16})
	cases := []struct {
		id        string
		wantGroup string
		want      []string
		notWant   []string
	}{
		{
			id: "netstack-psp-relay", wantGroup: "floor",
			want: []string{
				"-name=vpc-netstack-psp-relay", "-reps=3", "-baseline=baseline.json", "-min-cpus=16", "-duration=30s",
				`-sidecar-argv=["vpcbench","relay","-listen","$SERVER_IP:4443"]`,
				`-server-argv=["vpcbench","server","-relay","$SERVER_IP:4443","-listen","$SERVER_IP:4433"]`,
				`-client-argv=["vpcbench","client","-relay","$SERVER_IP:4443","-server","$SERVER_IP:4433","-cc","bbr","-streams","$STREAMS","-omit","${OMIT_S}s","-duration","${DURATION_S}s"]`,
			},
			notWant: []string{"-relay-netns"},
		},
		{
			id: "netstack-psp-direct", wantGroup: "info",
			want:    []string{"-reps=1", `-server-argv=["vpcbench","server","-via","direct","-listen","$SERVER_IP:4433"]`},
			notWant: []string{"-sidecar-argv", "-baseline", "-relay-netns"},
		},
		{
			id: "netstack-psp-relay-rate1000mbit", wantGroup: "info",
			want: []string{"-rate=1000mbit", "-queue-limit=2640"},
		},
		{
			id: "netstack-psp-relay-netns", wantGroup: "info",
			want: []string{
				"-relay-netns",
				`-sidecar-argv=["vpcbench","relay","-listen","$RELAY_IP:4443"]`,
				`-server-argv=["vpcbench","server","-relay","$RELAY_IP:4443","-listen","$SERVER_IP:4433"]`,
				`-client-argv=["vpcbench","client","-relay","$RELAY_IP:4443","-server","$SERVER_IP:4433","-cc","bbr","-streams","$STREAMS","-omit","${OMIT_S}s","-duration","${DURATION_S}s"]`,
			},
		},
		{
			id: "netstack-psp-relay-xdp", wantGroup: "info",
			want: []string{"-name=vpc-netstack-psp-relay-xdp", "-relay-netns", `-sidecar-argv=["vpcbench","relay","-listen","$RELAY_IP:4443","-xdp","perf-r"]`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			r := rowByID(t, p, tc.id)
			if r.Group != tc.wantGroup {
				t.Errorf("group = %s, want %s", r.Group, tc.wantGroup)
			}
			for _, w := range tc.want {
				if !slices.Contains(r.Args, w) {
					t.Errorf("args have no %s:\n%s", w, strings.Join(r.Args, "\n"))
				}
			}
			for _, nw := range tc.notWant {
				if slices.ContainsFunc(r.Args, func(a string) bool { return strings.HasPrefix(a, nw) }) {
					t.Errorf("args have %s", nw)
				}
			}
		})
	}
}

func TestNodePlans(t *testing.T) {
	o := Options{Duration: "30s", Reps: 3, MinCPUs: 16, Host: true}
	cases := []struct {
		name      string
		only      []string
		wantRoles map[string][]string
		wantEmpty bool
	}{
		{name: "rig rows only", only: []string{"netstack-psp-relay"}, wantEmpty: true},
		{name: "no rows named", wantEmpty: true},
		{
			name: "direct row", only: []string{"netstack-psp-direct-2node"},
			wantRoles: map[string][]string{"client": {"netstack-psp-direct-2node"}, "server": {"netstack-psp-direct-2node"}},
		},
		{
			name: "both node rows", only: []string{"netstack-psp-direct-2node", "netstack-psp-relay-3node"},
			wantRoles: map[string][]string{
				"client": {"netstack-psp-direct-2node", "netstack-psp-relay-3node"},
				"server": {"netstack-psp-direct-2node", "netstack-psp-relay-3node"},
				"relay":  {"netstack-psp-relay-3node"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o.Only = tc.only
			data, err := VPC.NodePlans(o)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantEmpty {
				if data != "" {
					t.Fatalf("plans = %s, want none", data)
				}
				return
			}
			var plans map[string]Plan
			if err := json.Unmarshal([]byte(data), &plans); err != nil {
				t.Fatal(err)
			}
			if len(plans) != len(tc.wantRoles) {
				t.Fatalf("roles = %v, want %v", plans, tc.wantRoles)
			}
			for role, wantIDs := range tc.wantRoles {
				p := plans[role]
				var ids []string
				for _, r := range p.Rows {
					ids = append(ids, r.ID)
					if r.Cmd != "node" || !slices.Contains(r.Args, "-role="+role) {
						t.Errorf("%s row %s: cmd %q, args %v", role, r.ID, r.Cmd, r.Args)
					}
					if slices.ContainsFunc(r.Args, func(a string) bool {
						return strings.HasPrefix(a, "-delay") || strings.HasPrefix(a, "-reps") || strings.HasPrefix(a, "-workload")
					}) {
						t.Errorf("%s row %s has a netns rig flag: %v", role, r.ID, r.Args)
					}
				}
				if !slices.Equal(ids, wantIDs) {
					t.Errorf("%s rows = %v, want %v", role, ids, wantIDs)
				}
				if p.Sysctls == nil || len(p.Modules) > 0 || !p.Tun {
					t.Errorf("%s plan: sysctls %v, modules %v, tun %v", role, p.Sysctls, p.Modules, p.Tun)
				}
			}
		})
	}
	// The row is an info row with no floor. The node argv waits for the other
	// hosts and stops the relay at the end.
	rows := VPC.rows(o)
	i := slices.IndexFunc(rows, func(r Row) bool { return r.ID == "netstack-psp-relay-3node" })
	r := rows[i]
	if r.Group != "info" || r.Hosts() != 3 || r.Cmd != "node" {
		t.Errorf("row = %+v", r)
	}
	for _, w := range []string{
		"-name=vpc-netstack-psp-relay-3node", "-duration=30s", "-min-cpus=16",
		`-sidecar-argv=["vpcbench","relay","-listen","$RELAY_IP:4443"]`,
		`-server-argv=["vpcbench","server","-relay","$RELAY_IP:4443","-listen","$SERVER_IP:4433","-start-timeout","5m"]`,
		`-client-argv=["vpcbench","client","-relay","$RELAY_IP:4443","-server","$SERVER_IP:4433","-cc","bbr","-streams","$STREAMS","-omit","${OMIT_S}s","-duration","${DURATION_S}s","-start-timeout","5m","-stop-relay"]`,
	} {
		if !slices.Contains(r.Args, w) {
			t.Errorf("args have no %s:\n%s", w, strings.Join(r.Args, "\n"))
		}
	}
	i = slices.IndexFunc(rows, func(r Row) bool { return r.ID == "netstack-psp-direct-2node" })
	if r := rows[i]; r.Hosts() != 2 || slices.ContainsFunc(r.Args, func(a string) bool { return strings.Contains(a, "stop-relay") || strings.HasPrefix(a, "-sidecar") }) {
		t.Errorf("direct row = %+v", r)
	}
}

func TestVPCProfileArgs(t *testing.T) {
	cases := []struct {
		name    string
		profile bool
		want    []string
	}{
		{name: "off"},
		{
			name: "on", profile: true,
			want: []string{
				`-sidecar-argv=["vpcbench","relay","-listen","$SERVER_IP:4443","-cpuprofile","$WORK_DIR/relay-cpu.pprof","-blockprofile","$WORK_DIR/relay-block.pprof","-mutexprofile","$WORK_DIR/relay-mutex.pprof"]`,
				`-server-argv=["vpcbench","server","-relay","$SERVER_IP:4443","-listen","$SERVER_IP:4433","-cpuprofile","$WORK_DIR/server-cpu.pprof","-blockprofile","$WORK_DIR/server-block.pprof","-mutexprofile","$WORK_DIR/server-mutex.pprof"]`,
				`-client-argv=["vpcbench","client","-relay","$SERVER_IP:4443","-server","$SERVER_IP:4433","-cc","bbr","-streams","$STREAMS","-omit","${OMIT_S}s","-duration","${DURATION_S}s","-cpuprofile","$WORK_DIR/client-cpu.pprof","-blockprofile","$WORK_DIR/client-block.pprof","-mutexprofile","$WORK_DIR/client-mutex.pprof"]`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := rowByID(t, parsePlan(t, VPC, Options{Duration: "30s", Reps: 3, MinCPUs: 16, Profile: tc.profile}), "netstack-psp-relay")
			for _, w := range tc.want {
				if !slices.Contains(r.Args, w) {
					t.Errorf("args have no %s:\n%s", w, strings.Join(r.Args, "\n"))
				}
			}
			if !tc.profile && slices.ContainsFunc(r.Args, func(a string) bool { return strings.Contains(a, "profile") }) {
				t.Errorf("args have a profile flag:\n%s", strings.Join(r.Args, "\n"))
			}
		})
	}
}

func TestGroups(t *testing.T) {
	if got := VPC.Groups(); !slices.Equal(got, []string{"floor", "info"}) {
		t.Errorf("VPC groups = %v", got)
	}
	if got := Netns.Groups(); !slices.Equal(got, []string{"floor"}) {
		t.Errorf("netns groups = %v", got)
	}
}

func TestSelects(t *testing.T) {
	cases := []struct {
		name      string
		suite     Suite
		only      []string
		wantFloor bool
		wantInfo  bool
	}{
		{name: "all rows", suite: VPC, wantFloor: true, wantInfo: true},
		{name: "empty row ID", suite: VPC, only: []string{""}, wantFloor: true, wantInfo: true},
		{name: "floor row only", suite: VPC, only: []string{"netstack-psp-relay"}, wantFloor: true},
		{name: "no floor row selected", suite: VPC, only: []string{"netstack-psp-relay-cubic"}, wantInfo: true},
		{name: "unknown row", suite: VPC, only: []string{"nope"}, wantFloor: true, wantInfo: true},
		{name: "netns", suite: Netns, only: []string{"iperf3-tcp-p1"}, wantFloor: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := Options{Duration: "10s", Only: tc.only}
			if got := tc.suite.Selects(o, "floor"); got != tc.wantFloor {
				t.Errorf("Selects(floor) = %v, want %v", got, tc.wantFloor)
			}
			if got := tc.suite.Selects(o, "info"); got != tc.wantInfo {
				t.Errorf("Selects(info) = %v, want %v", got, tc.wantInfo)
			}
		})
	}
}
