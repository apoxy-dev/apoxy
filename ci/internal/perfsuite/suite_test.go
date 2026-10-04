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
				"netstack-psp-direct", "netstack-psp-relay-cubic", "netstack-psp-relay-rate1000mbit"},
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
		},
		{
			id: "netstack-psp-direct", wantGroup: "info",
			want:    []string{"-reps=1", `-server-argv=["vpcbench","server","-via","direct","-listen","$SERVER_IP:4433"]`},
			notWant: []string{"-sidecar-argv", "-baseline"},
		},
		{
			id: "netstack-psp-relay-rate1000mbit", wantGroup: "info",
			want: []string{"-rate=1000mbit", "-queue-limit=2640"},
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
