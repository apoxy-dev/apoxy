package perfsuite

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestFloodRows(t *testing.T) {
	// The run has two rows before the row of each case.
	const before = "flood-direct-2node-p256,flood-direct-2node-p256-min"
	const counter = `-server-argv=["vpcbench","flood-counter","-id","ID","-seq","SEQ","-listen","$SERVER_IP:4433","-xdp","$DEV","-start-timeout","5m"]`
	cases := []struct {
		id        string
		wantHosts int
		want      []string
		notWant   []string
	}{
		{
			id: "flood-relay-3node-p16-xdp", wantHosts: 3,
			want: []string{
				"-name=vpc-flood-relay-3node-xdp", "-streams=16", "-omit=5s", "-duration=30s", "-min-cpus=16", "-max-steal=5", "-relay-xdp", "-server-xdp", "-no-nic-poll", counter,
				`-sidecar-argv=["vpcbench","flood-relay","-id","ID","-seq","SEQ","-listen","$RELAY_IP:4443","-xdp","$DEV","-xdp-mode","driver","-start-timeout","5m"]`,
				`-client-argv=["vpcbench","flood-source","-id","ID","-seq","SEQ","-server","$SERVER_IP:4433","-relay","$RELAY_IP:4443","-ports","$STREAMS","-omit","${OMIT_S}s","-duration","${DURATION_S}s","-start-timeout","5m"]`,
			},
			notWant: []string{"-relay-xdp-generic", "-relay-channels"},
		},
		{
			id: "flood-relay-3node-p16-xdp-min", wantHosts: 3,
			want: []string{
				"-name=vpc-flood-relay-3node-xdp-min", "-streams=16", "-relay-xdp",
				`-client-argv=["vpcbench","flood-source","-id","ID","-seq","SEQ","-server","$SERVER_IP:4433","-relay","$RELAY_IP:4443","-size","68","-ports","$STREAMS","-omit","${OMIT_S}s","-duration","${DURATION_S}s","-start-timeout","5m"]`,
			},
		},
		{
			id: "flood-relay-3node-p256-xdp", wantHosts: 3,
			want: []string{
				"-name=vpc-flood-relay-3node-xdp", "-streams=256", "-relay-xdp", "-server-xdp",
				`-client-argv=["vpcbench","flood-source","-id","ID","-seq","SEQ","-server","$SERVER_IP:4433","-relay","$RELAY_IP:4443","-next-ports","256","-ports","$STREAMS","-omit","${OMIT_S}s","-duration","${DURATION_S}s","-start-timeout","5m"]`,
			},
			notWant: []string{"-relay-xdp-generic"},
		},
		{
			id: "flood-relay-3node-p16-xdp-geneve", wantHosts: 3,
			want: []string{
				"-name=vpc-flood-relay-3node-xdp-geneve", "-streams=16", "-relay-xdp", "-relay-xdp-generic", "-server-xdp",
				`-sidecar-argv=["vpcbench","flood-relay","-id","ID","-seq","SEQ","-listen","$RELAY_IP:4443","-xdp","$DEV","-xdp-mode","chain","-start-timeout","5m"]`,
			},
		},
		{
			id: "flood-relay-3node-p16-xdp-generic", wantHosts: 3,
			want: []string{
				"-name=vpc-flood-relay-3node-xdp-generic", "-relay-xdp", "-relay-xdp-generic",
				`-sidecar-argv=["vpcbench","flood-relay","-id","ID","-seq","SEQ","-listen","$RELAY_IP:4443","-xdp","$DEV","-xdp-mode","generic","-start-timeout","5m"]`,
			},
		},
		{
			id: "flood-relay-3node-p16-xdp-20g", wantHosts: 3,
			want: []string{
				"-name=vpc-flood-relay-3node-xdp-20g",
				`-client-argv=["vpcbench","flood-source","-id","ID","-seq","SEQ","-server","$SERVER_IP:4433","-relay","$RELAY_IP:4443","-wire-gbps","20","-ports","$STREAMS","-omit","${OMIT_S}s","-duration","${DURATION_S}s","-start-timeout","5m"]`,
			},
		},
		{
			id: "flood-relay-3node-p16-xdp-q1", wantHosts: 3,
			want: []string{"-name=vpc-flood-relay-3node-xdp-q1", "-relay-xdp", "-relay-channels=1"},
		},
		{
			id: "flood-relay-3node-p16-xdp-tunnel", wantHosts: 3,
			want: []string{
				"-name=vpc-flood-relay-3node-xdp-tunnel",
				`-sidecar-argv=["vpcbench","flood-relay","-id","ID","-seq","SEQ","-listen","$RELAY_IP:4443","-xdp","$DEV","-xdp-mode","driver","-start-timeout","5m","-tunnel-rate","1e11"]`,
			},
		},
		{
			id: "flood-direct-2node-p16", wantHosts: 2,
			want: []string{
				"-name=vpc-flood-direct-2node", "-streams=16", "-server-xdp", "-no-nic-poll", counter,
				`-client-argv=["vpcbench","flood-source","-id","ID","-seq","SEQ","-server","$SERVER_IP:4433","-ports","$STREAMS","-omit","${OMIT_S}s","-duration","${DURATION_S}s","-start-timeout","5m"]`,
			},
			notWant: []string{"-sidecar-argv", "-relay-xdp"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			o := Options{Duration: "30s", Reps: 3, MinCPUs: 16, Host: true, Only: append(strings.Split(before, ","), tc.id)}
			rows := VPC.rows(o)
			i := slices.IndexFunc(rows, func(r Row) bool { return r.ID == tc.id })
			if i < 0 {
				t.Fatalf("no row %s", tc.id)
			}
			r := rows[i]
			if r.Group != "info" || r.Cmd != "node" || r.Hosts() != tc.wantHosts {
				t.Errorf("group %s, cmd %s, hosts %d, want info, node and %d hosts", r.Group, r.Cmd, r.Hosts(), tc.wantHosts)
			}
			for _, w := range tc.want {
				w = strings.ReplaceAll(strings.ReplaceAll(w, `"ID"`, `"`+tc.id+`"`), `"SEQ"`, `"3"`)
				if !slices.Contains(r.Args, w) {
					t.Errorf("args have no %s:\n%s", w, strings.Join(r.Args, "\n"))
				}
			}
			for _, nw := range tc.notWant {
				if slices.ContainsFunc(r.Args, func(a string) bool { return strings.HasPrefix(a, nw) }) {
					t.Errorf("args have %s", nw)
				}
			}
			// A flood row has no flag of the netns rig and no floor.
			if slices.ContainsFunc(r.Args, func(a string) bool {
				return strings.HasPrefix(a, "-reps") || strings.HasPrefix(a, "-workload") || strings.HasPrefix(a, "-baseline") || strings.HasPrefix(a, "-delay")
			}) {
				t.Errorf("args have a flag of the netns rig: %v", r.Args)
			}
		})
	}
}

// TestFloodRowsNotInDefaultRun checks that a run with no row names, as the
// nightly run is, has no flood row, and that each row of the suite has its own ID.
func TestFloodRowsNotInDefaultRun(t *testing.T) {
	o := Options{Duration: "30s", Reps: 3, MinCPUs: 16, Host: true}
	for _, r := range parsePlan(t, VPC, o).Rows {
		if strings.HasPrefix(r.ID, "flood-") {
			t.Errorf("the default run has the flood row %s", r.ID)
		}
	}
	if data, err := VPC.NodePlans(o); err != nil || data != "" {
		t.Errorf("node plans of the default run = %q, %v, want none", data, err)
	}
	ids := map[string]bool{}
	for _, r := range VPC.rows(o) {
		if ids[r.ID] {
			t.Errorf("two rows have the ID %s", r.ID)
		}
		ids[r.ID] = true
		if !strings.HasPrefix(r.ID, "flood-") {
			continue
		}
		if !slices.Contains(r.Args, "-server-xdp") {
			t.Errorf("the row %s does not set the link of the counter host for XDP", r.ID)
		}
		if !slices.Contains(r.Args, "-no-nic-poll") {
			t.Errorf("the hosts of the row %s read their NIC counters while the packets flow", r.ID)
		}
	}
	if len(ids) != len(vpcRows)+len(floodRows) {
		t.Errorf("the suite has %d rows, want %d", len(ids), len(vpcRows)+len(floodRows))
	}
}

func TestFloodNodePlans(t *testing.T) {
	cases := []struct {
		name      string
		only      []string
		profile   bool
		wantRoles map[string][]string
	}{
		{
			name: "relay row", only: []string{"flood-relay-3node-p16-xdp"},
			wantRoles: map[string][]string{"client": {"flood-relay-3node-p16-xdp"}, "server": {"flood-relay-3node-p16-xdp"}, "relay": {"flood-relay-3node-p16-xdp"}},
		},
		{
			name: "direct row and relay row with profiles", only: []string{"flood-direct-2node-p16", "flood-relay-3node-p16-xdp-geneve"}, profile: true,
			wantRoles: map[string][]string{
				"client": {"flood-direct-2node-p16", "flood-relay-3node-p16-xdp-geneve"},
				"server": {"flood-direct-2node-p16", "flood-relay-3node-p16-xdp-geneve"},
				"relay":  {"flood-relay-3node-p16-xdp-geneve"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := VPC.NodePlans(Options{Duration: "30s", MinCPUs: 16, Host: true, Only: tc.only, Profile: tc.profile})
			if err != nil {
				t.Fatal(err)
			}
			var plans map[string]Plan
			if err := json.Unmarshal([]byte(data), &plans); err != nil {
				t.Fatal(err)
			}
			if len(plans) != len(tc.wantRoles) {
				t.Fatalf("roles = %v, want %v", plans, tc.wantRoles)
			}
			for role, wantIDs := range tc.wantRoles {
				var ids []string
				for _, r := range plans[role].Rows {
					ids = append(ids, r.ID)
					if r.Cmd != "node" || !slices.Contains(r.Args, "-role="+role) {
						t.Errorf("%s row %s: cmd %q, args %v", role, r.ID, r.Cmd, r.Args)
					}
					argv := map[string]string{"client": "-client-argv=", "server": "-server-argv=", "relay": "-sidecar-argv="}[role]
					has := slices.ContainsFunc(r.Args, func(a string) bool {
						return strings.HasPrefix(a, argv) && strings.Contains(a, `"-kernel","$WORK_DIR/`+role+`-kernel"`)
					})
					if has != tc.profile {
						t.Errorf("%s row %s: profile flags %v, want %v", role, r.ID, has, tc.profile)
					}
				}
				if !slices.Equal(ids, wantIDs) {
					t.Errorf("%s rows = %v, want %v", role, ids, wantIDs)
				}
				if slices.Contains(plans[role].Modules, "sch_netem") {
					t.Errorf("%s plan loads netem", role)
				}
			}
		})
	}
}
