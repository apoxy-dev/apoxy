package perfsuite

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestENIRows(t *testing.T) {
	const (
		server    = `-server-argv=["vpcbench","server","-relay","$RELAY_CTL_IP:4443","-listen","$SERVER_IP:4433","-start-timeout","5m"]`
		client    = `-client-argv=["vpcbench","client","-relay","$RELAY_CTL_IP:4443","-server","$SERVER_IP:4433","-cc","bbr","-streams","$STREAMS","-omit","${OMIT_S}s","-duration","${DURATION_S}s","-start-timeout","5m","-stop-relay"]`
		relayZC   = `-sidecar-argv=["vpcbench","relay","-imds","-zero-copy","on","-listen","$RELAY_CTL_IP:4443","-kernel","$WORK_DIR/relay-kernel"]`
		relayCopy = `-sidecar-argv=["vpcbench","relay","-imds","-zero-copy","off","-listen","$RELAY_CTL_IP:4443","-kernel","$WORK_DIR/relay-kernel"]`
	)
	common := []string{"-omit=5s", "-duration=30s", "-min-cpus=16", "-max-steal=5", "-relay-xdp", "-relay-link=eni1", "-no-nic-poll", server, client}
	cases := []struct {
		id      string
		profile bool
		want    []string
		notWant []string
	}{
		{
			id:      "netstack-psp-relay-3node-eni-zc-r1",
			want:    append([]string{"-name=vpc-netstack-psp-relay-3node-eni-zc", "-streams=4", relayZC}, common...),
			notWant: []string{"-relay-channels", "-relay-netns", "-server-xdp"},
		},
		{
			id:      "netstack-psp-relay-3node-eni-p16-copy-r2",
			want:    append([]string{"-name=vpc-netstack-psp-relay-3node-eni-p16-copy", "-streams=16", relayCopy}, common...),
			notWant: []string{"-relay-channels"},
		},
		{
			id:   "netstack-psp-relay-3node-eni-1flow-zc-r2",
			want: append([]string{"-name=vpc-netstack-psp-relay-3node-eni-1flow-zc", "-streams=1", relayZC}, common...),
		},
		{
			id:   "netstack-psp-relay-3node-eni-q1-copy-r1",
			want: append([]string{"-name=vpc-netstack-psp-relay-3node-eni-q1-copy", "-streams=16", "-relay-channels=1", relayCopy}, common...),
		},
		{
			id: "netstack-psp-relay-3node-eni-p16-zc-prof",
			want: append([]string{"-name=vpc-netstack-psp-relay-3node-eni-p16-zc", "-streams=16",
				`-sidecar-argv=["vpcbench","relay","-imds","-zero-copy","on","-listen","$RELAY_CTL_IP:4443","-kernel","$WORK_DIR/relay-kernel","-cpuprofile","$WORK_DIR/relay-cpu.pprof"]`}, common...),
		},
		{
			id: "netstack-psp-relay-3node-eni-zc-r1", profile: true,
			want: []string{`-sidecar-argv=["vpcbench","relay","-imds","-zero-copy","on","-listen","$RELAY_CTL_IP:4443",` +
				`"-cpuprofile","$WORK_DIR/relay-cpu.pprof","-blockprofile","$WORK_DIR/relay-block.pprof","-mutexprofile","$WORK_DIR/relay-mutex.pprof",` +
				`"-trace","$WORK_DIR/relay.trace","-kernel","$WORK_DIR/relay-kernel"]`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			tests := VPC.rows(Options{Duration: "30s", MinCPUs: 16, Host: true, Only: []string{tc.id}, Profile: tc.profile})
			i := slices.IndexFunc(tests, func(r Row) bool { return r.ID == tc.id })
			if i < 0 {
				t.Fatalf("no perf test case %s", tc.id)
			}
			r := tests[i]
			if r.Group != "info" || r.Cmd != "node" || r.Hosts() != 3 || !r.eni {
				t.Errorf("group %s, cmd %s, hosts %d, eni %v, want info, node, 3 hosts and the ENI", r.Group, r.Cmd, r.Hosts(), r.eni)
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

func TestRelayENI(t *testing.T) {
	cases := []struct {
		name    string
		only    []string
		want    bool
		wantErr bool
	}{
		{name: "default run", want: false},
		{name: "flood perf test case", only: []string{"flood-relay-3node-p16-xdp"}, want: false},
		{name: "ENI perf test case", only: []string{"flood-direct-2node-p16", "netstack-psp-relay-3node-eni-p16-zc-r1"}, want: true},
		{name: "unknown perf test case", only: []string{"netstack-psp-relay-3node-eni-p32-zc-r1"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := VPC.RelayENI(Options{Duration: "30s", MinCPUs: 16, Host: true, Only: tc.only})
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("RelayENI = %v, %v, want %v and error %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// TestENIRunIDs checks the IDs of one boot: each case in each mode two times,
// and one profile perf test case, all with their own ID and all not in the default run.
func TestENIRunIDs(t *testing.T) {
	o := Options{Duration: "30s", MinCPUs: 16, Host: true}
	var ids []string
	for _, r := range eniPerfTests(o) {
		ids = append(ids, r.ID)
	}
	if len(ids) != len(eniCases)*len(eniModes)*eniReps+1 {
		t.Fatalf("ENI perf test cases = %d: %v", len(ids), ids)
	}
	for _, id := range ids {
		if strings.Count(strings.Join(ids, ","), id+",") > 1 {
			t.Errorf("two perf test cases have the ID %s", id)
		}
	}
	data, err := VPC.NodePlans(Options{Duration: "30s", MinCPUs: 16, Host: true, Only: ids})
	if err != nil {
		t.Fatal(err)
	}
	var plans map[string]Plan
	if err := json.Unmarshal([]byte(data), &plans); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"client", "server", "relay"} {
		var got []string
		for _, r := range plans[role].Rows {
			got = append(got, r.ID)
			if !slices.Contains(r.Args, "-role="+role) {
				t.Errorf("%s perf test case %s has no -role", role, r.ID)
			}
		}
		if !slices.Equal(got, ids) {
			t.Errorf("%s perf test cases = %v, want %v", role, got, ids)
		}
		if slices.Contains(plans[role].Modules, "sch_netem") {
			t.Errorf("%s plan loads netem", role)
		}
	}
	if data, err := VPC.NodePlans(o); err != nil || data != "" {
		t.Errorf("node plans of the default run = %q, %v, want none", data, err)
	}
}
