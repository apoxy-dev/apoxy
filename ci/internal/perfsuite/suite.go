// Package perfsuite has the perf suites of the CI module: the rows of each
// suite, the plan for perfagent, the summary of the results and the Slack
// text. It has no Dagger code, so its tests run with plain go test.
package perfsuite

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Row is one "perfrig run" or "perfrig node" of a suite. perfagent adds -out
// and -out-dir.
type Row struct {
	ID    string `json:"id"`
	Group string `json:"group"`
	// Cmd is the perfrig command: run (the default) or node.
	Cmd  string   `json:"cmd,omitempty"`
	Args []string `json:"args"`
	// hosts is the number of hosts of a node row: 2 with no relay, 3 with one
	// and 4 with two. It is 0 for a row of the netns rig.
	hosts int
	// netem tells that a node row adds a netem delay on each host.
	netem bool
}

// Hosts returns the number of hosts of a node row, or 0 for a row of the netns rig.
func (r Row) Hosts() int { return r.hosts }

// Plan is the perfagent spec without the parts that the perf module sets.
type Plan struct {
	Sysctls map[string]string `json:"sysctls,omitempty"`
	Modules []string          `json:"modules,omitempty"`
	Tun     bool              `json:"tun,omitempty"`
	Remove  []string          `json:"remove,omitempty"`
	Rows    []Row             `json:"rows"`
}

// Options set the rows of a run.
type Options struct {
	Duration string
	// Reps is the reps of each floor row. Info rows run one time.
	Reps    int
	MinCPUs int
	// Only selects rows by ID. Empty IDs are ignored, and no ID selects all rows.
	Only []string
	// Host tells that perfagent sets up the host: an EC2 instance, not a container.
	Host bool
	// Profile makes the VPC rows write pprof files, a short runtime trace and the
	// kernel counters. It costs some throughput.
	Profile bool
}

// Suite is a set of rows with their binaries.
type Suite struct {
	Name  string
	Title string
	// Bins are the commands (cmd/NAME) that the rows run, besides perfrig.
	Bins []string
	// Tun makes /dev/net/tun for the tun driver.
	Tun bool
	// Remove are file patterns that perfagent deletes before the upload.
	Remove []string
	rows   func(Options) []Row
}

// hostSysctls are global keys that a child netns does not see. Only the host can set them.
var hostSysctls = map[string]string{
	"net.core.rmem_max":           "134217728",
	"net.core.wmem_max":           "134217728",
	"net.core.netdev_max_backlog": "250000",
}

// Plan returns the plan JSON of the selected rows of the netns rig. It is
// empty when o selects only node rows.
func (s Suite) Plan(o Options) (string, error) {
	rows, err := s.selected(o)
	if err != nil {
		return "", err
	}
	rows = slices.DeleteFunc(rows, func(r Row) bool { return r.hosts > 0 })
	if len(rows) == 0 {
		return "", nil
	}
	p := Plan{Tun: s.Tun, Remove: s.Remove, Rows: rows}
	if o.Host {
		p.Sysctls = hostSysctls
		p.Modules = []string{"sch_netem"}
	}
	b, err := json.Marshal(p)
	return string(b), err
}

// NodePlans returns a JSON object with a plan for each host role of the selected
// node rows, with -role set in each row. It is empty when o selects no node row.
func (s Suite) NodePlans(o Options) (string, error) {
	rows, err := s.selected(o)
	if err != nil {
		return "", err
	}
	rows = slices.DeleteFunc(rows, func(r Row) bool { return r.hosts == 0 })
	if len(rows) == 0 {
		return "", nil
	}
	// The hosts of a row with two relays are in two regions, and the other node
	// rows need all hosts in one region.
	two := func(r Row) bool { return r.hosts > 3 }
	if slices.ContainsFunc(rows, two) && slices.ContainsFunc(rows, func(r Row) bool { return !two(r) }) {
		return "", errors.New("the rows with two relays and the other node rows run in separate calls: select one kind with --rows")
	}
	plans := map[string]Plan{}
	for _, role := range []string{"client", "server", "relay", "relay2"} {
		var picked []Row
		for _, r := range rows {
			if (role == "relay" && r.hosts < 3) || (role == "relay2" && r.hosts < 4) {
				continue
			}
			r.Args = append(slices.Clone(r.Args), "-role="+role)
			picked = append(picked, r)
		}
		if len(picked) == 0 {
			continue
		}
		p := Plan{Tun: s.Tun, Remove: s.Remove, Rows: picked}
		if o.Host {
			p.Sysctls = hostSysctls
			if slices.ContainsFunc(picked, func(r Row) bool { return r.netem }) {
				p.Modules = []string{"sch_netem"}
			}
		}
		plans[role] = p
	}
	b, err := json.Marshal(plans)
	return string(b), err
}

// selected returns the rows that o selects. With no row IDs, it selects all
// rows of the netns rig: the node rows run only when o names them.
func (s Suite) selected(o Options) ([]Row, error) {
	rows := s.rows(o)
	// A workflow input with no rows gives an empty ID.
	only := slices.DeleteFunc(slices.Clone(o.Only), func(id string) bool { return id == "" })
	if len(only) == 0 {
		return slices.DeleteFunc(rows, func(r Row) bool { return r.hosts > 0 }), nil
	}
	var picked []Row
	for _, id := range only {
		i := slices.IndexFunc(rows, func(r Row) bool { return r.ID == id })
		if i < 0 {
			return nil, fmt.Errorf("unknown %s row %q", s.Name, id)
		}
		picked = append(picked, rows[i])
	}
	return picked, nil
}

// Selects reports whether o selects a row of group. It is true when o is not valid.
func (s Suite) Selects(o Options, group string) bool {
	rows, err := s.selected(o)
	return err != nil || slices.ContainsFunc(rows, func(r Row) bool { return r.Group == group })
}

// Groups returns the result groups of the suite, floor first.
func (s Suite) Groups() []string {
	var groups []string
	for _, r := range s.rows(Options{}) {
		if !slices.Contains(groups, r.Group) {
			groups = append(groups, r.Group)
		}
	}
	slices.SortStableFunc(groups, func(a, b string) int {
		if a == "floor" {
			return -1
		}
		if b == "floor" {
			return 1
		}
		return 0
	})
	return groups
}

// common are the perfrig flags of all rows. A floor row with a failed median
// runs its reps one more time (perfrig -baseline).
func common(o Options, group string) []string {
	reps := 1
	args := []string{"-delay=10ms", "-duration=" + o.Duration, "-min-cpus=" + strconv.Itoa(o.MinCPUs), "-max-steal=5"}
	if group == "floor" {
		reps = max(o.Reps, 1)
		args = append(args, "-baseline=baseline.json")
	}
	return append(args, "-reps="+strconv.Itoa(reps))
}

// Netns is the netns + netem rig with iperf3. All rows are floor rows.
var Netns = Suite{
	Name:  "netns",
	Title: "netns rig",
	rows: func(o Options) []Row {
		row := func(id string, args ...string) Row {
			return Row{ID: id, Group: "floor", Args: append(args, common(o, "floor")...)}
		}
		return []Row{
			row("iperf3-tcp-p1", "-workload=iperf3-tcp", "-streams=1"),
			row("iperf3-tcp-p4", "-workload=iperf3-tcp", "-streams=4"),
			row("iperf3-tcp-p4-loss0.1", "-workload=iperf3-tcp", "-streams=4", "-loss=0.1"),
			row("iperf3-udp-p1", "-workload=iperf3-udp", "-streams=1"),
		}
	},
}

// vpcRow is one row of VPC. The result key has no CC, driver or transport,
// so the name holds them.
type vpcRow struct {
	id, name string
	floor    bool
	// direct runs the flows with no relay.
	direct bool
	// relayNetns runs the relay in its own netns, so that it sends the
	// packets to the server on a link. xdp forwards them in XDP there, or on
	// the NIC of the relay host of a node row.
	relayNetns, xdp bool
	// generic attaches the XDP program of a node row in generic mode. The
	// relay host then keeps its channels and its MTU.
	generic bool
	// xdpRelay attaches the XDP program on only one relay of a row with two
	// relays: 1 is the relay of the client and 2 the relay of the server. 0 is both.
	xdpRelay int
	// nodes runs each role on its own EC2 host, with no netem: 2 hosts with no
	// relay, 3 with one, and 4 with two relays that have a mesh session. The
	// client attaches at the first relay and the server at the second, and each
	// agent host is in the region of its relay. 0 runs the row in the netns rig.
	nodes int
	// streams is the flow count. 0 gives 4 flows.
	streams int
	// relay, server and client are more vpcbench flags. args are more perfrig flags.
	// A node row takes -delay, the netem delay on the egress of each host.
	relay, server, client []string
	args                  []string
}

// vpcRows are the floor row and the info rows.
var vpcRows = []vpcRow{
	{id: "netstack-psp-relay", name: "vpc-netstack-psp-relay", floor: true, client: []string{"-cc", "bbr"}},
	{id: "netstack-quic-relay", name: "vpc-netstack-quic-relay", server: []string{"-transport", "quic"}, client: []string{"-transport", "quic", "-cc", "bbr"}},
	{id: "tun-psp-relay-cubic", name: "vpc-tun-psp-relay-cubic", server: []string{"-driver", "tun"}, client: []string{"-driver", "tun", "-cc", "cubic"}},
	{id: "netstack-psp-relay-loss0.1", name: "vpc-netstack-psp-relay", client: []string{"-cc", "bbr"}, args: []string{"-loss=0.1"}},
	{id: "netstack-psp-direct", name: "vpc-netstack-psp-direct", direct: true, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-cubic", name: "vpc-netstack-psp-relay-cubic", client: []string{"-cc", "cubic"}},
	{id: "netstack-psp-relay-rate1000mbit", name: "vpc-netstack-psp-relay", client: []string{"-cc", "bbr"}, args: []string{"-rate=1000mbit", "-queue-limit=2640"}},
	{id: "netstack-psp-relay-netns", name: "vpc-netstack-psp-relay-netns", relayNetns: true, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-xdp", name: "vpc-netstack-psp-relay-xdp", relayNetns: true, xdp: true, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-direct-1flow", name: "vpc-netstack-psp-direct", direct: true, streams: 1, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-direct-2node", name: "vpc-netstack-psp-direct-2node", direct: true, nodes: 2, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-direct-2node-1flow", name: "vpc-netstack-psp-direct-2node", direct: true, nodes: 2, streams: 1, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-direct-2node-p16", name: "vpc-netstack-psp-direct-2node", direct: true, nodes: 2, streams: 16, client: []string{"-cc", "bbr"}},
	// Netem on the egress of each host gives 20 ms RTT, as in the netns rig.
	{id: "netstack-psp-direct-2node-20ms", name: "vpc-netstack-psp-direct-2node", direct: true, nodes: 2, client: []string{"-cc", "bbr"}, args: []string{"-delay=10ms"}},
	{id: "netstack-psp-direct-2node-1flow-20ms", name: "vpc-netstack-psp-direct-2node", direct: true, nodes: 2, streams: 1, client: []string{"-cc", "bbr"}, args: []string{"-delay=10ms"}},
	{id: "netstack-psp-relay-3node", name: "vpc-netstack-psp-relay-3node", nodes: 3, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-3node-p16", name: "vpc-netstack-psp-relay-3node", nodes: 3, streams: 16, client: []string{"-cc", "bbr"}},
	// The relay takes no lane ports, so each agent sends and receives on one port.
	{id: "netstack-psp-relay-3node-nolanes", name: "vpc-netstack-psp-relay-3node-nolanes", nodes: 3, relay: []string{"-lanes", "0"}, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-3node-p16-nolanes", name: "vpc-netstack-psp-relay-3node-nolanes", nodes: 3, streams: 16, relay: []string{"-lanes", "0"}, client: []string{"-cc", "bbr"}},
	// The relay forwards in XDP on its NIC, in driver mode when the driver takes the program.
	{id: "netstack-psp-relay-3node-xdp", name: "vpc-netstack-psp-relay-3node-xdp", nodes: 3, xdp: true, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-3node-p16-xdp", name: "vpc-netstack-psp-relay-3node-xdp", nodes: 3, streams: 16, xdp: true, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-3node-p8-xdp", name: "vpc-netstack-psp-relay-3node-xdp", nodes: 3, streams: 8, xdp: true, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-3node-p32-xdp", name: "vpc-netstack-psp-relay-3node-xdp", nodes: 3, streams: 32, xdp: true, client: []string{"-cc", "bbr"}},
	// One relay RX queue gets all packets, so the row gives the most packets that one CPU forwards.
	{id: "netstack-psp-relay-3node-p16-xdp-q1", name: "vpc-netstack-psp-relay-3node-xdp-q1", nodes: 3, streams: 16, xdp: true, client: []string{"-cc", "bbr"}, args: []string{"-relay-channels=1"}},
	// ENA takes the program in driver mode only with a small MTU. A link with MTU 9001 runs it in generic mode.
	{id: "netstack-psp-relay-3node-p16-xdp-generic", name: "vpc-netstack-psp-relay-3node-xdp-generic", nodes: 3, streams: 16, xdp: true, generic: true, client: []string{"-cc", "bbr"}},
	// The packets go from the relay of the client to the relay of the server on the
	// path between two regions. The XDP rows forward in generic mode on the two relays.
	{id: "netstack-psp-relay-4node-1flow", name: "vpc-netstack-psp-relay-4node", nodes: 4, streams: 1, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-4node", name: "vpc-netstack-psp-relay-4node", nodes: 4, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-4node-p16", name: "vpc-netstack-psp-relay-4node", nodes: 4, streams: 16, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-4node-1flow-xdp-generic", name: "vpc-netstack-psp-relay-4node-xdp-generic", nodes: 4, streams: 1, xdp: true, generic: true, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-4node-1flow-xdp", name: "vpc-netstack-psp-relay-4node-xdp", nodes: 4, streams: 1, xdp: true, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-4node-1flow-xdp-generic-relay1", name: "vpc-netstack-psp-relay-4node-xdp-generic-relay1", nodes: 4, streams: 1, xdp: true, generic: true, xdpRelay: 1, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-4node-1flow-xdp-generic-relay2", name: "vpc-netstack-psp-relay-4node-xdp-generic-relay2", nodes: 4, streams: 1, xdp: true, generic: true, xdpRelay: 2, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-4node-xdp-generic", name: "vpc-netstack-psp-relay-4node-xdp-generic", nodes: 4, xdp: true, generic: true, client: []string{"-cc", "bbr"}},
	{id: "netstack-psp-relay-4node-p16-xdp-generic", name: "vpc-netstack-psp-relay-4node-xdp-generic", nodes: 4, streams: 16, xdp: true, generic: true, client: []string{"-cc", "bbr"}},
}

// nodeStartTimeout is the time that vpcbench on one host waits for the hosts
// of the other roles. The hosts boot at the same time, but not in step.
const nodeStartTimeout = "5m"

// argv returns the vpcbench commands of the roles. The relay is the sidecar of
// the server, in the server netns, in its own netns or on its own host. sidecar2
// is the second relay of a row with two relays, else nil.
func (r vpcRow) argv(o Options) (sidecar, sidecar2, server, client []string) {
	relay := "$SERVER_IP:4443"
	if r.relayNetns || r.nodes > 0 {
		relay = "$RELAY_IP:4443"
	}
	relayArgv := func(listen string, n int) []string {
		argv := []string{"vpcbench", "relay", "-listen", listen}
		switch {
		case r.xdpRelay != 0 && r.xdpRelay != n:
		case r.xdp && r.generic:
			argv = append(argv, "-xdp", "$DEV", "-xdp-mode", "generic")
		case r.xdp && r.nodes > 0:
			argv = append(argv, "-xdp", "$DEV", "-xdp-mode", "driver")
		case r.xdp:
			// perf-r is the link of the perfrig relay netns.
			argv = append(argv, "-xdp", "perf-r")
		}
		return append(argv, r.relay...)
	}
	sidecar = relayArgv(relay, 1)
	server = []string{"vpcbench", "server", "-relay", relay, "-listen", "$SERVER_IP:4433"}
	client = []string{"vpcbench", "client", "-relay", relay, "-server", "$SERVER_IP:4433"}
	if r.nodes > 3 {
		// The relay with the lower mesh name dials, so the first relay dials the second.
		const relay2 = "$RELAY2_IP:4443"
		sidecar = append(sidecar, "-mesh", "relay-1")
		sidecar2 = append(relayArgv(relay2, 2), "-mesh", "relay-2", "-join", relay, "-start-timeout", nodeStartTimeout)
		server = []string{"vpcbench", "server", "-relay", relay2, "-listen", "$SERVER_IP:4433"}
		client = append(client, "-server-relay", relay2)
	}
	if r.direct {
		sidecar = nil
		server = []string{"vpcbench", "server", "-via", "direct", "-listen", "$SERVER_IP:4433"}
		client = []string{"vpcbench", "client", "-via", "direct", "-server", "$SERVER_IP:4433"}
	}
	server = append(server, r.server...)
	client = append(append(client, r.client...), "-streams", "$STREAMS", "-omit", "${OMIT_S}s", "-duration", "${DURATION_S}s")
	if r.nodes > 0 {
		server = append(server, "-start-timeout", nodeStartTimeout)
		client = append(client, "-start-timeout", nodeStartTimeout)
		if !r.direct {
			client = append(client, "-stop-relay")
		}
	}
	if o.Profile {
		if sidecar != nil {
			sidecar = append(sidecar, profileArgs("relay")...)
		}
		if sidecar2 != nil {
			sidecar2 = append(sidecar2, profileArgs("relay2")...)
		}
		server = append(server, profileArgs("server")...)
		client = append(client, profileArgs("client")...)
	}
	return sidecar, sidecar2, server, client
}

func (r vpcRow) row(o Options) Row {
	sidecar, sidecar2, server, client := r.argv(o)
	group := "info"
	if r.floor {
		group = "floor"
	}
	streams := "-streams=4"
	if r.streams > 0 {
		streams = "-streams=" + strconv.Itoa(r.streams)
	}
	var args []string
	if r.nodes > 0 {
		args = []string{"-name=" + r.name, streams, "-omit=5s", "-duration=" + o.Duration,
			"-min-cpus=" + strconv.Itoa(o.MinCPUs), "-max-steal=5"}
		if r.xdp {
			args = append(args, "-relay-xdp")
		}
		if r.generic {
			args = append(args, "-relay-xdp-generic")
		}
	} else {
		args = []string{"-workload=exec", "-name=" + r.name, "-netns-prefix=perf", "-ready=tcp:4433", streams, "-omit=5s"}
		args = append(args, common(o, group)...)
	}
	args = append(args, "-server-argv="+jsonArgv(server), "-client-argv="+jsonArgv(client))
	if sidecar != nil {
		args = append(args, "-sidecar-argv="+jsonArgv(sidecar))
	}
	if sidecar2 != nil {
		args = append(args, "-sidecar2-argv="+jsonArgv(sidecar2))
	}
	if r.relayNetns {
		args = append(args, "-relay-netns")
	}
	row := Row{ID: r.id, Group: group, Args: append(args, r.args...), hosts: r.nodes}
	if r.nodes > 0 {
		row.Cmd = "node"
		row.netem = slices.ContainsFunc(r.args, func(a string) bool { return strings.HasPrefix(a, "-delay=") })
	}
	return row
}

// profileArgs are the vpcbench flags that write the profiles, the runtime trace
// and the kernel counters of role to the work dir of the rep. perfagent uploads
// them with the results.
func profileArgs(role string) []string {
	var args []string
	for _, kind := range []string{"cpu", "block", "mutex"} {
		args = append(args, "-"+kind+"profile", "$WORK_DIR/"+role+"-"+kind+".pprof")
	}
	return append(args, "-trace", "$WORK_DIR/"+role+".trace", "-kernel", "$WORK_DIR/"+role+"-kernel")
}

// VPC is the VPC data path through the relay, with one floor row and info
// rows. The node rows run on 2, 3 or 4 EC2 hosts. The flood rows are node rows
// that measure the XDP forward of the relay with no agent.
var VPC = Suite{
	Name:  "vpc",
	Title: "VPC perf",
	Bins:  []string{"vpcbench"},
	Tun:   true,
	// The work dirs have the throwaway agent keys of each run.
	Remove: []string{"*-cred.json"},
	rows: func(o Options) []Row {
		rows := make([]Row, 0, len(vpcRows)+len(floodRows))
		for _, r := range vpcRows {
			rows = append(rows, r.row(o))
		}
		for _, r := range floodRows {
			rows = append(rows, r.row(o))
		}
		return rows
	},
}

// jsonArgv returns argv as a perfrig -server-argv value.
func jsonArgv(argv []string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(argv)
	return string(bytes.TrimSpace(buf.Bytes()))
}
