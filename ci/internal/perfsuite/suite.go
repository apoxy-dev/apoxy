// Package perfsuite has the perf suites of the CI module: the rows of each
// suite, the plan for perfagent, the summary of the results and the Slack
// text. It has no Dagger code, so its tests run with plain go test.
package perfsuite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
)

// Row is one "perfrig run" of a suite. perfagent adds -out and -out-dir.
type Row struct {
	ID    string   `json:"id"`
	Group string   `json:"group"`
	Args  []string `json:"args"`
}

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
	// Profile makes the VPC rows write pprof files. It costs some throughput.
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

// Plan returns the plan JSON of the suite.
func (s Suite) Plan(o Options) (string, error) {
	rows, err := s.selected(o)
	if err != nil {
		return "", err
	}
	p := Plan{Tun: s.Tun, Remove: s.Remove, Rows: rows}
	if o.Host {
		p.Sysctls = hostSysctls
		p.Modules = []string{"sch_netem"}
	}
	b, err := json.Marshal(p)
	return string(b), err
}

// selected returns the rows that o selects.
func (s Suite) selected(o Options) ([]Row, error) {
	rows := s.rows(o)
	// A workflow input with no rows gives an empty ID.
	only := slices.DeleteFunc(slices.Clone(o.Only), func(id string) bool { return id == "" })
	if len(only) == 0 {
		return rows, nil
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
	// packets to the server on a link. xdp forwards them in XDP there.
	relayNetns, xdp bool
	// server and client are more vpcbench flags. args are more perfrig run flags.
	server, client []string
	args           []string
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
}

func (r vpcRow) row(o Options) Row {
	// The relay is the sidecar of the server. perfrig stops it after the server exits.
	relay := "$SERVER_IP:4443"
	if r.relayNetns {
		relay = "$RELAY_IP:4443"
	}
	sidecar := []string{"vpcbench", "relay", "-listen", relay}
	if r.xdp {
		// perf-r is the link of the perfrig relay netns.
		sidecar = append(sidecar, "-xdp", "perf-r")
	}
	server := []string{"vpcbench", "server", "-relay", relay, "-listen", "$SERVER_IP:4433"}
	client := []string{"vpcbench", "client", "-relay", relay, "-server", "$SERVER_IP:4433"}
	if r.direct {
		sidecar = nil
		server = []string{"vpcbench", "server", "-via", "direct", "-listen", "$SERVER_IP:4433"}
		client = []string{"vpcbench", "client", "-via", "direct", "-server", "$SERVER_IP:4433"}
	}
	server = append(server, r.server...)
	client = append(append(client, r.client...), "-streams", "$STREAMS", "-omit", "${OMIT_S}s", "-duration", "${DURATION_S}s")
	if o.Profile {
		if sidecar != nil {
			sidecar = append(sidecar, profileArgs("relay")...)
		}
		server = append(server, profileArgs("server")...)
		client = append(client, profileArgs("client")...)
	}
	group := "info"
	if r.floor {
		group = "floor"
	}
	args := []string{"-workload=exec", "-name=" + r.name, "-netns-prefix=perf", "-ready=tcp:4433", "-streams=4", "-omit=5s"}
	args = append(args, common(o, group)...)
	args = append(args, "-server-argv="+jsonArgv(server), "-client-argv="+jsonArgv(client))
	if sidecar != nil {
		args = append(args, "-sidecar-argv="+jsonArgv(sidecar))
	}
	if r.relayNetns {
		args = append(args, "-relay-netns")
	}
	return Row{ID: r.id, Group: group, Args: append(args, r.args...)}
}

// profileArgs are the vpcbench flags that write the profiles of role to the
// work dir of the rep. perfagent uploads them with the results.
func profileArgs(role string) []string {
	var args []string
	for _, kind := range []string{"cpu", "block", "mutex"} {
		args = append(args, "-"+kind+"profile", "$WORK_DIR/"+role+"-"+kind+".pprof")
	}
	return args
}

// VPC is the VPC data path through the relay, with one floor row and info rows.
var VPC = Suite{
	Name:  "vpc",
	Title: "VPC perf",
	Bins:  []string{"vpcbench"},
	Tun:   true,
	// The work dirs have the throwaway CA and agent keys of each run.
	Remove: []string{"*-cred.json", "vpcbench-ca.pem"},
	rows: func(o Options) []Row {
		rows := make([]Row, 0, len(vpcRows))
		for _, r := range vpcRows {
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
