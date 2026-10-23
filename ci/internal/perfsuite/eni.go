package perfsuite

import (
	"slices"
	"strconv"
)

// eniCase is a perf test case of the relay on its own host and its own ENI, as a
// production relay node has it: the ENI at device index 1 has no kernel address,
// and the relay finds it in IMDS. The agents run on two other hosts. Each case
// runs with AF_XDP zero-copy and with copy, and two times in a run, each time
// with its own ID, so that one boot gives two results of each mode.
type eniCase struct {
	// stem is the part of the ID and the name after netstack-psp-relay-3node-.
	stem    string
	streams int
	// channels is the most channels of the relay link (0: half of the max).
	channels int
}

var eniCases = []eniCase{
	{stem: "eni", streams: 4},
	// The most load from one agent pair.
	{stem: "eni-p16", streams: 16},
	// The cost of each packet at a low rate.
	{stem: "eni-1flow", streams: 1},
	// One relay queue gets all packets: the most packets that one CPU forwards with AF_XDP.
	{stem: "eni-q1", streams: 16, channels: 1},
}

// eniModes are the zero-copy settings of the relay: the value of vpcbench -zero-copy by ID suffix.
var eniModes = []struct {
	suffix   string
	zeroCopy bool
}{{"zc", true}, {"copy", false}}

// eniReps is the number of IDs of each case and mode.
const eniReps = 2

// eniPerfTests returns the perf test cases of each case, mode and rep, and one
// zero-copy perf test case of 16 flows that writes a CPU profile of the relay,
// which costs some throughput.
func eniPerfTests(o Options) []Row {
	var tests []Row
	for _, c := range eniCases {
		for _, m := range eniModes {
			for rep := 1; rep <= eniReps; rep++ {
				tests = append(tests, c.perfTest(o, m.suffix, m.zeroCopy, "-r"+strconv.Itoa(rep), false))
			}
		}
	}
	return append(tests, eniCases[1].perfTest(o, "zc", true, "-prof", true))
}

// perfTest returns the node perf test case of the case with the zero-copy setting zc.
func (c eniCase) perfTest(o Options, mode string, zc bool, idSuffix string, prof bool) Row {
	const relay = "$RELAY_CTL_IP:4443"
	name := "vpc-netstack-psp-relay-3node-" + c.stem + "-" + mode
	// The BPF IRQ timer of -kernel measures the softirq time, which /proc/stat
	// can show too low, and the kernel stacks of the second half of the window.
	sidecar := []string{"vpcbench", "relay", "-imds", "-zero-copy=" + strconv.FormatBool(zc), "-listen", relay, "-kernel", "$WORK_DIR/relay-kernel"}
	server := []string{"vpcbench", "server", "-relay", relay, "-listen", "$SERVER_IP:4433", "-start-timeout", nodeStartTimeout}
	client := []string{"vpcbench", "client", "-relay", relay, "-server", "$SERVER_IP:4433", "-cc", "bbr",
		"-streams", "$STREAMS", "-omit", "${OMIT_S}s", "-duration", "${DURATION_S}s", "-start-timeout", nodeStartTimeout, "-stop-relay"}
	switch {
	case o.Profile:
		sidecar = append(slices.DeleteFunc(sidecar, func(a string) bool { return a == "-kernel" || a == "$WORK_DIR/relay-kernel" }), profileArgs("relay")...)
		server = append(server, profileArgs("server")...)
		client = append(client, profileArgs("client")...)
	case prof:
		sidecar = append(sidecar, "-cpuprofile", "$WORK_DIR/relay-cpu.pprof")
	}
	// The relay host does not read the counters of its ENI during the perf test case: a read
	// under load can reset an ENA link.
	args := []string{"-name=" + name, "-streams=" + strconv.Itoa(c.streams), "-omit=5s", "-duration=" + o.Duration,
		"-min-cpus=" + strconv.Itoa(o.MinCPUs), "-max-steal=5", "-relay-xdp", "-relay-link=eni1", "-no-nic-poll"}
	if c.channels > 0 {
		args = append(args, "-relay-channels="+strconv.Itoa(c.channels))
	}
	args = append(args, "-server-argv="+jsonArgv(server), "-client-argv="+jsonArgv(client), "-sidecar-argv="+jsonArgv(sidecar))
	return Row{ID: "netstack-psp-relay-3node-" + c.stem + "-" + mode + idSuffix, Group: "info", Cmd: "node", Args: args, hosts: 3, eni: true}
}

// RelayENI reports whether o selects a perf test case with the relay on its own ENI. The
// relay host of such a run gets a second ENI.
func (s Suite) RelayENI(o Options) (bool, error) {
	tests, err := s.selected(o)
	return slices.ContainsFunc(tests, func(r Row) bool { return r.eni }), err
}
