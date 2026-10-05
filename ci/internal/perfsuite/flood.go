package perfsuite

import (
	"slices"
	"strconv"
)

// floodRow is one row of the relay flood: the relay host forwards the packets of a
// source host in XDP, and no agent runs. A row runs only when a run names it.
type floodRow struct {
	id, name string
	// ports is the number of UDP source ports. One sender has at most 16.
	ports int
	// mode is the XDP mode of the relay program: driver, generic or chain.
	// Empty runs no relay: the source sends to the counter.
	mode string
	// relay and source are more vpcbench flags. args are more perfrig flags.
	relay, source []string
	args          []string
}

// floodMinSize is the smallest IP length that the relay program forwards: the
// IPv4 and UDP headers, and a PSP packet with an empty inner packet.
const floodMinSize = "68"

// floodSpread sends the packets of each source port to its own port of the counter.
var floodSpread = []string{"-next-ports", "256"}

// floodPaced sends gbps Gbit/s on the wire from 256 ports to 256 ports of the
// counter. A message of 64 packets gives each port a long time between two sends.
func floodPaced(gbps string) []string {
	return append([]string{"-wire-gbps", gbps, "-gso", "64"}, floodSpread...)
}

var floodRows = []floodRow{
	// One sender with 800-byte packets. The target is 20 Gbit/s on the wire.
	{id: "flood-relay-3node-p16-xdp", name: "vpc-flood-relay-3node-xdp", ports: 16, mode: "driver"},
	{id: "flood-relay-3node-p16-xdp-min", name: "vpc-flood-relay-3node-xdp-min", ports: 16, mode: "driver", source: []string{"-size", floodMinSize}},
	// 16 senders to 256 ports of the counter, so that all RX queues of the relay host and of the counter host get packets.
	{id: "flood-relay-3node-p256-xdp", name: "vpc-flood-relay-3node-xdp", ports: 256, mode: "driver", source: floodSpread},
	{id: "flood-relay-3node-p256-xdp-min", name: "vpc-flood-relay-3node-xdp-min", ports: 256, mode: "driver", source: append([]string{"-size", floodMinSize}, floodSpread...)},
	// The path of the product relay: behind the Geneve program of icx, which runs in generic mode.
	{id: "flood-relay-3node-p16-xdp-geneve", name: "vpc-flood-relay-3node-xdp-geneve", ports: 16, mode: "chain"},
	{id: "flood-relay-3node-p256-xdp-geneve", name: "vpc-flood-relay-3node-xdp-geneve", ports: 256, mode: "chain", source: floodSpread},
	{id: "flood-relay-3node-p16-xdp-generic", name: "vpc-flood-relay-3node-xdp-generic", ports: 16, mode: "generic"},
	// The source sends the target rate and no more, so the row gives the relay CPU at the target.
	{id: "flood-relay-3node-p16-xdp-20g", name: "vpc-flood-relay-3node-xdp-20g", ports: 16, mode: "driver", source: []string{"-wire-gbps", "20"}},
	{id: "flood-relay-3node-p16-xdp-geneve-20g", name: "vpc-flood-relay-3node-xdp-geneve-20g", ports: 16, mode: "chain", source: []string{"-wire-gbps", "20"}},
	// Rates near the limit of the relay host with all RX queues, and the relay CPU at these rates.
	{id: "flood-relay-3node-p256-xdp-50g", name: "vpc-flood-relay-3node-xdp-50g", ports: 256, mode: "driver", source: floodPaced("50")},
	{id: "flood-relay-3node-p256-xdp-70g", name: "vpc-flood-relay-3node-xdp-70g", ports: 256, mode: "driver", source: floodPaced("70")},
	{id: "flood-relay-3node-p256-xdp-geneve-55g", name: "vpc-flood-relay-3node-xdp-geneve-55g", ports: 256, mode: "chain", source: floodPaced("55")},
	// One relay RX queue gets all packets, so the row gives the most packets that one CPU forwards.
	{id: "flood-relay-3node-p16-xdp-q1", name: "vpc-flood-relay-3node-xdp-q1", ports: 16, mode: "driver", args: []string{"-relay-channels=1"}},
	// The tunnel limit of each sender, with a rate that drops no packet, and with the default rate of the relay command.
	{id: "flood-relay-3node-p16-xdp-tunnel", name: "vpc-flood-relay-3node-xdp-tunnel", ports: 16, mode: "driver", relay: []string{"-tunnel-rate", "1e11"}},
	{id: "flood-relay-3node-p16-xdp-tunnel-5g", name: "vpc-flood-relay-3node-xdp-tunnel-5g", ports: 16, mode: "driver", relay: []string{"-tunnel-rate", "5e9"}},
	// The run time counter of BPF programs gives the time of the relay program for each packet.
	{id: "flood-relay-3node-p16-xdp-stats", name: "vpc-flood-relay-3node-xdp-stats", ports: 16, mode: "driver", relay: []string{"-xdp-stats"}},
	// No relay: the most that the source host sends and that the counter host counts.
	{id: "flood-direct-2node-p16", name: "vpc-flood-direct-2node", ports: 16},
	{id: "flood-direct-2node-p16-min", name: "vpc-flood-direct-2node-min", ports: 16, source: []string{"-size", floodMinSize}},
	{id: "flood-direct-2node-p256", name: "vpc-flood-direct-2node", ports: 256, source: floodSpread},
	{id: "flood-direct-2node-p256-min", name: "vpc-flood-direct-2node-min", ports: 256, source: append([]string{"-size", floodMinSize}, floodSpread...)},
}

// argv returns the vpcbench commands of the roles. The relay is the sidecar.
func (r floodRow) argv(o Options) (sidecar, server, client []string) {
	const relay, counter = "$RELAY_IP:4443", "$SERVER_IP:4433"
	// The place of the row in the run lets a host find that it is at a different row than the source.
	seq := strconv.Itoa(slices.Index(o.Only, r.id) + 1)
	server = []string{"vpcbench", "flood-counter", "-id", r.id, "-seq", seq, "-listen", counter, "-xdp", "$DEV", "-start-timeout", nodeStartTimeout}
	client = []string{"vpcbench", "flood-source", "-id", r.id, "-seq", seq, "-server", counter}
	if r.mode != "" {
		sidecar = []string{"vpcbench", "flood-relay", "-id", r.id, "-seq", seq, "-listen", relay, "-xdp", "$DEV", "-xdp-mode", r.mode, "-start-timeout", nodeStartTimeout}
		sidecar = append(sidecar, r.relay...)
		client = append(client, "-relay", relay)
	}
	client = append(append(client, r.source...), "-ports", "$STREAMS", "-omit", "${OMIT_S}s", "-duration", "${DURATION_S}s", "-start-timeout", nodeStartTimeout)
	if o.Profile {
		if sidecar != nil {
			sidecar = append(sidecar, profileArgs("relay")...)
		}
		server = append(server, profileArgs("server")...)
		client = append(client, profileArgs("client")...)
	}
	return sidecar, server, client
}

func (r floodRow) row(o Options) Row {
	sidecar, server, client := r.argv(o)
	// The counter program runs in driver mode, so that the counter host is not the limit.
	// perfrig does not poll the NIC: a read of the ENA counters with full RX queues can reset the link.
	args := []string{"-name=" + r.name, "-streams=" + strconv.Itoa(r.ports), "-omit=5s", "-duration=" + o.Duration,
		"-min-cpus=" + strconv.Itoa(o.MinCPUs), "-max-steal=5", "-server-xdp", "-no-nic-poll"}
	hosts := 2
	if sidecar != nil {
		hosts = 3
		args = append(args, "-relay-xdp")
		if r.mode != "driver" {
			args = append(args, "-relay-xdp-generic")
		}
	}
	args = append(args, "-server-argv="+jsonArgv(server), "-client-argv="+jsonArgv(client))
	if sidecar != nil {
		args = append(args, "-sidecar-argv="+jsonArgv(sidecar))
	}
	return Row{ID: r.id, Group: "info", Cmd: "node", Args: append(args, r.args...), hosts: hosts}
}
