// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/cmd/internal/bench"
)

// The flood commands measure the XDP forward of the relay with no agent: the
// source sends PSP datagrams from many UDP ports, the relay runs the XDP program
// of the product, and the counter counts and drops the packets in XDP.
//
//	perfrig node -name vpc-flood-relay-3node-xdp -streams 16 -relay-xdp -server-xdp \
//	  -sidecar-argv '["vpcbench","flood-relay","-id","ROW","-listen","$RELAY_IP:4443","-xdp","$DEV","-xdp-mode","driver"]' \
//	  -server-argv '["vpcbench","flood-counter","-id","ROW","-listen","$SERVER_IP:4433","-xdp","$DEV"]' \
//	  -client-argv '["vpcbench","flood-source","-id","ROW","-relay","$RELAY_IP:4443","-server","$SERVER_IP:4433","-ports","$STREAMS","-omit","${OMIT_S}s","-duration","${DURATION_S}s"]'
const (
	floodRelayCmd   = "flood-relay"
	floodCounterCmd = "flood-counter"
	floodSourceCmd  = "flood-source"
)

const (
	ipv4Len = 20
	udpLen  = 8
	ethLen  = 14
	// floodMinSize is the smallest IP length that the relay program forwards: the
	// IPv4 and UDP headers, and a PSP packet with an empty inner packet.
	floodMinSize = ipv4Len + udpLen + pspwire.Overhead
	// floodMaxLen is the largest IP length of a PSP datagram, as in the relay.
	floodMaxLen = 40 + udpLen + pspwire.Overhead + vpcv1alpha1.MaxMTU
	// floodSPI is the SPI of the first sender. The low 31 bits must not be 0.
	floodSPI = 0x100
	// floodLanes is the most UDP ports of one agent session: its socket and its
	// lane ports. One sender has one SPI and one tunnel limit.
	floodLanes = 16
	// floodFirstPort and floodFirstNext are the first UDP port of the source and
	// of the counter.
	floodFirstPort = 30000
	floodFirstNext = 20000
	// floodMaxNext is the number of UDP ports that the counter counts.
	floodMaxNext = 256
	// floodMaxSegs is the most segments of one UDP GSO message.
	floodMaxSegs = 64
	// floodMaxGSO is the most UDP payload bytes of one GSO message.
	floodMaxGSO = 65507
)

// isFloodCmd reports whether cmd is a flood command.
func isFloodCmd(cmd string) bool {
	return cmd == floodRelayCmd || cmd == floodCounterCmd || cmd == floodSourceCmd
}

// floodOptions are the flags of the flood commands.
type floodOptions struct {
	// ID is the row. The source, the relay and the counter of one row have the same ID.
	ID string
	// Seq is the place of the row in the run, or 0. It tells which host is at a later row.
	Seq                   int
	Listen, Relay, Server string
	WorkDir               string
	XDP, XDPMode          string
	XDPHop                time.Duration
	// XDPStats turns on the run time counter of BPF programs, which costs time for each packet.
	XDPStats bool
	// TunnelRate is the tunnel limit of each sender in bits per second. 0: no limit.
	TunnelRate float64
	// Size is the IP length of each packet.
	Size, Ports, NextPorts int
	Batch, GSO, Sndbuf     int
	// WireGbps is the rate of all ports on the wire. 0: no limit.
	WireGbps               float64
	Omit, Duration, Settle time.Duration
	StartTimeout           time.Duration
	Profiles               bench.Profiles
	prof                   *bench.Running
}

// marked tells the profiles that the run took mark i of a measured window with the length window.
func (o floodOptions) marked(i int, window time.Duration) {
	if err := o.prof.Mark(i, window); err != nil {
		slog.Warn("Failed to start or write a part of the profiles", "mark", i, "error", err)
	}
}

// parseFloodFlags reads the flags of a flood command and checks them.
func parseFloodFlags(cmd string, args []string, out io.Writer) (floodOptions, error) {
	o := floodOptions{WorkDir: os.Getenv("WORK_DIR")}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&o.ID, "id", "", "row name; the source, the relay and the counter of one row must have the same")
	fs.IntVar(&o.Seq, "seq", 0, "place of the row in the run; a relay or a counter stops when the source is at a later row, and a source fails at once when the host is at a later row")
	fs.DurationVar(&o.StartTimeout, "start-timeout", 30*time.Second, "time limit of the wait for the other hosts")
	o.Profiles.AddFlags(fs)
	if cmd != floodSourceCmd {
		fs.StringVar(&o.Listen, "listen", "", "TCP control address; relay: also the UDP address of the PSP packets")
		fs.StringVar(&o.XDP, "xdp", "", "link of the XDP program")
	}
	switch cmd {
	case floodRelayCmd:
		fs.StringVar(&o.XDPMode, "xdp-mode", "driver", "XDP attach mode: driver (generic when the driver refuses the program), generic, or chain, which runs the program behind the Geneve program of icx in generic mode")
		fs.DurationVar(&o.XDPHop, "xdp-hop", 0, "time that the XDP program keeps the next hop of a row (0: a route lookup for each packet)")
		fs.Float64Var(&o.TunnelRate, "tunnel-rate", 0, "tunnel limit of each sender in bits per second, with a burst of 100 ms (0: no limit)")
		fs.BoolVar(&o.XDPStats, "xdp-stats", false, "measure the run time of the XDP program; the kernel then reads the clock two times for each packet")
	case floodCounterCmd:
		fs.StringVar(&o.XDPMode, "xdp-mode", "driver", "XDP attach mode: driver (generic when the driver refuses the program) or generic")
	case floodSourceCmd:
		fs.StringVar(&o.WorkDir, "work-dir", o.WorkDir, "directory for the marks of all hosts (default $WORK_DIR; empty: no file)")
		fs.StringVar(&o.Relay, "relay", "", "relay address host:port (empty: the packets go to the counter with no relay)")
		fs.StringVar(&o.Server, "server", "", "counter control address host:port")
		fs.IntVar(&o.Size, "size", 800, fmt.Sprintf("IP length of each packet, %d to %d", floodMinSize, floodMaxLen))
		fs.IntVar(&o.Ports, "ports", 16, "UDP source ports; each has one socket and one thread")
		fs.IntVar(&o.NextPorts, "next-ports", floodLanes, "UDP ports of the counter that the packets go to")
		fs.IntVar(&o.Batch, "batch", 16, "messages of one sendmmsg call")
		fs.IntVar(&o.GSO, "gso", 0, "packets of one UDP GSO message (0: 64, or 16 with -wire-gbps; 1: no GSO)")
		fs.IntVar(&o.Sndbuf, "sndbuf", 1<<20, "send buffer of each socket in bytes")
		fs.Float64Var(&o.WireGbps, "wire-gbps", 0, "rate of all ports on the wire in Gbit/s (0: no limit)")
		fs.DurationVar(&o.Omit, "omit", 5*time.Second, "warm-up before the measurement")
		fs.DurationVar(&o.Duration, "duration", 30*time.Second, "measured time")
		fs.DurationVar(&o.Settle, "settle", 3*time.Second, "time with no packets before each read of the counters")
	}
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	return o, o.check(cmd)
}

func (o floodOptions) check(cmd string) error {
	source := cmd == floodSourceCmd
	switch {
	case o.ID == "":
		return errors.New("-id is required")
	case o.StartTimeout <= 0 || o.Seq < 0:
		return errors.New("-start-timeout must be positive and -seq must not be negative")
	case !source && (o.Listen == "" || o.XDP == ""):
		return errors.New("-listen and -xdp are required")
	case cmd == floodRelayCmd && o.XDPMode != "driver" && o.XDPMode != "generic" && o.XDPMode != "chain":
		return fmt.Errorf("unknown -xdp-mode %q: want driver, generic or chain", o.XDPMode)
	case cmd == floodCounterCmd && o.XDPMode != "driver" && o.XDPMode != "generic":
		return fmt.Errorf("unknown -xdp-mode %q: want driver or generic", o.XDPMode)
	case o.XDPHop < 0 || o.TunnelRate < 0:
		return errors.New("-xdp-hop and -tunnel-rate must not be negative")
	case !source:
		return nil
	case o.Server == "":
		return errors.New("-server is required")
	case o.Size < floodMinSize || o.Size > floodMaxLen:
		return fmt.Errorf("-size must be %d to %d", floodMinSize, floodMaxLen)
	case o.Ports < 1 || o.Ports > 1024:
		return errors.New("-ports must be 1 to 1024")
	case o.NextPorts < 1 || o.NextPorts > floodMaxNext:
		return fmt.Errorf("-next-ports must be 1 to %d", floodMaxNext)
	case o.Batch < 1 || o.Batch > 1024 || o.GSO < 0 || o.GSO > floodMaxSegs:
		return fmt.Errorf("-batch must be 1 to 1024 and -gso must be 0 to %d", floodMaxSegs)
	case o.Sndbuf < 0 || o.WireGbps < 0:
		return errors.New("-sndbuf and -wire-gbps must not be negative")
	case o.Duration <= 0 || o.Omit < 0 || o.Settle < 0:
		return errors.New("-duration must be positive, and -omit and -settle must not be negative")
	}
	return nil
}

// floodMain runs a flood command and returns the exit code of the process.
func floodMain(cmd string, args []string) int {
	o, err := parseFloodFlags(cmd, args, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if o.prof, err = o.Profiles.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch cmd {
	case floodRelayCmd:
		err = runFloodRelay(ctx, o, nil)
	case floodCounterCmd:
		err = runFloodCounter(ctx, o, nil)
	default:
		err = runFloodSource(ctx, o, os.Stdout)
	}
	if perr := o.prof.Stop(); perr != nil {
		slog.Warn("Failed to write the profiles", "error", perr)
	}
	if err != nil {
		slog.Error("Benchmark failed", "error", err)
		return 1
	}
	return 0
}

// floodHello tells the relay or the counter the row of the source. The relay puts
// one flow for each source port i, to the port FirstNext + i%NextPorts of Next.
type floodHello struct {
	ID        string `json:"id"`
	Seq       int    `json:"seq,omitempty"`
	Ports     int    `json:"ports,omitempty"`
	FirstPort int    `json:"first_port,omitempty"`
	Next      string `json:"next,omitempty"`
	NextPorts int    `json:"next_ports,omitempty"`
	FirstNext int    `json:"first_next,omitempty"`
}

// senderOf returns the number of the sender of source port i, and its SPI. A
// sender is one agent session in the product.
func senderOf(i int) (sender int, spi uint32) {
	return i / floodLanes, floodSPI + uint32(i/floodLanes)
}

// floodNext returns the counter port of source port i.
func floodNext(i, nextPorts int) uint16 { return uint16(floodFirstNext + i%nextPorts) }

// floodPayload returns the UDP payloads of n PSP packets of the IP length size, one
// after the other. The cipher text and the ICV are fill bytes: the relay does not decrypt.
func floodPayload(size, n int, spi uint32) []byte {
	seg := size - ipv4Len - udpLen
	b := make([]byte, seg*n)
	for i := range n {
		p := b[i*seg : (i+1)*seg]
		// Next header IPv4, 2 words of IV and VC, crypt offset 2, and version 0 with a VC.
		p[0], p[1], p[2], p[3] = pspwire.NextHdrV4, 2, pspwire.VCLen/4, 0x03
		binary.BigEndian.PutUint32(p[4:8], spi)
		binary.BigEndian.PutUint64(p[8:16], uint64(i)+1)
		binary.BigEndian.PutUint32(p[16:20], vni<<8)
		for j := pspwire.PrefixLen; j < seg; j++ {
			p[j] = byte(j)
		}
	}
	return b
}

// floodSegs returns the packets of one GSO message for the flag value gso.
func floodSegs(gso, size int, paced bool) int {
	if gso == 0 {
		gso = floodMaxSegs
		if paced {
			gso = 16
		}
	}
	return max(min(gso, floodMaxGSO/(size-ipv4Len-udpLen)), 1)
}

// relayXDPStats are the counters of the relay XDP program.
type relayXDPStats struct {
	Packets     uint64 `json:"packets"`
	Bytes       uint64 `json:"bytes"`
	LaneDrops   uint64 `json:"lane_drops"`
	TunnelDrops uint64 `json:"tunnel_drops"`
	NoRow       uint64 `json:"no_row"`
	Expired     uint64 `json:"expired"`
	NoRoute     uint64 `json:"no_route"`
	Malformed   uint64 `json:"malformed"`
	TooLong     uint64 `json:"too_long"`
}

// floodLink is the settings of the link of a flood host.
type floodLink struct {
	Dev      string `json:"dev"`
	Driver   string `json:"driver,omitempty"`
	MTU      int    `json:"mtu"`
	Channels uint32 `json:"channels,omitempty"`
	RxRing   uint32 `json:"rx_ring,omitempty"`
	TxRing   uint32 `json:"tx_ring,omitempty"`
	// XDPMode is the attach mode of the program: driver, generic or chain.
	XDPMode string `json:"xdp_mode,omitempty"`
	// MaxLen and Redirect are the settings of the relay program.
	MaxLen   uint32 `json:"max_len,omitempty"`
	Redirect bool   `json:"redirect,omitempty"`
}

// floodMark is the counters of one flood host at one time, with no packets on
// the way. Each host sets its fields.
type floodMark struct {
	Nanos int64 `json:"nanos"` // Time since the host started.
	// Seq is the place of the row of the host, in the answer to a source of a different row.
	Seq  int        `json:"seq,omitempty"`
	Link *floodLink `json:"link,omitempty"`
	// NIC has the "ethtool -S" counters of the link, and its counters in
	// /sys/class/net/DEV/statistics with the prefix "sys_".
	NIC map[string]uint64 `json:"nic,omitempty"`
	// SNMP has the Icmp and Udp counters of /proc/net/snmp.
	SNMP map[string]uint64 `json:"snmp,omitempty"`
	// Kmsg are the new kernel log lines that name the link or its driver.
	Kmsg []string         `json:"kmsg,omitempty"`
	CPUs []bench.CPUTicks `json:"cpus,omitempty"`
	// IRQ is the time in ns that each CPU ran IRQ and softirq handlers, from BPF
	// timers. NetRX is the part of the NET_RX softirq, which runs the XDP program.
	IRQ   []uint64 `json:"irq_ns,omitempty"`
	NetRX []uint64 `json:"net_rx_ns,omitempty"`
	// Relay: the counters of the program, its run time, the packets that it
	// forwarded for each source port, and the datagrams that the socket got.
	XDP        *relayXDPStats `json:"xdp,omitempty"`
	XDPSeconds float64        `json:"xdp_s,omitempty"`
	Rows       []uint64       `json:"rows,omitempty"`
	SockPkts   uint64         `json:"sock_packets,omitempty"`
	// Counter: the packets and the frame bytes that the program counted for each port.
	PortPkts  []uint64 `json:"port_packets,omitempty"`
	PortBytes []uint64 `json:"port_bytes,omitempty"`
}

// floodHost is the result of one host in the measured window.
type floodHost struct {
	Link *floodLink `json:"link,omitempty"`
	// TxPPS and RxPPS are the packets of all queues of the NIC. RxPPS has only
	// the packets that the driver got.
	TxPPS float64 `json:"nic_tx_pps"`
	RxPPS float64 `json:"nic_rx_pps"`
	// RxDropped and RxOverruns are the packets that the device dropped before
	// the driver got them, for example because an RX ring was full.
	RxDropped  uint64 `json:"nic_rx_dropped"`
	RxOverruns uint64 `json:"nic_rx_overruns"`
	// XDPDrops are the packets that an XDP program dropped in driver mode. The
	// ENA driver also counts them as dropped packets of the link. RxDropped is without them.
	XDPDrops uint64 `json:"nic_rx_xdp_drop"`
	// ArrivedPPS are the packets at the NIC: RxPPS and RxDropped. A link with no
	// queue counters has the dropped packets in RxPPS.
	ArrivedPPS float64 `json:"nic_arrived_pps"`
	// RxQueues are the RX queues that got packets, and TopQueuePct is the
	// percent of the packets that the busiest queue got.
	RxQueues    int     `json:"rx_queues"`
	TopQueuePct float64 `json:"rx_top_queue_pct"`
	// XDPTxPPS are the packets of the XDP TX queues of the NIC.
	XDPTxPPS float64 `json:"nic_xdp_tx_pps"`
	// TxDropped are the packets that the link did not send, for example the
	// packets of a program in generic mode for a TX queue with no room.
	TxDropped uint64 `json:"nic_tx_dropped"`
	// Allowance are the EC2 limit counters of the ENA driver.
	Allowance map[string]uint64 `json:"allowance"`
	// ICMPOut are the ICMP messages that the host sent, and SndbufErrors the
	// UDP messages that its qdisc or its driver dropped.
	ICMPOut      uint64 `json:"icmp_out"`
	SndbufErrors uint64 `json:"udp_sndbuf_errors"`
	// IRQCores is the IRQ and softirq time of all CPUs in cores, from the BPF timers,
	// and NetRXCores its NET_RX part. BusyCPUs are the CPUs with 90 percent or more.
	IRQCores   float64 `json:"irq_cores"`
	NetRXCores float64 `json:"net_rx_cores"`
	TopCPUPct  float64 `json:"irq_top_cpu_pct"`
	BusyCPUs   int     `json:"irq_busy_cpus"`
	// HostCores is the busy time of all CPUs in /proc/stat, in cores.
	HostCores float64 `json:"host_cores"`
	// RxQueuePPS is the packets of each RX queue.
	RxQueuePPS []float64 `json:"rx_queue_pps,omitempty"`
	// LinkDowns is the number of times that the link lost its carrier. A driver
	// that resets the link sets its queue counters to 0, so the rates are then too low.
	LinkDowns uint64 `json:"link_downs"`
}

// floodResult is the JSON line of the source. perfrig reads the first three fields.
// A rate on the wire counts the Ethernet header and no FCS: 14 bytes above the IP length.
type floodResult struct {
	Seconds float64 `json:"seconds"`
	// BitsPerSecond and PacketsPerSecond are what the counter program counted.
	BitsPerSecond    float64 `json:"bits_per_second"`
	PacketsPerSecond float64 `json:"packets_per_second"`

	IPLen     int    `json:"ip_len"`
	FrameLen  int    `json:"frame_len"`
	Ports     int    `json:"ports"`
	NextPorts int    `json:"next_ports"`
	GSO       int    `json:"gso_segments"`
	Batch     int    `json:"batch"`
	Via       string `json:"via"`
	// TargetPPS is the rate of -wire-gbps, or 0.
	TargetPPS float64 `json:"target_pps"`
	// SentPPS are the packets that the sockets of the source took. OfferedPPS are
	// the packets that the NIC of the source sent, and OfferedGbps their wire rate.
	SentPPS     float64 `json:"sent_pps"`
	OfferedPPS  float64 `json:"offered_pps"`
	OfferedGbps float64 `json:"offered_gbps"`
	SendErrors  uint64  `json:"send_errors"`

	// RelayArrivedPPS are the packets at the NIC of the relay: the packets that the
	// driver got and the packets that the device dropped.
	RelayArrivedPPS float64 `json:"relay_arrived_pps"`
	// RelayXDPPPS are the packets that the relay program forwarded, and
	// RelayGbps their wire rate.
	RelayXDPPPS float64 `json:"relay_xdp_pps"`
	RelayGbps   float64 `json:"relay_gbps"`
	// RelaySentPPS are the packets that the NIC of the relay sent, on its TX queues
	// and its XDP TX queues. A full TX queue makes it less than RelayXDPPPS.
	RelaySentPPS float64 `json:"relay_sent_pps"`
	// RelayDrops are the packets that the program dropped or gave to the kernel, by reason.
	RelayDrops map[string]uint64 `json:"relay_drops,omitempty"`
	// RelaySockPackets are the datagrams that the relay socket got.
	RelaySockPackets uint64 `json:"relay_sock_packets"`
	// RelayXDPNanos is the run time of the program for each packet, with -xdp-stats.
	// RelayNanos is the IRQ and softirq time of the relay host for each forwarded packet.
	RelayXDPSeconds float64 `json:"relay_xdp_seconds"`
	RelayXDPNanos   float64 `json:"relay_xdp_ns_per_packet"`
	RelayNanos      float64 `json:"relay_ns_per_packet"`
	// RelayCores is the IRQ and softirq time of the relay host in cores.
	RelayCores        float64 `json:"relay_cores"`
	RelayCoresPerGbps float64 `json:"relay_cores_per_gbps"`
	RelayCoresPer10G  float64 `json:"relay_cores_per_10gbps"`

	// CounterArrivedPPS are the packets at the NIC of the counter host.
	CounterArrivedPPS float64 `json:"counter_arrived_pps"`
	// ServerCores is the IRQ and softirq time of the counter host in cores. The
	// counter is the server of perfrig.
	ServerCores        float64 `json:"server_cores"`
	ServerCoresPerGbps float64 `json:"server_cores_per_gbps"`

	Source  floodHost  `json:"source"`
	Relay   *floodHost `json:"relay,omitempty"`
	Counter floodHost  `json:"counter"`

	// The packets of each source port: sent, and forwarded by the relay program.
	PortSentPPS  []float64 `json:"port_sent_pps,omitempty"`
	PortRelayPPS []float64 `json:"port_relay_pps,omitempty"`
	// The packets that the counter program counted for each of its ports.
	NextPortPPS []float64 `json:"next_port_pps,omitempty"`
}

// floodRun is the config and the counts of the source in the measured window.
type floodRun struct {
	Size, Ports, NextPorts, GSO, Batch int
	TargetPPS                          float64
	Seconds                            float64
	Sent                               []uint64 // Packets of each port.
	Errors                             uint64
}

// allowanceCounters are the EC2 limit counters of the ENA driver.
var allowanceCounters = []string{"bw_in_allowance_exceeded", "bw_out_allowance_exceeded", "pps_allowance_exceeded",
	"conntrack_allowance_exceeded", "linklocal_allowance_exceeded"}

// Counters of the queues of the ENA driver. An XDP TX queue has "xdp_tx" in its name.
var (
	rxQueueCnt  = regexp.MustCompile(`^queue_(\d+)_rx_cnt$`)
	txQueueCnt  = regexp.MustCompile(`^queue_\d+_tx_cnt$`)
	xdpQueueCnt = regexp.MustCompile(`^queue_\d+_xdp_tx_cnt$`)
	xdpDropCnt  = regexp.MustCompile(`^queue_\d+_rx_xdp_drop$`)
)

// sub returns b - a, or 0 when the counter went back.
func sub(a, b uint64) uint64 {
	if b < a {
		return 0
	}
	return b - a
}

// kmsgText returns the time in seconds since the boot and the first line of the
// text of a /dev/kmsg record, which starts with "priority,sequence,time,flags;".
func kmsgText(record string) string {
	head, text, ok := strings.Cut(record, ";")
	if !ok {
		return ""
	}
	text, _, _ = strings.Cut(text, "\n")
	if f := strings.Split(head, ","); len(f) >= 3 {
		if us, err := strconv.ParseUint(f[2], 10, 64); err == nil {
			return fmt.Sprintf("%d.%06d %s", us/1e6, us%1e6, text)
		}
	}
	return text
}

// sliceDelta returns the increase of each value from a to b, divided by seconds.
func sliceDelta(a, b []uint64, seconds float64) []float64 {
	if len(b) == 0 || seconds <= 0 {
		return nil
	}
	out := make([]float64, len(b))
	for i, v := range b {
		if i < len(a) {
			v = sub(a[i], v)
		}
		out[i] = float64(v) / seconds
	}
	return out
}

// newFloodHost computes the result of one host from its marks at the start and
// at the end of the window, which had packets for the time seconds.
func newFloodHost(m [2]*floodMark, seconds float64) floodHost {
	h := floodHost{Allowance: map[string]uint64{}}
	if m[0] == nil || m[1] == nil || seconds <= 0 {
		return h
	}
	h.Link = m[1].Link
	var rx, tx, xdpTx, top uint64
	var txQueues int
	queues := map[int]uint64{}
	for k, v1 := range m[1].NIC {
		d := sub(m[0].NIC[k], v1)
		switch {
		case rxQueueCnt.MatchString(k):
			q, _ := strconv.Atoi(rxQueueCnt.FindStringSubmatch(k)[1])
			queues[q] = d
			rx += d
			top = max(top, d)
			if d > 0 {
				h.RxQueues++
			}
		case xdpQueueCnt.MatchString(k):
			xdpTx += d
		case xdpDropCnt.MatchString(k):
			h.XDPDrops += d
		case txQueueCnt.MatchString(k):
			tx += d
			txQueues++
		}
	}
	// A link with no queue counters, for example a veth link.
	if len(queues) == 0 {
		rx = sub(m[0].NIC["sys_rx_packets"], m[1].NIC["sys_rx_packets"])
	}
	if txQueues == 0 {
		tx = sub(m[0].NIC["sys_tx_packets"], m[1].NIC["sys_tx_packets"])
	}
	h.RxPPS, h.TxPPS, h.XDPTxPPS = float64(rx)/seconds, float64(tx)/seconds, float64(xdpTx)/seconds
	if rx > 0 && top > 0 {
		h.TopQueuePct = pct(float64(top), float64(rx))
	}
	for q := range len(queues) {
		h.RxQueuePPS = append(h.RxQueuePPS, float64(queues[q])/seconds)
	}
	h.RxDropped = sub(m[0].NIC["sys_rx_dropped"], m[1].NIC["sys_rx_dropped"])
	if h.RxDropped >= h.XDPDrops {
		h.RxDropped -= h.XDPDrops
	}
	h.RxOverruns = sub(m[0].NIC["sys_rx_over_errors"], m[1].NIC["sys_rx_over_errors"])
	h.TxDropped = sub(m[0].NIC["sys_tx_dropped"], m[1].NIC["sys_tx_dropped"])
	h.LinkDowns = sub(m[0].NIC["sys_carrier_down"], m[1].NIC["sys_carrier_down"])
	h.ArrivedPPS = h.RxPPS
	if len(queues) > 0 {
		h.ArrivedPPS += float64(h.RxDropped) / seconds
	}
	for _, k := range allowanceCounters {
		if v1, ok := m[1].NIC[k]; ok {
			h.Allowance[k] = sub(m[0].NIC[k], v1)
		}
	}
	h.ICMPOut = sub(m[0].SNMP["Icmp.OutMsgs"], m[1].SNMP["Icmp.OutMsgs"])
	h.SndbufErrors = sub(m[0].SNMP["Udp.SndbufErrors"], m[1].SNMP["Udp.SndbufErrors"])
	var irq, netRX uint64
	for i, v1 := range m[1].IRQ {
		if i >= len(m[0].IRQ) {
			break
		}
		d := sub(m[0].IRQ[i], v1)
		irq += d
		busy := float64(d) / 1e9 / seconds
		h.TopCPUPct = max(h.TopCPUPct, pct(busy, 1))
		if busy >= 0.9 {
			h.BusyCPUs++
		}
	}
	for i, v1 := range m[1].NetRX {
		if i < len(m[0].NetRX) {
			netRX += sub(m[0].NetRX[i], v1)
		}
	}
	h.IRQCores, h.NetRXCores = float64(irq)/1e9/seconds, float64(netRX)/1e9/seconds
	if k := hostKinds(mark{CPUs: m[0].CPUs}, mark{CPUs: m[1].CPUs}); k != nil {
		// The ticks are for the time between the marks, which is longer than the window.
		wall := time.Duration(m[1].Nanos - m[0].Nanos).Seconds()
		h.HostCores = (k.User + k.System + k.IRQ) * wall / seconds
	}
	return h
}

// newFloodResult computes the JSON line from the marks of the hosts at the
// start and at the end of the measured window. relay is nil with no relay.
func newFloodResult(run floodRun, src, relay, counter [2]*floodMark) floodResult {
	s := run.Seconds
	r := floodResult{
		Seconds: s, IPLen: run.Size, FrameLen: run.Size + ethLen, Ports: run.Ports, NextPorts: run.NextPorts,
		GSO: run.GSO, Batch: run.Batch, Via: "relay", TargetPPS: run.TargetPPS, SendErrors: run.Errors,
	}
	if s <= 0 {
		return r
	}
	wire := func(pps float64) float64 { return pps * float64(r.FrameLen) * 8 / 1e9 }
	var sent uint64
	for _, n := range run.Sent {
		sent += n
		r.PortSentPPS = append(r.PortSentPPS, float64(n)/s)
	}
	r.SentPPS = float64(sent) / s
	r.Source = newFloodHost(src, s)
	r.OfferedPPS, r.OfferedGbps = r.Source.TxPPS, wire(r.Source.TxPPS)
	r.Counter = newFloodHost(counter, s)
	r.CounterArrivedPPS = r.Counter.ArrivedPPS
	if counter[0] != nil && counter[1] != nil {
		var pkts, bytes uint64
		for i, n := range counter[1].PortPkts {
			if i < len(counter[0].PortPkts) {
				pkts += sub(counter[0].PortPkts[i], n)
				bytes += sub(counter[0].PortBytes[i], counter[1].PortBytes[i])
			}
		}
		r.PacketsPerSecond, r.BitsPerSecond = float64(pkts)/s, float64(bytes)*8/s
		if r.ServerCores = r.Counter.IRQCores; r.BitsPerSecond > 0 {
			r.ServerCoresPerGbps = r.ServerCores * 1e9 / r.BitsPerSecond
		}
		used := max(min(run.NextPorts, len(counter[1].PortPkts)), 0)
		r.NextPortPPS = sliceDelta(counter[0].PortPkts[:min(used, len(counter[0].PortPkts))], counter[1].PortPkts[:used], s)
	}
	if relay[0] == nil || relay[1] == nil {
		r.Via = "direct"
		return r
	}
	h := newFloodHost(relay, s)
	r.Relay = &h
	r.RelayArrivedPPS, r.RelaySentPPS = h.ArrivedPPS, h.TxPPS+h.XDPTxPPS
	r.RelaySockPackets = sub(relay[0].SockPkts, relay[1].SockPkts)
	r.PortRelayPPS = sliceDelta(relay[0].Rows, relay[1].Rows, s)
	r.RelayXDPSeconds = relay[1].XDPSeconds - relay[0].XDPSeconds
	x0, x1 := relay[0].XDP, relay[1].XDP
	if x0 == nil || x1 == nil {
		return r
	}
	fwd := sub(x0.Packets, x1.Packets)
	r.RelayXDPPPS = float64(fwd) / s
	r.RelayGbps = wire(r.RelayXDPPPS)
	runs := fwd
	for name, d := range map[string]uint64{
		"lane_meter": sub(x0.LaneDrops, x1.LaneDrops), "tunnel_meter": sub(x0.TunnelDrops, x1.TunnelDrops),
		"no_row": sub(x0.NoRow, x1.NoRow), "expired": sub(x0.Expired, x1.Expired), "no_route": sub(x0.NoRoute, x1.NoRoute),
		"malformed": sub(x0.Malformed, x1.Malformed), "too_long": sub(x0.TooLong, x1.TooLong),
	} {
		if d > 0 {
			if r.RelayDrops == nil {
				r.RelayDrops = map[string]uint64{}
			}
			r.RelayDrops[name] = d
			runs += d
		}
	}
	r.RelayCores = h.IRQCores
	if fwd > 0 {
		r.RelayXDPNanos = r.RelayXDPSeconds * 1e9 / float64(runs)
		r.RelayNanos = h.IRQCores * s * 1e9 / float64(fwd)
	}
	if r.RelayGbps > 0 {
		r.RelayCoresPerGbps = r.RelayCores / r.RelayGbps
		r.RelayCoresPer10G = r.RelayCoresPerGbps * 10
	}
	return r
}

// errSourceAhead tells that the source runs a later row than this host.
var errSourceAhead = errors.New("the source is at a later row")

// floodPeer serves the control port of the row id until its source disconnects or
// stops it. It fails when no source of the row comes in the time wait, or when a
// source of a later row comes: the source of this row is then gone.
func floodPeer(ctx context.Context, ln net.Listener, id string, seq int, wait time.Duration, handle func(req request, from netip.Addr) (reply, error)) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var mu sync.Mutex
	var owner net.Conn
	var stopped, ahead bool
	noSource := time.AfterFunc(wait, func() { cancel(fmt.Errorf("no source of the row %s in %s", id, wait)) })
	defer noSource.Stop()
	var wg sync.WaitGroup
	defer context.AfterFunc(ctx, func() { _ = ln.Close() })()
	for {
		c, err := ln.Accept()
		if err != nil {
			break
		}
		wg.Go(func() {
			defer c.Close()
			defer context.AfterFunc(ctx, func() { _ = c.Close() })()
			from := c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
			err := serveCtl(c, func(req request) (reply, error) {
				mu.Lock()
				defer mu.Unlock()
				if req.Flood == nil || req.Flood.ID != id {
					if req.Flood != nil && req.Op == "hello" && req.Flood.Seq > seq {
						ahead = true
					}
					return reply{Flood: &floodMark{Seq: seq}}, fmt.Errorf("this host runs the row %q", id)
				}
				switch {
				case req.Op == "stop":
					stopped = true
					return reply{}, nil
				case req.Op == "hello":
					owner = c
					noSource.Stop()
				case owner != c:
					return reply{}, errors.New("no hello on this connection")
				}
				return handle(req, from)
			})
			// The host stops when the connection closes, so that the answer arrives before.
			mu.Lock()
			defer mu.Unlock()
			switch {
			case owner == c || stopped:
				slog.Info("The source of the row is done", "remote", c.RemoteAddr(), "stopped", stopped, "error", err)
				cancel(nil)
			case ahead:
				cancel(errSourceAhead)
			}
		})
	}
	cause := context.Cause(ctx)
	cancel(nil)
	wg.Wait()
	if cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}
	return nil
}

// floodCtl is the control connection of the source to the relay or the counter.
type floodCtl struct {
	*ctl
	addr, id string
}

// dialFlood connects to the control port at addr and sends hello. It tries again
// while the host is at an earlier row: the process of that row stops at the hello.
// Each other error answer fails the source at once.
func dialFlood(ctx context.Context, addr string, hello floodHello, timeout time.Duration) (*floodCtl, *floodMark, error) {
	deadline := time.Now().Add(timeout)
	for {
		c, err := dialCtl(ctx, addr, time.Until(deadline))
		if err != nil {
			return nil, nil, err
		}
		rep, err := c.call(request{Op: "hello", Flood: &hello})
		if err == nil {
			return &floodCtl{ctl: c, addr: addr, id: hello.ID}, rep.Flood, nil
		}
		_ = c.c.Close()
		behind := rep.Flood != nil && rep.Flood.Seq < hello.Seq
		if rep.Error != "" && !behind {
			return nil, nil, err
		}
		// The process of the row before can still close its port.
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// mark gets mark i of the host. window is the length of the measured window.
func (c *floodCtl) mark(i int, window time.Duration) (*floodMark, error) {
	rep, err := c.call(request{Op: "mark", Index: i, Window: window, Flood: &floodHello{ID: c.id}})
	if err == nil && rep.Flood == nil {
		err = fmt.Errorf("%s sent no mark", c.addr)
	}
	return rep.Flood, err
}

// stopFlood tells the host at addr to end the row id. The source calls it when it
// fails, so that the other hosts go to their next row.
func stopFlood(addr, id string) {
	if addr == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := dialCtl(ctx, addr, 2*time.Second)
	if err != nil {
		return
	}
	defer c.c.Close()
	_ = c.c.SetDeadline(time.Now().Add(2 * time.Second))
	_ = c.enc.Encode(request{Op: "stop", Flood: &floodHello{ID: id}})
	var rep reply
	_ = c.dec.Decode(&rep)
}

// runFloodSource sends the packets, takes the marks of all hosts with no
// packets on the way, and prints the JSON line to out.
func runFloodSource(ctx context.Context, o floodOptions, out io.Writer) (err error) {
	// The other hosts wait for the source. A source that fails tells them to go on.
	defer func() {
		if err != nil {
			stopFlood(o.Relay, o.ID)
			stopFlood(o.Server, o.ID)
		}
	}()
	start := time.Now()
	counter, _, err := dialFlood(ctx, o.Server, floodHello{ID: o.ID, Seq: o.Seq}, o.StartTimeout)
	if err != nil {
		return err
	}
	defer counter.c.Close()
	sa, err := netip.ParseAddrPort(counter.c.RemoteAddr().String())
	if err != nil {
		return err
	}
	next := sa.Addr().Unmap()
	var relay *floodCtl
	dst := func(i int) netip.AddrPort { return netip.AddrPortFrom(next, floodNext(i, o.NextPorts)) }
	if o.Relay != "" {
		hello := floodHello{ID: o.ID, Seq: o.Seq, Ports: o.Ports, FirstPort: floodFirstPort, Next: next.String(), NextPorts: o.NextPorts, FirstNext: floodFirstNext}
		if relay, _, err = dialFlood(ctx, o.Relay, hello, o.StartTimeout); err != nil {
			return err
		}
		defer relay.c.Close()
		ra, err := netip.ParseAddrPort(relay.c.RemoteAddr().String())
		if err != nil {
			return err
		}
		dst = func(int) netip.AddrPort { return netip.AddrPortFrom(ra.Addr().Unmap(), ra.Port()) }
	}
	local, err := netip.ParseAddrPort(counter.c.LocalAddr().String())
	if relay != nil {
		local, err = netip.ParseAddrPort(relay.c.LocalAddr().String())
	}
	if err != nil {
		return err
	}
	paced := o.WireGbps > 0
	run := floodRun{Size: o.Size, Ports: o.Ports, NextPorts: o.NextPorts, GSO: floodSegs(o.GSO, o.Size, paced), Batch: o.Batch}
	if paced {
		run.Batch = 1
		run.TargetPPS = o.WireGbps * 1e9 / 8 / float64(o.Size+ethLen)
	}
	snd, err := newFloodSender(local.Addr().Unmap(), dst, run, o.Sndbuf)
	if err != nil {
		return err
	}
	defer snd.close()
	slog.Info("Source is ready", "id", o.ID, "local", local.Addr(), "relay", o.Relay, "counter", next, "ports", o.Ports,
		"ip_len", o.Size, "gso_segments", snd.segs, "batch", run.Batch, "target_pps", run.TargetPPS, "link", snd.dev)
	run.GSO = snd.segs

	// The warm-up also makes the caches and the queues of all hosts ready.
	if o.Omit > 0 {
		if _, err := snd.send(ctx, o.Omit); err != nil {
			return err
		}
	}
	var src, rel, cnt [2]*floodMark
	takeMarks := func(i int) error {
		// The device reports its drops with a delay, and the last packets must arrive.
		if err := bench.Sleep(ctx, o.Settle, nil); err != nil {
			return err
		}
		src[i-1] = snd.mark(start)
		if cnt[i-1], err = counter.mark(i, o.Duration); err != nil {
			return err
		}
		if relay != nil {
			if rel[i-1], err = relay.mark(i, o.Duration); err != nil {
				return err
			}
		}
		o.marked(i, o.Duration)
		return nil
	}
	if err := takeMarks(1); err != nil {
		return err
	}
	sent, err := snd.send(ctx, o.Duration)
	if err != nil {
		return err
	}
	if err := takeMarks(2); err != nil {
		return err
	}
	run.Seconds, run.Sent, run.Errors = sent.seconds, sent.packets, sent.errors
	res := newFloodResult(run, src, rel, cnt)
	if o.WorkDir != "" {
		marks := map[string]any{"id": o.ID, "run": run, "source": src, "relay": rel, "counter": cnt}
		if b, err := json.Marshal(marks); err == nil {
			err = os.WriteFile(filepath.Join(o.WorkDir, "flood-marks.json"), b, 0o644)
			if err != nil {
				slog.Warn("Failed to write the marks of the hosts", "error", err)
			}
		}
	}
	if relay != nil {
		if _, err := relay.call(request{Op: "stop", Flood: &floodHello{ID: o.ID}}); err != nil {
			slog.Warn("Failed to stop the relay", "error", err)
		}
	}
	hosts := map[string]*floodHost{"source": &res.Source, "relay": res.Relay, "counter": &res.Counter}
	for name, h := range hosts {
		if h != nil && h.LinkDowns > 0 {
			slog.Warn("The link of a host went down in the measured time; the rates from its queue counters are too low", "host", name, "link_downs", h.LinkDowns)
		}
	}
	slog.Info("Run done", "id", o.ID, "via", res.Via, "ip_len", res.IPLen, "ports", res.Ports, "seconds", res.Seconds,
		"offered_pps", res.OfferedPPS, "offered_gbps", res.OfferedGbps, "relay_xdp_pps", res.RelayXDPPPS, "relay_gbps", res.RelayGbps,
		"relay_sent_pps", res.RelaySentPPS, "counted_pps", res.PacketsPerSecond, "relay_cores", res.RelayCores, "relay_drops", res.RelayDrops)
	return json.NewEncoder(out).Encode(res)
}

// floodSent is the count of one send period.
type floodSent struct {
	seconds float64
	packets []uint64 // Of each port.
	errors  uint64
}

// snmpCounters returns the Icmp and Udp counters of /proc/net/snmp text, by
// "Group.Name". Each group has a line of names and then a line of values.
func snmpCounters(snmp string) map[string]uint64 {
	out := map[string]uint64{}
	names := map[string][]string{}
	for line := range strings.Lines(snmp) {
		f := strings.Fields(line)
		if len(f) < 2 || (f[0] != "Icmp:" && f[0] != "Udp:") {
			continue
		}
		head, ok := names[f[0]]
		if !ok {
			names[f[0]] = f
			continue
		}
		for i := 1; i < min(len(f), len(head)); i++ {
			if v, err := strconv.ParseUint(f[i], 10, 64); err == nil {
				out[strings.TrimSuffix(f[0], ":")+"."+head[i]] = v
			}
		}
	}
	return out
}
