// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"cmp"
	"context"
	"math"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/apoxy-dev/apoxy/cmd/internal/bench"
)

// mark is the counters of one side at one time. Each side sets its fields.
type mark struct {
	Nanos int64 `json:"nanos"` // Time since the side started.
	// CPU is the CPU time of the process, and of the relay XDP program. The
	// kernel work around the program is not in it.
	CPU float64 `json:"cpu_s"`
	// HostCPU is the busy CPU time of the host of the side, or -1.
	HostCPU float64 `json:"host_cpu_s,omitempty"`
	// Packets that the client sent, and TCP segments retransmitted (client and
	// server). With GSO, a retransmit is one packet of up to one MSS.
	Segments uint64 `json:"segments,omitempty"`
	Retrans  uint64 `json:"retrans,omitempty"`
	// Server: bytes that the sink got, and PSP packets that the binding got.
	Bytes     uint64 `json:"bytes,omitempty"`
	RxPackets uint64 `json:"rx_packets,omitempty"`
	// Drops are the send drops of the client, the receive drops of the server
	// and all drops of the relay.
	Drops uint64 `json:"drops,omitempty"`
	// RcvbufErrors is the UDP RcvbufErrors counter of the server netns, or -1.
	RcvbufErrors int64 `json:"rcvbuf_errors,omitempty"`
	// SockDrops are the drops of the agent socket of the server or of the relay
	// socket, or -1.
	SockDrops int64 `json:"sock_drops,omitempty"`
	// LinkDrops are the packets that the overlay of the client or the server
	// dropped before its driver got them, or -1.
	LinkDrops int64 `json:"link_drops,omitempty"`
	// XDPPackets are the PSP packets that the relay forwarded in XDP.
	XDPPackets uint64 `json:"xdp_packets,omitempty"`
	// CPUs are the ticks of each CPU of the host of the side.
	CPUs []bench.CPUTicks `json:"cpus,omitempty"`
	// Queue is the bytes in the queues of the agent socket and the lane sockets
	// since the last mark.
	Queue *sockQueue `json:"queue,omitempty"`
	// Lanes are the PSP packets that the side sent on each send lane.
	Lanes []uint64 `json:"lanes,omitempty"`
}

// sockQueue is the mean and the most bytes in the receive queue of a socket,
// and in its send path before the NIC completes the packets.
type sockQueue struct {
	RxMean int64 `json:"rx_mean"`
	RxMax  int64 `json:"rx_max"`
	TxMean int64 `json:"tx_mean"`
	TxMax  int64 `json:"tx_max"`
}

// queueSampler reads the queues of the sockets of a side each queueInterval.
type queueSampler struct {
	mu           sync.Mutex
	rx, tx, n    int64 // Sums and the sample count since the last take.
	rxMax, txMax int64
}

const queueInterval = 5 * time.Millisecond

// sampleQueues samples the queues of c and of the sockets of lanes until ctx
// ends. A sample is the sum of all sockets. It returns nil when it cannot read
// the queues of c.
func sampleQueues(ctx context.Context, c syscall.Conn, lanes func() []*net.UDPConn) *queueSampler {
	if rx, _ := sockMem(c); rx < 0 {
		return nil
	}
	q := &queueSampler{}
	go func() {
		t := time.NewTicker(queueInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			rx, tx := sockMem(c)
			for _, lc := range lanes() {
				if lrx, ltx := sockMem(lc); lrx >= 0 {
					rx, tx = rx+lrx, tx+ltx
				}
			}
			q.mu.Lock()
			q.rx, q.tx, q.n = q.rx+rx, q.tx+tx, q.n+1
			q.rxMax, q.txMax = max(q.rxMax, rx), max(q.txMax, tx)
			q.mu.Unlock()
		}
	}()
	return q
}

// take returns the queues since the last take, and starts again. It returns
// nil for a nil sampler or no samples.
func (q *queueSampler) take() *sockQueue {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.n == 0 {
		return nil
	}
	out := &sockQueue{RxMean: q.rx / q.n, RxMax: q.rxMax, TxMean: q.tx / q.n, TxMax: q.txMax}
	q.rx, q.tx, q.n, q.rxMax, q.txMax = 0, 0, 0, 0, 0
	return out
}

// topCPUs is the number of CPUs of each host in the result.
const topCPUs = 4

// cpuUse is the busy time of one CPU in percent, and its NET_RX and NET_TX
// softirq runs.
type cpuUse struct {
	CPU    int     `json:"cpu"`
	User   float64 `json:"user"`
	System float64 `json:"system"`
	IRQ    float64 `json:"irq"`
	NetRX  uint64  `json:"net_rx"`
	NetTX  uint64  `json:"net_tx"`
}

func (u cpuUse) busy() float64 { return u.User + u.System + u.IRQ }

// busiestCPUs returns the n busiest CPUs of the host from m0 to m1, the
// busiest first.
func busiestCPUs(m0, m1 mark, n int) []cpuUse {
	if len(m0.CPUs) == 0 || len(m0.CPUs) != len(m1.CPUs) {
		return nil
	}
	use := make([]cpuUse, 0, len(m1.CPUs))
	for i, b := range m1.CPUs {
		a := m0.CPUs[i]
		user, sys, irq := float64(b.User-a.User), float64(b.System-a.System), float64(b.IRQ-a.IRQ)
		all := user + sys + irq + float64(b.Idle-a.Idle)
		if all <= 0 {
			continue
		}
		use = append(use, cpuUse{CPU: i, User: pct(user, all), System: pct(sys, all), IRQ: pct(irq, all),
			NetRX: b.NetRX - a.NetRX, NetTX: b.NetTX - a.NetTX})
	}
	slices.SortStableFunc(use, func(a, b cpuUse) int { return cmp.Compare(b.busy(), a.busy()) })
	return use[:min(n, len(use))]
}

// pct returns v in percent of all, with one decimal.
func pct(v, all float64) float64 { return math.Round(v*1000/all) / 10 }

// cores returns the CPU seconds per second from m0 to m1.
func cores(m0, m1 mark) float64 {
	s := time.Duration(m1.Nanos - m0.Nanos).Seconds()
	if s <= 0 {
		return 0
	}
	return (m1.CPU - m0.CPU) / s
}

// hostCores returns the busy host CPU seconds per second from m0 to m1, or -1.
func hostCores(m0, m1 mark) float64 {
	s := time.Duration(m1.Nanos - m0.Nanos).Seconds()
	if m0.HostCPU < 0 || m1.HostCPU < 0 {
		return -1
	}
	if s <= 0 {
		return 0
	}
	return (m1.HostCPU - m0.HostCPU) / s
}

// result is the client JSON line. perfrig reads the first four fields.
type result struct {
	Seconds          float64 `json:"seconds"`
	BitsPerSecond    float64 `json:"bits_per_second"`
	PacketsPerSecond float64 `json:"packets_per_second"`
	Retransmits      uint64  `json:"retransmits"`
	// RetransPercent is the part of the packets that the client sent that are
	// retransmissions.
	RetransPercent float64 `json:"retrans_percent"`
	// ServerRetransmits are the TCP retransmits of the server, which sends ACKs.
	ServerRetransmits uint64 `json:"server_retransmits"`
	// IdleRTT is the probe RTT before the flows start. LoadRTT is the probe RTT in the measured window.
	IdleRTT bench.RTTStats `json:"idle_rtt_ms"`
	LoadRTT bench.RTTStats `json:"load_rtt_ms"`
	// Cores are the CPU seconds per second of each process in the measured window.
	ClientCores        float64 `json:"client_cores"`
	ServerCores        float64 `json:"server_cores"`
	RelayCores         float64 `json:"relay_cores"`
	ClientCoresPerGbps float64 `json:"client_cores_per_gbps"`
	ServerCoresPerGbps float64 `json:"server_cores_per_gbps"`
	RelayCoresPerGbps  float64 `json:"relay_cores_per_gbps"`
	// HostCores are the busy CPU seconds per second of the host of each side,
	// with the kernel work. The sides of the netns rig have one host. -1 is not known.
	ClientHostCores float64 `json:"client_host_cores"`
	ServerHostCores float64 `json:"server_host_cores"`
	RelayHostCores  float64 `json:"relay_host_cores"`
	// The busiest CPUs of the host of each side in the measured window.
	ClientTopCPUs []cpuUse `json:"client_top_cpus,omitempty"`
	ServerTopCPUs []cpuUse `json:"server_top_cpus,omitempty"`
	RelayTopCPUs  []cpuUse `json:"relay_top_cpus,omitempty"`
	// The queues of the agent and lane sockets in the measured window.
	ClientQueue *sockQueue `json:"client_queue,omitempty"`
	ServerQueue *sockQueue `json:"server_queue,omitempty"`
	// The PSP packets that each side sent on each send lane in the measured window.
	ClientLanePackets []uint64 `json:"client_lane_packets,omitempty"`
	ServerLanePackets []uint64 `json:"server_lane_packets,omitempty"`

	Driver    string `json:"driver"`
	Transport string `json:"transport"`
	Via       string `json:"via"`
	CC        string `json:"cc"`
	Streams   int    `json:"streams"`
	DeviceMTU int    `json:"device_mtu"`

	// Drops in the measured window. The counters of the kernel are -1 when the side cannot
	// read them. server_rcvbuf_errors counts all sockets of the server netns, also the
	// relay socket when the relay runs there. The socket drops count one socket each.
	ClientTxDrops      uint64 `json:"client_tx_drops"`
	ServerRxDrops      uint64 `json:"server_rx_drops"`
	RelayDrops         uint64 `json:"relay_drops"`
	RelayRcvbufDrops   int64  `json:"relay_rcvbuf_drops"`
	ServerRcvbufErrors int64  `json:"server_rcvbuf_errors"`
	ServerSockDrops    int64  `json:"server_sock_drops"`
	ClientLinkDrops    int64  `json:"client_link_drops"`
	ServerLinkDrops    int64  `json:"server_link_drops"`
	// RelayXDPPackets are the PSP packets that the relay forwarded in XDP in
	// the measured window.
	RelayXDPPackets uint64 `json:"relay_xdp_packets"`

	// Omit is the omit period, from the flow start to the window start.
	Omit period `json:"omit"`
	// Wall clock times of the flow start and of the window, in Unix milliseconds.
	FlowStartUnixMS   int64 `json:"flow_start_unix_ms"`
	WindowStartUnixMS int64 `json:"window_start_unix_ms"`
	WindowEndUnixMS   int64 `json:"window_end_unix_ms"`
}

// period is the rate, the loss and the drops of a part of the run.
type period struct {
	Seconds            float64        `json:"seconds"`
	BitsPerSecond      float64        `json:"bits_per_second"`
	Retransmits        uint64         `json:"retransmits"`
	RetransPercent     float64        `json:"retrans_percent"`
	ServerRetransmits  uint64         `json:"server_retransmits"`
	RTT                bench.RTTStats `json:"rtt_ms"`
	ClientTxDrops      uint64         `json:"client_tx_drops"`
	ServerRxDrops      uint64         `json:"server_rx_drops"`
	RelayDrops         uint64         `json:"relay_drops"`
	RelayRcvbufDrops   int64          `json:"relay_rcvbuf_drops"`
	ServerRcvbufErrors int64          `json:"server_rcvbuf_errors"`
	ServerSockDrops    int64          `json:"server_sock_drops"`
	ClientLinkDrops    int64          `json:"client_link_drops"`
	ServerLinkDrops    int64          `json:"server_link_drops"`
}

// newPeriod computes a period from the marks at its start and at its end.
func newPeriod(client, server, relay [2]mark) period {
	r := newResult(client, server, relay)
	return period{
		Seconds: r.Seconds, BitsPerSecond: r.BitsPerSecond, Retransmits: r.Retransmits, RetransPercent: r.RetransPercent,
		ServerRetransmits: r.ServerRetransmits, ClientTxDrops: r.ClientTxDrops, ServerRxDrops: r.ServerRxDrops,
		RelayDrops: r.RelayDrops, RelayRcvbufDrops: r.RelayRcvbufDrops,
		ServerRcvbufErrors: r.ServerRcvbufErrors, ServerSockDrops: r.ServerSockDrops,
		ClientLinkDrops: r.ClientLinkDrops, ServerLinkDrops: r.ServerLinkDrops,
	}
}

// newResult computes the rates from the marks at the start and at the end of
// the measured window. relay is zero with no relay.
func newResult(client, server, relay [2]mark) result {
	var r result
	s := time.Duration(server[1].Nanos - server[0].Nanos).Seconds()
	if s <= 0 {
		return r
	}
	r.Seconds = s
	r.BitsPerSecond = float64(server[1].Bytes-server[0].Bytes) * 8 / s
	r.PacketsPerSecond = float64(server[1].RxPackets-server[0].RxPackets) / s
	r.Retransmits = client[1].Retrans - client[0].Retrans
	r.ServerRetransmits = server[1].Retrans - server[0].Retrans
	if segs := client[1].Segments - client[0].Segments; segs > 0 {
		r.RetransPercent = float64(r.Retransmits) * 100 / float64(segs)
	}
	r.ClientCores, r.ServerCores, r.RelayCores = cores(client[0], client[1]), cores(server[0], server[1]), cores(relay[0], relay[1])
	r.ClientHostCores, r.ServerHostCores, r.RelayHostCores = hostCores(client[0], client[1]), hostCores(server[0], server[1]), hostCores(relay[0], relay[1])
	r.ClientTopCPUs = busiestCPUs(client[0], client[1], topCPUs)
	r.ServerTopCPUs = busiestCPUs(server[0], server[1], topCPUs)
	r.RelayTopCPUs = busiestCPUs(relay[0], relay[1], topCPUs)
	r.ClientQueue, r.ServerQueue = client[1].Queue, server[1].Queue
	r.ClientLanePackets, r.ServerLanePackets = laneDelta(client[0].Lanes, client[1].Lanes), laneDelta(server[0].Lanes, server[1].Lanes)
	if gbps := r.BitsPerSecond / 1e9; gbps > 0 {
		r.ClientCoresPerGbps = r.ClientCores / gbps
		r.ServerCoresPerGbps = r.ServerCores / gbps
		r.RelayCoresPerGbps = r.RelayCores / gbps
	}
	r.ClientTxDrops = client[1].Drops - client[0].Drops
	r.ServerRxDrops = server[1].Drops - server[0].Drops
	r.RelayDrops = relay[1].Drops - relay[0].Drops
	r.RelayRcvbufDrops = delta(relay[0].SockDrops, relay[1].SockDrops)
	r.ServerRcvbufErrors = delta(server[0].RcvbufErrors, server[1].RcvbufErrors)
	r.ServerSockDrops = delta(server[0].SockDrops, server[1].SockDrops)
	r.ClientLinkDrops = delta(client[0].LinkDrops, client[1].LinkDrops)
	r.ServerLinkDrops = delta(server[0].LinkDrops, server[1].LinkDrops)
	r.RelayXDPPackets = relay[1].XDPPackets - relay[0].XDPPackets
	return r
}

// laneDelta returns the increase of the packets of each lane from v0 to v1.
func laneDelta(v0, v1 []uint64) []uint64 {
	if len(v1) == 0 {
		return nil
	}
	out := make([]uint64, len(v1))
	for i, n := range v1 {
		out[i] = n
		if i < len(v0) {
			out[i] -= min(v0[i], n)
		}
	}
	return out
}

// delta returns the increase of a counter from v0 to v1, or -1 when a value
// is -1 (not known).
func delta(v0, v1 int64) int64 {
	if v0 < 0 || v1 < 0 {
		return -1
	}
	return max(v1-v0, 0)
}

// echo sends each UDP probe back to its sender until pc closes.
func echo(pc net.PacketConn) {
	b := make([]byte, 2048)
	for {
		n, from, err := pc.ReadFrom(b)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(b[:n], from)
	}
}

// snmpCounter returns a counter of /proc/net/snmp of this netns, or -1.
func snmpCounter(group, name string) int64 {
	b, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return -1
	}
	return snmpValue(string(b), group, name)
}

// snmpValue returns a counter of /proc/net/snmp, or -1. Each group has a line
// of names and then a line of values.
func snmpValue(snmp, group, name string) int64 {
	var names []string
	for line := range strings.Lines(snmp) {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != group {
			continue
		}
		if names == nil {
			names = f
			continue
		}
		for i, n := range names {
			if n == name && i < len(f) {
				v, err := strconv.ParseInt(f[i], 10, 64)
				if err != nil {
					return -1
				}
				return v
			}
		}
		return -1
	}
	return -1
}
