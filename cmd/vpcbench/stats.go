// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/apoxy-dev/apoxy/cmd/internal/bench"
)

// mark is the counters of one side at one time. Each side sets its fields.
type mark struct {
	Nanos int64   `json:"nanos"` // Time since the side started.
	CPU   float64 `json:"cpu_s"`
	// Client: TCP segments sent and retransmitted, and binding send drops.
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
}

// cores returns the CPU seconds per second from m0 to m1.
func cores(m0, m1 mark) float64 {
	s := time.Duration(m1.Nanos - m0.Nanos).Seconds()
	if s <= 0 {
		return 0
	}
	return (m1.CPU - m0.CPU) / s
}

// result is the client JSON line. perfrig reads the first four fields.
type result struct {
	Seconds          float64 `json:"seconds"`
	BitsPerSecond    float64 `json:"bits_per_second"`
	PacketsPerSecond float64 `json:"packets_per_second"`
	Retransmits      uint64  `json:"retransmits"`
	// RetransPercent is the part of the TCP segments of the client that are retransmissions.
	RetransPercent float64 `json:"retrans_percent"`
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

	Driver    string `json:"driver"`
	Transport string `json:"transport"`
	Via       string `json:"via"`
	CC        string `json:"cc"`
	Streams   int    `json:"streams"`
	DeviceMTU int    `json:"device_mtu"`

	// Drops in the measured window.
	ClientTxDrops      uint64 `json:"client_tx_drops"`
	ServerRxDrops      uint64 `json:"server_rx_drops"`
	RelayDrops         uint64 `json:"relay_drops"`
	ServerRcvbufErrors int64  `json:"server_rcvbuf_errors"`

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
	RTT                bench.RTTStats `json:"rtt_ms"`
	ClientTxDrops      uint64         `json:"client_tx_drops"`
	ServerRxDrops      uint64         `json:"server_rx_drops"`
	RelayDrops         uint64         `json:"relay_drops"`
	ServerRcvbufErrors int64          `json:"server_rcvbuf_errors"`
}

// newPeriod computes a period from the marks at its start and at its end.
func newPeriod(client, server, relay [2]mark) period {
	r := newResult(client, server, relay)
	return period{
		Seconds: r.Seconds, BitsPerSecond: r.BitsPerSecond, Retransmits: r.Retransmits, RetransPercent: r.RetransPercent,
		ClientTxDrops: r.ClientTxDrops, ServerRxDrops: r.ServerRxDrops, RelayDrops: r.RelayDrops,
		ServerRcvbufErrors: r.ServerRcvbufErrors,
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
	if segs := client[1].Segments - client[0].Segments; segs > 0 {
		r.RetransPercent = float64(r.Retransmits) * 100 / float64(segs)
	}
	r.ClientCores, r.ServerCores, r.RelayCores = cores(client[0], client[1]), cores(server[0], server[1]), cores(relay[0], relay[1])
	if gbps := r.BitsPerSecond / 1e9; gbps > 0 {
		r.ClientCoresPerGbps = r.ClientCores / gbps
		r.ServerCoresPerGbps = r.ServerCores / gbps
		r.RelayCoresPerGbps = r.RelayCores / gbps
	}
	r.ClientTxDrops = client[1].Drops - client[0].Drops
	r.ServerRxDrops = server[1].Drops - server[0].Drops
	r.RelayDrops = relay[1].Drops - relay[0].Drops
	r.ServerRcvbufErrors = -1
	if server[0].RcvbufErrors >= 0 && server[1].RcvbufErrors >= 0 {
		r.ServerRcvbufErrors = server[1].RcvbufErrors - server[0].RcvbufErrors
	}
	return r
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
