// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/cmd/internal/bench"
)

func TestParseFloodFlags(t *testing.T) {
	t.Setenv("WORK_DIR", "/work")
	relay := []string{"-id", "r1", "-listen", "10.0.0.3:4443", "-xdp", "ens5"}
	source := []string{"-id", "r1", "-server", "10.0.0.2:4433"}
	with := func(base []string, more ...string) []string { return append(append([]string{}, base...), more...) }
	cases := []struct {
		name    string
		cmd     string
		args    []string
		want    func(o floodOptions) bool
		wantErr string
	}{
		{
			name: "relay defaults", cmd: floodRelayCmd, args: relay,
			want: func(o floodOptions) bool {
				return o.ID == "r1" && o.Seq == 0 && o.Listen == "10.0.0.3:4443" && o.XDP == "ens5" && o.XDPMode == "driver" &&
					o.XDPHop == 0 && o.TunnelRate == 0 && !o.XDPStats && o.StartTimeout == 30*time.Second
			},
		},
		{
			name: "relay behind the Geneve program", cmd: floodRelayCmd,
			args: with(relay, "-xdp-mode", "chain", "-seq", "4", "-tunnel-rate", "5e9", "-xdp-hop", "1s", "-xdp-stats", "-start-timeout", "5m"),
			want: func(o floodOptions) bool {
				return o.XDPMode == "chain" && o.Seq == 4 && o.TunnelRate == 5e9 && o.XDPHop == time.Second && o.XDPStats && o.StartTimeout == 5*time.Minute
			},
		},
		{name: "relay with an unknown mode", cmd: floodRelayCmd, args: with(relay, "-xdp-mode", "native"), wantErr: `unknown -xdp-mode "native": want driver, generic or chain`},
		{name: "relay with no link", cmd: floodRelayCmd, args: []string{"-id", "r1", "-listen", ":4443"}, wantErr: "-listen and -xdp are required"},
		{name: "relay with no row", cmd: floodRelayCmd, args: relay[2:], wantErr: "-id is required"},
		{name: "relay with a negative tunnel rate", cmd: floodRelayCmd, args: with(relay, "-tunnel-rate", "-1"), wantErr: "must not be negative"},
		{name: "relay has no packet size", cmd: floodRelayCmd, args: with(relay, "-size", "800"), wantErr: "flag provided but not defined: -size"},
		{
			name: "counter defaults", cmd: floodCounterCmd, args: relay,
			want: func(o floodOptions) bool { return o.XDPMode == "driver" && o.XDP == "ens5" },
		},
		{name: "counter has no chain mode", cmd: floodCounterCmd, args: with(relay, "-xdp-mode", "chain"), wantErr: `unknown -xdp-mode "chain": want driver or generic`},
		{name: "counter has no tunnel rate", cmd: floodCounterCmd, args: with(relay, "-tunnel-rate", "1"), wantErr: "flag provided but not defined: -tunnel-rate"},
		{
			name: "source defaults", cmd: floodSourceCmd, args: source,
			want: func(o floodOptions) bool {
				return o.Server == "10.0.0.2:4433" && o.Relay == "" && o.WorkDir == "/work" && o.Size == 800 && o.Ports == 16 &&
					o.NextPorts == 16 && o.Batch == 16 && o.GSO == 0 && o.Sndbuf == 1<<20 && o.WireGbps == 0 &&
					o.Omit == 5*time.Second && o.Duration == 30*time.Second && o.Settle == 3*time.Second
			},
		},
		{
			name: "source flags", cmd: floodSourceCmd,
			args: with(source, "-relay", "10.0.0.3:4443", "-size", "68", "-ports", "256", "-next-ports", "8", "-batch", "4", "-gso", "1",
				"-wire-gbps", "20", "-omit", "1s", "-duration", "2s", "-settle", "0s", "-work-dir", ""),
			want: func(o floodOptions) bool {
				return o.Relay == "10.0.0.3:4443" && o.Size == 68 && o.Ports == 256 && o.NextPorts == 8 && o.Batch == 4 && o.GSO == 1 &&
					o.WireGbps == 20 && o.Omit == time.Second && o.Duration == 2*time.Second && o.Settle == 0 && o.WorkDir == ""
			},
		},
		{name: "source with no counter", cmd: floodSourceCmd, args: []string{"-id", "r1"}, wantErr: "-server is required"},
		{name: "packet below the smallest PSP packet", cmd: floodSourceCmd, args: with(source, "-size", "67"), wantErr: "-size must be 68 to 1500"},
		{name: "packet above the largest PSP packet", cmd: floodSourceCmd, args: with(source, "-size", "1501"), wantErr: "-size must be 68 to 1500"},
		{name: "no source port", cmd: floodSourceCmd, args: with(source, "-ports", "0"), wantErr: "-ports must be 1 to 1024"},
		{name: "too many counter ports", cmd: floodSourceCmd, args: with(source, "-next-ports", "257"), wantErr: "-next-ports must be 1 to 256"},
		{name: "too many segments", cmd: floodSourceCmd, args: with(source, "-gso", "65"), wantErr: "-gso must be 0 to 64"},
		{name: "no duration", cmd: floodSourceCmd, args: with(source, "-duration", "0s"), wantErr: "-duration must be positive"},
		{name: "negative sequence", cmd: floodSourceCmd, args: with(source, "-seq", "-1"), wantErr: "-seq must not be negative"},
		{name: "source has no listen", cmd: floodSourceCmd, args: with(source, "-listen", ":1"), wantErr: "flag provided but not defined: -listen"},
		{name: "extra argument", cmd: floodSourceCmd, args: with(source, "extra"), wantErr: "unexpected arguments"},
		{
			name: "profiles", cmd: floodCounterCmd, args: with(relay, "-cpuprofile", "c.pprof", "-kernel", "k"),
			want: func(o floodOptions) bool {
				return o.Profiles == bench.Profiles{CPU: "c.pprof", TraceTime: 3 * time.Second, Kernel: "k"}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := parseFloodFlags(tc.cmd, tc.args, io.Discard)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.True(t, tc.want(o), "options: %+v", o)
		})
	}
}

// TestFloodPayload checks that each packet of a message passes the header
// checks of the relay program, which are the checks of ParseHeader.
func TestFloodPayload(t *testing.T) {
	cases := []struct {
		name    string
		size, n int
		spi     uint32
	}{
		{name: "smallest packet", size: floodMinSize, n: 1, spi: floodSPI},
		{name: "one packet of 800 bytes", size: 800, n: 1, spi: floodSPI},
		{name: "GSO message", size: 800, n: 64, spi: floodSPI + 15},
		{name: "largest packet", size: floodMaxLen, n: 3, spi: 0x7fffffff},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seg := tc.size - ipv4Len - udpLen
			b := floodPayload(tc.size, tc.n, tc.spi)
			require.Len(t, b, seg*tc.n)
			// The relay program wants the PSP header, the VC and the ICV at least.
			require.GreaterOrEqual(t, seg, pspwire.Overhead)
			for i := range tc.n {
				h, err := pspwire.ParseHeader(b[i*seg : (i+1)*seg])
				require.NoError(t, err, "packet %d", i)
				assert.Equal(t, pspwire.Header{NextHdr: pspwire.NextHdrV4, SPI: tc.spi, IV: uint64(i) + 1, VNI: vni}, h, "packet %d", i)
			}
		})
	}
	assert.Equal(t, 68, floodMinSize, "the IPv4 and UDP headers, the PSP header, the VC and the ICV")
	assert.Equal(t, 1500, floodMaxLen)
}

func TestFloodSegs(t *testing.T) {
	cases := []struct {
		name      string
		gso, size int
		paced     bool
		want      int
	}{
		{name: "default", size: 800, want: 64},
		{name: "default with a rate", size: 800, paced: true, want: 16},
		{name: "no GSO", gso: 1, size: 800, want: 1},
		{name: "set", gso: 8, size: 68, want: 8},
		{name: "a message holds 65507 bytes", size: 1500, want: 44},
		{name: "smallest packet", size: 68, want: 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, floodSegs(tc.gso, tc.size, tc.paced))
		})
	}
}

func TestFloodFlows(t *testing.T) {
	cases := []struct {
		port, nextPorts int
		wantSender      int
		wantSPI         uint32
		wantNext        uint16
	}{
		{port: 0, nextPorts: 16, wantSender: 0, wantSPI: 0x100, wantNext: 20000},
		{port: 15, nextPorts: 16, wantSender: 0, wantSPI: 0x100, wantNext: 20015},
		{port: 16, nextPorts: 16, wantSender: 1, wantSPI: 0x101, wantNext: 20000},
		{port: 255, nextPorts: 16, wantSender: 15, wantSPI: 0x10f, wantNext: 20015},
		{port: 255, nextPorts: 256, wantSender: 15, wantSPI: 0x10f, wantNext: 20255},
		{port: 5, nextPorts: 1, wantSender: 0, wantSPI: 0x100, wantNext: 20000},
	}
	for _, tc := range cases {
		sender, spi := senderOf(tc.port)
		assert.Equal(t, tc.wantSender, sender, "port %d", tc.port)
		assert.Equal(t, tc.wantSPI, spi, "port %d", tc.port)
		assert.Equal(t, tc.wantNext, floodNext(tc.port, tc.nextPorts), "port %d", tc.port)
	}
}

func TestSNMPCounters(t *testing.T) {
	const snmp = `Ip: Forwarding DefaultTTL
Ip: 1 64
Icmp: InMsgs InErrors OutMsgs OutDestUnreachs
Icmp: 7 0 12 9
IcmpMsg: InType3 OutType3
IcmpMsg: 5 9
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors
Udp: 100 3 4 200 5 6
UdpLite: InDatagrams
UdpLite: 0
`
	cases := []struct {
		name string
		snmp string
		want map[string]uint64
	}{
		{name: "Icmp and Udp", snmp: snmp, want: map[string]uint64{
			"Icmp.InMsgs": 7, "Icmp.InErrors": 0, "Icmp.OutMsgs": 12, "Icmp.OutDestUnreachs": 9,
			"Udp.InDatagrams": 100, "Udp.NoPorts": 3, "Udp.InErrors": 4, "Udp.OutDatagrams": 200, "Udp.RcvbufErrors": 5, "Udp.SndbufErrors": 6,
		}},
		{name: "names with no values", snmp: "Udp: InDatagrams\n", want: map[string]uint64{}},
		{name: "empty", want: map[string]uint64{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, snmpCounters(tc.snmp))
		})
	}
}

func TestKmsgText(t *testing.T) {
	cases := []struct{ name, record, want string }{
		{name: "record", record: "6,1234,12000345,-;ena 0000:00:05.0 eth0: Trigger reset is on\n SUBSYSTEM=pci\n", want: "12.000345 ena 0000:00:05.0 eth0: Trigger reset is on"},
		{name: "text with a semicolon", record: "4,1,2,-;a; b\n", want: "0.000002 a; b"},
		{name: "no time", record: "4;text\n", want: "text"},
		{name: "no text", record: "4,1,2,-", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, kmsgText(tc.record))
		})
	}
}

func TestNewFloodHost(t *testing.T) {
	const sec = int64(time.Second)
	cases := []struct {
		name    string
		m       [2]*floodMark
		seconds float64
		want    floodHost
	}{
		{name: "no marks", seconds: 1, want: floodHost{Allowance: map[string]uint64{}}},
		{
			name:    "ENA link with an XDP program",
			seconds: 2,
			m: [2]*floodMark{
				{
					NIC: map[string]uint64{"queue_0_rx_cnt": 100, "queue_1_rx_cnt": 0, "queue_0_tx_cnt": 10, "queue_8_xdp_tx_cnt": 50,
						"sys_rx_dropped": 5, "sys_rx_over_errors": 1, "sys_carrier_down": 2, "pps_allowance_exceeded": 3, "bw_in_allowance_exceeded": 0},
					SNMP: map[string]uint64{"Icmp.OutMsgs": 1, "Udp.SndbufErrors": 2},
					IRQ:  []uint64{0, 1e9, 0}, NetRX: []uint64{0, 1e9, 0},
					CPUs: []bench.CPUTicks{{Idle: 100}, {Idle: 100}},
				},
				{
					Nanos: 4 * sec, Link: &floodLink{Dev: "ens5", Driver: "ena"},
					NIC: map[string]uint64{"queue_0_rx_cnt": 3100, "queue_1_rx_cnt": 1000, "queue_0_tx_cnt": 30, "queue_8_xdp_tx_cnt": 4050,
						"sys_rx_dropped": 25, "sys_rx_over_errors": 3, "sys_carrier_down": 3, "pps_allowance_exceeded": 10, "bw_in_allowance_exceeded": 0},
					SNMP: map[string]uint64{"Icmp.OutMsgs": 4, "Udp.SndbufErrors": 9},
					IRQ:  []uint64{19e8, 15e8, 2e8}, NetRX: []uint64{18e8, 15e8, 0},
					CPUs: []bench.CPUTicks{{IRQ: 100, Idle: 200}, {System: 100, Idle: 200}},
				},
			},
			want: floodHost{
				Link: &floodLink{Dev: "ens5", Driver: "ena"}, TxPPS: 10, RxPPS: 2000, XDPTxPPS: 2000, RxDropped: 20, RxOverruns: 2, ArrivedPPS: 2010,
				RxQueues: 2, TopQueuePct: 75, RxQueuePPS: []float64{1500, 500}, LinkDowns: 1,
				Allowance: map[string]uint64{"pps_allowance_exceeded": 7, "bw_in_allowance_exceeded": 0},
				ICMPOut:   3, SndbufErrors: 7,
				IRQCores: 1.3, NetRXCores: 1.15, TopCPUPct: 95, BusyCPUs: 1,
				// Half of the ticks of 2 CPUs in 4 s are busy, and the packets ran for 2 s.
				HostCores: 2,
			},
		},
		{
			name:    "link with no queue counters",
			seconds: 1,
			m: [2]*floodMark{
				{NIC: map[string]uint64{"sys_rx_packets": 10, "sys_tx_packets": 20}},
				{NIC: map[string]uint64{"sys_rx_packets": 110, "sys_tx_packets": 520}},
			},
			want: floodHost{RxPPS: 100, TxPPS: 500, ArrivedPPS: 100, Allowance: map[string]uint64{}},
		},
		{
			name:    "ENA link with a program that drops",
			seconds: 1,
			m: [2]*floodMark{
				{NIC: map[string]uint64{"queue_0_rx_cnt": 0, "queue_0_rx_xdp_drop": 0, "queue_1_rx_cnt": 5, "queue_1_rx_xdp_drop": 5, "sys_rx_dropped": 5}},
				{NIC: map[string]uint64{"queue_0_rx_cnt": 600, "queue_0_rx_xdp_drop": 598, "queue_1_rx_cnt": 405, "queue_1_rx_xdp_drop": 405, "sys_rx_dropped": 1103}},
			},
			// The link counts the 998 packets of the program and 100 packets of the device as dropped.
			want: floodHost{
				RxPPS: 1000, ArrivedPPS: 1100, RxDropped: 100, XDPDrops: 998, RxQueues: 2, TopQueuePct: 60, RxQueuePPS: []float64{600, 400},
				Allowance: map[string]uint64{},
			},
		},
		{
			name:    "link that does not count the packets of the program as dropped",
			seconds: 1,
			m: [2]*floodMark{
				{NIC: map[string]uint64{"queue_0_rx_cnt": 0, "queue_0_rx_xdp_drop": 0}},
				{NIC: map[string]uint64{"queue_0_rx_cnt": 1000, "queue_0_rx_xdp_drop": 1000, "sys_rx_dropped": 30}},
			},
			want: floodHost{
				RxPPS: 1000, ArrivedPPS: 1030, RxDropped: 30, XDPDrops: 1000, RxQueues: 1, TopQueuePct: 100, RxQueuePPS: []float64{1000},
				Allowance: map[string]uint64{},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := newFloodHost(tc.m, tc.seconds)
			assert.InDelta(t, tc.want.IRQCores, got.IRQCores, 1e-9)
			assert.InDelta(t, tc.want.NetRXCores, got.NetRXCores, 1e-9)
			assert.InDelta(t, tc.want.HostCores, got.HostCores, 1e-9)
			got.IRQCores, got.NetRXCores, got.HostCores = tc.want.IRQCores, tc.want.NetRXCores, tc.want.HostCores
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNewFloodResult(t *testing.T) {
	run := floodRun{Size: 800, Ports: 2, NextPorts: 2, GSO: 64, Batch: 16, Seconds: 2, Sent: []uint64{3000, 1000}, Errors: 1}
	src := [2]*floodMark{
		{NIC: map[string]uint64{"queue_0_tx_cnt": 0, "queue_1_tx_cnt": 500}},
		{NIC: map[string]uint64{"queue_0_tx_cnt": 2500, "queue_1_tx_cnt": 1500}},
	}
	counter := [2]*floodMark{
		{NIC: map[string]uint64{"queue_0_rx_cnt": 0}, IRQ: []uint64{0}, PortPkts: []uint64{10, 0, 0}, PortBytes: []uint64{8140, 0, 0}},
		{
			NIC: map[string]uint64{"queue_0_rx_cnt": 2990, "sys_rx_dropped": 10}, IRQ: []uint64{1e9},
			PortPkts: []uint64{2010, 1000, 0}, PortBytes: []uint64{8140 + 2000*814, 814000, 0},
		},
	}
	relay := [2]*floodMark{
		{
			NIC: map[string]uint64{"queue_0_rx_cnt": 0, "queue_1_rx_cnt": 0}, XDP: &relayXDPStats{Packets: 100, NoRoute: 1},
			IRQ: []uint64{0, 0}, Rows: []uint64{100, 0}, SockPkts: 2, XDPSeconds: 1,
		},
		{
			NIC: map[string]uint64{"queue_0_rx_cnt": 2600, "queue_1_rx_cnt": 1000, "sys_rx_dropped": 400,
				"queue_0_tx_cnt": 20, "queue_2_xdp_tx_cnt": 2780, "sys_tx_dropped": 200},
			XDP: &relayXDPStats{Packets: 3100, NoRoute: 601, TunnelDrops: 5},
			IRQ: []uint64{15e8, 5e8}, Rows: []uint64{2100, 1000}, SockPkts: 602, XDPSeconds: 1.0003605,
		},
	}
	cases := []struct {
		name  string
		run   floodRun
		relay [2]*floodMark
		check func(t *testing.T, r floodResult)
	}{
		{
			name: "through the relay", run: run, relay: relay,
			check: func(t *testing.T, r floodResult) {
				assert.Equal(t, "relay", r.Via)
				assert.Equal(t, 814, r.FrameLen)
				assert.Equal(t, 2000.0, r.SentPPS)
				assert.Equal(t, 1750.0, r.OfferedPPS)
				assert.InDelta(t, 1750*814*8/1e9, r.OfferedGbps, 1e-12)
				assert.Equal(t, 2000.0, r.RelayArrivedPPS, "the packets of the queues and the packets that the device dropped")
				assert.Equal(t, 1500.0, r.RelayXDPPPS)
				assert.InDelta(t, 1500*814*8/1e9, r.RelayGbps, 1e-12)
				assert.Equal(t, 1400.0, r.RelaySentPPS, "the packets of the TX queues and of the XDP TX queues")
				assert.Equal(t, map[string]uint64{"no_route": 600, "tunnel_meter": 5}, r.RelayDrops)
				assert.Equal(t, uint64(600), r.RelaySockPackets)
				assert.Equal(t, []float64{1000, 500}, r.PortRelayPPS)
				assert.InDelta(t, 100, r.RelayXDPNanos, 1e-4, "the program ran for 3000 forwarded and 605 other packets")
				assert.InDelta(t, 1.0, r.RelayCores, 1e-9)
				assert.InDelta(t, 2e9/3000, r.RelayNanos, 1e-6)
				assert.InDelta(t, 10/(1500*814*8/1e9), r.RelayCoresPer10G, 1e-6)
				assert.Equal(t, 1500.0, r.PacketsPerSecond)
				assert.Equal(t, 1500.0*814*8, r.BitsPerSecond)
				assert.Equal(t, 1500.0, r.CounterArrivedPPS)
				assert.InDelta(t, 0.5, r.ServerCores, 1e-9)
				assert.InDelta(t, 0.5/(1500*814*8/1e9), r.ServerCoresPerGbps, 1e-6)
				assert.Equal(t, []float64{1000, 500}, r.NextPortPPS)
				assert.Equal(t, []float64{1500, 500}, r.PortSentPPS)
				assert.Equal(t, uint64(1), r.SendErrors)
				require.NotNil(t, r.Relay)
				assert.InDelta(t, 72.2, r.Relay.TopQueuePct, 1e-9)
				assert.Equal(t, uint64(200), r.Relay.TxDropped)
			},
		},
		{
			name: "with no relay", run: run,
			check: func(t *testing.T, r floodResult) {
				assert.Equal(t, "direct", r.Via)
				assert.Nil(t, r.Relay)
				assert.Zero(t, r.RelayXDPPPS)
				assert.Equal(t, 1500.0, r.PacketsPerSecond)
				assert.Equal(t, 1750.0, r.OfferedPPS)
			},
		},
		{
			name: "no time", run: floodRun{Size: 68, Ports: 1},
			check: func(t *testing.T, r floodResult) {
				assert.Equal(t, 82, r.FrameLen)
				assert.Zero(t, r.PacketsPerSecond)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newFloodResult(tc.run, src, tc.relay, counter)
			tc.check(t, r)
			// perfrig reads the rate and the time from the JSON line.
			b, err := json.Marshal(r)
			require.NoError(t, err)
			var line struct {
				Seconds       *float64 `json:"seconds"`
				BitsPerSecond *float64 `json:"bits_per_second"`
			}
			require.NoError(t, json.Unmarshal(b, &line))
			require.NotNil(t, line.Seconds)
			require.NotNil(t, line.BitsPerSecond)
			assert.Equal(t, r.BitsPerSecond, *line.BitsPerSecond)
		})
	}
}

// TestFloodPeer checks when a relay or a counter of the row "a" at the place 2
// of the run stops, and what the source gets.
func TestFloodPeer(t *testing.T) {
	ctx := context.Background()
	const wait = 5 * time.Second
	cases := []struct {
		name string
		wait time.Duration
		// source talks to the host at addr. It returns when the host must stop.
		source  func(t *testing.T, addr string)
		wantErr string
	}{
		{
			name: "the source of the row disconnects",
			source: func(t *testing.T, addr string) {
				c, m, err := dialFlood(ctx, addr, floodHello{ID: "a", Seq: 2, Ports: 3}, wait)
				require.NoError(t, err)
				assert.Equal(t, int64(3), m.Nanos, "the hello answer")
				m, err = c.mark(2, time.Second)
				require.NoError(t, err)
				assert.Equal(t, int64(2), m.Nanos, "the mark answer")
				require.NoError(t, c.c.Close())
			},
		},
		{
			name: "the source stops the row on its connection",
			source: func(t *testing.T, addr string) {
				c, _, err := dialFlood(ctx, addr, floodHello{ID: "a", Seq: 2}, wait)
				require.NoError(t, err)
				_, err = c.call(request{Op: "stop", Flood: &floodHello{ID: "a"}})
				require.NoError(t, err, "the answer arrives before the host stops")
				require.NoError(t, c.c.Close())
			},
		},
		{
			name:   "a failed source stops the row on a new connection",
			source: func(t *testing.T, addr string) { stopFlood(addr, "a") },
		},
		{
			name: "a source at an earlier row fails at once and the host stays",
			source: func(t *testing.T, addr string) {
				start := time.Now()
				_, _, err := dialFlood(ctx, addr, floodHello{ID: "b", Seq: 1}, wait)
				require.ErrorContains(t, err, `this host runs the row "a"`)
				assert.Less(t, time.Since(start), wait/2)
				// The stop of a different row does nothing.
				stopFlood(addr, "b")
				c, _, err := dialFlood(ctx, addr, floodHello{ID: "a", Seq: 2}, wait)
				require.NoError(t, err)
				require.NoError(t, c.c.Close())
			},
		},
		{
			name: "a source of a different row with no place fails at once and the host stays",
			source: func(t *testing.T, addr string) {
				_, _, err := dialFlood(ctx, addr, floodHello{ID: "b", Seq: 2}, wait)
				require.ErrorContains(t, err, `this host runs the row "a"`)
				c, _, err := dialFlood(ctx, addr, floodHello{ID: "a", Seq: 2}, wait)
				require.NoError(t, err)
				require.NoError(t, c.c.Close())
			},
		},
		{
			name: "a source at a later row stops the host",
			source: func(t *testing.T, addr string) {
				// The source tries again until its time ends, because no host of its row comes.
				_, _, err := dialFlood(ctx, addr, floodHello{ID: "c", Seq: 3}, 500*time.Millisecond)
				require.Error(t, err)
			},
			wantErr: "the source is at a later row",
		},
		{
			name: "a mark on a connection with no hello",
			source: func(t *testing.T, addr string) {
				c, err := dialCtl(ctx, addr, wait)
				require.NoError(t, err)
				_, err = c.call(request{Op: "mark", Index: 1, Flood: &floodHello{ID: "a"}})
				require.ErrorContains(t, err, "no hello on this connection")
				_, err = c.call(request{Op: "mark", Index: 1})
				require.ErrorContains(t, err, `this host runs the row "a"`)
				require.NoError(t, c.c.Close())
				stopFlood(addr, "a")
			},
		},
		{name: "no source", wait: 100 * time.Millisecond, source: func(*testing.T, string) {}, wantErr: "no source of the row a in 100ms"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			if tc.wait == 0 {
				tc.wait = wait
			}
			done := make(chan error, 1)
			go func() {
				done <- floodPeer(ctx, ln, "a", 2, tc.wait, func(req request, from netip.Addr) (reply, error) {
					assert.Equal(t, netip.MustParseAddr("127.0.0.1"), from)
					if req.Op == "hello" {
						return reply{Flood: &floodMark{Nanos: int64(req.Flood.Ports)}}, nil
					}
					return reply{Flood: &floodMark{Nanos: int64(req.Index)}}, nil
				})
			}()
			tc.source(t, ln.Addr().String())
			select {
			case err := <-done:
				if tc.wantErr != "" {
					require.ErrorContains(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
			case <-time.After(wait):
				t.Fatal("the host did not stop")
			}
		})
	}
}

// TestFloodPeerContext checks that the host stops with no error when its context ends.
func TestFloodPeerContext(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- floodPeer(ctx, ln, "a", 0, time.Minute, func(request, netip.Addr) (reply, error) { return reply{}, nil })
	}()
	c, _, err := dialFlood(ctx, ln.Addr().String(), floodHello{ID: "a"}, 5*time.Second)
	require.NoError(t, err)
	defer c.c.Close()
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the host did not stop")
	}
}
