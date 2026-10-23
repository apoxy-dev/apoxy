// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/cmd/internal/bench"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	relaydp "github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func TestParseFlags(t *testing.T) {
	t.Setenv("WORK_DIR", "/work")
	cases := []struct {
		name    string
		cmd     string
		args    []string
		want    func(o options) bool
		wantErr string
	}{
		{
			name: "relay", cmd: "relay", args: []string{"-iface", "perf-r", "-listen", ":4443"},
			want: func(o options) bool {
				return o.Iface == "perf-r" && o.Listen == ":4443" && o.WorkDir == "/work" && o.MTU == 0 && o.Lanes == relay.MaxLaneSources
			},
		},
		{name: "relay has no XDP", cmd: "relay", args: []string{"-iface", "r", "-listen", ":4443", "-xdp", "ens5"}, wantErr: "flag provided but not defined: -xdp"},
		{name: "relay has no PSP socket", cmd: "relay", args: []string{"-iface", "r", "-listen", ":4443", "-psp-listen", ":1000"}, wantErr: "flag provided but not defined: -psp-listen"},
		{
			name: "relay with no lanes", cmd: "relay", args: []string{"-iface", "r", "-listen", ":4443", "-lanes", "0"},
			want: func(o options) bool { return o.Lanes == 0 },
		},
		{name: "relay with too many lanes", cmd: "relay", args: []string{"-iface", "r", "-listen", ":4443", "-lanes", "4"}, wantErr: "-lanes must be 0 to 3"},
		{name: "relay with no listen", cmd: "relay", args: []string{"-iface", "r"}, wantErr: "-listen is required"},
		{name: "relay with no iface", cmd: "relay", args: []string{"-listen", ":4443"}, wantErr: "set one of -iface and -imds"},
		{name: "relay with iface and imds", cmd: "relay", args: []string{"-iface", "r", "-imds", "-listen", ":4443"}, wantErr: "set one of -iface and -imds"},
		{
			name: "relay on IMDS with zero-copy", cmd: "relay", args: []string{"-imds", "-zero-copy", "-listen", ":4443"},
			want: func(o options) bool { return o.IMDS && o.Iface == "" && o.ZeroCopy },
		},
		{
			name: "relay with copy mode", cmd: "relay", args: []string{"-iface", "r", "-zero-copy=false", "-listen", ":4443"},
			want: func(o options) bool { return !o.ZeroCopy },
		},
		{
			name: "relay copy mode by default", cmd: "relay", args: []string{"-iface", "r", "-listen", ":4443"},
			want: func(o options) bool { return !o.ZeroCopy },
		},
		{name: "relay with a bad zero-copy", cmd: "relay", args: []string{"-iface", "r", "-zero-copy=auto", "-listen", ":4443"}, wantErr: `invalid boolean value "auto" for -zero-copy`},
		{
			name: "relay needs no work dir", cmd: "relay", args: []string{"-iface", "r", "-listen", ":4443", "-work-dir", ""},
			want: func(o options) bool { return o.WorkDir == "" },
		},
		{name: "server with no work dir", cmd: "server", args: []string{"-listen", ":4433", "-relay", "r:1", "-work-dir", ""}, wantErr: "set -work-dir or WORK_DIR"},
		{name: "no start timeout", cmd: "server", args: []string{"-listen", ":4433", "-relay", "r:1", "-start-timeout", "0s"}, wantErr: "-start-timeout must be positive"},
		{name: "relay has no driver", cmd: "relay", args: []string{"-iface", "r", "-listen", ":4443", "-driver", "tun"}, wantErr: "flag provided but not defined: -driver"},
		{name: "relay has no mesh", cmd: "relay", args: []string{"-iface", "r", "-listen", ":4443", "-mesh", "b"}, wantErr: "flag provided but not defined: -mesh"},
		{name: "server has no iface", cmd: "server", args: []string{"-listen", ":4433", "-relay", "r:1", "-iface", "r"}, wantErr: "flag provided but not defined: -iface"},
		{name: "client has no relay of the server", cmd: "client", args: []string{"-server", "s:1", "-relay", "r:1", "-server-relay", "r2:1"}, wantErr: "flag provided but not defined: -server-relay"},
		{
			name: "server defaults", cmd: "server", args: []string{"-listen", ":4433", "-relay", "10.0.0.1:4443"},
			want: func(o options) bool {
				return o.Driver == "netstack" && o.Transport == "psp" && o.Via == "relay" && o.Relay == "10.0.0.1:4443"
			},
		},
		{name: "server with no relay", cmd: "server", args: []string{"-listen", ":4433"}, wantErr: "-relay is required with -via relay"},
		{
			name: "server direct needs no relay", cmd: "server", args: []string{"-listen", ":4433", "-via", "direct", "-work-dir", ""},
			want: func(o options) bool { return o.Via == "direct" && o.Relay == "" },
		},
		{name: "unknown driver", cmd: "server", args: []string{"-listen", ":4433", "-relay", "r:1", "-driver", "xdp"}, wantErr: `unknown -driver "xdp"`},
		{name: "unknown transport", cmd: "server", args: []string{"-listen", ":4433", "-relay", "r:1", "-transport", "tcp"}, wantErr: `unknown -transport "tcp"`},
		{name: "unknown via", cmd: "server", args: []string{"-listen", ":4433", "-relay", "r:1", "-via", "peer"}, wantErr: `unknown -via "peer"`},
		{name: "direct with quic", cmd: "server", args: []string{"-listen", ":4433", "-via", "direct", "-transport", "quic"}, wantErr: "-via direct sends only PSP"},
		{name: "server has no streams", cmd: "server", args: []string{"-listen", ":4433", "-relay", "r:1", "-streams", "2"}, wantErr: "flag provided but not defined: -streams"},
		{
			name: "client defaults", cmd: "client", args: []string{"-server", "10.0.0.2:4433", "-relay", "10.0.0.2:4443"},
			want: func(o options) bool {
				return o.Streams == 4 && o.Omit == 5*time.Second && o.Duration == 30*time.Second && o.CC == "" &&
					o.Idle == time.Second && o.ProbeInterval == 10*time.Millisecond && o.StartTimeout == 30*time.Second && !o.StopRelay
			},
		},
		{
			name: "client flags", cmd: "client",
			args: []string{"-server", "s:1", "-relay", "r:1", "-cc", "bbr", "-streams", "8", "-omit", "1s", "-duration", "2s", "-driver", "tun", "-transport", "quic", "-mtu", "1360", "-start-timeout", "5m", "-stop-relay"},
			want: func(o options) bool {
				return o.CC == "bbr" && o.Streams == 8 && o.Omit == time.Second && o.Duration == 2*time.Second &&
					o.Driver == "tun" && o.Transport == "quic" && o.MTU == 1360 && o.StartTimeout == 5*time.Minute && o.StopRelay
			},
		},
		{name: "client with no server", cmd: "client", args: []string{"-relay", "r:1"}, wantErr: "-server is required"},
		{name: "client has no listen", cmd: "client", args: []string{"-listen", ":1"}, wantErr: "flag provided but not defined: -listen"},
		{name: "no streams", cmd: "client", args: []string{"-server", "s:1", "-relay", "r:1", "-streams", "0"}, wantErr: "-streams and -duration must be positive"},
		{name: "no duration", cmd: "client", args: []string{"-server", "s:1", "-relay", "r:1", "-duration", "0s"}, wantErr: "-streams and -duration must be positive"},
		{name: "negative mtu", cmd: "client", args: []string{"-server", "s:1", "-relay", "r:1", "-mtu", "-1"}, wantErr: "-mtu must not be negative"},
		{name: "extra argument", cmd: "client", args: []string{"-server", "s:1", "-relay", "r:1", "extra"}, wantErr: "unexpected arguments"},
		{
			name: "profiles", cmd: "relay", args: []string{"-iface", "r", "-listen", ":4443", "-cpuprofile", "c.pprof", "-blockprofile", "b.pprof", "-mutexprofile", "m.pprof", "-trace", "r.trace", "-kernel", "k"},
			want: func(o options) bool {
				return o.Profiles == bench.Profiles{CPU: "c.pprof", Block: "b.pprof", Mutex: "m.pprof", Trace: "r.trace", TraceTime: 3 * time.Second, Kernel: "k"}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := parseFlags(tc.cmd, tc.args, io.Discard)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.True(t, tc.want(o), "options: %+v", o)
		})
	}
}

func TestNewResult(t *testing.T) {
	sec := int64(time.Second)
	cases := []struct {
		name                  string
		client, server, relay [2]mark
		want                  result
	}{
		{
			name: "all sides",
			client: [2]mark{
				{Nanos: 0, HostCPU: 10, Segments: 100, Drops: 1, LinkDrops: 4, Lanes: []uint64{60, 40}, TCP: map[string]uint64{"dsack": 1, "sack_recovery": 2}},
				{
					Nanos: 2 * sec, CPU: 1, HostCPU: 16, Segments: 1100, Retrans: 10, Drops: 3, LinkDrops: 9, Lanes: []uint64{560, 440, 100},
					TCP: map[string]uint64{"dsack": 1, "sack_recovery": 5},
				},
			},
			server: [2]mark{
				{Nanos: sec, HostCPU: 20, Retrans: 1, RcvbufErrors: 5, SockDrops: 1, RxLanes: []uint64{100}},
				{Nanos: 3 * sec, CPU: 2, HostCPU: 28, Retrans: 3, Bytes: 250e6, RxPackets: 2000, Drops: 6, RcvbufErrors: 17, SockDrops: 4, LinkDrops: 2, Lanes: []uint64{30}, RxLanes: []uint64{1100, 0, 1000}},
			},
			relay: [2]mark{
				{
					Nanos: 0, HostCPU: 5, KickCPU: 0.25, Drops: 1,
					DropReasons: map[string]uint64{"malformed": 1},
					CPUs:        []bench.CPUTicks{{User: 10, Idle: 90}, {Idle: 100}},
				},
				{
					Nanos: 2 * sec, CPU: 0.5, HostCPU: 7, KickCPU: 0.5, Drops: 5,
					DropReasons: map[string]uint64{"malformed": 1, "tx_full": 3, "unknown_spi": 1},
					CPUs:        []bench.CPUTicks{{User: 30, System: 40, Idle: 230}, {IRQ: 150, Idle: 150}},
				},
			},
			want: result{
				Seconds: 2, BitsPerSecond: 1e9, PacketsPerSecond: 1000, Retransmits: 10, RetransPercent: 1,
				ServerRetransmits: 2, ClientCores: 0.5, ServerCores: 1, RelayCores: 0.25, RelayKickCores: 0.125,
				ClientCoresPerGbps: 0.5, ServerCoresPerGbps: 1, RelayCoresPerGbps: 0.25,
				ClientHostCores: 3, ServerHostCores: 4, RelayHostCores: 1,
				ClientTxDrops: 2, ServerRxDrops: 6, RelayDrops: 4, ServerRcvbufErrors: 12, ServerSockDrops: 3,
				ClientLinkDrops: 5, ServerLinkDrops: 2,
				RelayDropReasons: map[string]uint64{"tx_full": 3, "unknown_spi": 1},
				RelayHostCPU:     &cpuKinds{User: 0.1, System: 0.2, IRQ: 0.75}, RelayTopCPUs: []cpuUse{{CPU: 1, IRQ: 75}, {CPU: 0, User: 10, System: 20}},
				ClientLanePackets: []uint64{500, 400, 100}, ServerLanePackets: []uint64{30},
				ServerRxLanePackets: []uint64{1000, 0, 1000},
				ClientTCP:           map[string]uint64{"sack_recovery": 3},
			},
		},
		{
			name:   "no relay and no kernel counters",
			client: [2]mark{{HostCPU: -1, LinkDrops: -1}, {Nanos: sec, HostCPU: -1, Segments: 0, LinkDrops: -1}},
			server: [2]mark{
				{HostCPU: -1, RcvbufErrors: -1, SockDrops: -1, LinkDrops: 3},
				{Nanos: sec, HostCPU: -1, Bytes: 125e6, RcvbufErrors: -1, SockDrops: -1, LinkDrops: -1},
			},
			want: result{
				Seconds: 1, BitsPerSecond: 1e9, ServerRcvbufErrors: -1, ServerSockDrops: -1,
				ClientHostCores: -1, ServerHostCores: -1,
				ClientLinkDrops: -1, ServerLinkDrops: -1,
			},
		},
		{
			// The netstack link drops are an estimate, which can go down a little.
			name:   "link drops go down",
			client: [2]mark{{LinkDrops: 10}, {Nanos: sec, LinkDrops: 7}},
			server: [2]mark{{}, {Nanos: sec, Bytes: 125e6}},
			want:   result{Seconds: 1, BitsPerSecond: 1e9},
		},
		{
			name:   "empty window",
			server: [2]mark{{Nanos: sec}, {Nanos: sec}},
			want:   result{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, newResult(tc.client, tc.server, tc.relay))
		})
	}
}

func TestBusiestCPUs(t *testing.T) {
	m0 := mark{CPUs: []bench.CPUTicks{{}, {}, {}}}
	cases := []struct {
		name   string
		m0, m1 mark
		n      int
		want   []cpuUse
	}{
		{
			name: "busiest first",
			m0:   m0,
			m1: mark{CPUs: []bench.CPUTicks{
				{User: 10, Idle: 90},
				{User: 5, System: 15, IRQ: 80, NetRX: 7, NetTX: 2},
				{System: 30, IRQ: 10, Idle: 60},
			}},
			n:    2,
			want: []cpuUse{{CPU: 1, User: 5, System: 15, IRQ: 80, NetRX: 7, NetTX: 2}, {CPU: 2, System: 30, IRQ: 10}},
		},
		{
			name: "idle CPU in the window",
			m0:   m0,
			m1:   mark{CPUs: []bench.CPUTicks{{User: 1, Idle: 2}, {}, {}}},
			n:    4,
			want: []cpuUse{{CPU: 0, User: 33.3}},
		},
		{name: "no ticks", m1: mark{CPUs: []bench.CPUTicks{{User: 1}}}, n: 4},
		{name: "CPU count changed", m0: m0, m1: mark{CPUs: []bench.CPUTicks{{User: 1}}}, n: 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, busiestCPUs(tc.m0, tc.m1, tc.n))
		})
	}
}

func TestHostKinds(t *testing.T) {
	m0 := mark{CPUs: []bench.CPUTicks{{User: 100, System: 50, IRQ: 10, Idle: 1000}, {Idle: 500}}}
	cases := []struct {
		name   string
		m0, m1 mark
		want   *cpuKinds
	}{
		{
			name: "two CPUs",
			m0:   m0,
			m1:   mark{CPUs: []bench.CPUTicks{{User: 150, System: 150, IRQ: 60, Idle: 1800}, {IRQ: 1000, Idle: 500}}},
			want: &cpuKinds{User: 0.05, System: 0.1, IRQ: 1.05},
		},
		{name: "no ticks in the window", m0: m0, m1: m0},
		{name: "no CPUs", m0: mark{}, m1: mark{}},
		{name: "CPU count changed", m0: m0, m1: mark{CPUs: []bench.CPUTicks{{User: 1}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, hostKinds(tc.m0, tc.m1))
		})
	}
}

func TestCounterDelta(t *testing.T) {
	cases := []struct {
		name   string
		v0, v1 map[string]uint64
		want   map[string]uint64
	}{
		{name: "no counters"},
		{name: "no increase", v0: map[string]uint64{"no_row": 4}, v1: map[string]uint64{"no_row": 4}},
		{name: "new result", v1: map[string]uint64{"no_route": 3}, want: map[string]uint64{"no_route": 3}},
		{
			name: "one increase", v0: map[string]uint64{"no_row": 4, "expired": 2}, v1: map[string]uint64{"no_row": 9, "expired": 2},
			want: map[string]uint64{"no_row": 5},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, counterDelta(tc.v0, tc.v1))
		})
	}
}

// TestRelayDrops checks the drop counters that a relay mark reads from the
// data plane of the relay.
func TestRelayDrops(t *testing.T) {
	// A PSP packet with an SPI that has no SA.
	psp := make([]byte, 64)
	psp[0], psp[1], psp[2], psp[3] = 4, 2, 2, 0x03
	binary.BigEndian.PutUint32(psp[4:8], 7)
	cases := []struct {
		name    string
		packets [][]byte
		drops   uint64
		reasons map[string]uint64
	}{
		{name: "no drops"},
		{name: "one reason", packets: [][]byte{{1, 2, 3}, {9, 9}}, drops: 2, reasons: map[string]uint64{"malformed": 2}},
		{
			name: "two reasons", packets: [][]byte{psp, {1, 2, 3}, psp, psp}, drops: 4,
			reasons: map[string]uint64{"malformed": 1, "unknown_spi": 3},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := vpctest.NewCA()
			require.NoError(t, err)
			plane, err := vpctest.NewLoopback()
			require.NoError(t, err)
			t.Cleanup(func() { _ = plane.Close() })
			r, err := relay.NewRouter(relay.Config{
				Relay: &dp.RelayRef{Id: relayID}, Trust: vpctest.NewTrust(ca), Addresses: &addresses{}, Target: plane.Target,
			})
			require.NoError(t, err)
			var rx []relaydp.RxPacket
			for _, p := range tc.packets {
				rx = append(rx, relaydp.RxPacket{From: netip.MustParseAddrPort("127.0.0.1:4000"), Payload: p})
			}
			plane.Target.Receive(rx, &relaydp.TxBatch{})
			drops, reasons := relayDrops(r)
			assert.Equal(t, tc.drops, drops)
			assert.Equal(t, tc.reasons, reasons)
		})
	}
}

func TestQueueSamplerTake(t *testing.T) {
	cases := []struct {
		name string
		q    *queueSampler
		want *sockQueue
	}{
		{name: "nil sampler"},
		{name: "no samples", q: &queueSampler{}},
		{
			name: "mean and most",
			q:    &queueSampler{rx: 30, tx: 3000, n: 3, rxMax: 20, txMax: 1500},
			want: &sockQueue{RxMean: 10, RxMax: 20, TxMean: 1000, TxMax: 1500},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.q.take())
			if tc.q != nil {
				assert.Nil(t, tc.q.take(), "take starts again")
			}
		})
	}
}

func TestNewPeriod(t *testing.T) {
	sec := int64(time.Second)
	cases := []struct {
		name                  string
		client, server, relay [2]mark
		want                  period
	}{
		{
			name:   "all sides",
			client: [2]mark{{Segments: 100, LinkDrops: 1}, {Nanos: sec, Segments: 300, Retrans: 4, Drops: 2, LinkDrops: 6}},
			server: [2]mark{{RcvbufErrors: 1}, {Nanos: sec, Retrans: 1, Bytes: 50e6, Drops: 3, RcvbufErrors: 4, SockDrops: 1, LinkDrops: 1}},
			relay: [2]mark{
				{Drops: 1, DropReasons: map[string]uint64{"closed": 1}},
				{Nanos: sec, Drops: 2, DropReasons: map[string]uint64{"closed": 1, "send_queue": 1}},
			},
			want: period{
				Seconds: 1, BitsPerSecond: 400e6, Retransmits: 4, RetransPercent: 2, ServerRetransmits: 1,
				ClientTxDrops: 2, ServerRxDrops: 3, RelayDrops: 1, ServerRcvbufErrors: 3, ServerSockDrops: 1,
				ClientLinkDrops: 5, ServerLinkDrops: 1, RelayDropReasons: map[string]uint64{"send_queue": 1},
			},
		},
		{name: "no omit", server: [2]mark{{Nanos: sec}, {Nanos: sec}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, newPeriod(tc.client, tc.server, tc.relay))
		})
	}
}

func TestResultJSON(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, json.NewEncoder(&buf).Encode(result{Seconds: 30, BitsPerSecond: 2e9, PacketsPerSecond: 1e5, Retransmits: 7}))

	// perfrig reads these fields of the last line (cmd/perfrig Throughput).
	var tp struct {
		Seconds          float64 `json:"seconds"`
		BitsPerSecond    float64 `json:"bits_per_second"`
		PacketsPerSecond float64 `json:"packets_per_second"`
		Retransmits      int64   `json:"retransmits"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &tp))
	assert.Equal(t, 30.0, tp.Seconds)
	assert.Equal(t, 2e9, tp.BitsPerSecond)
	assert.Equal(t, 1e5, tp.PacketsPerSecond)
	assert.Equal(t, int64(7), tp.Retransmits)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &fields))
	for _, f := range []string{
		"retrans_percent", "idle_rtt_ms", "load_rtt_ms",
		"client_cores", "server_cores", "relay_cores",
		"client_cores_per_gbps", "server_cores_per_gbps", "relay_cores_per_gbps",
		"client_host_cores", "server_host_cores", "relay_host_cores",
		"driver", "transport", "via", "cc", "streams", "device_mtu",
		"server_retransmits", "client_tx_drops", "server_rx_drops", "relay_drops", "server_rcvbuf_errors",
		"server_sock_drops", "client_link_drops", "server_link_drops",
		"omit", "flow_start_unix_ms", "window_start_unix_ms", "window_end_unix_ms",
	} {
		assert.Contains(t, fields, f)
	}
	for _, f := range []string{"probes", "lost", "p50", "p90", "p99", "max"} {
		assert.Contains(t, fields["load_rtt_ms"], f)
	}
	for _, f := range []string{
		"seconds", "bits_per_second", "retransmits", "retrans_percent", "server_retransmits", "rtt_ms",
		"client_tx_drops", "server_rx_drops", "relay_drops", "server_rcvbuf_errors",
		"server_sock_drops", "client_link_drops", "server_link_drops",
	} {
		assert.Contains(t, fields["omit"], f)
	}
}

func TestSnmpValue(t *testing.T) {
	const snmp = "Tcp: RtoAlgorithm OutSegs RetransSegs\nTcp: 1 500 7\nUdp: InDatagrams RcvbufErrors\nUdp: 10 x\n"
	cases := []struct {
		group, name string
		want        int64
	}{
		{"Tcp:", "OutSegs", 500},
		{"Tcp:", "RetransSegs", 7},
		{"Tcp:", "Missing", -1},
		{"Udp:", "RcvbufErrors", -1}, // Not a number.
		{"Ip:", "Forwarding", -1},
	}
	for _, tc := range cases {
		t.Run(tc.group+tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, snmpValue(snmp, tc.group, tc.name))
		})
	}
}

func TestCAEncoding(t *testing.T) {
	ca, err := vpctest.NewCA()
	require.NoError(t, err)
	cases := []struct {
		name    string
		in      []byte
		wantErr string
	}{
		{name: "from the relay", in: encodeCA(ca)},
		{name: "not PEM", in: []byte("not PEM"), wantErr: "no CA cert and key"},
		{name: "cert only", in: encodeCA(ca)[:bytes.Index(encodeCA(ca), []byte("-----BEGIN EC"))], wantErr: "no CA cert and key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeCA(tc.in)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.True(t, got.Cert.Equal(ca.Cert))
			assert.True(t, got.Key.Equal(ca.Key))
		})
	}
}

// TestLoopback runs the server and the client with -via direct on loopback, for
// one second. TestRelay runs the relay cases, which need a relay device.
func TestLoopback(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the agents for a few seconds")
	}
	runPair(t, options{WorkDir: t.TempDir(), Driver: "netstack", Transport: "psp", Via: "direct", StartTimeout: 30 * time.Second})
}

// runPair runs the server and the client of o in this process and checks the result. With -via
// relay, o.Relay is the control address of a relay, which the client stops at the end.
func runPair(t *testing.T, o options) {
	t.Helper()
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	so := o
	so.Listen = "127.0.0.1:0"
	addr := make(chan netip.AddrPort, 1)
	serverErr := make(chan error, 1)
	wg.Go(func() { serverErr <- runServer(ctx, so, func(a netip.AddrPort) { addr <- a }) })
	co := o
	select {
	case a := <-addr:
		co.Server = a.String()
	case err := <-serverErr:
		t.Fatalf("server stopped: %v", err)
	}
	co.Streams, co.Omit, co.Duration = 2, 200*time.Millisecond, time.Second
	co.Idle, co.ProbeInterval = 200*time.Millisecond, 10*time.Millisecond
	// The client stops the relay, as "perfrig node" does.
	co.StopRelay = o.Via == "relay"

	var out bytes.Buffer
	require.NoError(t, runClient(ctx, co, &out))
	require.NoError(t, <-serverErr, "the server returns when the client disconnects")

	var res result
	require.NoError(t, json.Unmarshal(out.Bytes(), &res))
	t.Logf("result: %s", out.Bytes())
	// With -via relay the agents send only to the relay, so data at the server went through it.
	assert.Greater(t, res.BitsPerSecond, 0.0)
	assert.Greater(t, res.PacketsPerSecond, 0.0)
	// A loaded host can delay the marks and the idle probes, so there is no upper limit here.
	assert.GreaterOrEqual(t, res.Seconds, 0.8)
	assert.Greater(t, res.LoadRTT.Probes, 0)
	assert.Less(t, res.LoadRTT.Lost, res.LoadRTT.Probes)
	assert.GreaterOrEqual(t, res.Omit.Seconds, 0.15)
	assert.Greater(t, res.Omit.RTT.Probes, 0)
	assert.LessOrEqual(t, res.FlowStartUnixMS, res.WindowStartUnixMS)
	assert.GreaterOrEqual(t, res.WindowEndUnixMS-res.WindowStartUnixMS, int64(800))
	assert.GreaterOrEqual(t, res.RetransPercent, 0.0)
	assert.Equal(t, o.Via, res.Via)
	assert.Equal(t, o.Transport, res.Transport)
	assert.Equal(t, "netstack", res.Driver)
	assert.NotEmpty(t, res.CC)
	assert.Positive(t, res.DeviceMTU)
	assert.Positive(t, res.ServerCores)
	// The netstack can read its link counters.
	assert.GreaterOrEqual(t, res.ClientLinkDrops, int64(0))
	assert.GreaterOrEqual(t, res.ServerLinkDrops, int64(0))
	if o.Via == "relay" {
		assert.Positive(t, res.RelayCores, "the relay answered the marks")
	} else {
		assert.Zero(t, res.RelayCores)
	}
}
