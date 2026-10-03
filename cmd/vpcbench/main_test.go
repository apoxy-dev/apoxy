// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/cmd/internal/bench"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
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
			name: "relay", cmd: "relay", args: []string{"-listen", ":4443"},
			want: func(o options) bool { return o.Listen == ":4443" && o.WorkDir == "/work" && o.MTU == 0 },
		},
		{name: "relay with no listen", cmd: "relay", wantErr: "-listen is required"},
		{name: "relay with no work dir", cmd: "relay", args: []string{"-listen", ":4443", "-work-dir", ""}, wantErr: "set -work-dir or WORK_DIR"},
		{name: "relay has no driver", cmd: "relay", args: []string{"-listen", ":4443", "-driver", "tun"}, wantErr: "flag provided but not defined: -driver"},
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
					o.Idle == time.Second && o.ProbeInterval == 10*time.Millisecond
			},
		},
		{
			name: "client flags", cmd: "client",
			args: []string{"-server", "s:1", "-relay", "r:1", "-cc", "bbr", "-streams", "8", "-omit", "1s", "-duration", "2s", "-driver", "tun", "-transport", "quic", "-mtu", "1400"},
			want: func(o options) bool {
				return o.CC == "bbr" && o.Streams == 8 && o.Omit == time.Second && o.Duration == 2*time.Second &&
					o.Driver == "tun" && o.Transport == "quic" && o.MTU == 1400
			},
		},
		{name: "client with no server", cmd: "client", args: []string{"-relay", "r:1"}, wantErr: "-server is required"},
		{name: "client has no listen", cmd: "client", args: []string{"-listen", ":1"}, wantErr: "flag provided but not defined: -listen"},
		{name: "no streams", cmd: "client", args: []string{"-server", "s:1", "-relay", "r:1", "-streams", "0"}, wantErr: "-streams and -duration must be positive"},
		{name: "no duration", cmd: "client", args: []string{"-server", "s:1", "-relay", "r:1", "-duration", "0s"}, wantErr: "-streams and -duration must be positive"},
		{name: "negative mtu", cmd: "client", args: []string{"-server", "s:1", "-relay", "r:1", "-mtu", "-1"}, wantErr: "-mtu must not be negative"},
		{name: "extra argument", cmd: "client", args: []string{"-server", "s:1", "-relay", "r:1", "extra"}, wantErr: "unexpected arguments"},
		{
			name: "profiles", cmd: "relay", args: []string{"-listen", ":4443", "-cpuprofile", "c.pprof", "-blockprofile", "b.pprof", "-mutexprofile", "m.pprof"},
			want: func(o options) bool {
				return o.Profiles == bench.Profiles{CPU: "c.pprof", Block: "b.pprof", Mutex: "m.pprof"}
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
				{Nanos: 0, Segments: 100, Drops: 1, LinkDrops: 4},
				{Nanos: 2 * sec, CPU: 1, Segments: 1100, Retrans: 10, Drops: 3, LinkDrops: 9},
			},
			server: [2]mark{
				{Nanos: sec, Retrans: 1, RcvbufErrors: 5, SockDrops: 1},
				{Nanos: 3 * sec, CPU: 2, Retrans: 3, Bytes: 250e6, RxPackets: 2000, Drops: 6, RcvbufErrors: 17, SockDrops: 4, LinkDrops: 2},
			},
			relay: [2]mark{{Nanos: 0, Drops: 1, SockDrops: 2}, {Nanos: 2 * sec, CPU: 0.5, Drops: 5, SockDrops: 9}},
			want: result{
				Seconds: 2, BitsPerSecond: 1e9, PacketsPerSecond: 1000, Retransmits: 10, RetransPercent: 1,
				ServerRetransmits: 2, ClientCores: 0.5, ServerCores: 1, RelayCores: 0.25,
				ClientCoresPerGbps: 0.5, ServerCoresPerGbps: 1, RelayCoresPerGbps: 0.25,
				ClientTxDrops: 2, ServerRxDrops: 6, RelayDrops: 4, RelayRcvbufDrops: 7, ServerRcvbufErrors: 12, ServerSockDrops: 3,
				ClientLinkDrops: 5, ServerLinkDrops: 2,
			},
		},
		{
			name:   "no relay and no kernel counters",
			client: [2]mark{{LinkDrops: -1}, {Nanos: sec, Segments: 0, LinkDrops: -1}},
			server: [2]mark{
				{RcvbufErrors: -1, SockDrops: -1, LinkDrops: 3},
				{Nanos: sec, Bytes: 125e6, RcvbufErrors: -1, SockDrops: -1, LinkDrops: -1},
			},
			want: result{
				Seconds: 1, BitsPerSecond: 1e9, ServerRcvbufErrors: -1, ServerSockDrops: -1,
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
			relay:  [2]mark{{Drops: 1}, {Nanos: sec, Drops: 2, SockDrops: 2}},
			want: period{
				Seconds: 1, BitsPerSecond: 400e6, Retransmits: 4, RetransPercent: 2, ServerRetransmits: 1,
				ClientTxDrops: 2, ServerRxDrops: 3, RelayDrops: 1, RelayRcvbufDrops: 2, ServerRcvbufErrors: 3, ServerSockDrops: 1,
				ClientLinkDrops: 5, ServerLinkDrops: 1,
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
		"driver", "transport", "via", "cc", "streams", "device_mtu",
		"server_retransmits", "client_tx_drops", "server_rx_drops", "relay_drops", "relay_rcvbuf_drops",
		"server_rcvbuf_errors", "server_sock_drops", "client_link_drops", "server_link_drops",
		"omit", "flow_start_unix_ms", "window_start_unix_ms", "window_end_unix_ms",
	} {
		assert.Contains(t, fields, f)
	}
	for _, f := range []string{"probes", "lost", "p50", "p90", "p99", "max"} {
		assert.Contains(t, fields["load_rtt_ms"], f)
	}
	for _, f := range []string{
		"seconds", "bits_per_second", "retransmits", "retrans_percent", "server_retransmits", "rtt_ms",
		"client_tx_drops", "server_rx_drops", "relay_drops", "relay_rcvbuf_drops",
		"server_rcvbuf_errors", "server_sock_drops", "client_link_drops", "server_link_drops",
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

func TestCAFile(t *testing.T) {
	ca, err := vpctest.NewCA()
	require.NoError(t, err)
	cases := []struct {
		name    string
		write   func(dir string) error
		wantErr string
	}{
		{name: "written by the relay", write: func(dir string) error { return writeCA(dir, ca) }},
		{name: "no file", write: func(string) error { return nil }, wantErr: "no such file"},
		{
			name:    "no key",
			write:   func(dir string) error { return os.WriteFile(filepath.Join(dir, caFile), []byte("not PEM"), 0o600) },
			wantErr: "has no CA cert and key",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, tc.write(dir))
			got, err := loadCA(dir)
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

// TestLoopback runs the relay, the server and the client in this process on
// loopback, with the netstack driver, for one second.
func TestLoopback(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the agents for a few seconds")
	}
	cases := []struct{ via, transport string }{
		{"relay", "psp"},
		{"relay", "quic"},
		{"direct", "psp"},
	}
	for _, tc := range cases {
		t.Run(tc.via+" "+tc.transport, func(t *testing.T) {
			var wg sync.WaitGroup
			defer wg.Wait()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			o := options{WorkDir: t.TempDir(), Driver: "netstack", Transport: tc.transport, Via: tc.via}
			if tc.via == "relay" {
				ro := o
				ro.Listen = "127.0.0.1:0"
				addr := make(chan netip.AddrPort, 1)
				relayErr := make(chan error, 1)
				wg.Go(func() { relayErr <- runRelay(ctx, ro, func(a netip.AddrPort) { addr <- a }) })
				select {
				case a := <-addr:
					o.Relay = a.String()
				case err := <-relayErr:
					t.Fatalf("relay stopped: %v", err)
				}
				t.Cleanup(func() { assert.NoError(t, <-relayErr) })
			}

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
			assert.Equal(t, tc.via, res.Via)
			assert.Equal(t, tc.transport, res.Transport)
			assert.Equal(t, "netstack", res.Driver)
			assert.NotEmpty(t, res.CC)
			assert.Positive(t, res.DeviceMTU)
			assert.Positive(t, res.ServerCores)
			// The netstack can read its link counters.
			assert.GreaterOrEqual(t, res.ClientLinkDrops, int64(0))
			assert.GreaterOrEqual(t, res.ServerLinkDrops, int64(0))
			if tc.via == "relay" {
				assert.Positive(t, res.RelayCores, "the relay answered the marks")
			} else {
				assert.Zero(t, res.RelayCores)
			}
		})
	}
}
