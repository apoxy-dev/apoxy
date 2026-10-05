package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLinkStats(t *testing.T) {
	const links = `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK"],"stats64":{"rx":{"bytes":0,"packets":0,"errors":0,"dropped":0},"tx":{"bytes":0,"packets":0,"errors":0,"dropped":0}}},` +
		`{"ifindex":2,"link_index":2,"ifname":"perf-s","mtu":1500,"qdisc":"noqueue","stats64":{` +
		`"rx":{"bytes":370,"packets":5,"errors":1,"dropped":2,"over_errors":3,"multicast":9,"fifo_errors":4,"missed_errors":5},` +
		`"tx":{"bytes":336,"packets":4,"errors":0,"dropped":7,"carrier_errors":6,"collisions":9,"carrier_changes":2}}}]`
	cases := []struct {
		name    string
		out     string
		want    map[string]int64
		wantErr bool
	}{
		{
			name: "two links", out: links,
			want: map[string]int64{
				"lo/rx_errors": 0, "lo/rx_dropped": 0, "lo/tx_errors": 0, "lo/tx_dropped": 0,
				"perf-s/rx_errors": 1, "perf-s/rx_dropped": 2, "perf-s/rx_over_errors": 3, "perf-s/rx_fifo_errors": 4,
				"perf-s/rx_missed_errors": 5, "perf-s/tx_errors": 0, "perf-s/tx_dropped": 7, "perf-s/tx_carrier_errors": 6,
			},
		},
		{name: "no stats", out: `[{"ifname":"lo"}]`, want: map[string]int64{}},
		{name: "not a number", out: `[{"ifname":"lo","stats64":{"rx":{"dropped":"x","errors":3}}}]`, want: map[string]int64{"lo/rx_errors": 3}},
		{name: "not JSON", out: "Cannot open network namespace", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLinkStats(tc.out)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseQdiscStats(t *testing.T) {
	const qdiscs = `[{"kind":"noqueue","handle":"0:","dev":"lo","root":true,"options":{},"bytes":0,"packets":0,"drops":0,"overlimits":0,"requeues":0},` +
		`{"kind":"netem","handle":"8a9c:","dev":"perf-c","root":true,"options":{"limit":1000,"delay":{"delay":0.001}},"bytes":336,"packets":4,"drops":3,"overlimits":1,"requeues":2,"backlog":0,"qlen":0},` +
		`{"kind":"mq","handle":"1:","dev":"perf-s","root":true,"drops":5,"overlimits":0,"requeues":8},` +
		`{"kind":"fq","handle":"2:","dev":"perf-s","parent":"1:1","drops":2,"overlimits":0,"requeues":3},` +
		`{"kind":"fq","handle":"3:","dev":"perf-s","parent":"1:2","drops":3,"overlimits":0,"requeues":5}]`
	cases := []struct {
		name    string
		out     string
		want    map[string]int64
		wantErr bool
	}{
		{
			name: "sum of each kind", out: qdiscs,
			want: map[string]int64{
				"lo/qdisc_noqueue_drops": 0, "lo/qdisc_noqueue_overlimits": 0, "lo/qdisc_noqueue_requeues": 0,
				"perf-c/qdisc_netem_drops": 3, "perf-c/qdisc_netem_overlimits": 1, "perf-c/qdisc_netem_requeues": 2,
				"perf-s/qdisc_mq_drops": 5, "perf-s/qdisc_mq_overlimits": 0, "perf-s/qdisc_mq_requeues": 8,
				"perf-s/qdisc_fq_drops": 5, "perf-s/qdisc_fq_overlimits": 0, "perf-s/qdisc_fq_requeues": 8,
			},
		},
		{name: "no qdisc", out: "[]", want: map[string]int64{}},
		{name: "not JSON", out: "Error: Cannot find device", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseQdiscStats(tc.out)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseVethStats(t *testing.T) {
	const stats = "NIC statistics:\n     peer_ifindex: 2\n" +
		"     rx_queue_0_xdp_packets: 0\n     rx_queue_0_xdp_bytes: 0\n     rx_queue_0_drops: 1\n     rx_queue_0_xdp_redirect: 9\n" +
		"     rx_queue_0_xdp_drops: 2\n     rx_queue_0_xdp_tx: 9\n     rx_queue_0_xdp_tx_errors: 3\n" +
		"     rx_queue_11_xdp_packets: 40\n     rx_queue_11_xdp_bytes: 280\n     rx_queue_11_drops: 10\n     rx_queue_11_xdp_drops: x\n" +
		"     tx_queue_0_xdp_xmit: 9\n     tx_queue_0_xdp_xmit_errors: 4\n     tx_queue_1_xdp_xmit_errors: 5\n" +
		"     rx_pp_alloc_fast: 7\n     rx_pp_recycle_ring_full: 7\n"
	cases := []struct {
		name string
		out  string
		want map[string]int64
	}{
		{
			name: "veth", out: stats,
			want: map[string]int64{
				"rx_queue_0_packets": 0, "rx_queue_11_packets": 40, "rx_queue_drops": 11, "rx_queue_xdp_drops": 2,
				"rx_queue_xdp_tx_errors": 3, "tx_queue_xdp_xmit_errors": 9,
			},
		},
		{name: "no stats", out: "no stats available\n", want: map[string]int64{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseVethStats(tc.out))
		})
	}
}

func TestParseSoftnet(t *testing.T) {
	cases := []struct {
		name string
		data string
		want map[string]int64
	}{
		{
			name: "two CPUs",
			data: "653ad92b 00001525 0000c6c4 00000000 00000000 00000000 00000000 00000000 00000000 007ea5de 00000002 00000000 00000000 00000000 00000000\n" +
				"5c8a88df 0000000a 00003d4f 00000000 00000000 00000000 00000000 00000000 00000000 007e581b 00000001 00000000 00000001 00000000 00000000\n",
			want: map[string]int64{"softnet/dropped": 0x1525 + 0xa, "softnet/time_squeeze": 0xc6c4 + 0x3d4f, "softnet/flow_limit": 3},
		},
		{name: "old kernel with 3 columns", data: "00000010 00000001 00000002\n", want: map[string]int64{"softnet/dropped": 1, "softnet/time_squeeze": 2}},
		{name: "not hex", data: "00000010 zz 00000002\n", want: map[string]int64{"softnet/time_squeeze": 2}},
		{name: "empty", data: "", want: map[string]int64{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseSoftnet(tc.data))
		})
	}
}

func TestIncreases(t *testing.T) {
	cases := []struct {
		name string
		a, b map[string]int64
		want map[string]int64
	}{
		{
			name: "only the counters that increased",
			a:    map[string]int64{"up": 5, "same": 7, "down": 9},
			b:    map[string]int64{"up": 8, "same": 7, "down": 2, "new": 4},
			want: map[string]int64{"up": 3},
		},
		{name: "no first read", a: nil, b: map[string]int64{"up": 8}, want: map[string]int64{}},
		{name: "no second read", a: map[string]int64{"up": 5}, b: nil, want: map[string]int64{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, increases(tc.a, tc.b))
		})
	}
}

func TestRigVeths(t *testing.T) {
	cases := []struct {
		name string
		cfg  config
		want []rigLink
	}{
		{name: "veth pair", cfg: config{NetnsPrefix: "p"}, want: []rigLink{{"p-client", clientDev}, {"p-server", serverDev}}},
		{
			name: "relay rig", cfg: config{NetnsPrefix: "p", RelayNetns: true},
			want: []rigLink{{"p-client", clientDev}, {"p-server", serverDev}, {"p-relay", relayDev},
				{"p-bridge", clientDev}, {"p-bridge", serverDev}, {"p-bridge", relayDev}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, newRig(tc.cfg).veths())
		})
	}
}

func TestRigDetail(t *testing.T) {
	cases := []struct {
		name string
		runs []Run
		want string
	}{
		{name: "no counters", runs: []Run{{}, {}}, want: ""},
		{name: "only packets", runs: []Run{{Rig: map[string]int64{"server/perf-s/rx_queue_0_packets": 9}}}, want: ""},
		{
			name: "each run",
			runs: []Run{
				{Rig: map[string]int64{"softnet/time_squeeze": 4, "bridge/perf-s/tx_dropped": 120, "server/perf-s/rx_queue_0_packets": 9}},
				{Rig: map[string]int64{"softnet/time_squeeze": 6}},
			},
			want: "rig counters by run: bridge/perf-s/tx_dropped 120 0, softnet/time_squeeze 4 6",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, rigDetail(tc.runs))
		})
	}
}
