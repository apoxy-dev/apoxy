package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDefaultRoute(t *testing.T) {
	const route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"ens5\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
		"ens5\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	dev, err := parseDefaultRoute(route)
	require.NoError(t, err)
	assert.Equal(t, "ens5", dev)
	_, err = parseDefaultRoute("Iface\tDestination\nlo\t0000007F\n")
	assert.ErrorContains(t, err, "no default route")
}

func TestParseEthtool(t *testing.T) {
	driver, version, fw := parseEthtoolInfo("driver: ena\nversion: 7.0.0-1012-aws\nfirmware-version: \nbus-info: 0000:00:05.0\n")
	assert.Equal(t, []string{"ena", "7.0.0-1012-aws", ""}, []string{driver, version, fw})

	const stats = "NIC statistics:\n     tx_timeout: 0\n     bw_out_allowance_exceeded: 0\n     bw_in_allowance_exceeded: 3\n" +
		"     pps_allowance_exceeded: x\n     queue_0_rx_cnt: 99\n     queue_0_rx_bytes: 9900\n     queue_12_rx_cnt: 1\n     queue_3_tx_cnt: 5\n     queue_3_tx_queue_stop: 2\n     queue_3_tx_dma_mapping_err: 1\n"
	got := parseEthtoolStats(stats, ethtoolCounters)
	assert.Equal(t, map[string]int64{"bw_out_allowance_exceeded": 0, "bw_in_allowance_exceeded": 3, "queue_0_rx_cnt": 99, "queue_12_rx_cnt": 1, "queue_3_tx_cnt": 5, "queue_3_tx_queue_stop": 2}, got)
	assert.Nil(t, parseEthtoolStats("NIC statistics:\n     tx_timeout: 0\n", ethtoolCounters))
}

func TestCounterDeltas(t *testing.T) {
	cases := []struct {
		name string
		a, b map[string]int64
		want map[string]int64
	}{
		{name: "increase", a: map[string]int64{"rx_dropped": 1, "tx_dropped": 5}, b: map[string]int64{"rx_dropped": 4, "tx_dropped": 5}, want: map[string]int64{"rx_dropped": 3, "tx_dropped": 0}},
		{name: "new counter", a: map[string]int64{}, b: map[string]int64{"rx_dropped": 4}, want: map[string]int64{}},
		{name: "no before", b: map[string]int64{"rx_dropped": 4}},
		{name: "counter went down", a: map[string]int64{"rx_dropped": 9}, b: map[string]int64{"rx_dropped": 4}, want: map[string]int64{"rx_dropped": 0}},
		{
			name: "busiest queue",
			a:    map[string]int64{"queue_0_rx_cnt": 10, "queue_1_rx_cnt": 5, "queue_2_rx_cnt": 7},
			b:    map[string]int64{"queue_0_rx_cnt": 910, "queue_1_rx_cnt": 105, "queue_2_rx_cnt": 7},
			want: map[string]int64{"queue_0_rx_cnt": 900, "queue_1_rx_cnt": 100, "queue_2_rx_cnt": 0, topQueueKey: 90},
		},
		{
			name: "queues with no packets",
			a:    map[string]int64{"queue_0_rx_cnt": 10},
			b:    map[string]int64{"queue_0_rx_cnt": 10},
			want: map[string]int64{"queue_0_rx_cnt": 0},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, counterDeltas(tc.a, tc.b))
		})
	}
}

func TestXDPFeatureList(t *testing.T) {
	cases := []struct {
		mask uint64
		want []string
	}{
		{mask: 0},
		{mask: 1 | 2 | 4, want: []string{"basic", "redirect", "ndo-xmit"}},
		{mask: 1 | 8 | 32, want: []string{"basic", "xsk-zerocopy", "rx-sg"}},
		{mask: 1 << 9, want: []string{"bit9"}},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, xdpFeatureList(tc.mask), "mask %b", tc.mask)
	}
}

func TestNodeFlag(t *testing.T) {
	f := nodeFlag{}
	require.NoError(t, f.Set("server=10.0.1.5"))
	require.NoError(t, f.Set("relay=10.0.1.6"))
	assert.Equal(t, "relay=10.0.1.6,server=10.0.1.5", f.String())
	for _, bad := range []string{"server", "proxy=10.0.1.7", "server="} {
		assert.Error(t, f.Set(bad), bad)
	}
}

func TestNicDetail(t *testing.T) {
	assert.Equal(t, "", nicDetail(nil, nil))
	nic := &NIC{Dev: "ens5", Driver: "ena", Version: "7.0.0", RxQueues: 8, XDPFeatures: []string{"basic", "redirect"}}
	assert.Equal(t, "nic ens5 ena 7.0.0, 8 rx queues, xdp basic redirect", nicDetail(nic, nil))
	got := nicDetail(&NIC{Dev: "ens5"}, map[string]int64{"rx_dropped": 2, "bw_in_allowance_exceeded": 7, topQueueKey: 100, "queue_0_rx_cnt": 1})
	assert.Equal(t, "nic ens5  , 0 rx queues, xdp none; nic counters: bw_in_allowance_exceeded 7, rx_dropped 2, rx_top_queue_pct 100", got)
}
