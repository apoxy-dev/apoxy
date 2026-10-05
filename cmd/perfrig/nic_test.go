package main

import (
	"os"
	"testing"
	"time"

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

func TestParseSNMP(t *testing.T) {
	const snmp = "Tcp: RtoAlgorithm RtoMin InErrs\nTcp: 1 200 7\n" +
		"Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors\n" +
		"Udp: 900 3 5 700 4 2 1\n" +
		"UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\nUdpLite: 9 9 9 9 9 9\n"
	cases := []struct {
		name  string
		data  string
		group string
		want  map[string]int64
	}{
		{
			name: "udp", data: snmp, group: "Udp",
			want: map[string]int64{"udp_in_datagrams": 900, "udp_in_errors": 5, "udp_out_datagrams": 700, "udp_rcvbuf_errors": 4, "udp_sndbuf_errors": 2},
		},
		{name: "no group", data: snmp, group: "Icmp", want: map[string]int64{}},
		{name: "names with no values", data: "Udp: InDatagrams OutDatagrams\n", group: "Udp", want: map[string]int64{}},
		{name: "short values", data: "Udp: InDatagrams NoPorts InErrors\nUdp: 8 x\n", group: "Udp", want: map[string]int64{"udp_in_datagrams": 8}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseSNMP(tc.data, tc.group, udpCounters))
		})
	}
}

func TestNodeNetemSteps(t *testing.T) {
	cfg := config{Delay: 10 * time.Millisecond, QueueLimit: 5000}
	netem := []string{"netem", "limit", "5000", "delay", "10ms"}
	queue := func(parent string) []string {
		return append([]string{"tc", "qdisc", "replace", "dev", "ens5", "parent", parent}, netem...)
	}
	cases := []struct {
		name     string
		txQueues int
		want     [][]string
	}{
		{name: "one queue", txQueues: 1, want: [][]string{append([]string{"tc", "qdisc", "replace", "dev", "ens5", "root"}, netem...)}},
		{name: "queue count not known", txQueues: 0, want: [][]string{append([]string{"tc", "qdisc", "replace", "dev", "ens5", "root"}, netem...)}},
		{
			name: "two queues", txQueues: 2,
			want: [][]string{{"tc", "qdisc", "replace", "dev", "ens5", "root", "handle", "1:", "mq"}, queue("1:1"), queue("1:2")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, nodeNetemSteps("ens5", tc.txQueues, cfg))
		})
	}
	// The class of a queue is in hex.
	steps := nodeNetemSteps("ens5", 16, cfg)
	require.Len(t, steps, 17)
	assert.Equal(t, queue("1:a"), steps[10])
	assert.Equal(t, queue("1:10"), steps[16])
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

func TestMaxCounters(t *testing.T) {
	cases := []struct {
		name       string
		a, b, want map[string]int64
	}{
		{name: "no counters"},
		{name: "no first read", b: map[string]int64{"queue_0_rx_cnt": 4}, want: map[string]int64{"queue_0_rx_cnt": 4}},
		{name: "no second read", a: map[string]int64{"queue_0_rx_cnt": 4}, want: map[string]int64{"queue_0_rx_cnt": 4}},
		{
			name: "a queue counter is 0 again",
			a:    map[string]int64{"queue_0_rx_cnt": 900, "rx_dropped": 3},
			b:    map[string]int64{"queue_0_rx_cnt": 2, "rx_dropped": 5, "queue_1_rx_cnt": 0},
			want: map[string]int64{"queue_0_rx_cnt": 900, "rx_dropped": 5, "queue_1_rx_cnt": 0},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, maxCounters(tc.a, tc.b))
		})
	}
}

func TestPeakCounters(t *testing.T) {
	if _, err := os.Stat("/proc/net/snmp"); err != nil {
		t.Skip("needs /proc/net/snmp")
	}
	stop := peakCounters(t.Context(), "lo", 5*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	assert.Contains(t, stop(), "udp_in_datagrams")
}

func TestXDPConf(t *testing.T) {
	cases := []struct {
		name        string
		in          linkConf
		maxChannels uint32
		limit       uint32
		generic     bool
		want        linkConf
	}{
		{name: "all channels in use", in: linkConf{channels: 8, mtu: 9001, forwarding: "0"}, maxChannels: 8, want: linkConf{channels: 4, mtu: xdpMaxMTU, forwarding: "1"}},
		{name: "half of the channels", in: linkConf{channels: 4, mtu: 9001, forwarding: "0"}, maxChannels: 8, want: linkConf{channels: 4, mtu: xdpMaxMTU, forwarding: "1"}},
		{name: "few channels and a small MTU", in: linkConf{channels: 2, mtu: 1500, forwarding: "1"}, maxChannels: 32, want: linkConf{channels: 2, mtu: 1500, forwarding: "1"}},
		{name: "odd maximum", in: linkConf{channels: 5, mtu: 3498, forwarding: "0"}, maxChannels: 5, want: linkConf{channels: 2, mtu: 3498, forwarding: "1"}},
		{name: "one channel", in: linkConf{channels: 1, mtu: 3499, forwarding: "0"}, maxChannels: 1, want: linkConf{channels: 1, mtu: xdpMaxMTU, forwarding: "1"}},
		{name: "limit below half", in: linkConf{channels: 8, mtu: 9001, forwarding: "0"}, maxChannels: 16, limit: 1, want: linkConf{channels: 1, mtu: xdpMaxMTU, forwarding: "1"}},
		{name: "limit above half", in: linkConf{channels: 8, mtu: 9001, forwarding: "0"}, maxChannels: 8, limit: 6, want: linkConf{channels: 4, mtu: xdpMaxMTU, forwarding: "1"}},
		{name: "generic mode", in: linkConf{channels: 8, mtu: 9001, forwarding: "0"}, maxChannels: 8, generic: true, want: linkConf{channels: 8, mtu: 9001, forwarding: "1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, xdpConf(tc.in, tc.maxChannels, tc.limit, tc.generic))
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
