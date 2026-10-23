package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestXSKSummary(t *testing.T) {
	socks := []xskSocket{
		{ifindex: 3, zeroCopy: true, stats: map[string]uint64{"rx_dropped": 1, "rx_full": 4}},
		{ifindex: 3, zeroCopy: true, stats: map[string]uint64{"rx_dropped": 2}},
		{ifindex: 3, zeroCopy: false},
		{ifindex: 7, zeroCopy: true, stats: map[string]uint64{"rx_dropped": 100}},
	}
	cases := []struct {
		name      string
		ifindex   uint32
		wantN     int
		wantZC    int
		wantStats map[string]uint64
	}{
		{name: "copy and zero-copy sockets", ifindex: 3, wantN: 3, wantZC: 2, wantStats: map[string]uint64{"rx_dropped": 3, "rx_full": 4}},
		{name: "one link of two", ifindex: 7, wantN: 1, wantZC: 1, wantStats: map[string]uint64{"rx_dropped": 100}},
		{name: "no sockets", ifindex: 9},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, zc, stats := xskSummary(socks, tc.ifindex)
			assert.Equal(t, tc.wantN, n)
			assert.Equal(t, tc.wantZC, zc)
			assert.Equal(t, tc.wantStats, stats)
		})
	}
}

func TestSumXSKCounters(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]int64
		want map[string]int64
	}{
		{
			name: "queues",
			in: map[string]int64{"queue_0_tx_xsk_cnt": 5, "queue_11_tx_xsk_cnt": 7, "queue_1_tx_xsk_wakeup_request": 2,
				"queue_1_rx_xsk_need_wakeup_set": 1, "queue_0_rx_cnt": 99, "total_resets": 1},
			want: map[string]int64{"tx_xsk_cnt": 12, "tx_xsk_wakeup_request": 2, "rx_xsk_need_wakeup_set": 1},
		},
		{name: "no AF_XDP counters", in: map[string]int64{"queue_0_rx_cnt": 99}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sumXSKCounters(tc.in))
		})
	}
}

func TestLinkResets(t *testing.T) {
	cases := []struct {
		name         string
		nic          map[string]int64
		carrierDowns int64
		want         int64
	}{
		// ENA takes the link down and up to set up XDP and the zero-copy sockets.
		{name: "setup down and up only", nic: map[string]int64{"total_resets": 0, "interface_down": 18}, carrierDowns: 12},
		{name: "a reset after an error", nic: map[string]int64{"total_resets": 1, "interface_down": 3}, carrierDowns: 3, want: 1},
		{name: "a driver with no reset counter", nic: map[string]int64{"rx_dropped": 4}, carrierDowns: 2, want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, linkResets(tc.nic, tc.carrierDowns))
		})
	}
}

func TestKmsg(t *testing.T) {
	cases := []struct {
		name      string
		rec       string
		wantUsec  uint64
		wantMsg   string
		wantOK    bool
		wantMatch bool
	}{
		{name: "ena reset", rec: "4,812,90123456,-;ena 0000:00:06.0 ens6: Trigger reset is on\n", wantUsec: 90123456, wantMsg: "ena 0000:00:06.0 ens6: Trigger reset is on", wantOK: true, wantMatch: true},
		{name: "link name", rec: "6,813,90123500,-;IPv6: ADDRCONF(NETDEV_CHANGE): ens6: link becomes ready\n SUBSYSTEM=net\n", wantUsec: 90123500, wantMsg: "IPv6: ADDRCONF(NETDEV_CHANGE): ens6: link becomes ready", wantOK: true, wantMatch: true},
		{name: "other driver", rec: "6,814,90123600,-;nvme nvme0: pci function 0000:00:04.0\n", wantUsec: 90123600, wantMsg: "nvme nvme0: pci function 0000:00:04.0", wantOK: true},
		{name: "no message", rec: "6,815,90123700,-", wantOK: false},
		{name: "bad time", rec: "6,815,x,-;ena", wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			usec, msg, ok := kmsgLine(tc.rec)
			assert.Equal(t, tc.wantOK, ok)
			if !ok {
				return
			}
			assert.Equal(t, tc.wantUsec, usec)
			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, tc.wantMatch, kmsgMatch(msg, "ens6"))
		})
	}
}

func TestKernelConfig(t *testing.T) {
	const cfg = "# Kernel config\nCONFIG_TICK_CPU_ACCOUNTING=y\n# CONFIG_IRQ_TIME_ACCOUNTING is not set\nCONFIG_XDP_SOCKETS=y\nCONFIG_XDP_SOCKETS_DIAG=m\n"
	cases := []struct{ name, want string }{
		{"CONFIG_IRQ_TIME_ACCOUNTING", "n"},
		{"CONFIG_XDP_SOCKETS_DIAG", "m"},
		{"CONFIG_XDP_SOCKETS", "y"},
		{"CONFIG_NONE", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, kernelConfig(strings.NewReader(cfg), tc.name))
		})
	}
}
