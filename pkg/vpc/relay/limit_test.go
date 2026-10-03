// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// TestTunnelLimit checks that one limit covers the PSP packets, data frames
// and peer frames of a session and its shards.
func TestTunnelLimit(t *testing.T) {
	const size = 1400
	srcIP, dstIP := netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("fd00:2::1")
	data := peerconn.EncodeData(nil, testVNI, ipPacket(srcIP, dstIP, make([]byte, size-peerconn.DataLen-40)))
	peer := peerconn.EncodeToRelay(nil, dstIP, srcIP, make([]byte, size-peerconn.ToRelayLen))
	require.Len(t, data, size)
	require.Len(t, peer, size)
	buf := make([]byte, maxUDP)

	// A sender sends one packet of size bytes from src or its shard.
	type sender func(r *Router, src, shard *Session) bool
	pspPacket := func(r *Router, _, _ *Session) bool {
		_, v := r.Forward(netip.MustParseAddrPort("192.0.2.1:1"), 7, size, t0)
		return v == Pass
	}
	dataFrame := func(r *Router, src, _ *Session) bool { return r.forwardData(src, data, buf, t0) }
	shardFrame := func(r *Router, _, shard *Session) bool { return r.forwardData(shard, data, buf, t0) }
	peerFrame := func(r *Router, src, _ *Session) bool { return r.forwardDatagram(src, peer, t0) }

	all := []sender{pspPacket, dataFrame, shardFrame, peerFrame}
	tight := Config{TunnelRate: 1 << 20, TunnelBurst: 64 << 10}
	cases := []struct {
		name     string
		cfg      Config
		sends    []sender // Used in turn.
		wantPass int      // Of 80 packets at one time.
	}{
		// A burst of 64 KiB lets 46 packets of 1400 B through.
		{name: "PSP packets", cfg: tight, sends: []sender{pspPacket}, wantPass: 46},
		{name: "data frames", cfg: tight, sends: []sender{dataFrame}, wantPass: 46},
		{name: "data frames on a shard", cfg: tight, sends: []sender{shardFrame}, wantPass: 46},
		{name: "peer frames", cfg: tight, sends: []sender{peerFrame}, wantPass: 46},
		{name: "one limit for all", cfg: tight, sends: all, wantPass: 46},
		// The default burst is 100 ms: 104857 B, 74 packets.
		{name: "default burst", cfg: Config{TunnelRate: 1 << 20}, sends: all, wantPass: 74},
		{name: "burst of at least 64 KiB", cfg: Config{TunnelRate: 1 << 16}, sends: all, wantPass: 46},
		{name: "no limit", sends: all, wantPass: 80},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, tc.cfg)
			src := localSession(t, r, "src", "192.0.2.1:1", "fd00:1::/96", dp.Mode_MODE_QUIC)
			localSession(t, r, "dst", "192.0.2.2:1", "fd00:2::/96", dp.Mode_MODE_QUIC)
			require.NoError(t, r.registerSPI(src, register(vpcA, dstIP.String(), time.Minute, 7), t0))
			require.NoError(t, r.attach(src, &Attachment{ID: "att-src"}))
			shard := newSession(src.id, func() netip.AddrPort { return netip.AddrPort{} })
			r.addSession(shard, t0)
			_, _, err := r.joinShard(shard, "att-src", 1)
			require.NoError(t, err)

			pass := 0
			for i := range 80 {
				if tc.sends[i%len(tc.sends)](r, src, shard) {
					pass++
				}
			}
			assert.Equal(t, tc.wantPass, pass)
			drops := uint64(80 - tc.wantPass)
			assert.Equal(t, drops, r.SenderStats(src).DropTunnelLimit)
			assert.Zero(t, r.SenderStats(shard).DropTunnelLimit)
			assert.Zero(t, r.SenderStats(src).DataDrops)
			assert.Equal(t, drops, r.drops[dropTunnelLimit].Load())
		})
	}
}

// TestDropMetric checks the drop counters that the router gives to Prometheus.
func TestDropMetric(t *testing.T) {
	// The lane and tunnel bursts are both 104857 B: 74 packets of 1400 B.
	r := NewRouter(nil, Config{LaneRate: 1 << 20, TunnelRate: 1 << 20})
	handle, _ := r.PacketHandler(t.Context(), &quic.Transport{Conn: newDiscardConn()})
	snd := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128")
	addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
	require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Minute, 1, 2), t0))
	src := netip.MustParseAddrPort("192.0.2.1:1000")

	handle([]byte{0x02, 1, 2, 3}, net.UDPAddrFromAddrPort(src))
	r.Forward(netip.MustParseAddrPort("192.0.2.9:1"), 1, 1400, t0)
	r.Forward(src, 9, 1400, t0)
	for range 75 {
		r.Forward(src, 1, 1400, t0)
	}
	// Lane 2 has its full burst, but the tunnel has none left.
	r.Forward(src, 2, 1400, t0)

	const want = `
# HELP apoxy_vpc_relay_dropped_packets_total Packets that the relay dropped before it forwarded them, by reason.
# TYPE apoxy_vpc_relay_dropped_packets_total counter
apoxy_vpc_relay_dropped_packets_total{reason="closed"} 0
apoxy_vpc_relay_dropped_packets_total{reason="lane_meter"} 1
apoxy_vpc_relay_dropped_packets_total{reason="malformed"} 1
apoxy_vpc_relay_dropped_packets_total{reason="tunnel_limit"} 1
apoxy_vpc_relay_dropped_packets_total{reason="unknown_source"} 1
apoxy_vpc_relay_dropped_packets_total{reason="unknown_spi"} 1
`
	assert.NoError(t, testutil.CollectAndCompare(r, strings.NewReader(want)))
	assert.Equal(t, uint64(1), r.MalformedDrops())
	assert.Equal(t, uint64(1), r.UnknownSourceDrops())
}
