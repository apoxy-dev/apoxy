// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// metricsID is the relay ID that relay-a gives in the tests of the member metrics.
const metricsID = "pop-a"

// memberKinds are the short names of the metrics of a member in memberSeries.
var memberKinds = map[string]string{
	"apoxy_vpc_relay_trunk_packets_total":         "packets",
	"apoxy_vpc_relay_trunk_bytes_total":           "bytes",
	"apoxy_vpc_relay_trunk_dropped_packets_total": "dropped",
	"apoxy_vpc_relay_mesh_rtt_seconds":            "rtt",
}

// memberSeries returns the series of member name in the metrics of r that are not zero,
// as "packets tx", "dropped rx trunk_no_row" or "rtt". Each must have the relay ID id.
func memberSeries(t *testing.T, r *Router, name, id string) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(r))
	fams, err := reg.Gather()
	require.NoError(t, err)
	out := map[string]float64{}
	for _, f := range fams {
		kind, ok := memberKinds[f.GetName()]
		if !ok {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			v := m.GetCounter().GetValue() + m.GetGauge().GetValue()
			if labels["peer_relay"] != name || v == 0 {
				continue
			}
			assert.Equal(t, id, labels["peer_relay_id"], "relay ID of %s", name)
			out[strings.TrimSpace(kind+" "+labels["direction"]+" "+labels["reason"])] = v
		}
	}
	return out
}

// TestTrunkMetricCounters checks the counters of a member by direction and by drop
// reason: the relay of the test has laptop, and relay-a has server.
func TestTrunkMetricCounters(t *testing.T) {
	const size = 100 + 40 // UDP payload bytes of a packet with an inner packet of 100 bytes.
	one := func(dir string) map[string]float64 {
		return map[string]float64{"packets " + dir: 1, "bytes " + dir: size}
	}
	dropped := func(dir, why string) map[string]float64 {
		return map[string]float64{"dropped " + dir + " " + why: 1}
	}
	// q is an agent in QUIC mode on the relay of the test: the relay has its clear packets.
	q := func(g *rowRig) *bridgeEnd { return g.bridgeEnd(dp.Mode_MODE_QUIC, "q", brQSocket, brQNet) }
	// toQ is a trunk packet of relay-a with a clear packet of server for q.
	toQ := func(g *rowRig) []byte { return g.sealed(trunkLane, inTag, innerOf(brServer, brQ, 100), false) }
	cases := []struct {
		name string
		do   func(t *testing.T, g *rowRig)
		want map[string]float64
	}{
		{
			name: "PSP packet of a row to the member",
			do: func(t *testing.T, g *rowRig) {
				require.NoError(t, g.register(rowDst, rowTTL, 5))
				_, pkts := g.packet(5, 100)
				require.Len(t, pkts, 1)
			},
			want: one("tx"),
		},
		{
			name: "PSP packet of a row that is too long for the path",
			do: func(t *testing.T, g *rowRig) {
				require.NoError(t, g.register(rowDst, rowTTL, 5))
				g.packet(5, trunkMTU+1)
			},
			want: dropped("tx", "trunk_mtu"),
		},
		{
			name: "PSP packet of a row while the member has no session",
			do: func(t *testing.T, g *rowRig) {
				require.NoError(t, g.register(rowDst, rowTTL, 5))
				g.away()
				g.packet(5, 100)
			},
			want: dropped("tx", "trunk_keys"),
		},
		{
			name: "clear packet of an agent in a trunk packet",
			do: func(t *testing.T, g *rowRig) {
				require.Len(t, g.bridgeSend(q(g), innerOf(brQ, brServer, 100)), 1)
			},
			want: one("tx"),
		},
		{
			name: "clear packet that is too long for the path",
			do:   func(_ *testing.T, g *rowRig) { g.bridgeSend(q(g), innerOf(brQ, brServer, trunkMTU+1)) },
			want: dropped("tx", "trunk_mtu"),
		},
		{
			name: "clear packet with no SA of the member",
			do: func(_ *testing.T, g *rowRig) {
				g.revoke()
				g.bridgeSend(q(g), innerOf(brQ, brServer, 100))
			},
			want: dropped("tx", "trunk_keys"),
		},
		{
			name: "trunk packet that the socket did not take",
			do: func(_ *testing.T, g *rowRig) {
				g.conn.refuse(errors.New("no buffer space"))
				g.bridgeSend(q(g), innerOf(brQ, brServer, 100))
			},
			want: map[string]float64{},
		},
		{
			name: "PSP packet of a row of the member",
			do: func(t *testing.T, g *rowRig) {
				g.give(serverRow(5, inTTL))
				_, pkts := g.fromServer(5)
				require.Len(t, pkts, 1)
			},
			want: one("rx"),
		},
		{
			name: "PSP packet with an SPI of no row",
			do:   func(_ *testing.T, g *rowRig) { g.fromServer(4) },
			want: dropped("rx", "trunk_no_row"),
		},
		{
			name: "PSP packet of a row after its end time",
			do: func(_ *testing.T, g *rowRig) {
				g.give(serverRow(5, time.Second))
				time.Sleep(time.Second + time.Nanosecond)
				g.fromServer(5)
			},
			want: dropped("rx", "trunk_expired"),
		},
		{
			name: "PSP packet of a row with a tag that the member has no entry for",
			do: func(_ *testing.T, g *rowRig) {
				row := serverRow(5, inTTL)
				row.SenderTag = 9
				g.give(row)
				g.fromServer(5)
			},
			want: dropped("rx", "trunk_sender"),
		},
		{
			name: "PSP packet of a row that Permit denies",
			do: func(_ *testing.T, g *rowRig) {
				g.give(serverRow(5, inTTL))
				g.r.SetPermit(denyAll)
				g.fromServer(5)
			},
			want: dropped("rx", "trunk_permit"),
		},
		{
			name: "PSP packet of a row to an address of no agent of this relay",
			do: func(_ *testing.T, g *rowRig) {
				g.give(rowTo(5, "fd00:f::1"))
				g.fromServer(5)
			},
			want: dropped("rx", "trunk_not_local"),
		},
		{
			name: "trunk packet with a clear packet",
			do: func(t *testing.T, g *rowRig) {
				e := q(g)
				g.arrive(toQ(g), g.addr)
				require.Len(t, e.frames, 1)
			},
			want: one("rx"),
		},
		{
			name: "the same trunk packet a second time",
			do: func(_ *testing.T, g *rowRig) {
				q(g)
				pkt := toQ(g)
				g.arrive(slices.Clone(pkt), g.addr)
				g.arrive(pkt, g.addr)
			},
			want: map[string]float64{"packets rx": 1, "bytes rx": size, "dropped rx trunk_replay": 1},
		},
		{
			name: "trunk packet with a PSP packet of an agent",
			do: func(t *testing.T, g *rowRig) {
				g.arrive(g.sealed(trunkLane, inTag, pspOfSize(t, 5, 100), true), g.addr)
			},
			want: dropped("rx", "trunk_payload"),
		},
		{
			name: "trunk packet with a changed byte",
			do: func(_ *testing.T, g *rowRig) {
				q(g)
				pkt := toQ(g)
				pkt[len(pkt)-1] ^= 1
				g.arrive(pkt, g.addr)
			},
			want: dropped("rx", "malformed"),
		},
		{
			name: "clear packet from an address that the sender does not have",
			do: func(_ *testing.T, g *rowRig) {
				q(g)
				g.arrive(g.sealed(trunkLane, inTag, innerOf("fd00:99::1", brQ, 100), false), g.addr)
			},
			want: dropped("rx", "trunk_source"),
		},
		{
			name: "clear packet for a session that takes no frame",
			do: func(_ *testing.T, g *rowRig) {
				q(g).refuse = errors.New("session closed")
				g.arrive(toQ(g), g.addr)
			},
			want: dropped("rx", "trunk_not_sent"),
		},
		{
			name: "probe of the member and the answer of the relay",
			do:   func(t *testing.T, g *rowRig) { require.True(t, g.ping()) },
			want: map[string]float64{},
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				g.ref = &dp.RelayRef{Id: metricsID}
				g.serve()
				tc.do(t, g)
				assert.Equal(t, tc.want, memberSeries(t, g.r, "relay-a", metricsID))
			})
		})
	}
}

// TestTrunkMetricReasons checks that each drop reason of a packet of a member has
// a series, and that no reason has two directions.
func TestTrunkMetricReasons(t *testing.T) {
	seen := map[dropReason]bool{}
	for _, d := range trunkDrops {
		assert.False(t, seen[d.why], "reason %s is in the list one time", dropLabels[d.why])
		seen[d.why] = true
	}
	for why := dropTrunkPayload; why < numDropReasons; why++ {
		assert.True(t, seen[why], "reason %s has a series", dropLabels[why])
	}
	for _, why := range []dropReason{dropMalformed, dropTrunkMTU, dropTrunkKeys} {
		assert.True(t, seen[why], "reason %s has a series", dropLabels[why])
	}
}

// TestTrunkMetricMembers checks that the relay has one set of series for each
// member, with the packets of all its agents, and none for a relay that is no member.
func TestTrunkMetricMembers(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		g.ref = &dp.RelayRef{Id: metricsID}
		tablet := g.agent(agentID(vpcA, "tablet"), spiTablet, "fd00:2::/96")
		g.start()
		b := g.second(true)
		other := atGen(liveEntry("y", agentID(vpcA, "other"), "", 3, prefixB), 20)
		require.NoError(t, g.m.pres.apply(b.sess, &dp.PresenceUpdate{Entries: []*dp.Presence{other}}))

		// laptop and tablet send to server on relay-a, and laptop sends to other on relay-b.
		require.NoError(t, g.register(rowDst, rowTTL, 5))
		require.NoError(t, g.r.registerSPI(tablet, register(vpcA, rowDst, rowTTL, 6), time.Now()))
		require.NoError(t, g.register(spiOnB, rowTTL, 7))
		g.packet(5, 100)
		g.handle(pspOfSize(t, 6, 100), net.UDPAddrFromAddrPort(netip.MustParseAddrPort(spiTablet)))
		g.packet(7, 100)
		// A relay that is no member has counters after a late packet.
		g.r.peers.of("relay-z").add(trunkTx, 100)

		const want = `
# HELP apoxy_vpc_relay_trunk_packets_total Packets of agents that the relay sent to a mesh member (tx), or got from the member and sent on (rx).
# TYPE apoxy_vpc_relay_trunk_packets_total counter
apoxy_vpc_relay_trunk_packets_total{direction="rx",peer_relay="relay-a",peer_relay_id="pop-a"} 0
apoxy_vpc_relay_trunk_packets_total{direction="tx",peer_relay="relay-a",peer_relay_id="pop-a"} 2
apoxy_vpc_relay_trunk_packets_total{direction="rx",peer_relay="relay-b",peer_relay_id=""} 0
apoxy_vpc_relay_trunk_packets_total{direction="tx",peer_relay="relay-b",peer_relay_id=""} 1
`
		assert.NoError(t, testutil.CollectAndCompare(g.r, strings.NewReader(want), "apoxy_vpc_relay_trunk_packets_total"))
		assert.Equal(t, len(trunkDrops)*2, testutil.CollectAndCount(g.r, "apoxy_vpc_relay_trunk_dropped_packets_total"),
			"each member has one series for each reason")

		g.r.sweepPeers()
		names := slices.Sorted(maps.Keys(g.r.peers.load()))
		assert.Equal(t, []string{"relay-a", "relay-b"}, names, "the sweep keeps only the counters of the members")
		assert.Equal(t, map[string]float64{"packets tx": 2, "bytes tx": 280}, memberSeries(t, g.r, "relay-a", metricsID))
	})
}

// TestTrunkMetricRelayID checks the relay ID label of a member: the mesh forgets
// the ID when the member restarts, and the series of the member stay the same.
func TestTrunkMetricRelayID(t *testing.T) {
	cases := []struct {
		name string
		ref  *dp.RelayRef // What relay-a gives of itself.
		do   func(g *rowRig)
		want string
	}{
		{name: "member gave an ID", ref: &dp.RelayRef{Id: metricsID}, want: metricsID},
		{name: "member gave no ID", want: ""},
		{
			name: "member closed with RESTART before the first read", ref: &dp.RelayRef{Id: metricsID},
			do:   func(g *rowRig) { g.lose(g.sess, meshRestart, 0) },
			want: metricsID,
		},
		{
			name: "member came back with a new ID", ref: &dp.RelayRef{Id: metricsID},
			do: func(g *rowRig) {
				g.lose(g.sess, meshRestart, 0)
				g.ref = &dp.RelayRef{Id: "pop-b"}
				g.rejoin(trunkRevision, trunkRigAddr)
			},
			want: "pop-b",
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				g.ref = tc.ref
				g.start()
				require.NoError(t, g.register(rowDst, rowTTL, 5))
				g.packet(5, 100)
				if tc.do != nil {
					tc.do(g)
				}
				assert.Equal(t, map[string]float64{"packets tx": 1, "bytes tx": 140}, memberSeries(t, g.r, "relay-a", tc.want))
			})
		})
	}
}

// TestTrunkMetricXDP checks that the packets that the XDP program sends to a member
// count for the member one time: while the XDP row is there, and after it goes.
func TestTrunkMetricXDP(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		f := newFakeXDP()
		g.r.setXDP(f, time.Now())
		g.ref = &dp.RelayRef{Id: metricsID}
		g.connect()
		g.announce(entryOf("x", server, 7, 10))
		g.r.mu.Lock()
		g.pair.src = netip.MustParseAddr("192.0.2.200")
		f.own = []netip.Addr{g.pair.src}
		g.r.mu.Unlock()
		require.NoError(t, g.register(rowDst, rowTTL, 5))
		flushXDP(g.r, time.Now())
		require.Equal(t, map[string]string{rowSrc + "/5": trunkRigAddr.String()}, f.installed())
		// forwarded sets the counters of the XDP row of laptop with SPI 5.
		forwarded := func(packets, bytes uint64) {
			row := f.rows[key(rowSrc, 5)]
			row.c = xdpCounters{packets: packets, bytes: bytes}
			f.rows[key(rowSrc, 5)] = row
		}
		steps := []struct {
			name string
			do   func()
			want map[string]float64
		}{
			{
				name: "the program sent 3 packets",
				do:   func() { forwarded(3, 420) },
				want: map[string]float64{"packets tx": 3, "bytes tx": 420},
			},
			{
				name: "the socket path sent 1 packet more",
				do:   func() { g.packet(5, 100) },
				want: map[string]float64{"packets tx": 4, "bytes tx": 560},
			},
			{
				name: "the row moved to an agent of this relay, and the program sent 2 packets to it",
				do: func() {
					g.agent(agentID(vpcA, "other"), "192.0.2.4:1", prefixA)
					flushXDP(g.r, time.Now())
					require.Equal(t, map[string]string{rowSrc + "/5": "192.0.2.4:1"}, f.installed())
					forwarded(2, 280)
				},
				want: map[string]float64{"packets tx": 4, "bytes tx": 560},
			},
			{
				name: "the row ended",
				do: func() {
					g.unregister(5)
					flushXDP(g.r, time.Now())
					require.Empty(t, f.installed())
				},
				want: map[string]float64{"packets tx": 4, "bytes tx": 560},
			},
		}
		for _, st := range steps {
			st.do()
			assert.Equal(t, st.want, memberSeries(t, g.r, "relay-a", metricsID), st.name)
		}
	})
}

// TestMeshRTT checks which connections give an RTT for the metric of a member.
func TestMeshRTT(t *testing.T) {
	placed := func(rtt time.Duration) context.Context {
		ctx, err := TraceContext(context.Background(), nil)
		require.NoError(t, err)
		rttOf(ctx).Store(int64(rtt))
		return ctx
	}
	cases := []struct {
		name string
		ctx  context.Context // Context of the connection. Nil is no session.
		want time.Duration
	}{
		{name: "no session"},
		{name: "connection with no place for the RTT", ctx: context.Background()},
		{name: "connection with no sample", ctx: placed(0)},
		{name: "connection with a sample", ctx: placed(3 * time.Millisecond), want: 3 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s *MeshSession
			if tc.ctx != nil {
				conn := newStubConn()
				conn.ctx = tc.ctx
				s = &MeshSession{qc: conn}
			}
			assert.Equal(t, tc.want, meshRTT(s))
		})
	}
}

// TestTrunkMetricRTT checks the RTT metric of a member on two relays with a mesh
// session on loopback. relay-a dials the session, and relay-b accepts it.
func TestTrunkMetricRTT(t *testing.T) {
	const id = "region-1.relay.example.net"
	cases := []struct {
		name  string
		place bool // The relay host of relay-b gives each connection the place for its RTT.
	}{
		{name: "accepting relay with the place for the RTT", place: true},
		{name: "accepting relay with no place for the RTT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := trunkNodes(t, func(_, b *trunkNode) {
				if tc.place {
					b.tr.ConnContext = TraceContext
				}
			})
			rtt := func(n *trunkNode, peer string) float64 { return memberSeries(t, n.r, peer, id)["rtt"] }
			has := func(n *trunkNode, peer string) func() bool {
				return func() bool { return rtt(n, peer) > 0 }
			}
			require.Eventually(t, has(a, "relay-b"), 10*time.Second, 5*time.Millisecond, "the relay that dialed has the RTT")
			assert.Less(t, rtt(a, "relay-b"), 5.0, "the value is in seconds")
			if tc.place {
				require.Eventually(t, has(b, "relay-a"), 10*time.Second, 5*time.Millisecond, "the relay that accepted has the RTT")
			} else {
				assert.Zero(t, rtt(b, "relay-a"), "a session with no place for the RTT has no value")
			}
			// The probes of the relays are no packets of agents.
			assert.NotContains(t, memberSeries(t, a.r, "relay-b", id), "packets tx")
			assert.NotContains(t, memberSeries(t, b.r, "relay-a", id), "packets rx")
		})
	}
}
