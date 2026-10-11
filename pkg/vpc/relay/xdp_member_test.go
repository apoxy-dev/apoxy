// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// TestXDPMemberRows checks which rows of relay-a the relay gives to the XDP program,
// at the relay socket of relay-a, with each check of the socket path.
func TestXDPMemberRows(t *testing.T) {
	member := trunkRigAddr.String()
	first := map[string]string{member + "/5": rowSrc}
	cases := []struct {
		name string
		// nat is the source port of the session of relay-a behind a NAT. Zero is no NAT.
		nat  uint16
		do   func(t *testing.T, g *rowRig) // Runs after the program has the row with SPI 5.
		want map[string]string             // Rows of the program after do, as "source/SPI".
	}{
		{name: "row of a sender of the member", want: first},
		{name: "session of the member from a port of a NAT", nat: 17149, want: first},
		{
			name: "second row to the same receiver",
			do:   func(_ *testing.T, g *rowRig) { g.give(serverRow(8, inTTL)) },
			want: map[string]string{member + "/5": rowSrc, member + "/8": rowSrc},
		},
		{
			name: "row of a tag that no entry has",
			do: func(_ *testing.T, g *rowRig) {
				row := serverRow(8, inTTL)
				row.SenderTag = 9
				g.give(row)
			},
			want: first,
		},
		{
			name: "row to an address that no agent of this relay has",
			do:   func(_ *testing.T, g *rowRig) { g.give(rowTo(8, "fd00:f::1")) },
			want: first,
		},
		{
			name: "row with the SPI of a trunk SA of the member",
			do: func(_ *testing.T, g *rowRig) {
				spis := g.pair.spis.Load()
				require.NotNil(t, spis)
				require.NotEmpty(t, *spis)
				g.give(serverRow((*spis)[0].spi, inTTL))
			},
			want: first,
		},
		{
			name: "Permit denies the destination after the sync",
			do:   func(_ *testing.T, g *rowRig) { g.r.SetPermit(denyAll) },
			want: map[string]string{},
		},
		{
			name: "entry of the sender goes after the sync",
			do:   func(_ *testing.T, g *rowRig) { g.announce(atGen(goneEntry("x"), 11)) },
			want: map[string]string{},
		},
		{
			name: "receiver closes after the sync",
			do:   func(_ *testing.T, g *rowRig) { g.r.removeSession(g.laptop) },
			want: map[string]string{},
		},
		{
			name: "receiver moves to a new address",
			do: func(_ *testing.T, g *rowRig) {
				g.r.mu.Lock()
				defer g.r.mu.Unlock()
				g.r.setAddr(g.laptop, netip.MustParseAddrPort("192.0.2.77:7"), time.Now())
			},
			want: map[string]string{member + "/5": "192.0.2.77:7"},
		},
		{
			name: "receiver moves to an address of the other family",
			do: func(_ *testing.T, g *rowRig) {
				g.r.mu.Lock()
				defer g.r.mu.Unlock()
				g.r.setAddr(g.laptop, netip.MustParseAddrPort("[2001:db8::9]:7"), time.Now())
			},
			want: map[string]string{},
		},
		{
			name: "member removes the row",
			do: func(_ *testing.T, g *rowRig) {
				g.give(&dp.SPIRow{Vpc: ref(vpcA), SenderTag: inTag, Spi: 5, Removed: true})
			},
			want: map[string]string{},
		},
		{
			name: "member gives the row again with a new end time",
			do:   func(_ *testing.T, g *rowRig) { g.give(serverRow(5, 2*inTTL)) },
			want: first,
		},
		{
			name: "member stops",
			do:   func(_ *testing.T, g *rowRig) { g.lose(g.sess, meshRestart, 0) },
			want: map[string]string{},
		},
		{
			name: "member is down",
			do:   func(_ *testing.T, g *rowRig) { g.away() },
			want: map[string]string{},
		},
		{
			name: "member leaves the member set",
			do:   func(_ *testing.T, g *rowRig) { g.m.SetMembers(nil); g.deliver() },
			want: map[string]string{},
		},
		{
			// The program has a meter for each row, and relay-a applied the meter of the row.
			name: "relay with a lane meter",
			do: func(_ *testing.T, g *rowRig) {
				g.r.mu.Lock()
				g.r.cfg.LaneRate = 1000
				g.r.mu.Unlock()
				g.r.Sweep(time.Now())
			},
			want: map[string]string{},
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				if tc.nat != 0 {
					g.nat = netip.AddrPortFrom(trunkRigAddr.Addr(), tc.nat)
				}
				f := newFakeXDP()
				g.r.setXDP(f, time.Now())
				g.serve()
				g.give(serverRow(5, inTTL))
				flushXDP(g.r, time.Now())
				require.Equal(t, first, f.installed(), "row of the member before the change")
				if tc.do != nil {
					tc.do(t, g)
				}
				flushXDP(g.r, time.Now())
				assert.Equal(t, tc.want, f.installed())
			})
		})
	}
}

// TestXDPMemberRowEnd checks that the row of a member goes from the program at
// its end time, and that the program has the end time before that.
func TestXDPMemberRowEnd(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		f := newFakeXDP()
		g.r.setXDP(f, time.Now())
		g.serve()
		end := time.Now().Add(2 * time.Second)
		g.give(serverRow(5, 2*time.Second))
		flushXDP(g.r, time.Now())
		row, ok := f.rows[key(trunkRigAddr.String(), 5)]
		require.True(t, ok)
		assert.True(t, row.expires.Equal(end), "the program has the end time of the row")
		assert.Zero(t, row.tunnel, "the relay of the sender applied the tunnel limit")

		time.Sleep(2*time.Second + time.Nanosecond)
		g.r.Sweep(time.Now())
		assert.Empty(t, f.installed())
	})
}

// TestXDPMemberEpoch checks that each change of the checks of a member row asks
// for an XDP sync, so that Run does not wait for the next sweep.
func TestXDPMemberEpoch(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		g.r.setXDP(newFakeXDP(), time.Now())
		g.serve()
		woke := func() bool {
			select {
			case <-g.r.xdpWake:
				return true
			default:
				return false
			}
		}
		steps := []struct {
			name string
			do   func()
		}{
			{"member gives a row", func() { g.give(serverRow(5, inTTL)) }},
			{"Permit changes", func() { g.r.SetPermit(denyAll) }},
			{"entry of a sender changes", func() { g.announce(entryOf("y", server, 9, 12)) }},
			{"route of an agent changes", func() { g.agent(agentID(vpcA, "other"), "192.0.2.4:1", "fd00:4::/96") }},
		}
		for _, st := range steps {
			flushXDP(g.r, time.Now())
			woke()
			st.do()
			assert.True(t, woke(), st.name)
		}
	})
}

// TestXDPMemberCounters checks that the packets that the program sends on count one
// time for the member and for the attachment, with the XDP row and after it goes.
func TestXDPMemberCounters(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		f := newFakeXDP()
		g.r.setXDP(f, time.Now())
		g.ref = &dp.RelayRef{Id: metricsID}
		g.serve()
		g.give(serverRow(5, inTTL))
		flushXDP(g.r, time.Now())
		k := key(trunkRigAddr.String(), 5)
		require.Contains(t, f.rows, k)
		// forwarded sets the counters of the XDP row of relay-a with SPI 5.
		forwarded := func(packets, bytes uint64) {
			row := f.rows[k]
			row.c = xdpCounters{packets: packets, bytes: bytes}
			f.rows[k] = row
		}
		type counts struct{ rxPackets, rxBytes, toPackets, toBytes float64 }
		steps := []struct {
			name string
			do   func()
			want counts
		}{
			{
				name: "the program sent 3 packets on",
				do:   func() { forwarded(3, 420) },
				want: counts{3, 420, 3, 300},
			},
			{
				name: "the socket path sent 1 packet more on",
				do:   func() { g.passes(5, rowSrc, "packet on the socket path") },
				want: counts{4, 560, 4, 400},
			},
			{
				name: "the member gives the row again, and the program sent 2 packets more",
				do: func() {
					g.give(serverRow(5, 2*inTTL))
					flushXDP(g.r, time.Now())
					require.Contains(t, f.rows, k)
					forwarded(5, 700)
				},
				want: counts{6, 840, 6, 600},
			},
			{
				name: "the row ended",
				do: func() {
					g.give(&dp.SPIRow{Vpc: ref(vpcA), SenderTag: inTag, Spi: 5, Removed: true})
					flushXDP(g.r, time.Now())
					require.Empty(t, f.installed())
				},
				want: counts{6, 840, 6, 600},
			},
		}
		for _, st := range steps {
			st.do()
			series := memberSeries(t, g.r, "relay-a", metricsID)
			packets, bytes := g.txOf(g.laptop)
			got := counts{series["packets rx"], series["bytes rx"], float64(packets), float64(bytes)}
			assert.Equal(t, st.want, got, st.name)
		}
		// Only the packet of the second step went on the socket path.
		assert.EqualValues(t, 1, g.r.socket[socketMemberRow].Load())
	})
}

// TestTrunkDataAddress checks that the relay sends the packets for relay-a to its relay
// socket from the member set, and not to the source port that a NAT gave the session.
func TestTrunkDataAddress(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		g.nat = netip.AddrPortFrom(trunkRigAddr.Addr(), 17149)
		g.start()
		assert.Equal(t, trunkRigAddr, g.pair.addr)
		assert.Same(t, g.pair, g.tk.from(trunkRigAddr))
		assert.Nil(t, g.tk.from(g.nat), "a pair is at the relay socket of its member")

		require.NoError(t, g.register(rowDst, rowTTL, 5))
		to, v := g.verdict(5)
		assert.Equal(t, Pass, v)
		assert.Equal(t, trunkRigAddr, to, "packet of a row to relay-a")
		sent, pkts := g.packet(5, 100)
		g.unchanged(sent, pkts)
	})
}
