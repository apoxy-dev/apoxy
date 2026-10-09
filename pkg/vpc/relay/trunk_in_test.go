// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// The tests of the rows of another relay have server on relay-a as the sender,
// and laptop on the relay of the test as the receiver. rowSrc is its socket.
const (
	inTag = 7           // Tag of server on relay-a.
	inDst = "fd00:1::1" // Address of laptop.
	inTTL = time.Minute
)

// serverRow is the SPIRow of relay-a for the row of server with spi to laptop.
func serverRow(spi uint32, left time.Duration) *dp.SPIRow {
	return &dp.SPIRow{Vpc: ref(vpcA), SenderTag: inTag, Spi: spi, Destination: inDst, ExpiresIn: durationpb.New(left)}
}

// rowTo is serverRow with another destination.
func rowTo(spi uint32, dst string) *dp.SPIRow {
	row := serverRow(spi, inTTL)
	row.Destination = dst
	return row
}

// dropsOf returns the drop counters of r that are not zero, by reason label.
func dropsOf(r *Router) map[string]uint64 {
	out := map[string]uint64{}
	for i := range r.drops {
		if n := r.drops[i].Load(); n > 0 {
			out[dropLabels[i]] = n
		}
	}
	return out
}

// serve opens the session of relay-a with keys in both directions, its entry
// of server and its SPIRows call.
func (g *rowRig) serve() {
	g.t.Helper()
	g.start()
	require.NoError(g.t, g.tk.rowsFrom(g.sess))
}

// give gives the relay rows in one message of the SPIRows call of the newest
// session of relay-a.
func (g *rowRig) give(rows ...*dp.SPIRow) {
	g.t.Helper()
	require.NoError(g.t, g.tk.setRows(g.sess, &dp.SPIRowUpdate{Rows: rows}, time.Now()))
}

// kept returns the number of rows of relay-a that the relay keeps. ok is false
// when the relay keeps no row set of relay-a.
func (g *rowRig) kept() (n int, ok bool) {
	g.r.mu.RLock()
	defer g.r.mu.RUnlock()
	in := g.r.in["relay-a"]
	if in == nil {
		return 0, false
	}
	return len(in.rows), true
}

// sealed returns payload in a trunk packet of relay-a with tag, sealed with the
// SA of lane. isPSP tells that the payload is a whole PSP packet.
func (g *rowRig) sealed(lane int, tag uint32, payload []byte, isPSP bool) []byte {
	g.t.Helper()
	sa := g.tx.SA(lane)
	require.NotNil(g.t, sa, "relay-a has an SA of lane %d of the relay", lane)
	pkt := make([]byte, len(payload)+pspwire.Overhead)
	var n int
	var err error
	if isPSP {
		n, err = sa.SealTrunkPSP(tag, pkt, payload)
	} else {
		n, err = sa.SealTrunk(tag, pkt, payload)
	}
	require.NoError(g.t, err)
	return pkt[:n]
}

// arrive gives the relay the packet pkt from addr, and returns what the relay
// sent for it.
func (g *rowRig) arrive(pkt []byte, from netip.AddrPort) []keptPacket {
	g.t.Helper()
	g.packets()
	g.handle(pkt, net.UDPAddrFromAddrPort(from))
	return g.packets()
}

// fromServer gives the relay a PSP packet of server with spi in a trunk packet
// from the address of relay-a. It returns the PSP packet and what the relay sent.
func (g *rowRig) fromServer(spi uint32) ([]byte, []keptPacket) {
	g.t.Helper()
	sent := pspOfSize(g.t, spi, 100)
	return sent, g.arrive(g.sealed(trunkLanePSP, inTag, sent, true), g.addr)
}

// passes checks that the receiver at to gets a PSP packet of server with spi,
// with no change, and that the relay counts no drop for it.
func (g *rowRig) passes(spi uint32, to string, msg string) {
	g.t.Helper()
	before := dropsOf(g.r)
	sent, out := g.fromServer(spi)
	require.Len(g.t, out, 1, msg)
	assert.Equal(g.t, netip.MustParseAddrPort(to), out[0].to, msg)
	assert.Equal(g.t, sent, out[0].b, msg)
	assert.Equal(g.t, before, dropsOf(g.r), msg)
}

// drops checks that the relay drops a PSP packet of server with spi, and
// counts it one time with the reason label why.
func (g *rowRig) drops(spi uint32, why string, msg string) {
	g.t.Helper()
	before := dropsOf(g.r)
	_, out := g.fromServer(spi)
	assert.Empty(g.t, out, msg)
	before[why]++
	assert.Equal(g.t, before, dropsOf(g.r), msg)
}

// txOf returns the packets and the inner bytes that the relay sent to the
// attachment of s.
func (g *rowRig) txOf(s *Session) (packets, bytes uint64) {
	g.r.mu.RLock()
	id := s.attachments[0].ID
	g.r.mu.RUnlock()
	for _, st := range g.r.AttachmentStats() {
		if st.ID == id {
			return st.TXPackets, st.TXBytes
		}
	}
	g.t.Fatalf("no stats of attachment %q", id)
	return 0, 0
}

// TestTrunkInDeliver checks which trunk packets of relay-a with a PSP packet
// go to a receiver on this relay, and why the others drop.
func TestTrunkInDeliver(t *testing.T) {
	stranger := netip.MustParseAddrPort("203.0.113.9:6081")
	other := agentID(vpcA, "other")
	v6 := ipPacket(netip.MustParseAddr("fd00:a::1"), netip.MustParseAddr(inDst), make([]byte, 60))
	cases := []struct {
		name  string
		setup func(t *testing.T, g *rowRig)
		lane  int
		tag   uint32         // Zero is the tag of server.
		spi   uint32         // SPI of the PSP packet. Zero is 5.
		clear []byte         // Payload that is sealed as a clear inner packet.
		junk  bool           // The payload is no PSP packet.
		from  netip.AddrPort // Source of the trunk packet. Zero is the address of relay-a.
		to    string         // Socket of the receiver that gets the packet. Empty is laptop.
		drop  string         // Reason label of the drop. Empty is no drop.
	}{
		{name: "row of the sender"},
		{
			name:  "row to an IPv4 address in the mapped form",
			setup: func(_ *testing.T, g *rowRig) { g.give(rowTo(8, "::ffff:10.7.0.1")) },
			spi:   8, to: "192.0.2.5:1",
		},
		{
			name: "Permit allows only the sender to the address",
			setup: func(_ *testing.T, g *rowRig) {
				g.r.SetPermit(func(srcVPC VPCKey, id string, dstVPC VPCKey, dst netip.Addr) bool {
					return srcVPC == vpcA && id == server && dstVPC == vpcA && dst == netip.MustParseAddr(inDst)
				})
			},
		},
		{
			// A row of another relay has no SA lane, so it uses no lane port.
			name: "receiver that reads a lane port",
			setup: func(_ *testing.T, g *rowRig) {
				g.r.mu.Lock()
				defer g.r.mu.Unlock()
				g.laptop.lanes, g.laptop.receive, g.laptop.laneSeen = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.9:1001")}, true, 1
			},
		},
		{name: "SPI with no row", spi: 6, drop: "trunk_no_row"},
		{name: "tag with no row", tag: inTag + 1, drop: "trunk_no_row"},
		{
			name: "row of a tag that no entry has",
			setup: func(_ *testing.T, g *rowRig) {
				row := serverRow(5, inTTL)
				row.SenderTag = 9
				g.give(row)
			},
			tag: 9, drop: "trunk_sender",
		},
		{
			name: "row in another VPC than the entry of its tag",
			setup: func(_ *testing.T, g *rowRig) {
				row := serverRow(8, inTTL)
				row.Vpc = ref(vpcB)
				g.give(row)
			},
			spi: 8, drop: "trunk_sender",
		},
		{
			name:  "Permit denies",
			setup: func(_ *testing.T, g *rowRig) { g.r.SetPermit(denyAll) },
			drop:  "trunk_permit",
		},
		{
			name: "Permit allows only another subject",
			setup: func(_ *testing.T, g *rowRig) {
				g.r.SetPermit(func(_ VPCKey, id string, _ VPCKey, _ netip.Addr) bool { return id == laptop })
			},
			drop: "trunk_permit",
		},
		{
			name:  "row to an address on the relay of the sender",
			setup: func(_ *testing.T, g *rowRig) { g.give(rowTo(8, rowDst)) },
			spi:   8, drop: "trunk_not_local",
		},
		{
			name: "row to an address on a third relay",
			setup: func(t *testing.T, g *rowRig) {
				b := g.second(true)
				require.NoError(t, g.m.pres.apply(b.sess, &dp.PresenceUpdate{Entries: []*dp.Presence{
					atGen(liveEntry("y", other, "", 3, prefixB), 10),
				}}))
				require.Equal(t, "y@relay-b", routeTable(g.r, vpcA)[prefixB])
				g.give(rowTo(8, "fd00:b::1"))
			},
			spi: 8, drop: "trunk_not_local",
		},
		{
			name:  "row to an address with no route",
			setup: func(_ *testing.T, g *rowRig) { g.give(rowTo(8, "fd00:f::1")) },
			spi:   8, drop: "trunk_not_local",
		},
		{name: "PSP packet on the lane with a replay window", lane: trunkLaneInner, drop: "trunk_lane"},
		{name: "clear packet on the lane for PSP packets", clear: v6, drop: "trunk_lane"},
		{name: "payload that is no PSP packet", junk: true, drop: "malformed"},
		{name: "packet from an address of no member", from: stranger, drop: "malformed"},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				v4 := g.agent(agentID(vpcA, "v4"), "192.0.2.5:1", "10.7.0.0/16")
				g.serve()
				g.give(serverRow(5, inTTL))
				if tc.setup != nil {
					tc.setup(t, g)
				}
				tag, spi, from := cmp.Or(tc.tag, inTag), cmp.Or(tc.spi, 5), g.addr
				if tc.from.IsValid() {
					from = tc.from
				}
				sent := pspOfSize(t, spi, 100)
				var pkt []byte
				switch {
				case tc.clear != nil:
					pkt = g.sealed(tc.lane, tag, tc.clear, false)
				case tc.junk:
					pkt = g.sealed(tc.lane, tag, make([]byte, 100), true)
				default:
					pkt = g.sealed(tc.lane, tag, sent, true)
				}
				out := g.arrive(pkt, from)

				receiver, socket := g.laptop, rowSrc
				if tc.to != "" {
					receiver, socket = v4, tc.to
				}
				packets, bytes := g.txOf(receiver)
				if tc.drop != "" {
					assert.Empty(t, out, "the relay sends nothing for a packet that it drops")
					assert.Equal(t, map[string]uint64{tc.drop: 1}, dropsOf(g.r))
					assert.Zero(t, packets)
					assert.Zero(t, bytes)
					return
				}
				require.Len(t, out, 1)
				assert.Equal(t, netip.MustParseAddrPort(socket), out[0].to, "the packet goes to the session address of the receiver")
				assert.Equal(t, sent, out[0].b, "the packet of the agent does not change")
				assert.Empty(t, dropsOf(g.r))
				// The attachment of the receiver counts the inner packet.
				assert.EqualValues(t, 1, packets)
				assert.EqualValues(t, 100, bytes)
			})
		})
	}
}

// TestTrunkInOrder checks that the packets of a row drop for the condition
// that is not there, and go at once when it comes.
func TestTrunkInOrder(t *testing.T) {
	const (
		row      = "row"
		entry    = "entry of the sender"
		permit   = "Permit"
		receiver = "receiver"
	)
	cases := []struct {
		name  string
		steps []string
		drop  string // Reason label of the drops before the last step.
	}{
		{name: "the row comes last", steps: []string{entry, permit, receiver, row}, drop: "trunk_no_row"},
		{name: "the entry of the sender comes last", steps: []string{row, receiver, permit, entry}, drop: "trunk_sender"},
		{name: "Permit allows last", steps: []string{row, entry, receiver, permit}, drop: "trunk_permit"},
		{name: "the receiver attaches last", steps: []string{permit, row, entry, receiver}, drop: "trunk_not_local"},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				g.connect()
				require.NoError(t, g.tk.rowsFrom(g.sess))
				g.r.SetPermit(denyAll)
				do := map[string]func(){
					row:      func() { g.give(rowTo(5, rowLocal)) },
					entry:    func() { g.announce(entryOf("x", server, inTag, 10)) },
					permit:   func() { g.r.SetPermit(SameVPC) },
					receiver: func() { g.agent(agentID(vpcA, "home"), rowHome, "fd00:3::/96") },
				}
				for i, step := range tc.steps {
					if i == len(tc.steps)-1 {
						g.drops(5, tc.drop, "packet before the last step")
					} else {
						_, out := g.fromServer(5)
						assert.Empty(t, out, "packet before the step %q", step)
					}
					do[step]()
				}
				g.passes(5, rowHome, "packet after the last step")
			})
		})
	}
}

// TestTrunkInEnd checks each way that a row of another relay ends. The row is
// SPI 5 of server on relay-a to laptop, and it carried a packet before.
func TestTrunkInEnd(t *testing.T) {
	const downAfter = 3 * time.Second
	cases := []struct {
		name string
		end  func(t *testing.T, g *rowRig)
		drop string // Reason label of the drop of the next packet.
		rows int    // Rows of relay-a that the relay keeps after the end.
		none bool   // The relay keeps no row set of relay-a after the end.
	}{
		{
			name: "the other relay removes the row",
			end: func(_ *testing.T, g *rowRig) {
				g.give(&dp.SPIRow{Vpc: ref(vpcA), SenderTag: inTag, Spi: 5, Removed: true})
			},
			drop: "trunk_no_row",
		},
		{
			name: "the time of the row ends",
			end:  func(*testing.T, *rowRig) { time.Sleep(inTTL + time.Nanosecond) },
			drop: "trunk_expired", rows: 1,
		},
		{
			name: "the sweep after the time of the row",
			end: func(_ *testing.T, g *rowRig) {
				time.Sleep(inTTL + time.Nanosecond)
				g.r.Sweep(time.Now())
			},
			drop: "trunk_no_row",
		},
		{
			name: "the sweep before the time of the row",
			end: func(t *testing.T, g *rowRig) {
				time.Sleep(inTTL)
				g.r.Sweep(time.Now())
				g.passes(5, rowSrc, "packet at the end time")
				g.r.SetPermit(denyAll)
			},
			drop: "trunk_permit", rows: 1,
		},
		{
			name: "the attachment of the sender ends",
			end:  func(_ *testing.T, g *rowRig) { g.announce(goneAt("x", 11)) },
			drop: "trunk_sender", rows: 1,
		},
		{
			name: "Permit stops allowing it",
			end:  func(_ *testing.T, g *rowRig) { g.r.SetPermit(denyAll) },
			drop: "trunk_permit", rows: 1,
		},
		{
			name: "the receiver closes",
			end:  func(_ *testing.T, g *rowRig) { g.r.removeSession(g.laptop) },
			drop: "trunk_not_local", rows: 1,
		},
		{
			name: "the receiver detaches",
			end: func(t *testing.T, g *rowRig) {
				_, _, err := g.r.detach(g.laptop, "att-"+rowSrc)
				require.NoError(t, err)
			},
			drop: "trunk_not_local", rows: 1,
		},
		{
			name: "the address goes to an agent of the other relay",
			end: func(t *testing.T, g *rowRig) {
				g.r.removeSession(g.laptop)
				g.announce(atGen(liveEntry("z", agentID(vpcA, "other"), "", 8, "fd00:1::/96"), 20))
				require.Equal(t, "z@relay-a", routeTable(g.r, vpcA)["fd00:1::/96"])
			},
			drop: "trunk_not_local", rows: 1,
		},
		{
			// A trunk packet from an address of no member is a malformed packet.
			name: "the other relay stops",
			end: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshRestart)
				g.deliver()
			},
			drop: "malformed", none: true,
		},
		{
			name: "the other relay leaves the member set",
			end: func(_ *testing.T, g *rowRig) {
				g.m.SetMembers(nil)
				g.deliver()
			},
			drop: "malformed", none: true,
		},
		{
			// The rows of a lost relay stay, as its attachments do. Its keys do not.
			name: "the other relay is lost",
			end: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				time.Sleep(downAfter - time.Nanosecond)
				g.deliver()
				g.passes(5, rowSrc, "packet while the other relay is up")
				time.Sleep(time.Nanosecond)
				g.deliver()
			},
			drop: "malformed", rows: 1,
		},
		{
			name: "the other relay has a new session",
			end: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				g.rejoin(trunkRowsRevision, trunkRigAddr)
			},
			drop: "trunk_no_row", none: true,
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				g.serve()
				g.give(serverRow(5, inTTL))
				g.passes(5, rowSrc, "packet before the end")

				tc.end(t, g)
				g.drops(5, tc.drop, "packet after the end")
				g.drops(5, tc.drop, "second packet after the end")
				rows, ok := g.kept()
				assert.Equal(t, tc.rows, rows, "rows of relay-a that the relay keeps")
				assert.Equal(t, !tc.none, ok, "the relay keeps a row set of relay-a")
			})
		})
	}
}

// TestTrunkInSession checks the rows of another relay after its new session:
// it gives its rows and entries again, and an old entry names no sender.
func TestTrunkInSession(t *testing.T) {
	const downAfter = 3 * time.Second
	moved := netip.MustParseAddrPort("198.51.100.7:6081")
	cases := []struct {
		name string
		down bool           // The other relay is down before its new session.
		addr netip.AddrPort // Address of the new session.
	}{
		{name: "new session before the other relay is down", addr: trunkRigAddr},
		{name: "new session from a new address before the other relay is down", addr: moved},
		{name: "other relay lost and back", down: true, addr: trunkRigAddr},
		{name: "other relay lost and back at a new address", down: true, addr: moved},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				g.serve()
				g.give(serverRow(5, inTTL))
				g.passes(5, rowSrc, "packet on the first session")

				first, old := g.sess, g.sealed(trunkLanePSP, inTag, pspOfSize(t, 5, 100), true)
				g.end(first, meshLost)
				if tc.down {
					time.Sleep(downAfter)
					g.deliver()
				} else {
					g.passes(5, rowSrc, "packet while the other relay is up")
				}
				rows, _ := g.kept()
				assert.Equal(t, 1, rows, "the rows stay with no session")

				g.rejoin(trunkRowsRevision, tc.addr)
				_, ok := g.kept()
				assert.False(t, ok, "the rows of the session before ended")
				g.drops(5, "trunk_no_row", "packet before the rows of the new session")
				assert.Equal(t, rpc.FailedPrecondition, rpc.CodeOf(g.tk.rowsFrom(first)), "SPIRows call on the session before")
				require.NoError(t, g.tk.rowsFrom(g.sess))
				g.give(serverRow(5, inTTL))
				g.drops(5, "trunk_sender", "packet with a tag that only the session before gave")
				// The other relay sends the entry again in the full set of its new session.
				g.announce(entryOf("x", server, inTag, 10))
				g.passes(5, rowSrc, "packet on the new session")

				if tc.addr != trunkRigAddr {
					before := dropsOf(g.r)
					assert.Empty(t, g.arrive(old, trunkRigAddr), "trunk packet from the address before")
					before["malformed"]++
					assert.Equal(t, before, dropsOf(g.r))
				}
			})
		})
	}
}

// TestTrunkInMembers checks that the row of one relay carries no packet of
// another relay with the same sender tag and SPI.
func TestTrunkInMembers(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		g.serve()
		// relay-b has an agent with the tag of server on relay-a, and a row for it.
		b := g.second(true)
		require.NoError(t, g.m.pres.apply(b.sess, &dp.PresenceUpdate{Entries: []*dp.Presence{
			atGen(liveEntry("y", agentID(vpcA, "other"), "", inTag, prefixB), 10),
		}}))
		require.NoError(t, g.tk.rowsFrom(b.sess))
		require.NoError(t, g.tk.setRows(b.sess, &dp.SPIRowUpdate{Rows: []*dp.SPIRow{serverRow(5, inTTL)}}, time.Now()))
		g.drops(5, "trunk_no_row", "packet of relay-a for a row of relay-b")

		sent := pspOfSize(t, 5, 100)
		pkt := make([]byte, len(sent)+pspwire.Overhead)
		n, err := b.tx.SA(trunkLanePSP).SealTrunkPSP(inTag, pkt, sent)
		require.NoError(t, err)
		out := g.arrive(pkt[:n], b.addr)
		require.Len(t, out, 1, "packet of relay-b for its row")
		assert.Equal(t, netip.MustParseAddrPort(rowSrc), out[0].to)
		assert.Equal(t, sent, out[0].b)
	})
}

// TestTrunkInNewPresence checks that a row of the session before carries no
// packet after a new session of the other relay has a Presence call.
func TestTrunkInNewPresence(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		g.serve()
		g.give(serverRow(5, inTTL))
		g.passes(5, rowSrc, "packet on the first session")
		g.end(g.sess, meshLost)
		// The hooks of the new session run at the deliver below, so the row stays.
		s := g.open(trunkRowsRevision)
		require.NoError(t, g.m.pres.accept(s))
		g.drops(5, "trunk_sender", "packet after the new Presence call")
		// The other relay can have given the tag to another agent.
		require.NoError(t, g.m.pres.apply(s, &dp.PresenceUpdate{Entries: []*dp.Presence{entryOf("x", server, inTag, 11)}}))
		g.drops(5, "trunk_sender", "packet with the tag of an entry of the new session")
		g.deliver()
		g.drops(5, "trunk_no_row", "packet after the hooks of the new session")
	})
}

// TestTrunkInEntriesGone checks that a row carries no packet after the relay
// drops the entries of the other relay, also when no route changes.
func TestTrunkInEntriesGone(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		g.connect()
		require.NoError(t, g.tk.rowsFrom(g.sess))
		// The entry of the sender has no prefix, so it gives no route.
		g.announce(atGen(liveEntry("x", server, "", inTag), 10))
		g.give(serverRow(5, inTTL))
		g.passes(5, rowSrc, "packet before the entries end")
		// Only the hook of the entries runs, so the rows and the keys stay.
		g.end(g.sess, meshLost)
		g.m.pres.down(MeshChange{Name: "relay-a", Down: MeshRestart})
		g.drops(5, "trunk_sender", "packet after the entries ended")
	})
}

// TestTrunkInRows checks which rows of a message the relay keeps. A row with a
// wrong form changes no row, and the other rows of its message are kept.
func TestTrunkInRows(t *testing.T) {
	with := func(change func(*dp.SPIRow)) *dp.SPIRow {
		row := serverRow(5, inTTL)
		change(row)
		return row
	}
	cases := []struct {
		name string
		row  *dp.SPIRow
		kept bool // The relay keeps the row of the case.
		rows int  // Rows of relay-a after the message. Zero is 3: SPI 5, 6 and 7.
	}{
		{name: "row", row: serverRow(5, inTTL), kept: true},
		{name: "highest tag", row: with(func(r *dp.SPIRow) { r.SenderTag = pspwire.MaxVNI }), kept: true, rows: 4},
		{name: "expiry of 1 ns", row: with(func(r *dp.SPIRow) { r.ExpiresIn = durationpb.New(time.Nanosecond) }), kept: true},
		{name: "tag 0", row: with(func(r *dp.SPIRow) { r.SenderTag = 0 })},
		{name: "tag above 24 bits", row: with(func(r *dp.SPIRow) { r.SenderTag = pspwire.MaxVNI + 1 })},
		{name: "reserved SPI", row: with(func(r *dp.SPIRow) { r.Spi = 0 })},
		{name: "no VPC", row: with(func(r *dp.SPIRow) { r.Vpc = nil })},
		{name: "VPC with no project", row: with(func(r *dp.SPIRow) { r.Vpc = &dp.VPCRef{VpcUid: vpcA.UID} })},
		{name: "no destination", row: with(func(r *dp.SPIRow) { r.Destination = "" })},
		{name: "destination that is a prefix", row: with(func(r *dp.SPIRow) { r.Destination = "fd00:1::1/128" })},
		{name: "no expires_in", row: with(func(r *dp.SPIRow) { r.ExpiresIn = nil })},
		{name: "expires_in of zero", row: with(func(r *dp.SPIRow) { r.ExpiresIn = durationpb.New(0) })},
		{name: "expires_in below zero", row: with(func(r *dp.SPIRow) { r.ExpiresIn = durationpb.New(-time.Second) })},
		{name: "expires_in out of range", row: with(func(r *dp.SPIRow) { r.ExpiresIn = &durationpb.Duration{Seconds: 1 << 50} })},
		{name: "removed row", row: &dp.SPIRow{Vpc: ref(vpcA), SenderTag: inTag, Spi: 5, Removed: true}, rows: 2},
		{name: "removed row with no VPC", row: &dp.SPIRow{SenderTag: inTag, Spi: 5, Removed: true}, rows: 2},
		{name: "removed row that the relay does not have", row: &dp.SPIRow{Vpc: ref(vpcA), SenderTag: inTag, Spi: 9, Removed: true}},
		{name: "removed row with tag 0", row: &dp.SPIRow{Vpc: ref(vpcA), Spi: 5, Removed: true}},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				g.serve()
				// The relay has a row with the SPI of the row of the case.
				g.give(serverRow(5, inTTL))
				g.r.mu.RLock()
				had := g.r.in["relay-a"].rows[rowKey{inTag, 5}]
				g.r.mu.RUnlock()
				// The message has the row of the case between two good rows.
				g.give(serverRow(6, inTTL), tc.row, serverRow(7, inTTL))
				g.r.mu.RLock()
				rows := g.r.in["relay-a"].rows
				got := rows[rowKey{tc.row.GetSenderTag(), tc.row.GetSpi()}]
				n := len(rows)
				g.r.mu.RUnlock()
				assert.Equal(t, tc.kept, got != nil && got != had, "the relay keeps the row of the case")
				assert.Equal(t, cmp.Or(tc.rows, 3), n, "rows that the relay keeps")
				g.passes(6, rowSrc, "row before the row of the case")
				g.passes(7, rowSrc, "row after the row of the case")
			})
		})
	}
}

// TestTrunkInAgain checks a row that the other relay sends again: the new end
// time and the new destination replace the old ones.
func TestTrunkInAgain(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		g.agent(agentID(vpcA, "home"), rowHome, "fd00:3::/96")
		g.serve()
		g.give(serverRow(5, inTTL))
		time.Sleep(inTTL - time.Second)
		g.give(serverRow(5, inTTL))
		time.Sleep(inTTL)
		g.passes(5, rowSrc, "packet at the new end time")
		time.Sleep(time.Nanosecond)
		g.drops(5, "trunk_expired", "packet after the new end time")

		g.give(rowTo(5, rowLocal))
		g.passes(5, rowHome, "packet after the row got a new destination")
	})
}

// TestTrunkInSweep checks what a sweep removes of the rows of another relay:
// each row after its time, and the empty row set of a session that ended.
func TestTrunkInSweep(t *testing.T) {
	cases := []struct {
		name  string
		ended bool          // The session of relay-a ended.
		wait  time.Duration // Time from the row to the sweep.
		rows  int
		set   bool // The relay keeps the row set.
	}{
		{name: "live row of a session", wait: inTTL, rows: 1, set: true},
		{name: "ended row of a session", wait: inTTL + time.Nanosecond, set: true},
		{name: "live row of a session that ended", ended: true, wait: inTTL, rows: 1, set: true},
		{name: "ended row of a session that ended", ended: true, wait: inTTL + time.Nanosecond},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				g.serve()
				g.give(serverRow(5, inTTL))
				if tc.ended {
					g.end(g.sess, meshLost)
				}
				time.Sleep(tc.wait)
				g.r.Sweep(time.Now())
				rows, ok := g.kept()
				assert.Equal(t, tc.rows, rows)
				assert.Equal(t, tc.set, ok)
				if !tc.ended {
					// The call of the session gives rows also after its set was empty.
					g.give(serverRow(6, inTTL))
					g.passes(6, rowSrc, "row after the sweep")
				}
			})
		})
	}
}

// TestTrunkInCall checks which SPIRows calls the relay refuses.
func TestTrunkInCall(t *testing.T) {
	cases := []struct {
		name string
		sess func(g *rowRig) *MeshSession // Session of the call, after relay-a connected.
		code rpc.Code
		msg  string
	}{
		{name: "first call of the session", sess: func(g *rowRig) *MeshSession { return g.sess }, code: rpc.OK},
		{
			name: "second call of the session",
			sess: func(g *rowRig) *MeshSession {
				require.NoError(g.t, g.tk.rowsFrom(g.sess))
				g.give(serverRow(5, inTTL))
				return g.sess
			},
			code: rpc.FailedPrecondition, msg: "already has an SPIRows call",
		},
		{
			name: "session of a relay from before the SPI rows",
			sess: func(g *rowRig) *MeshSession {
				g.end(g.sess, meshLost)
				return g.join(trunkRowsRevision - 1)
			},
			code: rpc.FailedPrecondition, msg: "has no SPI rows",
		},
		{
			name: "session that a new session replaced",
			sess: func(g *rowRig) *MeshSession {
				old := g.sess
				g.join(trunkRowsRevision)
				return old
			},
			code: rpc.FailedPrecondition, msg: "not a member with this session",
		},
		{
			name: "session of a relay that left the member set",
			sess: func(g *rowRig) *MeshSession {
				g.m.SetMembers(nil)
				return g.sess
			},
			code: rpc.FailedPrecondition, msg: "not a member with this session",
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				g.start()
				s := tc.sess(g)
				rows, _ := g.kept()
				err := g.tk.rowsFrom(s)
				require.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
				if tc.msg != "" {
					assert.ErrorContains(t, err, tc.msg)
				}
				after, _ := g.kept()
				assert.Equal(t, rows, after, "a refused call changes no row")
			})
		})
	}

	t.Run("message after a new call replaced the call", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			g := newRowRig(t, cfg)
			defer g.stop()
			g.serve()
			old := g.sess
			g.end(old, meshLost)
			g.rejoin(trunkRowsRevision, trunkRigAddr)
			require.NoError(t, g.tk.rowsFrom(g.sess))
			err := g.tk.setRows(old, &dp.SPIRowUpdate{Rows: []*dp.SPIRow{serverRow(5, inTTL)}}, time.Now())
			assert.Equal(t, rpc.FailedPrecondition, rpc.CodeOf(err), "error: %v", err)
			rows, ok := g.kept()
			assert.True(t, ok)
			assert.Zero(t, rows, "the call of the session before gives no row")
		})
	})
	t.Run("call of a new session before its hooks", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			g := newRowRig(t, cfg)
			defer g.stop()
			g.serve()
			g.give(serverRow(5, inTTL))
			g.end(g.sess, meshLost)
			// The hooks of the two new sessions run at the deliver below.
			g.open(trunkRowsRevision)
			s := g.open(trunkRowsRevision)
			require.NoError(t, g.tk.rowsFrom(s))
			rows, ok := g.kept()
			assert.True(t, ok)
			assert.Zero(t, rows, "the new call ends the rows of the session before")
			require.NoError(t, g.tk.setRows(s, &dp.SPIRowUpdate{Rows: []*dp.SPIRow{serverRow(6, inTTL)}}, time.Now()))
			g.deliver()
			rows, _ = g.kept()
			assert.Equal(t, 1, rows, "the hooks keep the rows of the call of the newest session")
		})
	})
	t.Run("new session that ends before its hooks", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			g := newRowRig(t, cfg)
			defer g.stop()
			g.serve()
			g.give(serverRow(5, inTTL))
			g.end(g.sess, meshLost)
			g.end(g.open(trunkRowsRevision), meshLost)
			g.deliver()
			_, ok := g.kept()
			assert.False(t, ok, "the rows of the session before the new session ended")
		})
	})
	t.Run("call that is not on a mesh session", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			g := newRowRig(t, cfg)
			defer g.stop()
			_, err := g.m.SPIRows(context.Background(), nil)
			assert.Equal(t, rpc.FailedPrecondition, rpc.CodeOf(err), "error: %v", err)
		})
	})
}

// TestTrunkInMetric checks the reason labels of the drops of the PSP packets of
// senders on another relay in the drop metric.
func TestTrunkInMetric(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		g.serve()
		other := serverRow(8, inTTL)
		other.SenderTag = 9
		g.give(serverRow(5, inTTL), rowTo(6, "fd00:f::1"), serverRow(7, time.Second), other)
		pkt := func(lane int, tag, spi uint32) []byte { return g.sealed(lane, tag, pspOfSize(t, spi, 100), true) }
		for range 2 {
			assert.Empty(t, g.arrive(pkt(trunkLanePSP, inTag, 6), g.addr))
		}
		for range 3 {
			assert.Empty(t, g.arrive(pkt(trunkLanePSP, 9, 8), g.addr))
		}
		for range 4 {
			assert.Empty(t, g.arrive(pkt(trunkLanePSP, inTag, 4), g.addr))
		}
		for range 5 {
			assert.Empty(t, g.arrive(pkt(trunkLaneInner, inTag, 5), g.addr))
		}
		time.Sleep(time.Second + time.Nanosecond)
		for range 6 {
			assert.Empty(t, g.arrive(pkt(trunkLanePSP, inTag, 7), g.addr))
		}
		g.r.SetPermit(denyAll)
		assert.Empty(t, g.arrive(pkt(trunkLanePSP, inTag, 5), g.addr))

		const want = `
# HELP apoxy_vpc_relay_dropped_packets_total Packets that the relay dropped before it forwarded them, by reason.
# TYPE apoxy_vpc_relay_dropped_packets_total counter
apoxy_vpc_relay_dropped_packets_total{reason="closed"} 0
apoxy_vpc_relay_dropped_packets_total{reason="lane_meter"} 0
apoxy_vpc_relay_dropped_packets_total{reason="malformed"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_malformed"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_no_session"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_not_local"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_not_sent"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_old_member"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_old_session"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_permit"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_source"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_too_large"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_unknown_tag"} 0
apoxy_vpc_relay_dropped_packets_total{reason="send_queue"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_expired"} 6
apoxy_vpc_relay_dropped_packets_total{reason="trunk_keys"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_lane"} 5
apoxy_vpc_relay_dropped_packets_total{reason="trunk_mtu"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_no_row"} 4
apoxy_vpc_relay_dropped_packets_total{reason="trunk_not_local"} 2
apoxy_vpc_relay_dropped_packets_total{reason="trunk_not_sent"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_permit"} 1
apoxy_vpc_relay_dropped_packets_total{reason="trunk_replay"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_sender"} 3
apoxy_vpc_relay_dropped_packets_total{reason="trunk_source"} 0
apoxy_vpc_relay_dropped_packets_total{reason="tunnel_limit"} 0
apoxy_vpc_relay_dropped_packets_total{reason="unknown_source"} 0
apoxy_vpc_relay_dropped_packets_total{reason="unknown_spi"} 0
`
		assert.NoError(t, testutil.CollectAndCompare(g.r, strings.NewReader(want), "apoxy_vpc_relay_dropped_packets_total"))
	})
}
