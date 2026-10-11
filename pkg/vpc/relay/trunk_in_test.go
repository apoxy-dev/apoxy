// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
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
// SA of lane. isPSP tells that the payload is no IP packet.
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

// fromServer gives the relay a PSP packet of server with spi from the address of
// relay-a, as relay-a sends it on. It returns the packet and what the relay sent.
func (g *rowRig) fromServer(spi uint32) ([]byte, []keptPacket) {
	g.t.Helper()
	sent := pspOfSize(g.t, spi, 100)
	return sent, g.arrive(slices.Clone(sent), g.addr)
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

// TestTrunkInDeliver checks which PSP packets from the address of relay-a go
// with no change to a receiver on this relay, and why the others drop.
func TestTrunkInDeliver(t *testing.T) {
	stranger := netip.MustParseAddrPort("203.0.113.9:6081")
	other := agentID(vpcA, "other")
	cases := []struct {
		name   string
		setup  func(t *testing.T, g *rowRig)
		spi    uint32         // SPI of the PSP packet. Zero is 5.
		sealed bool           // relay-a seals the PSP packet with its trunk SA and the tag of server.
		junk   int            // Length of a packet that is no PSP packet. Zero sends a PSP packet.
		from   netip.AddrPort // Source of the packet. Zero is the address of relay-a.
		to     string         // Socket of the receiver that gets the packet. Empty is laptop.
		drop   string         // Reason label of the drop. Empty is no drop.
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
		{
			name: "row of a tag that no entry has",
			setup: func(_ *testing.T, g *rowRig) {
				row := serverRow(5, inTTL)
				row.SenderTag = 9
				g.give(row)
			},
			drop: "trunk_sender",
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
		// A relay of this revision seals no PSP packet of a sender.
		{name: "PSP packet that the other relay sealed with its trunk SA", sealed: true, drop: "trunk_payload"},
		{name: "packet that is no PSP packet", junk: 100, drop: "malformed"},
		{name: "packet that is shorter than a PSP packet", junk: pspwire.Overhead - 1, drop: "malformed"},
		// The row of a member carries only the packets from the address of that member.
		{name: "packet from an address of no member", from: stranger, drop: "unknown_source"},
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
				spi, from := cmp.Or(tc.spi, 5), g.addr
				if tc.from.IsValid() {
					from = tc.from
				}
				sent := pspOfSize(t, spi, 100)
				pkt := slices.Clone(sent)
				switch {
				case tc.sealed:
					pkt = g.sealed(trunkLane, inTag, sent, true)
				case tc.junk > 0:
					pkt = make([]byte, tc.junk)
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

// TestTrunkInSourcePort checks that the relay takes the packets of relay-a from
// each source port of its address, and that each check of a packet stays.
func TestTrunkInSourcePort(t *testing.T) {
	// A NAT of the host of relay-a gives its session a port that its XDP forward does not use.
	port := netip.AddrPortFrom(trunkRigAddr.Addr(), 17149)
	stranger := netip.MustParseAddrPort("203.0.113.9:6081")
	row := func(spi uint32) func(*testing.T, *rowRig) []byte {
		return func(t *testing.T, _ *rowRig) []byte { return pspOfSize(t, spi, 100) }
	}
	inner := func(tag uint32) func(*testing.T, *rowRig) []byte {
		return func(_ *testing.T, g *rowRig) []byte {
			return g.sealed(trunkLane, tag, innerOf(brServer, brQ, 100), false)
		}
	}
	probe := func(_ *testing.T, g *rowRig) []byte {
		return g.sealed(trunkLane, trunkTagRelay, append([]byte{trunkMsgProbe}, make([]byte, 63)...), true)
	}
	// The packet has the SPI of the trunk SA, and a key that the relay did not give.
	otherKey := func(t *testing.T, g *rowRig) []byte { return pspOfSize(t, g.tx.SA(trunkLane).SPI(), 100) }
	cases := []struct {
		name   string
		setup  func(t *testing.T, g *rowRig)
		from   netip.AddrPort                       // Source of the packet. Zero is the address of the session of relay-a.
		pkt    func(t *testing.T, g *rowRig) []byte // Nil is the PSP packet of server with the SPI of its row.
		again  bool                                 // The relay got the packet from the session address before.
		to     string                               // Socket of the agent that gets the packet: laptop, or q in a data frame.
		answer bool                                 // relay-a gets an answer at the address of its session.
		drop   string                               // Reason label of the drop. Empty is no drop.
	}{
		{name: "PSP packet of a row from the session address", to: rowSrc},
		{name: "PSP packet of a row from another port", from: port, to: rowSrc},
		{name: "clear inner packet from another port", from: port, pkt: inner(inTag), to: brQSocket},
		{name: "probe of the member from another port", from: port, pkt: probe, answer: true},
		{name: "SPI with no row from another port", from: port, pkt: row(6), drop: "trunk_no_row"},
		{name: "SPI of the trunk SA with another key from another port", from: port, pkt: otherKey, drop: "malformed"},
		{name: "tag that no entry has from another port", from: port, pkt: inner(9), drop: "trunk_sender"},
		{name: "clear inner packet again from another port", from: port, pkt: inner(inTag), again: true, drop: "trunk_replay"},
		{
			name: "packet that is no PSP packet from another port",
			from: port, pkt: func(*testing.T, *rowRig) []byte { return make([]byte, 100) }, drop: "malformed",
		},
		{
			name: "keepalive of an agent from another port",
			from: port, pkt: func(*testing.T, *rowRig) []byte { return []byte{p2p.TypeKeepalive} },
		},
		{name: "PSP packet of a row from an address of no member", from: stranger, drop: "unknown_source"},
		{
			// An agent on the host of relay-a keeps its own rows.
			name:  "PSP packet of a row from the socket of an agent at the address of relay-a",
			setup: func(_ *testing.T, g *rowRig) { g.agent(agentID(vpcA, "near"), port.String(), "fd00:5::/96") },
			from:  port, drop: "unknown_spi",
		},
		{
			// The address does not tell which of the two members sent the packet.
			name:  "PSP packet of a row from another port of the address of two members",
			setup: func(_ *testing.T, g *rowRig) { g.secondAt(true, netip.AddrPortFrom(trunkRigAddr.Addr(), 7000)) },
			from:  port, drop: "unknown_source",
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				q := g.bridgeEnd(dp.Mode_MODE_QUIC, "q", brQSocket, brQNet)
				g.serve()
				g.give(serverRow(5, inTTL))
				if tc.setup != nil {
					tc.setup(t, g)
				}
				build, from := row(5), g.addr
				if tc.pkt != nil {
					build = tc.pkt
				}
				if tc.from.IsValid() {
					from = tc.from
				}
				pkt := build(t, g)
				sent := slices.Clone(pkt)
				if tc.again {
					require.Empty(t, g.arrive(slices.Clone(pkt), g.addr))
					require.Len(t, q.frames, 1, "the first copy of the packet")
					q.frames = nil
				}
				out := g.arrive(pkt, from)

				drops := map[string]uint64{}
				if tc.drop != "" {
					drops[tc.drop] = 1
				}
				assert.Equal(t, drops, dropsOf(g.r))
				switch {
				case tc.to == rowSrc:
					require.Len(t, out, 1)
					assert.Equal(t, netip.MustParseAddrPort(rowSrc), out[0].to)
					assert.Equal(t, sent, out[0].b, "the packet of the agent does not change")
				case tc.answer:
					// The NAT of relay-a passes only a packet to the address of the session.
					require.Len(t, out, 1)
					assert.Equal(t, g.addr, out[0].to)
					msg, _, _, err := g.rxq.ReceiveTrunk(out[0].b)
					require.NoError(t, err)
					assert.EqualValues(t, trunkMsgReply, msg[0])
				default:
					assert.Empty(t, out, "the relay sends nothing on its socket")
				}
				assert.Len(t, q.frames, btoi(tc.to == brQSocket))
				packets, _ := g.txOf(g.laptop)
				assert.EqualValues(t, btoi(tc.to == rowSrc), packets)
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
			// A PSP packet from an address of no member is the packet of no sender.
			name: "the other relay stops",
			end: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshRestart)
				g.deliver()
			},
			drop: "unknown_source", none: true,
		},
		{
			name: "the other relay leaves the member set",
			end: func(_ *testing.T, g *rowRig) {
				g.m.SetMembers(nil)
				g.deliver()
			},
			drop: "unknown_source", none: true,
		},
		{
			// The rows of a lost relay stay, as its attachments do. Its pair does not.
			name: "the other relay is lost",
			end: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				time.Sleep(downAfter - time.Nanosecond)
				g.deliver()
				g.passes(5, rowSrc, "packet while the other relay is up")
				time.Sleep(time.Nanosecond)
				g.deliver()
			},
			drop: "unknown_source", rows: 1,
		},
		{
			name: "the other relay has a new session",
			end: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				g.rejoin(trunkRevision, trunkRigAddr)
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

				first, old := g.sess, pspOfSize(t, 5, 100)
				g.end(first, meshLost)
				if tc.down {
					time.Sleep(downAfter)
					g.deliver()
				} else {
					g.passes(5, rowSrc, "packet while the other relay is up")
				}
				rows, _ := g.kept()
				assert.Equal(t, 1, rows, "the rows stay with no session")

				g.rejoin(trunkRevision, tc.addr)
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
					assert.Empty(t, g.arrive(old, trunkRigAddr), "packet from the address before")
					before["unknown_source"]++
					assert.Equal(t, before, dropsOf(g.r))
				}
			})
		})
	}
}

// TestTrunkInMembers checks that two members can have rows with the same SPI, and
// that each row carries only the packets from the address of its member.
func TestTrunkInMembers(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		g.agent(agentID(vpcA, "home"), rowHome, "fd00:3::/96")
		g.serve()
		// relay-b has an agent with the tag of server on relay-a, and a row for it.
		b := g.second(true)
		require.NoError(t, g.m.pres.apply(b.sess, &dp.PresenceUpdate{Entries: []*dp.Presence{
			atGen(liveEntry("y", agentID(vpcA, "other"), "", inTag, prefixB), 10),
		}}))
		require.NoError(t, g.tk.rowsFrom(b.sess))
		require.NoError(t, g.tk.setRows(b.sess, &dp.SPIRowUpdate{Rows: []*dp.SPIRow{serverRow(5, inTTL)}}, time.Now()))
		g.drops(5, "trunk_no_row", "packet of relay-a for a row of relay-b")

		fromB := func() []keptPacket {
			sent := pspOfSize(t, 5, 100)
			out := g.arrive(slices.Clone(sent), b.addr)
			require.Len(t, out, 1, "packet of relay-b for its row")
			assert.Equal(t, sent, out[0].b)
			return out
		}
		assert.Equal(t, netip.MustParseAddrPort(rowSrc), fromB()[0].to)

		// relay-a gives a row with the same SPI to another receiver.
		g.give(rowTo(5, rowLocal))
		g.passes(5, rowHome, "packet of relay-a for its row")
		assert.Equal(t, netip.MustParseAddrPort(rowSrc), fromB()[0].to, "the row of relay-b did not change")
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
		s := g.open(trunkRevision)
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
		// The key of a row is its SPI, so a row of another sender replaces the row.
		{name: "highest tag", row: with(func(r *dp.SPIRow) { r.SenderTag = pspwire.MaxVNI }), kept: true},
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
				had := g.r.in["relay-a"].rows[5]
				g.r.mu.RUnlock()
				// The message has the row of the case between two good rows.
				g.give(serverRow(6, inTTL), tc.row, serverRow(7, inTTL))
				g.r.mu.RLock()
				rows := g.r.in["relay-a"].rows
				got := rows[tc.row.GetSpi()]
				n := len(rows)
				g.r.mu.RUnlock()
				assert.Equal(t, tc.kept, got != nil && got != had, "the relay keeps the row of the case")
				if tc.kept {
					assert.Equal(t, tc.row.GetSenderTag(), got.tag)
				}
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
			name: "session of a relay from before the trunk revision",
			sess: func(g *rowRig) *MeshSession {
				g.end(g.sess, meshLost)
				return g.join(trunkRevision - 1)
			},
			code: rpc.FailedPrecondition, msg: "has no trunk",
		},
		{
			name: "session that a new session replaced",
			sess: func(g *rowRig) *MeshSession {
				old := g.sess
				g.join(trunkRevision)
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
			g.rejoin(trunkRevision, trunkRigAddr)
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
			g.open(trunkRevision)
			s := g.open(trunkRevision)
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
			g.end(g.open(trunkRevision), meshLost)
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
		pkt := func(spi uint32) []byte { return pspOfSize(t, spi, 100) }
		for range 2 {
			assert.Empty(t, g.arrive(pkt(6), g.addr))
		}
		for range 3 {
			assert.Empty(t, g.arrive(pkt(8), g.addr))
		}
		for range 4 {
			assert.Empty(t, g.arrive(pkt(4), g.addr))
		}
		for range 5 {
			assert.Empty(t, g.arrive(g.sealed(trunkLane, inTag, pkt(5), true), g.addr))
		}
		time.Sleep(time.Second + time.Nanosecond)
		for range 6 {
			assert.Empty(t, g.arrive(pkt(7), g.addr))
		}
		g.r.SetPermit(denyAll)
		assert.Empty(t, g.arrive(pkt(5), g.addr))

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
apoxy_vpc_relay_dropped_packets_total{reason="trunk_mtu"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_no_row"} 4
apoxy_vpc_relay_dropped_packets_total{reason="trunk_not_local"} 2
apoxy_vpc_relay_dropped_packets_total{reason="trunk_not_sent"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_payload"} 5
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
