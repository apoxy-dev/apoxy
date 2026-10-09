// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// The bridge tests with one relay have server on relay-a, which the test plays,
// with the tag inTag. The agents q and p are on the relay of the test.
const (
	brServerNet4 = "10.9.0.0/16" // IPv4 prefix of server. prefixA is its IPv6 prefix.
	brServer     = "fd00:a::1"
	brServer4    = "10.9.0.1"
	brQSocket    = "192.0.2.21:1"
	brQNet       = "fd00:21::/96"
	brQNet4      = "10.21.0.0/16"
	brQ          = "fd00:21::1"
	brQ4         = "10.21.0.1"
	brPSocket    = "192.0.2.22:1"
	brPNet       = "fd00:22::/96"
	brP          = "fd00:22::1"
)

// innerOf returns an IPv4 or IPv6 packet of n bytes from src to dst.
func innerOf(src, dst string, n int) []byte {
	s, d := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	header := 40
	if s.Is4() {
		header = 20
	}
	payload := make([]byte, n-header)
	for i := range payload {
		payload[i] = byte(i)
	}
	return ipPacket(s, d, payload)
}

// bridgeEnd is an agent of the relay of the test: a session with an attachment.
type bridgeEnd struct {
	s      *Session
	socket netip.AddrPort
	psp    *pspAgent // In PSP mode: its SAs to and from the relay.
	frames [][]byte  // In QUIC mode: the datagrams that the relay sent to it.
	refuse error     // The answer of its session to each datagram, if set.
}

// bridgeEnd adds the agent name at socket in mode, with an attachment that has
// prefixes. A PSP-mode agent takes the relay SAs, and gives no SA.
func (g *rowRig) bridgeEnd(mode dp.Mode, name, socket string, prefixes ...string) *bridgeEnd {
	g.t.Helper()
	e := &bridgeEnd{socket: netip.MustParseAddrPort(socket)}
	e.s = newSession(Identity{VPC: vpcA, ID: agentID(vpcA, name)}, func() netip.AddrPort { return e.socket })
	e.s.sendDatagram = func(b []byte) error {
		if e.refuse != nil {
			return e.refuse
		}
		e.frames = append(e.frames, slices.Clone(b))
		return nil
	}
	g.r.addSession(e.s, time.Now())
	require.NoError(g.t, g.r.openSync(e.s, mode, ref(vpcA), nil))
	require.NoError(g.t, g.r.attach(e.s, attachment("att-"+name, prefixes...)))
	if mode == dp.Mode_MODE_PSP {
		offer, err := g.r.offer(e.s, Network{ID: testVNI, MTU: 1280}, time.Now())
		require.NoError(g.t, err)
		e.psp = newPSPAgent(g.t, offer.GetRekey(), time.Now())
	}
	return e
}

// giveSAs gives the relay the SAs of the PSP-mode agent e for packets to e.
func (g *rowRig) giveSAs(e *bridgeEnd) {
	g.t.Helper()
	refused, err := g.r.rekey(e.s, e.psp.req, time.Now())
	require.NoError(g.t, err)
	require.Empty(g.t, refused)
}

// link opens the session of relay-a at revision rev, with keys in both
// directions and a full path. Then relay-a tells of the attachment of server.
func (g *rowRig) link(rev uint32) {
	g.t.Helper()
	g.pair = g.keyed(g.join(rev))
	g.tellServer(10)
}

// tellServer gives the relay the entry of server at generation gen on the
// newest session of relay-a.
func (g *rowRig) tellServer(gen uint64) {
	g.t.Helper()
	g.announce(atGen(liveEntry("x", server, "", inTag, prefixA, brServerNet4), gen))
}

// bridgeSend gives the relay inner from e: a data frame in QUIC mode, or a PSP
// packet with the relay SA from the socket of e. It returns what the relay sent.
func (g *rowRig) bridgeSend(e *bridgeEnd, inner []byte) []keptPacket {
	g.t.Helper()
	g.packets()
	if e.psp != nil {
		g.handle(e.psp.seal(g.t, inner), net.UDPAddrFromAddrPort(e.socket))
	} else {
		g.r.forwardData(e.s, peerconn.EncodeData(nil, testVNI, inner), make([]byte, maxUDP), time.Now())
	}
	return g.packets()
}

// noRoutes returns the addresses of the NoRoute messages that wait for s.
func noRoutes(r *Router, s *Session) []string {
	var out []string
	for _, m := range r.takeSync(s) {
		if nr := m.GetNoRoute(); nr != nil {
			out = append(out, nr.GetAddress())
		}
	}
	return out
}

// senderCounts are the counters of a sender that a bridged packet changes.
type senderCounts struct {
	sent, drops, trunk, tunnel uint64
}

func sentOf(r *Router, s *Session) senderCounts {
	st := r.SenderStats(s)
	return senderCounts{sent: st.DataSent, drops: st.DataDrops, trunk: st.DropTrunk, tunnel: st.DropTunnelLimit}
}

// TestTrunkBridgeSend checks what the relay does with the clear inner packet of
// one of its agents for an address on relay-a: a trunk packet, or which drop.
func TestTrunkBridgeSend(t *testing.T) {
	// unkeyed is a link with no SA of relay-a.
	unkeyed := func(_ *testing.T, g *rowRig) {
		g.join(trunkBridgeRevision)
		g.tellServer(10)
	}
	// unprobed is a link with the SAs of relay-a and no answer to the probe.
	unprobed := func(t *testing.T, g *rowRig) {
		_, err := g.offer(g.join(trunkBridgeRevision))
		require.NoError(t, err)
		g.tellServer(10)
	}
	// limited is unprobed after the probe run failed.
	limited := func(t *testing.T, g *rowRig) {
		unprobed(t, g)
		time.Sleep(trunkProbeWait)
		synctest.Wait()
		require.Equal(t, trunkPathLimited, trunkPath(g.pair.path.Load()))
	}
	cases := []struct {
		name    string
		psp     bool                          // The sender is in PSP mode and uses its relay SA.
		spare   bool                          // The frame comes on a session of the sender with no attachment.
		shard   bool                          // The frame comes on a shard of the sender.
		link    func(t *testing.T, g *rowRig) // Nil is a link at the bridge revision.
		setup   func(t *testing.T, g *rowRig) // Runs after the link.
		v4      bool                          // The inner packet is an IPv4 packet.
		size    int                           // Bytes of the inner packet. Zero is 100.
		drop    string                        // Reason label of the drop count of the relay.
		want    senderCounts                  // Counters of the sender after the packet.
		noRoute bool                          // The sender gets a NoRoute.
		check   func(t *testing.T, g *rowRig) // More checks after the packet.
	}{
		{name: "data frame", want: senderCounts{sent: 1}},
		{name: "data frame with an IPv4 packet", v4: true, want: senderCounts{sent: 1}},
		{name: "data frame on a shard of the sender", shard: true, want: senderCounts{sent: 1}},
		{name: "PSP packet to the relay", psp: true, want: senderCounts{sent: 1}},
		{name: "PSP packet to the relay with an IPv4 packet", psp: true, v4: true, want: senderCounts{sent: 1}},
		{name: "largest packet of a full path", size: trunkMTU, want: senderCounts{sent: 1}},
		{name: "one byte more than a full path carries", size: trunkMTU + 1, drop: "trunk_mtu", want: senderCounts{trunk: 1}},
		{name: "largest packet of a limited path", link: limited, size: trunkLimitedMTU, want: senderCounts{sent: 1}},
		{name: "one byte more than a limited path carries", link: limited, size: trunkLimitedMTU + 1, drop: "trunk_mtu", want: senderCounts{trunk: 1}},
		{name: "largest packet before the first probe result", link: unprobed, size: trunkLimitedMTU, want: senderCounts{sent: 1}},
		{name: "one byte more before the first probe result", link: unprobed, size: trunkLimitedMTU + 1, drop: "trunk_mtu", want: senderCounts{trunk: 1}},
		{name: "PSP packet that is too long for the trunk", psp: true, link: unprobed, size: trunkLimitedMTU + 1, drop: "trunk_mtu", want: senderCounts{trunk: 1}},
		{
			name: "other relay below the bridge revision",
			link: func(_ *testing.T, g *rowRig) { g.link(trunkBridgeRevision - 1) },
			drop: "trunk_keys", want: senderCounts{trunk: 1},
		},
		{
			name: "PSP packet for a relay below the bridge revision", psp: true,
			link: func(_ *testing.T, g *rowRig) { g.link(trunkBridgeRevision - 1) },
			drop: "trunk_keys", want: senderCounts{trunk: 1},
		},
		{name: "other relay gave no SA", link: unkeyed, drop: "trunk_keys", want: senderCounts{trunk: 1}},
		{name: "PSP packet with no SA of the other relay", psp: true, link: unkeyed, drop: "trunk_keys", want: senderCounts{trunk: 1}},
		{
			name:  "other relay revoked the SA of the lane with a replay window",
			setup: func(_ *testing.T, g *rowRig) { g.revoke(trunkLaneInner) },
			drop:  "trunk_keys", want: senderCounts{trunk: 1},
		},
		{
			// The packet goes on the lane with a replay window only.
			name:  "other relay revoked the SA of the lane for PSP packets",
			setup: func(_ *testing.T, g *rowRig) { g.revoke(trunkLanePSP) },
			want:  senderCounts{sent: 1},
		},
		{
			name: "other relay came back below the bridge revision",
			setup: func(_ *testing.T, g *rowRig) {
				g.rejoin(trunkBridgeRevision-1, trunkRigAddr)
				g.tellServer(11)
			},
			drop: "trunk_keys", want: senderCounts{trunk: 1},
		},
		{
			name: "other relay came back at the bridge revision",
			setup: func(_ *testing.T, g *rowRig) {
				g.rejoin(trunkBridgeRevision-1, trunkRigAddr)
				g.rejoin(trunkBridgeRevision, trunkRigAddr)
				g.tellServer(11)
			},
			want: senderCounts{sent: 1},
		},
		{
			// The keys stay while the other relay is up.
			name:  "session of the other relay ended",
			setup: func(_ *testing.T, g *rowRig) { g.end(g.sess, meshLost) },
			want:  senderCounts{sent: 1},
		},
		{
			name: "other relay is down",
			setup: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				time.Sleep(3 * time.Second)
				g.deliver()
				require.Nil(g.t, g.tk.pair("relay-a"))
			},
			drop: "trunk_keys", want: senderCounts{trunk: 1},
		},
		{
			// The route of a member that is down stays until the member leaves the set.
			name: "other relay left the member set after it was down",
			setup: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				time.Sleep(3 * time.Second)
				g.deliver()
				require.Nil(g.t, g.tk.pair("relay-a"))
				g.m.SetMembers(nil)
				g.deliver()
				require.NotContains(g.t, routeTable(g.r, vpcA), prefixA)
			},
			want: senderCounts{drops: 1}, noRoute: true,
		},
		{
			name: "SA with no sequence number left",
			setup: func(_ *testing.T, g *rowRig) {
				sa := g.pair.tx.SA(trunkLaneInner)
				for range 3 {
					_, _ = sa.ReserveN(math.MaxInt32)
				}
			},
			drop: "trunk_keys", want: senderCounts{drops: 1},
		},
		{
			name:  "Permit denies",
			setup: func(_ *testing.T, g *rowRig) { g.r.SetPermit(denyAll) },
			want:  senderCounts{drops: 1}, noRoute: true,
		},
		{name: "session with no sender tag", spare: true, want: senderCounts{drops: 1}},
		{
			name: "tunnel limit", size: 200,
			setup: func(_ *testing.T, g *rowRig) {
				g.r.mu.Lock()
				defer g.r.mu.Unlock()
				for s := range g.r.sessions {
					s.meter = rate.NewLimiter(1, 100)
				}
			},
			drop: "tunnel_limit", want: senderCounts{tunnel: 1},
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				mode := dp.Mode_MODE_QUIC
				if tc.psp {
					mode = dp.Mode_MODE_PSP
				}
				from := g.bridgeEnd(mode, "q", brQSocket, brQNet, brQNet4)
				if tc.link != nil {
					tc.link(t, g)
				} else {
					g.link(trunkBridgeRevision)
				}
				if tc.setup != nil {
					tc.setup(t, g)
				}
				// in is the connection that the packet comes on.
				in := from
				switch {
				case tc.spare:
					// The sessions of a subject send from the routes of the subject.
					spare := &bridgeEnd{s: newSession(from.s.id, func() netip.AddrPort { return netip.MustParseAddrPort("192.0.2.23:1") })}
					g.r.addSession(spare.s, time.Now())
					require.NoError(t, g.r.openSync(spare.s, dp.Mode_MODE_QUIC, ref(vpcA), nil))
					in, from = spare, spare
				case tc.shard:
					// A frame on a shard counts as the session of its attachment.
					in = &bridgeEnd{s: newSession(from.s.id, func() netip.AddrPort { return netip.AddrPort{} })}
					g.r.addSession(in.s, time.Now())
					_, _, err := g.r.joinShard(in.s, "att-q", 1)
					require.NoError(t, err)
				}
				src, dst, nextHdr := brQ, brServer, pspwire.NextHdrV6
				if tc.v4 {
					src, dst, nextHdr = brQ4, brServer4, pspwire.NextHdrV4
				}
				inner := innerOf(src, dst, cmp.Or(tc.size, 100))
				noRoutes(g.r, from.s)
				g.r.mu.RLock()
				tag := from.s.tag
				g.r.mu.RUnlock()

				out := g.bridgeSend(in, inner)
				assert.Equal(t, tc.want, sentOf(g.r, from.s))
				drops := map[string]uint64{}
				if tc.drop != "" {
					drops[tc.drop] = 1
				}
				assert.Equal(t, drops, dropsOf(g.r))
				var told []string
				if tc.noRoute {
					told = []string{dst}
				}
				assert.Equal(t, told, noRoutes(g.r, from.s), "an address with a route gets no NoRoute")
				if tc.want.sent == 0 {
					assert.Empty(t, out, "the relay sends no part of a packet that it drops")
					return
				}
				require.Len(t, out, 1, "one trunk packet for one inner packet")
				assert.Equal(t, g.addr, out[0].to)
				assert.Len(t, out[0].b, len(inner)+pspwire.Overhead)
				assert.Equal(t, g.inner, binary.BigEndian.Uint32(out[0].b[4:8]), "the packet goes on the lane with a replay window")
				payload, gotTag, gotNext, err := g.rxq.ReceiveTrunk(slices.Clone(out[0].b))
				require.NoError(t, err)
				assert.Equal(t, inner, payload, "the inner packet does not change")
				assert.NotZero(t, tag)
				assert.Equal(t, tag, gotTag, "the tag is the tag of the sender on this relay")
				assert.EqualValues(t, nextHdr, gotNext)
				// The attachment of the sender counts the inner packet.
				rx, _ := g.rxOf(from.s)
				assert.EqualValues(t, 1, rx)
			})
		})
	}
}

// rxOf returns the packets and the inner bytes that the relay sent on for the
// attachment of s.
func (g *rowRig) rxOf(s *Session) (packets, bytes uint64) {
	g.r.mu.RLock()
	id := s.attachments[0].ID
	g.r.mu.RUnlock()
	for _, st := range g.r.AttachmentStats() {
		if st.ID == id {
			return st.RXPackets, st.RXBytes
		}
	}
	g.t.Fatalf("no stats of attachment %q", id)
	return 0, 0
}

// TestTrunkBridgeLimit checks that a packet that the trunk does not carry takes
// nothing from the tunnel limit, and that the limit applies to the others.
func TestTrunkBridgeLimit(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		q := g.bridgeEnd(dp.Mode_MODE_QUIC, "q", brQSocket, brQNet)
		g.link(trunkBridgeRevision)
		// The limit has room for one frame with the largest packet.
		g.r.mu.Lock()
		q.s.meter = rate.NewLimiter(1, trunkMTU+peerconn.DataLen+1)
		g.r.mu.Unlock()

		assert.Empty(t, g.bridgeSend(q, innerOf(brQ, brServer, trunkMTU+1)))
		assert.Len(t, g.bridgeSend(q, innerOf(brQ, brServer, trunkMTU)), 1, "the packet that did not fit took nothing from the limit")
		assert.Empty(t, g.bridgeSend(q, innerOf(brQ, brServer, trunkMTU)), "the limit is empty")
		assert.Equal(t, senderCounts{sent: 1, trunk: 1, tunnel: 1}, sentOf(g.r, q.s))
		assert.Equal(t, map[string]uint64{"trunk_mtu": 1, "tunnel_limit": 1}, dropsOf(g.r))
		packets, bytes := g.rxOf(q.s)
		assert.EqualValues(t, 1, packets)
		assert.EqualValues(t, trunkMTU, bytes)
	})
}

// TestTrunkBridgeDeliver checks which clear inner packets of server on relay-a
// go to an agent of this relay, in which form, and why the others drop.
func TestTrunkBridgeDeliver(t *testing.T) {
	other := agentID(vpcA, "other")
	cases := []struct {
		name    string
		setup   func(t *testing.T, g *rowRig, q, p *bridgeEnd)
		tag     uint32 // Zero is the tag of server.
		src     string // Empty is the IPv6 address of server.
		dst     string // Empty is the IPv6 address of q.
		payload []byte // Payload in place of an inner packet from src to dst.
		again   bool   // The relay gets the trunk packet two times.
		toPSP   bool   // The PSP-mode agent p gets the packet.
		drop    string // Reason label of the drop. Empty is no drop.
	}{
		{name: "to a QUIC-mode agent"},
		{name: "to a PSP-mode agent", dst: brP, toPSP: true},
		{name: "IPv4 packet", src: brServer4, dst: brQ4},
		{
			name: "Permit allows only the sender to the address",
			setup: func(_ *testing.T, g *rowRig, _, _ *bridgeEnd) {
				g.r.SetPermit(func(srcVPC VPCKey, id string, dstVPC VPCKey, dst netip.Addr) bool {
					return srcVPC == vpcA && id == server && dstVPC == vpcA && dst == netip.MustParseAddr(brQ)
				})
			},
		},
		{
			name: "sender with two attachments",
			setup: func(_ *testing.T, g *rowRig, _, _ *bridgeEnd) {
				g.announce(atGen(liveEntry("x2", server, "", inTag, "fd00:a2::/96"), 10))
			},
			src: "fd00:a2::1",
		},
		{name: "packet that the relay gets again", again: true, drop: "trunk_replay"},
		{name: "tag that no entry has", tag: 9, drop: "trunk_sender"},
		{name: "source address with no route", src: "fd00:f::1", drop: "trunk_source"},
		{
			name: "source address of another sender of the other relay",
			setup: func(_ *testing.T, g *rowRig, _, _ *bridgeEnd) {
				g.announce(atGen(liveEntry("y", other, "", 8, "fd00:c::/96"), 10))
			},
			src: "fd00:c::1", drop: "trunk_source",
		},
		{name: "source address of an agent of this relay", src: brP, drop: "trunk_source"},
		{
			// An attachment of this relay keeps the route of its prefix.
			name: "source address that the entry lists and an agent of this relay has",
			setup: func(_ *testing.T, g *rowRig, _, _ *bridgeEnd) {
				g.announce(atGen(liveEntry("x", server, "", inTag, prefixA, brPNet), 11))
			},
			src: brP, drop: "trunk_source",
		},
		{
			// A tag and the ID of an attachment are of one relay only.
			name: "source address of an attachment of a third relay with the same ID and tag",
			setup: func(t *testing.T, g *rowRig, _, _ *bridgeEnd) {
				b := g.second(true)
				require.NoError(t, g.m.pres.apply(b.sess, &dp.PresenceUpdate{Entries: []*dp.Presence{
					atGen(liveEntry("x", server, "", inTag, prefixB), 10),
				}}))
				routes := routeTable(g.r, vpcA)
				require.Equal(t, "x@relay-b", routes[prefixB])
				require.Equal(t, "x@relay-a", routes[prefixA])
			},
			src: "fd00:b::1", drop: "trunk_source",
		},
		{
			name:  "Permit denies",
			setup: func(_ *testing.T, g *rowRig, _, _ *bridgeEnd) { g.r.SetPermit(denyAll) },
			drop:  "trunk_permit",
		},
		{
			name: "Permit allows only another subject",
			setup: func(_ *testing.T, g *rowRig, _, _ *bridgeEnd) {
				g.r.SetPermit(func(_ VPCKey, id string, _ VPCKey, _ netip.Addr) bool { return id == other })
			},
			drop: "trunk_permit",
		},
		{name: "destination on the relay of the sender", dst: "fd00:a::2", drop: "trunk_not_local"},
		{
			name: "destination on a third relay",
			setup: func(t *testing.T, g *rowRig, _, _ *bridgeEnd) {
				b := g.second(true)
				require.NoError(t, g.m.pres.apply(b.sess, &dp.PresenceUpdate{Entries: []*dp.Presence{
					atGen(liveEntry("y", other, "", 3, prefixB), 10),
				}}))
				require.Equal(t, "y@relay-b", routeTable(g.r, vpcA)[prefixB])
			},
			dst: "fd00:b::1", drop: "trunk_not_local",
		},
		{name: "destination with no route", dst: "fd00:f::1", drop: "trunk_not_local"},
		{
			name: "PSP-mode agent that gave the relay no SA",
			setup: func(_ *testing.T, g *rowRig, _, _ *bridgeEnd) {
				g.bridgeEnd(dp.Mode_MODE_PSP, "p2", "192.0.2.24:1", "fd00:24::/96")
			},
			dst: "fd00:24::1", drop: "trunk_not_sent",
		},
		{
			name: "PSP-mode agent whose SA has no sequence number left",
			setup: func(_ *testing.T, g *rowRig, _, p *bridgeEnd) {
				g.r.mu.RLock()
				sa := p.s.tx.SA(0)
				g.r.mu.RUnlock()
				for range 3 {
					_, _ = sa.ReserveN(math.MaxInt32)
				}
			},
			dst: brP, drop: "trunk_not_sent",
		},
		{
			name:  "QUIC-mode agent whose session takes no datagram",
			setup: func(_ *testing.T, _ *rowRig, q, _ *bridgeEnd) { q.refuse = errors.New("test") },
			drop:  "trunk_not_sent",
		},
		{
			// A session has its mode from its Session call.
			name: "agent with no Session call",
			setup: func(_ *testing.T, g *rowRig, _, _ *bridgeEnd) {
				s := newSession(Identity{VPC: vpcA, ID: agentID(vpcA, "idle")}, func() netip.AddrPort { return netip.MustParseAddrPort("192.0.2.25:1") })
				g.r.addSession(s, time.Now())
				require.NoError(g.t, g.r.attach(s, attachment("att-idle", "fd00:25::/96")))
			},
			dst: "fd00:25::1", drop: "trunk_not_sent",
		},
		{name: "payload with a short IPv6 header", payload: append([]byte{0x60}, make([]byte, 38)...), drop: "malformed"},
		{name: "payload with a short IPv4 header", payload: append([]byte{0x45}, make([]byte, 18)...), drop: "malformed"},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				q := g.bridgeEnd(dp.Mode_MODE_QUIC, "q", brQSocket, brQNet, brQNet4)
				p := g.bridgeEnd(dp.Mode_MODE_PSP, "p", brPSocket, brPNet)
				g.giveSAs(p)
				g.link(trunkBridgeRevision)
				if tc.setup != nil {
					tc.setup(t, g, q, p)
				}
				inner := tc.payload
				if inner == nil {
					inner = innerOf(cmp.Or(tc.src, brServer), cmp.Or(tc.dst, brQ), 100)
				}
				pkt := g.sealed(trunkLaneInner, cmp.Or(tc.tag, inTag), inner, false)
				var out []keptPacket
				if tc.again {
					require.Empty(t, g.arrive(slices.Clone(pkt), g.addr))
					require.Len(t, q.frames, 1, "the first copy of the packet")
					q.frames = nil
					before, _ := g.txOf(q.s)
					require.EqualValues(t, 1, before)
				}
				out = g.arrive(pkt, g.addr)

				if tc.drop != "" {
					assert.Empty(t, out, "the relay sends nothing for a packet that it drops")
					assert.Empty(t, q.frames)
					assert.Equal(t, map[string]uint64{tc.drop: 1}, dropsOf(g.r))
					for _, e := range []*bridgeEnd{q, p} {
						packets, _ := g.txOf(e.s)
						assert.EqualValues(t, btoi(tc.again && e == q), packets)
					}
					return
				}
				assert.Empty(t, dropsOf(g.r))
				to, idle := q, p
				if tc.toPSP {
					to, idle = p, q
					// The relay seals the packet with the SA of the agent, as for a data frame.
					require.Len(t, out, 1)
					assert.Equal(t, p.socket, out[0].to)
					assert.Empty(t, q.frames)
					got, vni, err := p.psp.rxq.Receive(out[0].b)
					require.NoError(t, err)
					assert.Equal(t, inner, got)
					assert.EqualValues(t, testVNI, vni)
				} else {
					assert.Empty(t, out, "a data frame goes on the session, not on the socket")
					require.Len(t, q.frames, 1)
					// The frame has the network ID of the VPC, and its flags are zero.
					assert.Equal(t, peerconn.EncodeData(nil, testVNI, inner), q.frames[0])
				}
				// The attachment of the receiver counts the inner packet.
				packets, bytes := g.txOf(to.s)
				assert.EqualValues(t, 1, packets)
				assert.EqualValues(t, len(inner), bytes)
				packets, _ = g.txOf(idle.s)
				assert.Zero(t, packets)
			})
		})
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// TestTrunkBridgeSession checks that the sender of a clear inner packet is an
// entry from the session that gave the trunk SA of the packet to relay-a.
func TestTrunkBridgeSession(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		q := g.bridgeEnd(dp.Mode_MODE_QUIC, "q", brQSocket, brQNet)
		inner := innerOf(brServer, brQ, 100)
		// arrive gives the relay inner in a trunk packet of relay-a with sa.
		arrive := func(sa *engine.TxSA) {
			t.Helper()
			pkt := make([]byte, len(inner)+pspwire.Overhead)
			n, err := sa.SealTrunk(inTag, pkt, inner)
			require.NoError(t, err)
			q.frames = nil
			g.arrive(pkt[:n], g.addr)
		}
		passes := func(sa *engine.TxSA, msg string) {
			t.Helper()
			before := dropsOf(g.r)
			arrive(sa)
			assert.Len(t, q.frames, 1, msg)
			assert.Equal(t, before, dropsOf(g.r), msg)
		}
		drops := func(sa *engine.TxSA, msg string) {
			t.Helper()
			before := dropsOf(g.r)
			arrive(sa)
			assert.Empty(t, q.frames, msg)
			before["trunk_sender"]++
			assert.Equal(t, before, dropsOf(g.r), msg)
		}

		// relay-a refuses the first SA of the lane, and the relay offers a new one.
		g.before = func(n int, req keys.Request) error {
			if n == 0 {
				return g.hold(req.SAs[trunkLaneInner].SPI)
			}
			return nil
		}
		g.link(trunkBridgeRevision)
		first := g.tx.SA(trunkLaneInner)
		passes(first, "SA after relay-a refused the SA of the first offer")

		// The router looks at the SAs each second.
		lifetime := g.r.bridge.Load().lifetime
		for range int((lifetime*3/4 + time.Second) / time.Second) {
			time.Sleep(time.Second)
			g.r.tickBridge(time.Now())
		}
		reqs := g.requests()
		require.Len(t, reqs, 1)
		require.Equal(t, keys.OpRekey, reqs[0].Op)
		rekeyed := g.tx.SA(trunkLaneInner)
		require.NotSame(t, first, rekeyed)
		passes(rekeyed, "SA of a rekey on the session")

		// The keys and the entries stay while relay-a is up.
		g.end(g.sess, meshLost)
		passes(rekeyed, "packet after the session ended")

		// The relay offers new SAs on the new session. Its Presence call comes later.
		s := g.open(trunkBridgeRevision)
		g.deliver()
		require.Len(t, g.requests(), 1)
		second := g.tx.SA(trunkLaneInner)
		require.NotSame(t, rekeyed, second)
		passes(rekeyed, "SA of the session before, before the new Presence call")
		drops(second, "SA of the new session, before its Presence call")

		require.NoError(t, g.m.pres.accept(s))
		g.sess = s
		drops(rekeyed, "SA of the session before, after the new Presence call")
		// relay-a can have given the tag to another agent.
		drops(second, "tag that only the session before gave")
		g.tellServer(11)
		passes(second, "SA and entry of the new session")
		drops(rekeyed, "SA of the session before, with the entry of the new session")
	})
}

// TestTrunkBridgeUnsentSA checks that the relay takes no inner packet with a
// trunk SA that relay-a did not get: the SA of a rekey that waits for a session.
func TestTrunkBridgeUnsentSA(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		q := g.bridgeEnd(dp.Mode_MODE_QUIC, "q", brQSocket, brQNet)
		g.link(trunkBridgeRevision)
		// The router looks at the SAs each second.
		tick := func() {
			time.Sleep(time.Second)
			g.r.tickBridge(time.Now())
		}
		for range int((g.r.bridge.Load().lifetime*3/4 - 2*time.Second) / time.Second) {
			tick()
		}
		require.Empty(t, g.requests(), "no rekey before 3/4 of the lifetime")
		// The keys stay for a time after the session ended, and the rekey comes then.
		g.end(g.sess, meshLost)
		var pending []keys.Request
		for range 3 {
			tick()
			g.tk.mu.Lock()
			pending = slices.Clone(g.pair.pending)
			g.tk.mu.Unlock()
			if len(pending) > 0 {
				break
			}
		}
		require.Len(t, pending, 1, "the rekey waits for a session")
		require.Empty(t, g.requests(), "relay-a gets no rekey with no session")
		i := slices.IndexFunc(pending[0].SAs, func(sa keys.SA) bool { return sa.Lane == trunkLaneInner })
		require.GreaterOrEqual(t, i, 0)
		sa, err := engine.NewTxSA(pending[0].SAs[i].SPI, pending[0].SAs[i].Key, 0, trunkPayload)
		require.NoError(t, err)
		pkt := make([]byte, 100+pspwire.Overhead)
		n, err := sa.SealTrunk(inTag, pkt, innerOf(brServer, brQ, 100))
		require.NoError(t, err)

		assert.Empty(t, g.arrive(pkt[:n], g.addr))
		assert.Empty(t, q.frames)
		assert.Equal(t, map[string]uint64{"trunk_sender": 1}, dropsOf(g.r))
	})
}

// TestTrunkBridgeShards checks that the data frames for an agent with shards go
// on the shard of their flow, as the frames from an agent of this relay do.
func TestTrunkBridgeShards(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		q := g.bridgeEnd(dp.Mode_MODE_QUIC, "q", brQSocket, brQNet)
		// The connections that got each flow, by source port.
		got := map[int][]*Session{}
		count := func(s *Session) {
			s.sendDatagram = func(b []byte) error {
				port := int(binary.BigEndian.Uint16(b[peerconn.DataLen+40:]))
				got[port] = append(got[port], s)
				return nil
			}
		}
		count(q.s)
		for _, i := range []uint32{1, 3} {
			sh := newSession(q.s.id, func() netip.AddrPort { return netip.AddrPort{} })
			g.r.addSession(sh, time.Now())
			_, _, err := g.r.joinShard(sh, "att-q", i)
			require.NoError(t, err)
			count(sh)
		}
		g.link(trunkBridgeRevision)

		const flows = 64
		// A flow uses one connection, so each flow has two packets.
		for range 2 {
			for port := range flows {
				payload := []byte{byte(port >> 8), byte(port), 0, 53}
				inner := ipPacket(netip.MustParseAddr(brServer), netip.MustParseAddr(brQ), payload)
				require.Empty(t, g.arrive(g.sealed(trunkLaneInner, inTag, inner, false), g.addr))
			}
		}
		assert.Empty(t, dropsOf(g.r))
		assert.Len(t, got, flows)
		used := map[*Session]bool{}
		for port, conns := range got {
			require.Len(t, conns, 2)
			assert.Same(t, conns[0], conns[1], "flow %d is on two connections", port)
			used[conns[0]] = true
		}
		assert.Len(t, used, 3, "the flows use the session and its two shards")
		packets, _ := g.txOf(q.s)
		assert.EqualValues(t, 2*flows, packets, "the attachment of the session counts the frames on its shards")
	})
}

// TestTrunkBridgeNoSeal checks that the relay counts one data drop, with no
// trunk reason, for a trunk packet that it cannot seal or send.
func TestTrunkBridgeNoSeal(t *testing.T) {
	cases := []struct {
		name string
		// setup takes away one thing that the seal needs. It returns the undo.
		setup func(g *rowRig, h *hop, buf *[]byte) func()
	}{
		{name: "no SA", setup: func(_ *rowRig, h *hop, _ *[]byte) func() { h.sa = nil; return nil }},
		{name: "no buffer", setup: func(_ *rowRig, _ *hop, buf *[]byte) func() { *buf = nil; return nil }},
		{
			name: "no bridge",
			setup: func(g *rowRig, _ *hop, _ *[]byte) func() {
				br := g.r.bridge.Swap(nil)
				return func() { g.r.bridge.Store(br) }
			},
		},
		{
			name: "socket that takes no packet",
			setup: func(g *rowRig, _ *hop, _ *[]byte) func() {
				g.conn.refuse(errors.New("test"))
				return func() { g.conn.refuse(nil) }
			},
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				q := g.bridgeEnd(dp.Mode_MODE_QUIC, "q", brQSocket, brQNet)
				g.link(trunkBridgeRevision)
				inner := innerOf(brQ, brServer, 100)
				frame := peerconn.EncodeData(nil, testVNI, inner)
				g.r.mu.RLock()
				h := g.r.nextHop(q.s, inner)
				g.r.mu.RUnlock()
				require.Equal(t, "relay-a", h.home)
				require.NotNil(t, h.sa)
				buf := make([]byte, maxUDP)
				g.packets()
				require.True(t, g.r.deliver(q.s, h, frame, inner, buf, time.Now()), "the hop carries the packet")
				require.Len(t, g.packets(), 1)

				if undo := tc.setup(g, &h, &buf); undo != nil {
					defer undo()
				}
				assert.False(t, g.r.deliver(q.s, h, frame, inner, buf, time.Now()))
				assert.Empty(t, g.packets())
				assert.Equal(t, senderCounts{sent: 1, drops: 1}, sentOf(g.r, q.s))
				assert.Empty(t, dropsOf(g.r), "the drop has no trunk reason, because no SA failed")
				assert.Empty(t, noRoutes(g.r, q.s))
			})
		})
	}
}

// TestTrunkBridgeSenderEnds checks a packet that is on its way to relay-a when the
// session of its sender ends: it has the tag of the sender, and never the tag 0.
func TestTrunkBridgeSenderEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, trunkRigConfig(t))
		defer g.stop()
		q := g.bridgeEnd(dp.Mode_MODE_QUIC, "q", brQSocket, brQNet)
		g.link(trunkBridgeRevision)
		inner := innerOf(brQ, brServer, 100)
		frame := peerconn.EncodeData(nil, testVNI, inner)
		hopOf := func() (hop, uint32) {
			g.r.mu.RLock()
			defer g.r.mu.RUnlock()
			return g.r.nextHop(q.s, inner), q.s.tag
		}
		h, tag := hopOf()
		require.NotZero(t, tag)
		require.Equal(t, tag, h.tag)

		// The session ends after the relay made the hop of the packet.
		g.r.removeSession(q.s)
		buf := make([]byte, maxUDP)
		g.packets()
		require.True(t, g.r.trunkCarries(q.s, h, inner))
		require.True(t, g.r.deliver(q.s, h, frame, inner, buf, time.Now()))
		sent := g.packets()
		require.Len(t, sent, 1)
		_, got, _, err := g.rxq.ReceiveTrunk(slices.Clone(sent[0].b))
		require.NoError(t, err)
		assert.Equal(t, tag, got, "tag of the trunk packet")

		// A hop from after the end has no tag, and the relay seals no packet for it.
		late, tag := hopOf()
		require.Zero(t, tag)
		assert.Equal(t, "relay-a", late.home)
		assert.Zero(t, late.tag)
		assert.False(t, g.r.trunkCarries(q.s, late, inner))
		assert.False(t, g.r.deliver(q.s, late, frame, inner, buf, time.Now()))
		assert.Empty(t, g.packets())
		assert.Empty(t, noRoutes(g.r, q.s))
	})
}

// TestInnerSource checks the source address that the relay reads from an inner
// packet. An address has the form of the routes: an IPv4 address is not mapped.
func TestInnerSource(t *testing.T) {
	v4 := innerOf("10.1.2.3", "10.9.9.9", 28)
	v6 := innerOf("fd00:1::2", "fd00:9::9", 48)
	cases := []struct {
		name string
		pkt  []byte
		want string // Empty is no address.
	}{
		{name: "IPv4 packet", pkt: v4, want: "10.1.2.3"},
		{name: "IPv6 packet", pkt: v6, want: "fd00:1::2"},
		{name: "IPv6 packet with a mapped IPv4 source", pkt: innerOf("::ffff:10.1.2.3", "fd00:9::9", 48), want: "10.1.2.3"},
		{name: "IPv4 header only", pkt: v4[:20], want: "10.1.2.3"},
		{name: "IPv6 header only", pkt: v6[:40], want: "fd00:1::2"},
		{name: "IPv4 header that is one byte short", pkt: v4[:19]},
		{name: "IPv6 header that is one byte short", pkt: v6[:39]},
		{name: "IPv6 version with the length of an IPv4 header", pkt: v6[:20]},
		{name: "other IP version", pkt: append([]byte{0x50}, v6[1:]...)},
		{name: "empty packet"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := innerSource(tc.pkt)
			if tc.want == "" {
				assert.False(t, ok)
				assert.False(t, got.IsValid())
				return
			}
			require.True(t, ok)
			assert.Equal(t, netip.MustParseAddr(tc.want), got)
		})
	}
}

// relayEnd is an agent of a relay in the tests with two relays: a socket, and
// a session with an attachment.
type relayEnd struct {
	n      *trunkNode
	s      *Session
	udp    *net.UDPConn
	addr   string      // An address of its attachment.
	psp    *pspAgent   // In PSP mode: its SAs to and from the relay.
	frames chan []byte // In QUIC mode: the datagrams that the relay sent to it.
}

func newRelayEnd(t *testing.T, n *trunkNode, mode dp.Mode, name, prefix string) *relayEnd {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = udp.Close() })
	ap := netip.MustParseAddrPort(udp.LocalAddr().String())
	e := &relayEnd{n: n, udp: udp, addr: netip.MustParsePrefix(prefix).Addr().Next().String(), frames: make(chan []byte, 16)}
	e.s = newSession(Identity{VPC: vpcA, ID: agentID(vpcA, name)}, func() netip.AddrPort { return ap })
	e.s.sendDatagram = func(b []byte) error {
		e.frames <- slices.Clone(b)
		return nil
	}
	n.r.addSession(e.s, time.Now())
	require.NoError(t, n.r.openSync(e.s, mode, ref(vpcA), nil))
	require.NoError(t, n.r.attach(e.s, attachment("att-"+name, prefix)))
	if mode == dp.Mode_MODE_PSP {
		offer, err := n.r.offer(e.s, Network{ID: testVNI, MTU: 1280}, time.Now())
		require.NoError(t, err)
		e.psp = newPSPAgent(t, offer.GetRekey(), time.Now())
		refused, err := n.r.rekey(e.s, e.psp.req, time.Now())
		require.NoError(t, err)
		require.Empty(t, refused)
	}
	return e
}

// send sends inner to the relay of e: a data frame in QUIC mode, or a PSP
// packet with the relay SA from the socket of e.
func (e *relayEnd) send(t *testing.T, inner []byte) {
	t.Helper()
	if e.psp == nil {
		e.n.r.forwardData(e.s, peerconn.EncodeData(nil, testVNI, inner), make([]byte, maxUDP), time.Now())
		return
	}
	_, err := e.udp.WriteToUDPAddrPort(e.psp.seal(t, inner), e.n.addr)
	require.NoError(t, err)
}

// recv returns the next inner packet that the relay of e sent to e, and the
// network ID that came with it.
func (e *relayEnd) recv(t *testing.T) (inner []byte, vni uint32) {
	t.Helper()
	if e.psp == nil {
		select {
		case b := <-e.frames:
			vni, inner, err := peerconn.DecodeData(b)
			require.NoError(t, err)
			assert.Zero(t, b[peerconn.DataLen-1], "flags of the data frame")
			return inner, vni
		case <-time.After(5 * time.Second):
			t.Fatal("no data frame from the relay")
			return nil, 0
		}
	}
	buf := make([]byte, maxUDP+1)
	require.NoError(t, e.udp.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, from, err := e.udp.ReadFromUDPAddrPort(buf)
	require.NoError(t, err, "no PSP packet from the relay")
	assert.Equal(t, e.n.addr, from, "the packet comes from the socket of the relay")
	inner, vni, err = e.psp.rxq.Receive(buf[:n])
	require.NoError(t, err)
	return inner, vni
}

// TestTrunkBridgeBetweenRelays sends inner packets between agents of two relays on
// loopback, for each pair of modes that a relay opens. The packets do not change.
func TestTrunkBridgeBetweenRelays(t *testing.T) {
	t.Parallel()
	const quic, psp = dp.Mode_MODE_QUIC, dp.Mode_MODE_PSP
	cases := []struct {
		name     string
		from, to dp.Mode
	}{
		{name: "QUIC to QUIC", from: quic, to: quic},
		{name: "QUIC to PSP", from: quic, to: psp},
		{name: "PSP to QUIC", from: psp, to: quic},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tap := &tapConn{}
			a, b := trunkNodes(t, func(a, b *trunkNode) {
				tap.PacketConn, tap.from = b.conn.PacketConn, a.addr
				b.conn.PacketConn = tap
			})
			for _, d := range []struct{ n, peer *trunkNode }{{a, b}, {b, a}} {
				require.Eventually(t, func() bool { return d.n.path(d.peer.name) == trunkPathFull },
					10*time.Second, 10*time.Millisecond, "%s: probe result for %s", d.n.name, d.peer.name)
			}
			snd := newRelayEnd(t, a, tc.from, "laptop", "fd00:1::/96")
			rcv := newRelayEnd(t, b, tc.to, "server", prefixA)
			// relay-a needs the route of the receiver, and relay-b the entry of the sender.
			require.Eventually(t, func() bool { return routeTable(a.r, vpcA)[prefixA] == "att-server@relay-b" },
				10*time.Second, 5*time.Millisecond, "relay-a has the route of the attachment of relay-b")
			require.Eventually(t, func() bool { return routeTable(b.r, vpcA)["fd00:1::/96"] == "att-laptop@relay-a" },
				10*time.Second, 5*time.Millisecond, "relay-b has the attachment of the sender")
			lane := a.txSPIs("relay-b")[trunkLaneInner]
			// carried returns the trunk packets of relay-a with a clear inner packet.
			// The probes of relay-a are on the same lane.
			carried := func() [][]byte {
				return slices.DeleteFunc(tap.with(lane), func(p []byte) bool { return p[0] == pspwire.NextHdrPSP })
			}

			// A packet that is too long for the trunk goes nowhere.
			snd.send(t, innerOf(snd.addr, rcv.addr, trunkMTU+1))
			require.Eventually(t, func() bool { return a.r.SenderStats(snd.s).DropTrunk == 1 }, 5*time.Second, 5*time.Millisecond)
			assert.Zero(t, len(carried()), "trunk packets for the packet that is too long")

			sizes := []int{48, trunkMTU}
			for i, size := range sizes {
				inner := innerOf(snd.addr, rcv.addr, size)
				snd.send(t, inner)
				got, vni := rcv.recv(t)
				assert.Equal(t, inner, got, "the inner packet does not change")
				assert.EqualValues(t, testVNI, vni)
				pkts := carried()
				require.Len(t, pkts, i+1, "one trunk packet for one inner packet")
				assert.Len(t, pkts[i], size+pspwire.Overhead)
			}

			// relay-b drops a trunk packet that it gets again.
			_, err := a.conn.PacketConn.WriteTo(carried()[0], net.UDPAddrFromAddrPort(b.addr))
			require.NoError(t, err)
			require.Eventually(t, func() bool { return b.r.drops[dropTrunkReplay].Load() == 1 }, 5*time.Second, 5*time.Millisecond)

			st := a.r.SenderStats(snd.s)
			assert.EqualValues(t, 2, st.DataSent)
			assert.Zero(t, st.DataDrops)
			assert.Equal(t, map[string]uint64{"trunk_mtu": 1}, dropsOf(a.r))
			assert.Equal(t, map[string]uint64{"trunk_replay": 1}, dropsOf(b.r))
			// The attachment of the receiver counts the inner packets.
			rx := b.r.AttachmentStats()
			require.Len(t, rx, 1)
			assert.EqualValues(t, 2, rx[0].TXPackets)
			assert.EqualValues(t, sizes[0]+sizes[1], rx[0].TXBytes)
			select {
			case extra := <-rcv.frames:
				t.Errorf("the receiver got a second copy of a packet: %d bytes", len(extra))
			default:
			}
		})
	}
}

// TestTrunkBridgeNames checks the table that gives the bridge the pair of a
// member by its name, when the pairs change.
func TestTrunkBridgeNames(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		assert.Nil(t, g.tk.bridgeTo("relay-a"), "member with no session")
		g.join(trunkBridgeRevision)
		assert.Nil(t, g.tk.bridgeTo("relay-a"), "member that gave no SA")
		_, err := g.offer(g.sess)
		require.NoError(t, err)
		assert.Same(t, g.tk.pair("relay-a"), g.tk.bridgeTo("relay-a"))
		assert.Nil(t, g.tk.bridgeTo("relay-b"), "name of no member")

		g.second(true)
		require.NotNil(t, g.tk.bridgeTo("relay-a"))
		assert.NotNil(t, g.tk.pair("relay-b"))
		assert.Nil(t, g.tk.bridgeTo("relay-b"), "member below the bridge revision")

		moved := netip.MustParseAddrPort("198.51.100.7:6081")
		old := g.tk.pair("relay-a")
		g.rejoin(trunkBridgeRevision, moved)
		assert.NotSame(t, old, g.tk.bridgeTo("relay-a"), "member at a new address has a new pair")
		assert.Same(t, g.tk.pair("relay-a"), g.tk.bridgeTo("relay-a"))

		g.end(g.sess, meshLost)
		time.Sleep(3 * time.Second)
		g.deliver()
		assert.Nil(t, g.tk.bridgeTo("relay-a"), "member that is down")
	})
}
