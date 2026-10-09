// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// trunkNode is a mesh node with a router, so it has a PSP bridge and a trunk.
type trunkNode struct {
	*meshNode
	r    *Router
	conn *cutConn
}

func newTrunkNode(t *testing.T, ca *testCA, name string) *trunkNode {
	t.Helper()
	n := &trunkNode{meshNode: newCutNode(t, ca, name), r: NewRouter(nil, Config{})}
	n.conn = n.tr.Conn.(*cutConn)
	n.tr.NonQUICPacketHandler, n.tr.NonQUICBatchEnd = n.r.PacketHandler(n.ctx, n.tr)
	n.m.SetRouter(n.r)
	return n
}

func (n *trunkNode) trunk() *trunk   { return n.r.trunk.Load() }
func (n *trunkNode) bridge() *bridge { return n.r.bridge.Load() }

// txSPIs returns the SPIs of the SAs that n holds for packets to member name,
// by lane. It returns nil if a lane has no SA.
func (n *trunkNode) txSPIs(name string) []uint32 {
	p := n.trunk().pair(name)
	if p == nil {
		return nil
	}
	spis := make([]uint32, trunkLanes)
	for lane := range spis {
		sa := p.tx.SA(lane)
		if sa == nil {
			return nil
		}
		spis[lane] = sa.SPI()
	}
	return spis
}

// path returns the probe result that n has for member name.
func (n *trunkNode) path(name string) trunkPath {
	if p := n.trunk().pair(name); p != nil {
		return trunkPath(p.path.Load())
	}
	return trunkPathUnknown
}

// keyed waits until each node of a pair holds the SAs of the other node.
func keyed(t *testing.T, a, b *trunkNode) {
	t.Helper()
	require.Eventually(t, func() bool { return a.txSPIs(b.name) != nil && b.txSPIs(a.name) != nil },
		10*time.Second, 5*time.Millisecond, "%s and %s have trunk keys in both directions", a.name, b.name)
}

// trunkNodes starts relay-a, which dials, and relay-b, and waits for their
// trunk keys. setup runs before the relays start.
func trunkNodes(t *testing.T, setup func(a, b *trunkNode)) (a, b *trunkNode) {
	t.Helper()
	ca := newCA(t)
	a, b = newTrunkNode(t, ca, "relay-a"), newTrunkNode(t, ca, "relay-b")
	if setup != nil {
		setup(a, b)
	}
	a.m.SetMembers([]MeshMember{b.member()})
	b.m.SetMembers([]MeshMember{a.member()})
	b.start(t)
	a.start(t)
	require.Equal(t, MeshChange{Name: "relay-b", Up: true}, a.change(t, 10*time.Second))
	require.Equal(t, MeshChange{Name: "relay-a", Up: true}, b.change(t, 10*time.Second))
	keyed(t, a, b)
	return a, b
}

// sealTrunk seals payload with the SA of lane that from holds for packets to
// member to. isPSP tells that the payload is a whole PSP packet.
func sealTrunk(t *testing.T, from *trunkNode, to string, lane int, tag uint32, payload []byte, isPSP bool) []byte {
	t.Helper()
	p := from.trunk().pair(to)
	require.NotNil(t, p, "%s has a pair for %s", from.name, to)
	sa := p.tx.SA(lane)
	require.NotNil(t, sa, "%s has an SA of lane %d for %s", from.name, lane, to)
	pkt := make([]byte, len(payload)+pspwire.Overhead)
	var n int
	var err error
	if isPSP {
		n, err = sa.SealTrunkPSP(tag, pkt, payload)
	} else {
		n, err = sa.SealTrunk(tag, pkt, payload)
	}
	require.NoError(t, err)
	return pkt[:n]
}

// openTrunk opens a trunk packet with the receive queue of n, as the packet
// handler of n does.
func openTrunk(n *trunkNode, pkt []byte) (payload []byte, tag uint32, nextHdr uint8, err error) {
	br := n.bridge()
	br.rxMu.Lock()
	defer br.rxMu.Unlock()
	return br.rxq.ReceiveTrunk(append([]byte(nil), pkt...))
}

// TestTrunkKeys starts two relays with a mesh session. Each gives the other
// trunk SAs, and a packet that one relay seals opens on the other with its tag.
func TestTrunkKeys(t *testing.T) {
	t.Parallel()
	a, b := trunkNodes(t, nil)
	v4 := ipPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), make([]byte, 64))
	v6 := ipPacket(netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("fd00:2::1"), make([]byte, 64))
	// The library does not read a PSP payload, so its content can be anything.
	agentPkt := make([]byte, 200)
	for i := range agentPkt {
		agentPkt[i] = byte(i)
	}
	cases := []struct {
		name    string
		lane    int
		tag     uint32
		payload []byte
		isPSP   bool
		nextHdr uint8
		want    error
	}{
		{name: "PSP packet of an agent", lane: trunkLanePSP, tag: 7, payload: agentPkt, isPSP: true, nextHdr: pspwire.NextHdrPSP},
		{name: "largest PSP packet with the highest tag", lane: trunkLanePSP, tag: pspwire.MaxVNI, payload: make([]byte, trunkPayload), isPSP: true, nextHdr: pspwire.NextHdrPSP},
		{name: "clear IPv4 packet", lane: trunkLaneInner, tag: 0x00a5c3, payload: v4, nextHdr: pspwire.NextHdrV4},
		{name: "clear IPv6 packet", lane: trunkLaneInner, tag: 1, payload: v6, nextHdr: pspwire.NextHdrV6},
		{name: "clear packet on the lane with no replay window", lane: trunkLanePSP, tag: 1, payload: v6, want: engine.ErrPayload},
	}
	for _, d := range []struct{ from, to *trunkNode }{{a, b}, {b, a}} {
		for _, tc := range cases {
			t.Run(d.from.name+"/"+tc.name, func(t *testing.T) {
				pkt := sealTrunk(t, d.from, d.to.name, tc.lane, tc.tag, tc.payload, tc.isPSP)
				assert.LessOrEqual(t, len(pkt), maxUDP)
				// A trunk SA has VNI 0, so the VNI field is free for the tag.
				assert.Equal(t, tc.tag, binary.BigEndian.Uint32(pkt[pspwire.HeaderLen:])>>8)
				assert.True(t, d.to.trunk().pair(d.from.name).receives(binary.BigEndian.Uint32(pkt[4:8])),
					"the SA is a receive SA of the pair")
				payload, tag, nextHdr, err := openTrunk(d.to, pkt)
				require.ErrorIs(t, err, tc.want)
				if tc.want != nil {
					return
				}
				assert.Equal(t, tc.payload, payload)
				assert.Equal(t, tc.tag, tag)
				assert.Equal(t, tc.nextHdr, nextHdr)
				// The functions of the other SAs do not open a trunk packet.
				br := d.to.bridge()
				br.rxMu.Lock()
				_, _, err = br.rxq.Receive(append([]byte(nil), pkt...))
				br.rxMu.Unlock()
				assert.Error(t, err)
			})
		}
		t.Run(d.from.name+"/replay", func(t *testing.T) {
			// Only the lane for clear packets has a replay window.
			pkt := sealTrunk(t, d.from, d.to.name, trunkLanePSP, 3, agentPkt, true)
			for range 2 {
				_, _, _, err := openTrunk(d.to, pkt)
				assert.NoError(t, err)
			}
			pkt = sealTrunk(t, d.from, d.to.name, trunkLaneInner, 3, v6, false)
			_, _, _, err := openTrunk(d.to, pkt)
			assert.NoError(t, err)
			_, _, _, err = openTrunk(d.to, pkt)
			assert.ErrorIs(t, err, engine.ErrReplay)
		})
		t.Run(d.from.name+"/packet of a sender", func(t *testing.T) {
			// The trunk has no rows yet, so the relay drops a packet with a sender tag.
			before := d.to.r.MalformedDrops()
			pkt := sealTrunk(t, d.from, d.to.name, trunkLanePSP, 7, agentPkt, true)
			_, err := d.from.tr.WriteTo(pkt, net.UDPAddrFromAddrPort(d.to.addr))
			require.NoError(t, err)
			require.Eventually(t, func() bool { return d.to.r.MalformedDrops() == before+1 }, 5*time.Second, 5*time.Millisecond)
		})
	}
}

// TestTrunkMemberSA checks that a relay does not accept the SA of one member
// in a packet from the address of another member.
func TestTrunkMemberSA(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	a, b, c := newTrunkNode(t, ca, "relay-a"), newTrunkNode(t, ca, "relay-b"), newTrunkNode(t, ca, "relay-c")
	a.m.SetMembers([]MeshMember{b.member(), c.member()})
	b.m.SetMembers([]MeshMember{a.member()})
	c.m.SetMembers([]MeshMember{a.member()})
	b.start(t)
	c.start(t)
	a.start(t)
	keyed(t, a, b)
	keyed(t, a, c)
	tk, br := a.trunk(), a.bridge()
	assert.Same(t, tk.pair("relay-b"), tk.from(b.addr))
	assert.Same(t, tk.pair("relay-c"), tk.from(c.addr))
	assert.Nil(t, tk.from(netip.MustParseAddrPort("192.0.2.9:6081")), "an address of no member")

	probe := make([]byte, trunkPayload)
	probe[0] = trunkMsgProbe
	cases := []struct {
		name string
		from *trunkNode // Member that sealed the packet.
		pair string     // Member whose address the packet comes from.
		want bool
	}{
		{name: "SA of the member", from: b, pair: "relay-b", want: true},
		{name: "SA of another member", from: c, pair: "relay-b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := sealTrunk(t, tc.from, "relay-a", trunkLaneInner, trunkTagRelay, probe, true)
			assert.Equal(t, tc.want, tk.receive(br, tk.pair(tc.pair), pkt))
		})
	}

	// A call of relay-c changes only the SAs that relay-a has from relay-c.
	fromB, fromC := a.txSPIs("relay-b"), a.txSPIs("relay-c")
	calls := []struct {
		name    string
		req     keys.Request
		refused []uint32
	}{
		{name: "revoke of the SAs of another member", req: keys.Request{Op: keys.OpRevoke, SPIs: fromB}},
		{
			name:    "offer with the SPI of another member",
			req:     keys.Request{Op: keys.OpOffer, SAs: []keys.SA{{SPI: fromB[trunkLaneInner], Key: make([]byte, 16), ExpiresIn: time.Minute, Lane: trunkLaneInner}}},
			refused: []uint32{fromB[trunkLaneInner]},
		},
	}
	sc := c.m.Session("relay-a")
	require.NotNil(t, sc)
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			res, err := sc.Client().TrunkKeys(ctx, keyproto.ToProto(tc.req))
			require.NoError(t, err)
			assert.Equal(t, tc.refused, res.GetRefusedSpis())
			assert.Equal(t, fromB, a.txSPIs("relay-b"))
			assert.Equal(t, fromC, a.txSPIs("relay-c"))
		})
	}
}

// TestTrunkProbe checks the full-size probe of a pair: a path that carries
// the largest packet is not limited, and a path that loses it is limited to 1280.
func TestTrunkProbe(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		max  int64 // Longest packet that the socket of relay-a sends. Zero is no limit.
		path trunkPath
		mtu  int
	}{
		{name: "path carries the largest packet", path: trunkPathFull, mtu: 1372},
		{name: "path carries one byte less", max: maxUDP - 1, path: trunkPathLimited, mtu: 1280},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := trunkNodes(t, func(a, _ *trunkNode) { a.conn.max.Store(tc.max) })
			// relay-a loses its probes and its answers to the probes of relay-b,
			// so the two relays get the same result.
			for _, d := range []struct{ n, peer *trunkNode }{{a, b}, {b, a}} {
				require.Eventually(t, func() bool { return d.n.path(d.peer.name) == tc.path },
					10*time.Second, 10*time.Millisecond, "%s: probe result for %s", d.n.name, d.peer.name)
				assert.Equal(t, tc.mtu, d.n.trunk().pair(d.peer.name).mtu())
			}
			assert.Zero(t, a.r.MalformedDrops()+b.r.MalformedDrops(), "a relay dropped a probe or an answer")
		})
	}
}

// TestTrunkRekey checks that a relay gives new SAs to the member before the
// old ones end, and that the old ones work until then.
func TestTrunkRekey(t *testing.T) {
	t.Parallel()
	a, b := trunkNodes(t, nil)
	first := a.txSPIs("relay-b")
	v6 := ipPacket(netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("fd00:2::1"), make([]byte, 64))
	old := sealTrunk(t, a, "relay-b", trunkLaneInner, 5, v6, false)

	// relay-b rekeys its receive SAs at 3/4 of their lifetime.
	br := b.bridge()
	now := time.Now().Add(br.lifetime * 3 / 4)
	b.r.tickBridge(now)
	var second []uint32
	require.Eventually(t, func() bool {
		second = a.txSPIs("relay-b")
		return second != nil && second[trunkLanePSP] != first[trunkLanePSP] && second[trunkLaneInner] != first[trunkLaneInner]
	}, 10*time.Second, 5*time.Millisecond, "relay-a got new SAs for all lanes")
	pair := b.trunk().pair("relay-a")
	for _, spi := range append(first, second...) {
		assert.True(t, pair.receives(spi), "SA %#x is a receive SA of the pair", spi)
	}
	_, tag, _, err := openTrunk(b, old)
	require.NoError(t, err, "an SA from before the rekey works in the overlap")
	assert.EqualValues(t, 5, tag)
	_, tag, _, err = openTrunk(b, sealTrunk(t, a, "relay-b", trunkLaneInner, 6, v6, false))
	require.NoError(t, err)
	assert.EqualValues(t, 6, tag)

	// The SAs from before the rekey end after a quarter of the lifetime.
	b.r.tickBridge(now.Add(br.lifetime / 4))
	for _, spi := range first {
		assert.False(t, pair.receives(spi), "SA %#x ended", spi)
	}
	for _, spi := range second {
		assert.True(t, pair.receives(spi), "SA %#x stays", spi)
	}
	_, _, _, err = openTrunk(b, sealTrunk(t, a, "relay-b", trunkLaneInner, 7, v6, false))
	assert.NoError(t, err)
}

// TestTrunkSessionEnd checks the keys of a pair when its session ends: they
// stay while the member is up, go when it is down, and come again with it.
func TestTrunkSessionEnd(t *testing.T) {
	t.Parallel()
	// The down time of the protocol. The test does not read it from the code.
	const downAfter = 3 * time.Second
	a, b := trunkNodes(t, nil)
	sa, sb := a.session(t), b.session(t)
	pa, pb := a.trunk().pair("relay-b"), b.trunk().pair("relay-a")
	firstA, firstB := a.txSPIs("relay-b"), b.txSPIs("relay-a")

	// A new session opens before the down time: each relay keeps the pair and
	// gets a new offer of the other.
	sb.close(dp.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, "test")
	assert.NotSame(t, sa, a.session(t))
	assert.NotSame(t, sb, b.session(t))
	var secondA, secondB []uint32
	require.Eventually(t, func() bool {
		secondA, secondB = a.txSPIs("relay-b"), b.txSPIs("relay-a")
		return secondA != nil && secondB != nil && secondA[0] != firstA[0] && secondB[0] != firstB[0]
	}, 10*time.Second, 5*time.Millisecond, "each relay got a new offer on the new session")
	assert.Same(t, pa, a.trunk().pair("relay-b"))
	assert.Same(t, pb, b.trunk().pair("relay-a"))

	// relay-a removes the member: its keys go at once. relay-b keeps the
	// keys for the down time, because the member is up for it.
	rxA, rxB := *pa.spis.Load(), *pb.spis.Load()
	a.m.SetMembers(nil)
	require.Equal(t, MeshChange{Name: "relay-b", Down: MeshRemoved}, a.change(t, time.Second))
	lost := time.Now()
	require.Eventually(t, func() bool { return a.trunk().pair("relay-b") == nil }, 5*time.Second, 5*time.Millisecond)
	assert.Nil(t, a.trunk().from(b.addr))
	for lane := range trunkLanes {
		assert.Nil(t, pa.tx.SA(lane), "relay-a has no SA of lane %d for relay-b", lane)
	}
	for _, spi := range rxA {
		_, ok := a.bridge().table.Stats(spi)
		assert.False(t, ok, "relay-a has no receive SA %#x", spi)
	}
	if time.Since(lost) < downAfter-time.Second {
		assert.True(t, b.m.Up("relay-a"))
		assert.Same(t, pb, b.trunk().pair("relay-a"), "relay-b keeps the pair while the member is up")
		assert.NotNil(t, b.txSPIs("relay-a"))
	}
	require.Equal(t, MeshChange{Name: "relay-a", Down: MeshLost}, b.change(t, downAfter+5*time.Second))
	require.Eventually(t, func() bool { return b.trunk().pair("relay-a") == nil }, 5*time.Second, 5*time.Millisecond)
	for lane := range trunkLanes {
		assert.Nil(t, pb.tx.SA(lane), "relay-b has no SA of lane %d for relay-a", lane)
	}
	for _, spi := range rxB {
		_, ok := b.bridge().table.Stats(spi)
		assert.False(t, ok, "relay-b has no receive SA %#x", spi)
	}

	// The member comes back: the relays make keys again, in a new pair.
	a.m.SetMembers([]MeshMember{b.member()})
	require.Equal(t, MeshChange{Name: "relay-b", Up: true}, a.change(t, 10*time.Second))
	require.Equal(t, MeshChange{Name: "relay-a", Up: true}, b.change(t, 10*time.Second))
	keyed(t, a, b)
	assert.NotSame(t, pa, a.trunk().pair("relay-b"))
	assert.NotSame(t, pb, b.trunk().pair("relay-a"))
	agentPkt := make([]byte, 100)
	for _, d := range []struct{ from, to *trunkNode }{{a, b}, {b, a}} {
		_, tag, _, err := openTrunk(d.to, sealTrunk(t, d.from, d.to.name, trunkLanePSP, 9, agentPkt, true))
		require.NoError(t, err, "packet from %s", d.from.name)
		assert.EqualValues(t, 9, tag)
		require.Eventually(t, func() bool { return d.from.path(d.to.name) == trunkPathFull }, 10*time.Second, 10*time.Millisecond)
	}
}

// TestTrunkKeysCall checks what the TrunkKeys handler refuses.
func TestTrunkKeysCall(t *testing.T) {
	t.Parallel()
	a, b := trunkNodes(t, nil)
	sa := a.session(t)
	held := b.txSPIs("relay-a")
	offer := func(spi, vni uint32, lane int) *dp.KeysRequest {
		return keyproto.ToProto(keys.Request{Op: keys.OpOffer, SAs: []keys.SA{{SPI: spi, Key: make([]byte, 16), VNI: vni, ExpiresIn: time.Minute, Lane: lane}}})
	}
	cases := []struct {
		name    string
		req     *dp.KeysRequest
		code    rpc.Code
		refused []uint32
	}{
		{name: "SA with a VNI", req: offer(0x2001, 7, trunkLanePSP), code: rpc.InvalidArgument},
		{name: "SA of a lane that a trunk does not have", req: offer(0x2002, 0, trunkLanes), code: rpc.InvalidArgument},
		{name: "no op", req: &dp.KeysRequest{}, code: rpc.InvalidArgument},
		{name: "SA with a bad key", req: keyproto.ToProto(keys.Request{Op: keys.OpOffer, SAs: []keys.SA{{SPI: 0x2003, Key: make([]byte, 5), ExpiresIn: time.Minute}}}), code: rpc.InvalidArgument},
		{name: "SPI that the relay holds", req: offer(held[trunkLaneInner], 0, trunkLaneInner), code: rpc.OK, refused: []uint32{held[trunkLaneInner]}},
		{name: "revoke of an SPI of no SA", req: keyproto.ToProto(keys.Request{Op: keys.OpRevoke, SPIs: []uint32{0x2004}}), code: rpc.OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			res, err := sa.Client().TrunkKeys(ctx, tc.req)
			require.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
			if err == nil {
				assert.Equal(t, tc.refused, res.GetRefusedSpis())
			}
			assert.Equal(t, held, b.txSPIs("relay-a"), "a refused call changes no SA")
		})
	}

	t.Run("call that is not on a mesh session", func(t *testing.T) {
		_, err := b.m.TrunkKeys(context.Background(), offer(0x2005, 0, trunkLanePSP))
		assert.Equal(t, rpc.FailedPrecondition, rpc.CodeOf(err), "error: %v", err)
	})
	t.Run("session that a new session replaced", func(t *testing.T) {
		old := b.session(t)
		old.close(dp.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, "test")
		require.NotSame(t, old, b.session(t))
		req, err := keyproto.FromProto(offer(0x2006, 0, trunkLanePSP))
		require.NoError(t, err)
		_, err = b.trunk().apply(old, req, time.Now())
		assert.Equal(t, rpc.FailedPrecondition, rpc.CodeOf(err), "error: %v", err)
	})
	t.Run("relay that is not a member", func(t *testing.T) {
		cur := b.m.Session("relay-a")
		require.NotNil(t, cur)
		b.m.SetMembers(nil)
		req, err := keyproto.FromProto(offer(0x2007, 0, trunkLanePSP))
		require.NoError(t, err)
		_, err = b.trunk().apply(cur, req, time.Now())
		assert.Equal(t, rpc.FailedPrecondition, rpc.CodeOf(err), "error: %v", err)
		require.Eventually(t, func() bool { return b.trunk().pair("relay-a") == nil }, 5*time.Second, 5*time.Millisecond)
	})
}

// TestTrunkOff checks a relay with no mesh: it has no trunk, and a trunk
// packet is a malformed packet for it as before.
func TestTrunkOff(t *testing.T) {
	r, handle := localRouter(t)
	require.Nil(t, r.trunk.Load())
	// A real trunk packet of another relay, for a relay that has no such SA.
	a, _ := trunkNodes(t, nil)
	from := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:6081"))
	for i, pkt := range [][]byte{
		sealTrunk(t, a, "relay-b", trunkLanePSP, 7, make([]byte, 100), true),
		sealTrunk(t, a, "relay-b", trunkLaneInner, trunkTagRelay, make([]byte, trunkPayload), true),
	} {
		handle(pkt, from)
		assert.EqualValues(t, i+1, r.MalformedDrops())
	}
	r.tickBridge(time.Now())
	assert.Zero(t, r.UnknownSourceDrops())
}

// trunkRigAddr is the address of relay-a in the tests with the fake clock. It
// is the address of a stubConn.
var trunkRigAddr = netip.MustParseAddrPort("192.0.2.1:6081")

// movedConn is a stubConn of a relay at another address.
type movedConn struct {
	*stubConn
	addr netip.AddrPort
}

func (c movedConn) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.addr) }

// trunkClient is the mesh client of a session to a member that the test
// controls. Only TrunkKeys has an answer.
type trunkClient struct {
	dp.MeshClient
	keys func(*dp.KeysRequest) (*dp.KeysResponse, error)
}

func (trunkClient) Presence(context.Context) (rpc.ClientStreamClient[dp.PresenceUpdate, emptypb.Empty], error) {
	return nil, rpc.Errorf(rpc.Unimplemented, "the member has no Presence call")
}

func (c trunkClient) TrunkKeys(_ context.Context, in *dp.KeysRequest) (*dp.KeysResponse, error) {
	return c.keys(in)
}

// keptPacket is one write of a keepConn.
type keptPacket struct {
	b  []byte
	to netip.AddrPort
}

// keepConn is a discardConn that keeps the packets of its writes.
type keepConn struct {
	*discardConn
	mu   sync.Mutex
	pkts []keptPacket
}

func (c *keepConn) WriteTo(b []byte, to net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pkts = append(c.pkts, keptPacket{append([]byte(nil), b...), addrPort(to)})
	return len(b), nil
}

// trunkRig is a relay on the fake clock, and relay-a, a member that the test
// plays: it gets the calls and the packets of the relay, and calls the mesh hooks.
type trunkRig struct {
	t      *testing.T
	m      *Mesh
	r      *Router
	tk     *trunk
	conn   *keepConn
	tr     *quic.Transport
	handle func([]byte, net.Addr)
	stubs  map[*MeshSession]*stubConn
	addr   netip.AddrPort // Address of the member. Its sessions and packets come from it.

	rxq    *engine.RxQueue // Opens the packets of the relay.
	rx     *keys.Peer      // SAs of the member for packets from the relay.
	inner  uint32          // SPI of the newest one with a replay window.
	sender *keys.Sender
	tx     *keys.TxPeer // SAs of the relay for packets to it.

	mu    sync.Mutex
	calls []keys.Request // TrunkKeys calls of the relay since the last requests.
	n     int            // Number of all calls.
	// before runs at the start of call n of the relay. Its error is the
	// answer to the call. With no error, the member applies the request.
	before func(n int, req keys.Request) error
}

// trunkRigConfig returns the mesh config of a rig. It makes keys, so call it
// out of the fake clock.
func trunkRigConfig(t *testing.T) MeshConfig {
	t.Helper()
	ca := newCA(t)
	return MeshConfig{TLS: meshTLS(ca.meshCert(t, "relay-m")), Verify: ca.verifyName}
}

func newTrunkRig(t *testing.T, cfg MeshConfig) *trunkRig {
	t.Helper()
	g := &trunkRig{
		t: t, r: NewRouter(nil, Config{}), conn: &keepConn{discardConn: newDiscardConn()},
		stubs: map[*MeshSession]*stubConn{}, addr: trunkRigAddr,
	}
	var err error
	g.m, err = NewMesh("relay-m", cfg)
	require.NoError(t, err)
	g.tr = &quic.Transport{Conn: g.conn}
	g.handle, _ = g.r.PacketHandler(t.Context(), g.tr)
	g.m.SetRouter(g.r)
	g.tk = g.r.trunk.Load()
	g.m.SetMembers([]MeshMember{{Name: "relay-a", Addr: trunkRigAddr}})

	table, err := engine.NewRxTable(engine.RxConfig{Queues: 1})
	require.NoError(t, err)
	recv, err := keys.NewReceiver(table, pspwire.AESGCM128)
	require.NoError(t, err)
	g.rx, err = recv.NewPeer(keys.PeerConfig{Trunk: true, MTU: trunkPayload, Lanes: trunkLanes, NoReplayLanes: 1})
	require.NoError(t, err)
	g.sender, err = keys.NewSender(trunkPayload)
	require.NoError(t, err)
	g.rxq, g.tx = table.Queue(0), g.sender.NewPeer()
	return g
}

// stop ends the sessions and waits for the goroutines of the trunk.
func (g *trunkRig) stop() {
	for _, c := range g.stubs {
		c.cancel(&quic.IdleTimeoutError{})
	}
	synctest.Wait()
	g.m.wg.Wait()
	_ = g.conn.Close()
	_ = g.tr.Close()
}

// open opens a session that relay-a dialed, at revision rev. The hooks run
// at the next deliver.
func (g *trunkRig) open(rev uint32) *MeshSession {
	g.t.Helper()
	conn := newStubConn()
	s := g.m.newSession(movedConn{conn, g.addr}, false)
	g.stubs[s] = conn
	s.client = trunkClient{keys: g.call}
	require.True(g.t, g.m.track(s))
	require.NoError(g.t, g.m.admit(s, "relay-a", nil, &dp.Version{Revision: rev}, nil))
	return s
}

// end closes the connection of s with cause.
func (g *trunkRig) end(s *MeshSession, cause error) {
	g.stubs[s].cancel(cause)
	synctest.Wait()
}

// deliver calls the mesh hooks for the changes that wait, as Run does.
func (g *trunkRig) deliver() {
	synctest.Wait()
	g.m.deliver()
	synctest.Wait()
}

// call is the TrunkKeys handler of the member.
func (g *trunkRig) call(in *dp.KeysRequest) (*dp.KeysResponse, error) {
	req, err := keyproto.FromProto(in)
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	n, before := g.n, g.before
	g.n++
	g.calls = append(g.calls, req)
	g.mu.Unlock()
	if before != nil {
		if err := before(n, req); err != nil {
			return nil, err
		}
	}
	refused, err := g.tx.Apply(req, time.Now())
	return &dp.KeysResponse{RefusedSpis: refused}, err
}

// requests returns the TrunkKeys calls of the relay since the last call of it.
func (g *trunkRig) requests() []keys.Request {
	synctest.Wait()
	g.mu.Lock()
	defer g.mu.Unlock()
	calls := g.calls
	g.calls = nil
	return calls
}

// packets returns the packets that the relay sent since the last call of it.
func (g *trunkRig) packets() []keptPacket {
	synctest.Wait()
	g.conn.mu.Lock()
	defer g.conn.mu.Unlock()
	pkts := g.conn.pkts
	g.conn.pkts = nil
	return pkts
}

// hold makes the member hold spi from another relay, so that it refuses it.
func (g *trunkRig) hold(spi uint32) error {
	_, err := g.sender.NewPeer().Apply(keys.Request{Op: keys.OpOffer, SAs: []keys.SA{{SPI: spi, Key: make([]byte, 16), ExpiresIn: time.Minute}}}, time.Now())
	return err
}

// offer gives the relay new SAs of the member on s, as a TrunkKeys call of
// the member does.
func (g *trunkRig) offer(s *MeshSession) (keys.Request, error) {
	g.t.Helper()
	req, err := g.rx.Offer(time.Now())
	require.NoError(g.t, err)
	if _, err = g.tk.apply(s, req, time.Now()); err == nil {
		g.inner = req.SAs[trunkLaneInner].SPI
	}
	return req, err
}

// message opens a packet of the relay and returns the message of the relay in it.
func (g *trunkRig) message(pkt keptPacket) []byte {
	g.t.Helper()
	assert.Equal(g.t, g.addr, pkt.to)
	assert.Equal(g.t, g.inner, binary.BigEndian.Uint32(pkt.b[4:8]), "a message goes on the lane with a replay window")
	msg, tag, nextHdr, err := g.rxq.ReceiveTrunk(pkt.b)
	require.NoError(g.t, err)
	assert.EqualValues(g.t, trunkTagRelay, tag)
	assert.EqualValues(g.t, pspwire.NextHdrPSP, nextHdr)
	return msg
}

// send seals msg with the newest SA of the relay and gives the packet to the
// relay from the address of the member.
func (g *trunkRig) send(tag uint32, msg []byte) {
	g.t.Helper()
	sa := g.tx.SA(trunkLaneInner)
	require.NotNil(g.t, sa, "the member has an SA of the relay")
	pkt := make([]byte, len(msg)+pspwire.Overhead)
	n, err := sa.SealTrunkPSP(tag, pkt, msg)
	require.NoError(g.t, err)
	g.handle(pkt[:n], net.UDPAddrFromAddrPort(g.addr))
	synctest.Wait()
}

// keyed gives the relay the SAs of the member on s and answers the probe of
// the relay. Then the pair has keys in both directions and a full path.
func (g *trunkRig) keyed(s *MeshSession) *trunkPair {
	g.t.Helper()
	_, err := g.offer(s)
	require.NoError(g.t, err)
	pkts := g.packets()
	require.Len(g.t, pkts, 1, "the relay sends a probe when the pair has keys in both directions")
	return g.answer(pkts[0])
}

// answer sends the answer of the member to the probe of the relay in pkt.
// Then the pair has a full path.
func (g *trunkRig) answer(pkt keptPacket) *trunkPair {
	g.t.Helper()
	msg := g.message(pkt)
	msg[0] = trunkMsgReply
	g.send(trunkTagRelay, msg)
	p := g.tk.pair("relay-a")
	require.NotNil(g.t, p)
	require.Equal(g.t, trunkPathFull, trunkPath(p.path.Load()))
	return p
}

// ping reports whether the keys of the pair work in both directions: the
// member sends a probe and opens the answer of the relay.
func (g *trunkRig) ping() bool {
	g.t.Helper()
	g.packets()
	probe := make([]byte, 64)
	probe[0] = trunkMsgProbe
	g.send(trunkTagRelay, probe)
	for _, pkt := range g.packets() {
		if msg, _, _, err := g.rxq.ReceiveTrunk(pkt.b); err == nil && len(msg) == len(probe) && msg[0] == trunkMsgReply {
			return true
		}
	}
	return false
}

// removed checks that the relay removed p and all its keys. rx has the SPIs
// of the receive SAs that p had.
func (g *trunkRig) removed(p *trunkPair, rx []uint32) {
	g.t.Helper()
	assert.NotSame(g.t, p, g.tk.pair("relay-a"))
	for lane := range trunkLanes {
		assert.Nil(g.t, p.tx.SA(lane), "the relay has no SA of lane %d of the member", lane)
	}
	g.noSAs(p, rx)
}

// noSAs checks that the relay has no receive SA with an SPI of rx.
func (g *trunkRig) noSAs(p *trunkPair, rx []uint32) {
	g.t.Helper()
	require.NotEmpty(g.t, rx)
	for _, spi := range rx {
		_, ok := g.r.bridge.Load().table.Stats(spi)
		assert.False(g.t, ok, "the relay has no receive SA %#x", spi)
		assert.False(g.t, p.receives(spi))
	}
}

func spisOfRequest(req keys.Request) []uint32 {
	spis := make([]uint32, len(req.SAs))
	for i, sa := range req.SAs {
		spis[i] = sa.SPI
	}
	return spis
}

// TestTrunkProbeTime checks with the fake clock when a probe run sends, when
// it fails, when the next run starts, and which answer passes it.
func TestTrunkProbeTime(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newTrunkRig(t, cfg)
		defer g.stop()
		s := g.open(trunkRevision)
		g.deliver()
		require.Len(t, g.requests(), 1)
		assert.Empty(t, g.packets(), "no probe before the member gave its SAs")
		_, err := g.offer(s)
		require.NoError(t, err)
		p := g.tk.pair("relay-a")
		require.NotNil(t, p)
		path := func() trunkPath {
			synctest.Wait()
			return trunkPath(p.path.Load())
		}

		// A run sends 3 packets 300 ms apart, and fails 1 s after its start.
		var first []byte
		for i := range 3 {
			pkts := g.packets()
			require.Len(t, pkts, 1, "packet %d of the run", i)
			assert.Len(t, pkts[0].b, maxUDP)
			msg := g.message(pkts[0])
			require.Len(t, msg, trunkPayload)
			assert.EqualValues(t, trunkMsgProbe, msg[0])
			assert.Equal(t, make([]byte, trunkPayload-trunkProbeLen), msg[trunkProbeLen:])
			if i == 0 {
				first = slices.Clone(msg[:trunkProbeLen])
			}
			assert.Equal(t, first, msg[:trunkProbeLen], "each packet of a run has the ID of the run")
			time.Sleep(300*time.Millisecond - time.Nanosecond)
			assert.Empty(t, g.packets(), "the packets of a run are 300 ms apart")
			time.Sleep(time.Nanosecond)
		}
		assert.Empty(t, g.packets(), "a run has 3 packets")
		time.Sleep(100*time.Millisecond - time.Nanosecond)
		assert.Equal(t, trunkPathUnknown, path())
		assert.Equal(t, 1280, p.mtu(), "the limit before the first result")
		time.Sleep(time.Nanosecond)
		assert.Equal(t, trunkPathLimited, path())
		assert.Equal(t, 1280, p.mtu())

		// The next run starts 30 s after a failed run.
		time.Sleep(30*time.Second - time.Nanosecond)
		assert.Empty(t, g.packets())
		time.Sleep(time.Nanosecond)
		pkts := g.packets()
		require.Len(t, pkts, 1)
		reply := slices.Clone(g.message(pkts[0]))
		assert.NotEqual(t, first, reply[:trunkProbeLen], "a new run has a new ID")
		reply[0] = trunkMsgReply
		late := make([]byte, trunkPayload)
		copy(late, first)
		late[0] = trunkMsgReply
		other := slices.Clone(reply)
		other[0] = 0x03
		wrong := []struct {
			name string
			tag  uint32
			msg  []byte
		}{
			{"answer to the run before", trunkTagRelay, late},
			{"answer that is 1 byte shorter", trunkTagRelay, reply[:trunkPayload-1]},
			{"answer with the tag of a sender", 7, reply},
			{"message of an unknown type", trunkTagRelay, other},
			{"message with no ID", trunkTagRelay, reply[:trunkProbeLen-1]},
		}
		for i, w := range wrong {
			g.send(w.tag, w.msg)
			assert.Equal(t, trunkPathLimited, path(), w.name)
			assert.EqualValues(t, i+1, g.r.MalformedDrops(), w.name)
		}
		g.send(trunkTagRelay, reply)
		assert.Equal(t, trunkPathFull, path())
		assert.Equal(t, 1372, p.mtu())
		assert.EqualValues(t, len(wrong), g.r.MalformedDrops())

		// A passed run is the last run of the session.
		time.Sleep(5 * time.Minute)
		assert.Empty(t, g.packets())
		assert.Equal(t, trunkPathFull, path())
	})
}

// TestTrunkAnswer checks the answer of a relay to the probes of a member: the
// same size and ID, and at most 10 answers each second.
func TestTrunkAnswer(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newTrunkRig(t, cfg)
		defer g.stop()
		s := g.open(trunkRevision)
		g.deliver()
		g.keyed(s)
		sizes := []int{trunkProbeLen, 100, trunkPayload}
		for _, size := range sizes {
			probe := make([]byte, size)
			probe[0] = trunkMsgProbe
			binary.BigEndian.PutUint64(probe[1:], uint64(size))
			g.send(trunkTagRelay, probe)
			pkts := g.packets()
			require.Len(t, pkts, 1, "probe of %d bytes", size)
			probe[0] = trunkMsgReply
			assert.Equal(t, probe, g.message(pkts[0]), "probe of %d bytes", size)
		}
		probe := make([]byte, trunkPayload)
		probe[0] = trunkMsgProbe
		for range 20 {
			g.send(trunkTagRelay, probe)
		}
		assert.Len(t, g.packets(), 10-len(sizes), "the answers of one moment")
		assert.EqualValues(t, 20-(10-len(sizes)), g.r.MalformedDrops())
		time.Sleep(time.Second)
		for range 20 {
			g.send(trunkTagRelay, probe)
		}
		assert.Len(t, g.packets(), 10, "the answers 1 s later")
	})
}

// TestTrunkDownTime checks with the fake clock how long the keys of a pair
// stay after its session ended, and what a new session does to them.
func TestTrunkDownTime(t *testing.T) {
	const downAfter = 3 * time.Second
	lost := &quic.IdleTimeoutError{}
	restart := &quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART)}
	cases := []struct {
		name string
		// run gets a pair p with keys in both directions on s. rx has the
		// SPIs of the receive SAs of the relay.
		run func(t *testing.T, g *trunkRig, s *MeshSession, p *trunkPair, rx []uint32)
	}{
		{"no new session", func(t *testing.T, g *trunkRig, s *MeshSession, p *trunkPair, rx []uint32) {
			g.end(s, lost)
			time.Sleep(downAfter - time.Nanosecond)
			g.deliver()
			assert.Same(t, p, g.tk.pair("relay-a"))
			assert.True(t, g.ping(), "the keys work while the member is up")
			time.Sleep(time.Nanosecond)
			g.deliver()
			g.removed(p, rx)
			assert.False(t, g.ping())
		}},
		{"new session before the down time", func(t *testing.T, g *trunkRig, s *MeshSession, p *trunkPair, rx []uint32) {
			tx := p.tx.SA(trunkLaneInner).SPI()
			g.end(s, lost)
			time.Sleep(time.Second)
			s2 := g.open(trunkRevision)
			g.deliver()
			reqs := g.requests()
			require.Len(t, reqs, 1, "the relay makes a new offer on the new session")
			assert.Equal(t, keys.OpOffer, reqs[0].Op)
			require.Len(t, reqs[0].SAs, trunkLanes)
			assert.Same(t, p, g.tk.pair("relay-a"))
			for _, spi := range append(spisOfRequest(reqs[0]), rx...) {
				assert.True(t, p.receives(spi), "SA %#x is a receive SA of the pair", spi)
			}
			require.NotNil(t, p.tx.SA(trunkLaneInner), "the SAs of the member stay")
			assert.Equal(t, tx, p.tx.SA(trunkLaneInner).SPI())
			assert.True(t, g.ping())
			time.Sleep(time.Minute)
			g.deliver()
			assert.Same(t, p, g.tk.pair("relay-a"))
			assert.Empty(t, g.packets(), "no probe before the member gave its SAs on the new session")
			// The member gives new SAs, and the relay probes the path again. The
			// result of the session before stays until the new run ends.
			_, err := g.offer(s2)
			require.NoError(t, err)
			assert.Len(t, g.packets(), 1)
			assert.True(t, g.ping())
			time.Sleep(time.Second - time.Nanosecond)
			synctest.Wait()
			assert.Equal(t, 1372, p.mtu())
			time.Sleep(time.Nanosecond)
			synctest.Wait()
			assert.Equal(t, 1280, p.mtu(), "the new run got no answer")
		}},
		{"new session from a new address", func(t *testing.T, g *trunkRig, s *MeshSession, p *trunkPair, rx []uint32) {
			g.end(s, lost)
			g.addr = netip.MustParseAddrPort("198.51.100.7:6081")
			s2 := g.open(trunkRevision)
			g.deliver()
			// A pair is for one address, so the member gets a new pair.
			g.removed(p, rx)
			p2 := g.tk.pair("relay-a")
			require.NotNil(t, p2)
			assert.Nil(t, g.tk.from(trunkRigAddr))
			assert.Same(t, p2, g.tk.from(g.addr))
			_, err := g.offer(s2)
			require.NoError(t, err)
			pkts := g.packets()
			require.Len(t, pkts, 1)
			assert.Equal(t, g.addr, pkts[0].to, "the probe goes to the new address")
			assert.True(t, g.ping())
			g.addr = trunkRigAddr
			assert.False(t, g.ping(), "a packet from the address before")
		}},
		{"the member stops", func(t *testing.T, g *trunkRig, s *MeshSession, p *trunkPair, rx []uint32) {
			g.end(s, restart)
			g.deliver()
			g.removed(p, rx)
			assert.False(t, g.ping())
		}},
		{"the member leaves the set", func(t *testing.T, g *trunkRig, _ *MeshSession, p *trunkPair, rx []uint32) {
			g.m.SetMembers(nil)
			g.deliver()
			g.removed(p, rx)
			assert.False(t, g.ping())
		}},
		{"the member stops, and its new session gives SAs before the hooks run", func(t *testing.T, g *trunkRig, s *MeshSession, p *trunkPair, rx []uint32) {
			g.end(s, restart)
			s2 := g.open(trunkRevision)
			req, err := g.offer(s2)
			require.NoError(t, err)
			g.deliver()
			assert.Same(t, p, g.tk.pair("relay-a"), "the pair has the SAs of the new session")
			for _, sa := range req.SAs {
				tx := p.tx.SA(sa.Lane)
				require.NotNil(t, tx, "the SA of lane %d from the new session stays", sa.Lane)
				assert.Equal(t, sa.SPI, tx.SPI())
			}
			g.noSAs(p, rx)
			reqs := g.requests()
			require.Len(t, reqs, 1)
			assert.Equal(t, keys.OpOffer, reqs[0].Op)
			assert.True(t, g.ping())
		}},
		{"the member stops, and its new session gives SAs after the hooks run", func(t *testing.T, g *trunkRig, s *MeshSession, p *trunkPair, rx []uint32) {
			g.end(s, restart)
			s2 := g.open(trunkRevision)
			g.deliver()
			g.removed(p, rx)
			p2 := g.tk.pair("relay-a")
			require.NotNil(t, p2)
			assert.Nil(t, p2.tx.SA(trunkLaneInner))
			assert.Empty(t, g.packets(), "no probe before the member gave its SAs")
			_, err := g.offer(s2)
			require.NoError(t, err)
			assert.Len(t, g.packets(), 1)
			assert.True(t, g.ping())
		}},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newTrunkRig(t, cfg)
				defer g.stop()
				s := g.open(trunkRevision)
				g.deliver()
				reqs := g.requests()
				require.Len(t, reqs, 1)
				p := g.keyed(s)
				require.True(t, g.ping())
				tc.run(t, g, s, p, spisOfRequest(reqs[0]))
			})
		})
	}
}

// TestTrunkGive checks the calls of a relay that gives its SAs to a member
// that refuses them, or that does not answer the call.
func TestTrunkGive(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, g *trunkRig)
	}{
		{"the member holds one SPI from another relay", func(t *testing.T, g *trunkRig) {
			g.before = func(n int, req keys.Request) error {
				if n == 0 {
					return g.hold(req.SAs[trunkLaneInner].SPI)
				}
				return nil
			}
			s := g.open(trunkRevision)
			g.deliver()
			reqs := g.requests()
			require.Len(t, reqs, 2)
			require.Len(t, reqs[0].SAs, trunkLanes)
			require.Len(t, reqs[1].SAs, 1, "the relay offers a new SA for the lane of the refused SPI")
			refused, next := reqs[0].SAs[trunkLaneInner], reqs[1].SAs[0]
			assert.Equal(t, refused.Lane, next.Lane)
			assert.NotEqual(t, refused.SPI, next.SPI)
			p := g.keyed(s)
			assert.True(t, p.receives(next.SPI))
			g.noSAs(p, []uint32{refused.SPI})
			assert.True(t, g.ping())
		}},
		{"the member holds the SPIs of each offer", func(t *testing.T, g *trunkRig) {
			g.before = func(n int, req keys.Request) error {
				if n > maxClashes {
					return nil
				}
				for _, sa := range req.SAs {
					if err := g.hold(sa.SPI); err != nil {
						return err
					}
				}
				return nil
			}
			s := g.open(trunkRevision)
			g.deliver()
			require.Len(t, g.requests(), maxClashes+1, "the relay stops after some refused offers")
			// The relay starts again after the wait of a failed call.
			time.Sleep(300 * time.Millisecond)
			reqs := g.requests()
			require.Len(t, reqs, 1)
			assert.Equal(t, keys.OpOffer, reqs[0].Op)
			assert.Len(t, reqs[0].SAs, trunkLanes)
			g.keyed(s)
			assert.True(t, g.ping())
		}},
		{"a call fails", func(t *testing.T, g *trunkRig) {
			g.before = func(n int, _ keys.Request) error {
				if n == 0 {
					return rpc.Errorf(rpc.Unavailable, "test")
				}
				return nil
			}
			s := g.open(trunkRevision)
			g.deliver()
			first := g.requests()
			require.Len(t, first, 1)
			_, err := g.offer(s)
			require.NoError(t, err)
			// The wait before the next call is 200 ms and at most 50% more.
			time.Sleep(200*time.Millisecond - time.Nanosecond)
			require.Empty(t, g.requests())
			assert.Empty(t, g.packets(), "no probe before the member has the SAs of the relay")
			time.Sleep(100*time.Millisecond + time.Nanosecond)
			reqs := g.requests()
			require.Len(t, reqs, 1)
			assert.Equal(t, keys.OpOffer, reqs[0].Op, "the next call is a new offer of all lanes")
			require.Len(t, reqs[0].SAs, trunkLanes)
			for _, sa := range reqs[0].SAs {
				assert.NotContains(t, spisOfRequest(first[0]), sa.SPI)
			}
			pkts := g.packets()
			require.Len(t, pkts, 1, "the relay sends a probe when the pair has keys in both directions")
			g.answer(pkts[0])
			assert.True(t, g.ping())
			time.Sleep(time.Minute)
			assert.Empty(t, g.requests())
		}},
		{"the member has no trunk", func(t *testing.T, g *trunkRig) {
			g.before = func(int, keys.Request) error { return rpc.Errorf(rpc.Unimplemented, "test") }
			s := g.open(trunkRevision)
			g.deliver()
			reqs := g.requests()
			require.Len(t, reqs, 1)
			time.Sleep(time.Minute)
			assert.Empty(t, g.requests(), "the relay makes no more calls on the session")
			p := g.tk.pair("relay-a")
			require.NotNil(t, p)
			g.noSAs(p, spisOfRequest(reqs[0]))
			assert.Equal(t, 1280, p.mtu())
			// A new session of the member gets a new offer.
			g.end(s, &quic.IdleTimeoutError{})
			g.open(trunkRevision)
			g.deliver()
			assert.Len(t, g.requests(), 1)
		}},
		{"the member is at a revision from before the trunk", func(t *testing.T, g *trunkRig) {
			s := g.open(trunkRevision - 1)
			g.deliver()
			assert.Empty(t, g.requests(), "a member from before the trunk gets no call")
			assert.Nil(t, g.tk.pair("relay-a"))
			_, err := g.offer(s)
			assert.Equal(t, rpc.FailedPrecondition, rpc.CodeOf(err), "error: %v", err)
			assert.Nil(t, g.tk.pair("relay-a"))
			assert.Empty(t, g.packets())
		}},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newTrunkRig(t, cfg)
				defer g.stop()
				tc.run(t, g)
			})
		})
	}
}

// TestTrunkRekeyTime checks with the fake clock that the member gets new SAs
// at 3/4 of the lifetime, and a new offer of all lanes if that call fails.
func TestTrunkRekeyTime(t *testing.T) {
	cases := []struct {
		name string
		fail bool // The rekey call fails.
	}{
		{name: "the member gets the rekey"},
		{name: "the rekey call fails", fail: true},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newTrunkRig(t, cfg)
				defer g.stop()
				g.before = func(n int, _ keys.Request) error {
					if tc.fail && n == 1 {
						return rpc.Errorf(rpc.Unavailable, "test")
					}
					return nil
				}
				s := g.open(trunkRevision)
				g.deliver()
				first := g.requests()
				require.Len(t, first, 1)
				p := g.keyed(s)
				// The router looks at the SAs each second.
				ticks := func(d time.Duration) {
					for range int(d / time.Second) {
						time.Sleep(time.Second)
						g.r.tickBridge(time.Now())
					}
				}
				lifetime := g.r.bridge.Load().lifetime
				ticks(lifetime*3/4 - 2*time.Second)
				require.Empty(t, g.requests(), "no rekey before 3/4 of the lifetime")
				ticks(3 * time.Second)
				want := []keys.Op{keys.OpRekey}
				if tc.fail {
					// The call after a failed call is a new offer of all lanes.
					want = append(want, keys.OpOffer)
				}
				reqs := g.requests()
				require.Len(t, reqs, len(want))
				for i, op := range want {
					assert.Equal(t, op, reqs[i].Op, "call %d", i)
					require.Len(t, reqs[i].SAs, trunkLanes, "call %d", i)
				}
				newest := reqs[len(reqs)-1]
				for _, spi := range append(spisOfRequest(first[0]), spisOfRequest(newest)...) {
					assert.True(t, p.receives(spi), "SA %#x is a receive SA of the pair", spi)
				}
				assert.Empty(t, g.packets(), "a rekey starts no probe run")
				assert.True(t, g.ping(), "the member sends with the newest SA")
				// The SAs from before the rekey end a quarter of the lifetime later.
				ticks(lifetime / 4)
				g.noSAs(p, spisOfRequest(first[0]))
				for _, spi := range spisOfRequest(newest) {
					assert.True(t, p.receives(spi), "SA %#x stays", spi)
				}
			})
		})
	}
}
