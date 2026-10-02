// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// The largest PSP packet must fit in one quic-go read of 1452 B.
func TestMaxMTU(t *testing.T) {
	assert.Equal(t, 1452, MaxMTU+pspwire.Overhead)
}

func TestNew(t *testing.T) {
	dm, used := &Demux{}, &Demux{}
	tr := newTransport(t, dm.Handle)
	b, err := New(Config{Transport: tr, Demux: used})
	require.NoError(t, err)
	defer b.Close()
	cases := []struct {
		name    string
		cfg     Config
		wantMTU int // Zero means New fails.
	}{
		{"default MTU", Config{Transport: tr, Demux: dm, VNI: 1}, DefaultMTU},
		{"largest MTU", Config{Transport: tr, Demux: dm, VNI: pspwire.MaxVNI, MTU: MaxMTU}, MaxMTU},
		{"no transport", Config{Demux: dm, VNI: 1}, 0},
		{"no demux", Config{Transport: tr, VNI: 1}, 0},
		{"transport has no handler", Config{Transport: newTransport(t, nil), Demux: dm}, 0},
		{"demux has a binding", Config{Transport: tr, Demux: used}, 0},
		{"VNI too large", Config{Transport: tr, Demux: dm, VNI: pspwire.MaxVNI + 1}, 0},
		{"MTU too large", Config{Transport: tr, Demux: dm, MTU: MaxMTU + 1}, 0},
		{"negative MTU", Config{Transport: tr, Demux: dm, MTU: -1}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := New(tc.cfg)
			if tc.wantMTU == 0 {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantMTU, b.mtu)
			require.NoError(t, b.Close())
		})
	}
}

// xfer sends pkt from one node to the other through the engines, as the
// driver does, and returns the inner packet that arrived.
func xfer(t *testing.T, from *node, pkt []byte) []byte {
	t.Helper()
	phy := seal(from, pkt)
	if phy == nil {
		return nil
	}
	dst := netip.AddrPortFrom(netip.AddrFrom16([16]byte(phy[:16])).Unmap(), binary.BigEndian.Uint16(phy[16:addrLen]))
	require.Equal(t, from.peer.Addr(), dst)
	return open(from.other.b, phy[addrLen:])
}

func TestDatapath(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	spoof := netip.MustParseAddr("10.0.0.77")
	far := netip.MustParseAddr("10.9.9.9")
	cases := []struct {
		name string
		pkt  []byte
		want Stats // Counter changes on a, then b.
	}{
		{"IPv4", packet(a.v4, b.v4, 17, 1, 2, 1000), Stats{RxPackets: 1}},
		{"IPv6", packet(a.v6, b.v6, 6, 1, 2, 1000), Stats{RxPackets: 1}},
		{"MTU-size packet", packet(a.v4, b.v4, 17, 1, 2, DefaultMTU), Stats{RxPackets: 1}},
		{"no route", packet(a.v4, far, 17, 1, 2, 100), Stats{TxNoRoute: 1}},
		{"too large", packet(a.v4, b.v4, 17, 1, 2, DefaultMTU+1), Stats{TxDrops: 1}},
		{"not IP", make([]byte, 100), Stats{TxDrops: 1}},
		{"source not routed to the sender", packet(spoof, b.v4, 17, 1, 2, 100), Stats{RxDrops: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := add(a.b.Stats(), b.b.Stats())
			got := xfer(t, a, tc.pkt)
			assert.Equal(t, tc.want, sub(add(a.b.Stats(), b.b.Stats()), before))
			if tc.want.RxPackets == 1 {
				assert.Equal(t, tc.pkt, got)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

func add(x, y Stats) Stats {
	return Stats{x.RxPackets + y.RxPackets, x.RxDrops + y.RxDrops, x.RxNoDriver + y.RxNoDriver, x.RxOther + y.RxOther,
		x.TxPackets + y.TxPackets, x.TxNoRoute + y.TxNoRoute, x.TxDrops + y.TxDrops}
}

func sub(x, y Stats) Stats {
	return Stats{x.RxPackets - y.RxPackets, x.RxDrops - y.RxDrops, x.RxNoDriver - y.RxNoDriver, x.RxOther - y.RxOther,
		x.TxPackets - y.TxPackets, x.TxNoRoute - y.TxNoRoute, x.TxDrops - y.TxDrops}
}

// TestReceive gives packets to the receive path. It opens them in place and
// gives the inner packet to the driver.
func TestReceive(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	pkt := packet(a.v4, b.v4, 17, 1, 2, 500)
	cases := []struct {
		name    string
		pkt     []byte
		drv     *capture // Nil means no driver.
		want    Stats
		deliver bool
	}{
		{"PSP", seal(a, pkt)[addrLen:], &capture{}, Stats{RxPackets: 1}, true},
		{"no driver", seal(a, pkt)[addrLen:], nil, Stats{RxNoDriver: 1}, false},
		{"driver drops", seal(a, pkt)[addrLen:], &capture{fail: true}, Stats{RxDrops: 1}, false},
		{"unknown SA", append([]byte{pspwire.NextHdrV4, 1}, make([]byte, 100)...), &capture{}, Stats{RxDrops: 1}, false},
		{"PSP in IPv6", []byte{pspwire.NextHdrV6, 1}, &capture{}, Stats{RxDrops: 1}, false},
		{"probe", []byte{0x02, 1}, &capture{}, Stats{RxOther: 1}, false},
		{"empty", nil, &capture{}, Stats{RxOther: 1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.drv != nil {
				d := newDriver(b.b, tc.drv.deliver)
				b.b.drv.Store(d)
				defer b.b.drv.Store(nil)
			}
			before := b.b.Stats()
			b.b.demux.Handle(tc.pkt, nil)
			assert.Equal(t, tc.want, sub(b.b.Stats(), before))
			if tc.deliver {
				assert.Equal(t, [][]byte{pkt}, tc.drv.got)
			} else if tc.drv != nil {
				assert.Empty(t, tc.drv.got)
			}
		})
	}

	// A closed binding leaves the demux.
	require.NoError(t, b.b.Close())
	before := b.b.Stats()
	b.b.demux.Handle(seal(a, pkt)[addrLen:], nil)
	assert.Equal(t, before, b.b.Stats())
}

func TestRemovePeer(t *testing.T) {
	a, b := newPair(t)
	now := time.Now()
	pkt := packet(a.v4, b.v4, 17, 1, 2, 100)
	require.Empty(t, xfer(t, a, pkt), "no SA before the offer")
	offer(t, now, a, b)
	require.Equal(t, pkt, xfer(t, a, pkt))

	// b removes its peer for a: its receive SAs go at once.
	revoke := b.b.RemovePeer(b.peer)
	assert.Equal(t, keys.OpRevoke, revoke.Op)
	assert.Len(t, revoke.SPIs, 1)
	assert.Empty(t, xfer(t, a, pkt))
	assert.Equal(t, uint64(1), b.b.Stats().RxDrops)
	// a applies the revoke and has no SA to b.
	require.NoError(t, give(a, revoke, now))
	assert.Empty(t, xfer(t, a, pkt))
	assert.Equal(t, uint64(2), a.b.Stats().TxNoRoute, "one before the offer, one now")
	// b has no route to a.
	assert.Empty(t, xfer(t, b, packet(b.v4, a.v4, 17, 1, 2, 100)))
	assert.Equal(t, uint64(1), b.b.Stats().TxNoRoute)

	_, err := b.peer.Offer(now)
	assert.ErrorIs(t, err, ErrClosed)
	_, err = b.peer.Refused(nil, now)
	assert.ErrorIs(t, err, ErrClosed)
	_, err = b.peer.Apply(keys.Request{Op: keys.OpRevoke}, now)
	assert.ErrorIs(t, err, ErrClosed)
	assert.ErrorIs(t, b.b.AddRoute(netip.MustParsePrefix("10.0.0.1/32"), b.peer), ErrClosed)
	assert.Equal(t, keys.Request{Op: keys.OpRevoke}, b.b.RemovePeer(b.peer), "a second remove does nothing")
}

func TestRoutes(t *testing.T) {
	a, b := newPair(t)
	p2, err := a.b.AddPeer(addrOf(b.tr))
	require.NoError(t, err)
	pfx := netip.MustParsePrefix("10.1.0.0/24")
	steps := []struct {
		name string
		do   func() error
		want error // For bool results, ErrRouteTaken stands for false.
	}{
		{"add", func() error { return a.b.AddRoute(netip.MustParsePrefix("10.1.0.9/24"), a.peer) }, nil},
		{"add again", func() error { return a.b.AddRoute(pfx, a.peer) }, nil},
		{"add for another peer", func() error { return a.b.AddRoute(pfx, p2) }, engine.ErrRouteTaken},
		{"remove for another peer", func() error { return removed(a.b.RemoveRoute(pfx, p2)) }, engine.ErrRouteTaken},
		{"remove unmasked", func() error { return removed(a.b.RemoveRoute(netip.MustParsePrefix("10.1.0.1/24"), a.peer)) }, nil},
		{"remove again", func() error { return removed(a.b.RemoveRoute(pfx, a.peer)) }, engine.ErrRouteTaken},
		{"add for the other peer", func() error { return a.b.AddRoute(pfx, p2) }, nil},
	}
	for _, s := range steps {
		assert.ErrorIs(t, s.do(), s.want, s.name)
	}
	assert.Equal(t, []netip.Prefix{netip.PrefixFrom(b.v4, 32), netip.PrefixFrom(b.v6, 128)}, a.peer.routes)
	assert.Equal(t, []netip.Prefix{pfx}, p2.routes)
	// RemovePeer removes the routes of the peer.
	a.b.RemovePeer(p2)
	assert.Equal(t, 2, a.b.routes.Len())
}

func removed(ok bool) error {
	if !ok {
		return engine.ErrRouteTaken
	}
	return nil
}

// TestLanes gives the peer 4 lanes from a receiver with 4 queues.
func TestLanes(t *testing.T) {
	a, b := newPair(t)
	tab, err := engine.NewRxTable(engine.RxConfig{Queues: 4})
	require.NoError(t, err)
	r, err := keys.NewReceiver(tab, pspwire.AESGCM128)
	require.NoError(t, err)
	rp, err := r.NewPeer(keys.PeerConfig{VNI: testVNI, MTU: DefaultMTU, Lanes: 4, Sources: func(netip.Addr) bool { return true }})
	require.NoError(t, err)
	now := time.Now()
	req, err := rp.Offer(now)
	require.NoError(t, err)
	require.NoError(t, give(a, req, now))
	lane := map[uint32]int{}
	for _, sa := range req.SAs {
		lane[sa.SPI] = sa.Lane
	}

	flows := func() map[int]int {
		used := map[int]int{}
		for port := range uint16(256) {
			pkt := packet(a.v4, b.v4, 6, port, 443, 100)
			sa := a.peer.txSA(pkt)
			require.NotNil(t, sa)
			require.Equal(t, sa, a.peer.txSA(pkt), "one flow uses one lane")
			used[lane[sa.SPI()]]++
		}
		return used
	}
	assert.Len(t, flows(), 4)
	assert.Equal(t, int32(4), a.peer.lanes.Load())

	// The flows of a lane with no SA use another lane.
	revoke := func(l int) {
		_, err := a.peer.Apply(keys.Request{Op: keys.OpRevoke, SPIs: []uint32{req.SAs[l].SPI}}, now)
		require.NoError(t, err)
	}
	revoke(1)
	used := flows()
	assert.Len(t, used, 3)
	assert.Zero(t, used[1])
	assert.Equal(t, int32(4), a.peer.lanes.Load())
	revoke(3)
	assert.Len(t, flows(), 2)
	assert.Equal(t, int32(3), a.peer.lanes.Load())

	// An SA must have the VNI of the binding.
	other := keys.Request{Op: keys.OpOffer, SAs: []keys.SA{{SPI: 5, Key: make([]byte, 16), VNI: testVNI + 1, ExpiresIn: time.Minute}}}
	_, err = a.peer.Apply(other, now)
	assert.ErrorContains(t, err, "VNI")
}

// TestRekeyInFlight seals packets before each rekey and opens them after
// it, in reverse order. No packet is lost.
func TestRekeyInFlight(t *testing.T) {
	a, b := newPair(t)
	now := time.Now()
	offer(t, now, a, b)
	const rounds, perRound = 10, 50
	for round := range rounds {
		var inFlight [][]byte
		for _, n := range []*node{a, b} {
			for i := range perRound {
				phy := make([]byte, 2048)
				m, _ := (&driver{b: n.b}).VirtToPhy(packet(n.v4, n.other.v4, 17, uint16(i), 9, 500), phy)
				require.NotZero(t, m)
				inFlight = append(inFlight, phy[addrLen:m])
			}
		}
		now = now.Add(engine.DefaultLifetime * 4 / 5)
		ups, err := rekey(now, a, b)
		require.NoError(t, err)
		require.Equal(t, 2, ups, "round %d", round)
		for i := len(inFlight) - 1; i >= 0; i-- {
			to := b // The first perRound packets are from a.
			if i >= perRound {
				to = a
			}
			require.NotNil(t, open(to.b, inFlight[i]), "round %d packet %d", round, i)
		}
	}
	for _, n := range []*node{a, b} {
		st := n.b.Stats()
		assert.Equal(t, Stats{RxPackets: rounds * perRound}, st)
	}
}

func TestKeysProto(t *testing.T) {
	sas := []keys.SA{
		{SPI: 0x8000_0101, Key: bytes.Repeat([]byte{1}, 16), VNI: 7, ExpiresIn: 10 * time.Minute, Lane: 0},
		{SPI: 0x0000_0202, Key: bytes.Repeat([]byte{2}, 32), VNI: 7, ExpiresIn: time.Second, Lane: 15},
	}
	for _, req := range []keys.Request{
		{Op: keys.OpOffer, SAs: sas},
		{Op: keys.OpRekey, SAs: sas[:1]},
		{Op: keys.OpRevoke, SPIs: []uint32{1, 2}},
	} {
		m := KeysToProto(req)
		wire, err := proto.Marshal(m)
		require.NoError(t, err)
		var back dp.KeysRequest
		require.NoError(t, proto.Unmarshal(wire, &back))
		got, err := KeysFromProto(&back)
		require.NoError(t, err)
		assert.Equal(t, req, got)
	}

	bad := []struct {
		name string
		m    *dp.KeysRequest
	}{
		{"no op", &dp.KeysRequest{}},
		{"lane too large", rekeyOf(&dp.SA{Spi: 1, ExpiresIn: durationpb.New(time.Minute), Lane: keys.MaxLanes})},
		{"no expiry", rekeyOf(&dp.SA{Spi: 1})},
		{"bad expiry", rekeyOf(&dp.SA{Spi: 1, ExpiresIn: &durationpb.Duration{Seconds: 1, Nanos: -1}})},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := KeysFromProto(tc.m)
			assert.Error(t, err)
		})
	}
}

func rekeyOf(sa *dp.SA) *dp.KeysRequest {
	return &dp.KeysRequest{Op: &dp.KeysRequest_Rekey{Rekey: &dp.RekeySA{Sas: []*dp.SA{sa}}}}
}

func TestInnerDst(t *testing.T) {
	v4, v6 := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("fd00::2")
	cases := []struct {
		name string
		pkt  []byte
		want netip.Addr // Invalid means no address.
	}{
		{"IPv4", packet(v4, v4, 17, 1, 2, 28), v4},
		{"IPv6", packet(v6, v6, 17, 1, 2, 48), v6},
		{"short IPv4", packet(v4, v4, 17, 1, 2, 28)[:19], netip.Addr{}},
		{"short IPv6", packet(v6, v6, 17, 1, 2, 48)[:39], netip.Addr{}},
		{"empty", nil, netip.Addr{}},
		{"version 5", append([]byte{0x50}, make([]byte, 40)...), netip.Addr{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := innerDst(tc.pkt)
			assert.Equal(t, tc.want.IsValid(), ok)
			assert.Equal(t, tc.want, got)
		})
	}
}
