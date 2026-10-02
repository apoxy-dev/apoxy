// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
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
		name             string
		cfg              Config
		wantMTU, wantDev int // Zero means New fails.
	}{
		{"default MTU", Config{Transport: tr, Demux: dm, VNI: 1}, DefaultMTU, DefaultMTU},
		{"largest MTU", Config{Transport: tr, Demux: dm, VNI: pspwire.MaxVNI, MTU: MaxMTU}, MaxMTU, MaxMTU},
		{"smaller device MTU", Config{Transport: tr, Demux: dm, MTU: 1400, DeviceMTU: DefaultMTU}, 1400, DefaultMTU},
		{"no transport", Config{Demux: dm, VNI: 1}, 0, 0},
		{"no demux", Config{Transport: tr, VNI: 1}, 0, 0},
		{"transport has no handler", Config{Transport: newTransport(t, nil), Demux: dm}, 0, 0},
		{"demux has a binding", Config{Transport: tr, Demux: used}, 0, 0},
		{"VNI too large", Config{Transport: tr, Demux: dm, VNI: pspwire.MaxVNI + 1}, 0, 0},
		{"MTU too large", Config{Transport: tr, Demux: dm, MTU: MaxMTU + 1}, 0, 0},
		{"negative MTU", Config{Transport: tr, Demux: dm, MTU: -1}, 0, 0},
		{"device MTU above MTU", Config{Transport: tr, Demux: dm, DeviceMTU: DefaultMTU + 1}, 0, 0},
		{"negative device MTU", Config{Transport: tr, Demux: dm, DeviceMTU: -1}, 0, 0},
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
			assert.Equal(t, tc.wantDev, b.DeviceMTU())
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

func TestDemux(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	c := &capture{}
	b.b.drv.Store(newDriver(b.b, c.deliver))
	var probes [][]byte
	cases := []struct {
		name      string
		probe     bool // The demux has a Probe function.
		pkt       []byte
		wantProbe bool
		want      Stats
	}{
		{"probe", true, []byte{p2p.TypeProbe, 1}, true, Stats{}},
		{"PSP", true, seal(a, packet(a.v4, b.v4, 17, 1, 2, 100))[addrLen:], false, Stats{RxPackets: 1}},
		{"other", true, []byte{0x01, 1}, false, Stats{RxOther: 1}},
		{"probe with no Probe function", false, []byte{p2p.TypeProbe, 1}, false, Stats{RxOther: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probes = nil
			b.b.demux.Probe = nil
			if tc.probe {
				b.b.demux.Probe = func(pkt []byte, _ net.Addr) { probes = append(probes, pkt) }
			}
			before := b.b.Stats()
			b.b.demux.Handle(tc.pkt, nil)
			assert.Equal(t, tc.want, sub(b.b.Stats(), before))
			if tc.wantProbe {
				assert.Equal(t, [][]byte{tc.pkt}, probes)
			} else {
				assert.Empty(t, probes)
			}
		})
	}
}

// tcpSyn returns an IPv4 TCP packet with flags and an MSS option, with a valid checksum.
func tcpSyn(src, dst netip.Addr, flags header.TCPFlags, mss uint16) []byte {
	opts := []byte{2, 4, byte(mss >> 8), byte(mss)}
	pkt := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+len(opts))
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)), TTL: 64, Protocol: uint8(header.TCPProtocolNumber),
		SrcAddr: tcpip.AddrFrom4(src.As4()), DstAddr: tcpip.AddrFrom4(dst.As4()),
	})
	tcp := header.TCP(pkt[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{SrcPort: 1, DstPort: 2, DataOffset: uint8(len(tcp)), Flags: flags, WindowSize: 1000})
	copy(tcp.Options(), opts)
	x := header.PseudoHeaderChecksum(header.TCPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(tcp)))
	tcp.SetChecksum(^tcp.CalculateChecksum(x))
	return pkt
}

// xferQUIC sends pkt from one node to the other as a QUIC data frame, and returns the inner
// packet that arrived.
func xferQUIC(t *testing.T, from *node, pkt []byte) []byte {
	t.Helper()
	f := seal(from, pkt)
	require.NotNil(t, f)
	require.Zero(t, binary.BigEndian.Uint16(f[16:addrLen]), "not a data frame")
	to := from.other.b
	c := &capture{}
	to.drv.Store(newDriver(to, c.deliver))
	defer to.drv.Store(nil)
	to.HandleData(f[addrLen:])
	if len(c.got) == 0 {
		return nil
	}
	return c.got[0]
}

// TestClampMSS sends TCP SYN packets from a to b. The clamp of a lowers the MSS when a
// sends, and the clamp of b when b receives. The QUIC path also clamps to QUICMTU.
func TestClampMSS(t *testing.T) {
	syn, synAck := header.TCPFlagSyn, header.TCPFlagSyn|header.TCPFlagAck
	cases := []struct {
		name           string
		mtu            int
		clampA, clampB int  // SetClampMTU of a and b.
		quicA, quicB   bool // UseQUIC of a and b.
		flags          header.TCPFlags
		mss, wantMSS   uint16
	}{
		{"no clamp", 1400, 0, 0, false, false, syn, 1360, 1360},
		{"send clamp", 1400, 1280, 0, false, false, syn, 1360, 1240},
		{"receive clamp", 1400, 0, 1280, false, false, synAck, 1360, 1240},
		{"lower of two", 1400, 1300, 1280, false, false, syn, 1360, 1240},
		{"mss below clamp", 1400, 1280, 0, false, false, syn, 1000, 1000},
		{"clamp at device MTU", 1400, 1400, 1400, false, false, syn, 1360, 1360},
		{"no SYN", 1400, 1280, 1280, false, false, header.TCPFlagAck, 1360, 1360},
		{"QUIC send", 1400, 0, 0, true, false, syn, 1360, QUICMTU - 40},
		{"QUIC receive", 1400, 0, 0, false, true, synAck, 1360, QUICMTU - 40},
		{"QUIC with a lower clamp", 1400, 1280, 0, true, false, syn, 1360, 1240},
		{"QUIC with a higher clamp", MaxMTU, 1400, 0, true, false, syn, 1372, QUICMTU - 40},
		{"QUIC at the default MTU", DefaultMTU, 0, 0, true, true, syn, 1240, 1240},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPairMTU(t, tc.mtu)
			offer(t, time.Now(), a, b)
			a.b.SetClampMTU(tc.clampA)
			b.b.SetClampMTU(tc.clampB)
			for _, x := range []struct {
				n  *node
				on bool
			}{{a, tc.quicA}, {b, tc.quicB}} {
				if x.on {
					x.n.b.UseQUIC(&peerconn.Conn{})
				}
			}
			pkt := tcpSyn(a.v4, b.v4, tc.flags, tc.mss)
			var got []byte
			if tc.quicA {
				got = xferQUIC(t, a, pkt)
			} else {
				got = xfer(t, a, pkt)
			}
			require.NotEmpty(t, got)
			assert.Equal(t, tcpSyn(a.v4, b.v4, tc.flags, tc.wantMSS), got)
			tcp := header.TCP(got[header.IPv4MinimumSize:])
			assert.True(t, tcp.IsChecksumValid(tcpip.AddrFrom4(a.v4.As4()), tcpip.AddrFrom4(b.v4.As4()), 0, 0))
		})
	}
}

func TestSetClampMTU(t *testing.T) {
	a, _ := newPairMTU(t, 1400)
	steps := []struct{ set, want, wantOld int }{
		{1280, 1280, 0},
		{1300, 1300, 1280},
		{1000, DefaultMTU, 1300},
		{1400, 0, DefaultMTU},
		{1300, 1300, 0},
		{0, 0, 1300},
	}
	for _, s := range steps {
		assert.Equal(t, s.wantOld, a.b.SetClampMTU(s.set), "set %d", s.set)
		assert.Equal(t, s.want, a.b.ClampMTU(), "set %d", s.set)
	}
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
