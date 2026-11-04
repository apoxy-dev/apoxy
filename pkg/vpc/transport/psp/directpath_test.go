// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

var (
	// The lists of a and b: two sessions each.
	ownA = []netip.Prefix{netip.MustParsePrefix("fd00:a::/96"), netip.MustParsePrefix("fd00:a::1:0:0/96")}
	ownB = []netip.Prefix{netip.MustParsePrefix("fd00:b::/96"), netip.MustParsePrefix("fd00:b::1:0:0/96")}
	// advertised is a network that a advertises: not in its list.
	advertised = netip.MustParseAddr("fd00:7::5")
	// elsewhere is an address of a third agent, on the relay route.
	elsewhere = netip.MustParseAddr("fd00:c::1")
)

// base returns the overlay address of a session prefix.
func base(p netip.Prefix) netip.Addr { return p.Addr().Next() }

// takenPkt is a packet that the take-out got.
type takenPkt struct {
	pkt []byte
	src Source
}

// dnode is a node with a direct peer for the other node, and a take-out that keeps what it gets.
type dnode struct {
	*node
	other  *dnode
	direct *Peer
	own    []netip.Prefix
	got    *capture // The packets of a driver with no pipe.
	taken  chan takenPkt
}

// directRx is the receive driver of newDirect.
type directRx int

const (
	directNone    directRx = iota // The test starts the driver.
	directNoPipe                  // A driver with no receive pipe.
	directConsume                 // A pipe whose consumer opens the packets.
	directWorkers                 // A pipe with two open workers.
)

func (k directRx) String() string {
	return [...]string{"none", "no pipe", "pipe, consumer opens", "pipe, two open workers"}[k]
}

// newDirect returns a and b with the inner MTU mtu, which route ::/0 to their relay peer, and have
// a direct peer for the other node with SAs both ways. The test sets the direct routes and sources.
func newDirect(t *testing.T, kind directRx, mtu int) (*dnode, *dnode) {
	t.Helper()
	na, nb := newPairMTU(t, mtu)
	now := time.Now()
	offer(t, now, na, nb)
	a, b := &dnode{node: na, own: ownA}, &dnode{node: nb, own: ownB}
	a.other, b.other = b, a
	for _, n := range []*dnode{a, b} {
		require.NoError(t, n.b.AddRoute(netip.MustParsePrefix("::/0"), n.peer))
		var err error
		n.direct, err = n.b.AddDirect(addrOf(n.other.tr))
		require.NoError(t, err)
		n.b.SetOwn(n.own)
		n.taken = make(chan takenPkt, 256)
		n.b.SetTakeOut(func(pkt []byte, src Source) {
			select {
			case n.taken <- takenPkt{bytes.Clone(pkt), src}:
			default:
				t.Error("the take-out channel is full")
			}
		})
		switch kind {
		case directNoPipe:
			n.got = &capture{}
			n.b.drv.Store(fakeDriver(n.b, n.got.deliver))
		case directConsume, directWorkers:
			useNetstack(t, n.node, channel.New(256, DefaultMTU, ""), 2, int(kind-directConsume)*2)
		}
	}
	for _, x := range [][2]*dnode{{a, b}, {b, a}} {
		req, err := x[0].direct.Offer(now)
		require.NoError(t, err)
		refused, err := x[1].direct.Apply(req, now)
		require.NoError(t, err)
		require.Empty(t, refused)
	}
	return a, b
}

// secondLink gives a a link for its second session, with a relay route to b, and returns the
// receive peer of b for that relay. The other sources of a use the first link.
func secondLink(t *testing.T, a *dnode) *Peer {
	t.Helper()
	require.NoError(t, a.l.AddSource(ownA[0]))
	a.b.SetDefault(a.l)
	l, err := a.b.AddLink()
	require.NoError(t, err)
	require.NoError(t, l.AddSource(ownA[1]))
	r, err := l.AddRelay(addrOf(a.other.tr))
	require.NoError(t, err)
	require.NoError(t, a.b.AddRoute(netip.MustParsePrefix("::/0"), r))
	rx, err := a.other.l.AddRelay(addrOf(a.tr))
	require.NoError(t, err)
	req, err := rx.Offer(time.Now())
	require.NoError(t, err)
	_, err = r.Apply(req, time.Now())
	require.NoError(t, err)
	return rx
}

// direct sets the direct routes of a and b to each other: all prefixes of the other list.
func direct(t *testing.T, a, b *dnode) {
	t.Helper()
	require.NoError(t, a.b.SetDirect(a.direct, b.own, b.own))
	require.NoError(t, b.b.SetDirect(b.direct, a.own, a.own))
}

// rxCount returns the packets that the receive SAs of p accepted.
func rxCount(p *Peer) uint64 {
	var n uint64
	for _, c := range p.RxReport() {
		n += c.Packets
	}
	return n
}

// rxCounts returns rxCount of each peer.
func rxCounts(peers ...*Peer) []uint64 {
	out := make([]uint64, len(peers))
	for i, p := range peers {
		out[i] = rxCount(p)
	}
	return out
}

// udp6 returns an IPv6 UDP packet of 100 B.
func udp6(src, dst netip.Addr, sport, dport uint16) []byte {
	return packet(src, dst, 17, sport, dport, 100)
}

// channelPkt returns a channel packet between the overlay addresses of two sessions.
func channelPkt(from, to netip.Prefix) []byte {
	return udp6(base(from), base(to), ChannelPort, ChannelPort)
}

// withDestOpts returns the IPv6 packet pkt with n more Destination Options headers after the
// IPv6 header.
func withDestOpts(pkt []byte, n int) []byte {
	if n == 0 {
		return pkt
	}
	out := append(bytes.Clone(pkt[:40]), pkt[6], 0, 1, 4, 0, 0, 0, 0) // A PadN option of 4 bytes.
	out = append(out, pkt[40:]...)
	out[6] = 60
	binary.BigEndian.PutUint16(out[4:], uint16(len(out)-40))
	return withDestOpts(out, n-1)
}

// takeOne returns the next packet of the take-out of n.
func takeOne(t *testing.T, n *dnode) takenPkt {
	t.Helper()
	select {
	case p := <-n.taken:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("the take-out got no packet")
		return takenPkt{}
	}
}

// noTake checks that the take-out of n has no packet.
func noTake(t *testing.T, n *dnode) {
	t.Helper()
	select {
	case p := <-n.taken:
		t.Fatalf("the take-out got a packet from %+v", p.src)
	default:
	}
}

// waitRx waits until n counted want more packets than in before, as received or dropped.
func waitRx(t *testing.T, n *dnode, before Stats, want uint64) {
	t.Helper()
	require.Eventually(t, func() bool { return counted(sub(n.b.Stats(), before)) >= want },
		5*time.Second, time.Millisecond)
	assert.Equal(t, want, counted(sub(n.b.Stats(), before)))
}

// settle waits until the value of f stays the same for 50 ms, and returns it.
func settle(t *testing.T, f func() uint64) uint64 {
	t.Helper()
	v := f()
	require.Eventually(t, func() bool {
		last := v
		time.Sleep(50 * time.Millisecond)
		v = f()
		return v == last
	}, 10*time.Second, time.Millisecond)
	return v
}

// delivered returns the number of packets that the driver of n with no pipe got.
func delivered(n *dnode) int {
	n.got.mu.Lock()
	defer n.got.mu.Unlock()
	return len(n.got.got)
}

// TestDirectTable sends packets from many sources of a to b. A packet from the own list to a direct
// route goes to the direct peer from each link, and another packet takes its link route.
func TestDirectTable(t *testing.T) {
	a, b := newDirect(t, directNoPipe, 0)
	rx2 := secondLink(t, a)
	direct(t, a, b)
	cases := []struct {
		name     string
		from, to *dnode
		pkt      []byte
		want     *Peer // The receive peer of the packet.
	}{
		{"first session to first session", a, b, udp6(base(ownA[0]), base(ownB[0]), 1, 2), b.direct},
		{"second session, second link", a, b, udp6(base(ownA[1]), base(ownB[0]), 1, 2), b.direct},
		{"to the second session of b", a, b, udp6(base(ownA[1]), base(ownB[1]), 1, 2), b.direct},
		{"other address of the session", a, b, udp6(ownA[0].Addr().Next().Next(), ownB[1].Addr(), 1, 2), b.direct},
		{"b to a, one link", b, a, udp6(base(ownB[1]), base(ownA[0]), 1, 2), a.direct},
		{"advertised source", a, b, udp6(advertised, base(ownB[0]), 1, 2), b.peer},
		{"IPv4 source", a, b, packet(a.v4, b.v4, 17, 1, 2, 100), b.peer},
		{"no direct route, first link", a, b, udp6(base(ownA[0]), elsewhere, 1, 2), b.peer},
		{"no direct route, second link", a, b, udp6(base(ownA[1]), elsewhere, 1, 2), rx2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peers := []*Peer{tc.to.direct, tc.to.peer, rx2}
			counts, before := rxCounts(peers...), tc.to.b.Stats()
			n, err := tc.from.b.Send([][]byte{tc.pkt})
			require.NoError(t, err)
			require.Equal(t, 1, n)
			waitRx(t, tc.to, before, 1)
			assert.Equal(t, Stats{RxPackets: 1}, sub(tc.to.b.Stats(), before))
			for i, p := range peers {
				want := counts[i]
				if p == tc.want {
					want++
				}
				assert.Equal(t, want, rxCount(p), "receive peer %d", i)
			}
		})
	}
}

// TestDirectPathTCP sends TCP between the netstacks of a and b on direct routes, with no relay
// route. TCP gives GSO packets to the driver, which sends them on the direct table too.
func TestDirectPathTCP(t *testing.T) {
	a, b := newDirect(t, directNone, 0)
	direct(t, a, b)
	for _, n := range []*dnode{a, b} {
		require.True(t, n.b.RemoveRoute(netip.MustParsePrefix("::/0"), n.peer))
	}
	a.v6, b.v6 = base(ownA[0]), base(ownB[0])
	sa, sb := startNetstack(t, a.node, testWindow), startNetstack(t, b.node, testWindow)
	echo(t, sb, b.v6, 8000)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, sa, fullAddr(b.v6, 8000), protoOf(b.v6))
	require.NoError(t, err)
	defer c.Close()
	data := make([]byte, testData)
	_, _ = rand.Read(data)
	go func() { _, _ = c.Write(data) }()
	got := make([]byte, len(data))
	_, err = io.ReadFull(c, got)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(data, got))
	assert.GreaterOrEqual(t, rxCount(b.direct), uint64(testData/b.b.mtu), "packets on the direct peer of b")
	assert.NotZero(t, rxCount(a.direct), "packets on the direct peer of a")
	for _, n := range []*dnode{a, b} {
		assert.Zero(t, rxCount(n.peer), "packets on the relay peer")
		assert.Zero(t, n.b.Stats().TxNoRoute, "packets with no route")
	}
	assert.Less(t, sa.NICInfo()[1].Stats.Tx.Packets.Value(), a.b.Stats().TxPackets, "TCP used GSO")
}

// TestDirectSources changes the sources of the direct peer of b with no new SAs. The receive
// check takes each new list at once.
func TestDirectSources(t *testing.T) {
	a, b := newDirect(t, directNoPipe, 0)
	require.NoError(t, a.b.SetDirect(a.direct, ownB, ownB))
	from0, from1 := udp6(base(ownA[0]), base(ownB[0]), 1, 2), udp6(base(ownA[1]), base(ownB[0]), 1, 2)
	steps := []struct {
		name    string
		sources []netip.Prefix
		pkt     []byte
		pass    bool
	}{
		{"no sources", nil, from0, false},
		{"first session", ownA[:1], from0, true},
		{"second session not in the list", ownA[:1], from1, false},
		{"both sessions", ownA, from1, true},
		{"first session out", ownA[1:], from0, false},
		{"second session stays", ownA[1:], from1, true},
	}
	for _, st := range steps {
		require.NoError(t, b.b.SetDirect(b.direct, st.sources, ownA), st.name)
		before, count := b.b.Stats(), rxCount(b.direct)
		_, err := a.b.Send([][]byte{st.pkt})
		require.NoError(t, err, st.name)
		waitRx(t, b, before, 1)
		want := Stats{RxDrops: 1}
		if st.pass {
			want = Stats{RxPackets: 1}
			count++
		}
		assert.Equal(t, want, sub(b.b.Stats(), before), st.name)
		assert.Equal(t, count, rxCount(b.direct), st.name)
	}
}

// TestTakeOut sends packets to b on the direct route, the relay route and in data frames. The
// take-out gets the channel packets to the list of b with the peer of the SA and the outer source.
func TestTakeOut(t *testing.T) {
	for _, kind := range []directRx{directNoPipe, directConsume, directWorkers} {
		t.Run(kind.String(), func(t *testing.T) {
			a, b := newDirect(t, kind, 0)
			// The second session of b is on the relay route.
			require.NoError(t, a.b.SetDirect(a.direct, ownB, ownB[:1]))
			require.NoError(t, b.b.SetDirect(b.direct, ownA, ownA))
			cases := []struct {
				name string
				pkt  []byte
				want *Peer // The peer in the Source of the take-out. Nil is no take-out.
			}{
				{name: "direct route", pkt: channelPkt(ownA[0], ownB[0]), want: b.direct},
				{name: "relay route", pkt: channelPkt(ownA[0], ownB[1]), want: b.peer},
				{name: "from an advertised source on the relay route", pkt: udp6(advertised, base(ownB[1]), ChannelPort, ChannelPort), want: b.peer},
				{name: "other address of the list", pkt: udp6(base(ownA[0]), ownB[0].Addr(), 7, ChannelPort), want: b.direct},
				{name: "extension header", pkt: withDestOpts(channelPkt(ownA[0], ownB[0]), 1), want: b.direct},
				{name: "nine extension headers", pkt: withDestOpts(channelPkt(ownA[0], ownB[0]), 9), want: b.direct},
				{name: "not in the list of b", pkt: udp6(base(ownA[0]), elsewhere, ChannelPort, ChannelPort)},
				{name: "other port", pkt: udp6(base(ownA[0]), base(ownB[0]), ChannelPort, ChannelPort+1)},
				{name: "TCP to port 1001", pkt: packet(base(ownA[0]), base(ownB[0]), 6, 7, ChannelPort, 100)},
				{name: "IPv4", pkt: packet(a.v4, b.v4, 17, ChannelPort, ChannelPort, 100)},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					before, drv := b.b.Stats(), 0
					if b.got != nil {
						drv = delivered(b)
					}
					_, err := a.b.Send([][]byte{tc.pkt})
					require.NoError(t, err)
					waitRx(t, b, before, 1)
					assert.Equal(t, Stats{RxPackets: 1}, sub(b.b.Stats(), before))
					if tc.want == nil {
						noTake(t, b)
						drv++
					} else {
						got := takeOne(t, b)
						assert.Equal(t, tc.pkt, got.pkt)
						assert.Same(t, tc.want, got.src.Peer)
						assert.Nil(t, got.src.Link)
						assert.Equal(t, addrOf(a.tr), got.src.Addr)
					}
					if b.got != nil {
						assert.Equal(t, drv, delivered(b), "packets of the driver")
					}
				})
			}

			t.Run("replay", func(t *testing.T) {
				f := seal(a.node, channelPkt(ownA[0], ownB[0]))
				require.NotNil(t, f)
				before := b.b.Stats()
				from := net.UDPAddrFromAddrPort(addrOf(a.tr))
				b.b.demux.Handle(bytes.Clone(f[addrLen:]), from)
				b.b.demux.Handle(bytes.Clone(f[addrLen:]), from)
				b.b.demux.BatchEnd()
				waitRx(t, b, before, 2)
				assert.Equal(t, Stats{RxPackets: 1, RxDrops: 1}, sub(b.b.Stats(), before))
				assert.Same(t, b.direct, takeOne(t, b).src.Peer)
				noTake(t, b)
			})

			t.Run("data frame", func(t *testing.T) {
				qa, qb := quicPair(t, a.tr, b.tr)
				pa, pb := peerconn.New(qa), peerconn.New(qb)
				t.Cleanup(func() { _ = pa.Close(); _ = pb.Close() })
				pb.HandleData(b.l)
				require.NoError(t, a.peer.UseQUIC(pa))
				defer func() { require.NoError(t, a.peer.UseQUIC(nil)) }()
				pkt := channelPkt(ownA[0], ownB[1])
				before := b.b.Stats()
				_, err := a.b.Send([][]byte{pkt})
				require.NoError(t, err)
				got := takeOne(t, b)
				assert.Equal(t, pkt, got.pkt)
				assert.Equal(t, Source{Link: b.l}, got.src)
				assert.Equal(t, Stats{RxPackets: 1}, sub(b.b.Stats(), before))
			})
		})
	}
}

// TestTakeOutSources gives one read with channel packets from two outer sources and one packet
// that fails to open. Each packet of the take-out has its own source.
func TestTakeOutSources(t *testing.T) {
	for _, kind := range []directRx{directNoPipe, directConsume, directWorkers} {
		t.Run(kind.String(), func(t *testing.T) {
			a, b := newDirect(t, kind, 0)
			direct(t, a, b)
			x, y := netip.MustParseAddrPort("192.0.2.1:7"), netip.MustParseAddrPort("[2001:db8::1]:9")
			var pkts [][]byte
			for i := range 4 {
				pkt := channelPkt(ownA[i%2], ownB[0])
				pkt[len(pkt)-1] = byte(i)
				f := seal(a.node, pkt)
				require.NotNil(t, f)
				pkts = append(pkts, bytes.Clone(f[addrLen:]))
			}
			pkts[2][len(pkts[2])-1] ^= 1
			from := []netip.AddrPort{x, y, x, y}
			before := b.b.Stats()
			for i, p := range pkts {
				b.b.demux.Handle(p, net.UDPAddrFromAddrPort(from[i]))
			}
			b.b.demux.BatchEnd()
			waitRx(t, b, before, 4)
			assert.Equal(t, Stats{RxPackets: 3, RxDrops: 1}, sub(b.b.Stats(), before))
			for _, i := range []int{0, 1, 3} {
				got := takeOne(t, b)
				assert.Equal(t, byte(i), got.pkt[len(got.pkt)-1])
				assert.Equal(t, Source{Peer: b.direct, Addr: from[i]}, got.src, "packet %d", i)
			}
			noTake(t, b)
		})
	}
}

// TestChannelNoHead checks the heads for ICMP errors: a packet on a relay route has one, a
// channel packet and a packet on a direct route have none.
func TestChannelNoHead(t *testing.T) {
	a, _ := newDirect(t, directNoPipe, 0)
	require.NoError(t, a.b.SetDirect(a.direct, ownB, ownB[:1]))
	cases := []struct {
		name string
		pkt  []byte
		head bool
	}{
		{"relay route", udp6(base(ownA[0]), base(ownB[1]), 7, 8), true},
		{"channel packet on the relay route", channelPkt(ownA[0], ownB[1]), false},
		{"channel packet to another agent", udp6(base(ownA[0]), elsewhere, 7, ChannelPort), false},
		{"channel packet with extension headers", withDestOpts(channelPkt(ownA[0], ownB[1]), 9), false},
		{"direct route", udp6(base(ownA[0]), base(ownB[0]), 7, 8), false},
	}
	now := time.Now()
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.b.Send([][]byte{tc.pkt})
			require.NoError(t, err)
			dst, _ := innerDst(tc.pkt)
			// Each case has its own time, so that the hold of an earlier head has ended.
			head := a.b.TakeHead(a.l, dst, now.Add(time.Duration(i+1)*time.Minute))
			if tc.head {
				assert.Equal(t, tc.pkt, head)
			} else {
				assert.Nil(t, head)
			}
		})
	}
}

// TestHeadAfterInstall keeps heads on the relay route, then adds a direct route. Tick gives each
// head one time, and TakeHead gives no head of the own list to a destination that goes direct now.
func TestHeadAfterInstall(t *testing.T) {
	a, _ := newDirect(t, directNoPipe, 0)
	dst := base(ownB[0])
	fromList, fromOther := udp6(base(ownA[0]), dst, 7, 8), udp6(advertised, dst, 7, 8)
	now := time.Now()
	_, err := a.b.Send([][]byte{fromList})
	require.NoError(t, err)
	_, heads, err := a.b.Tick(now)
	require.NoError(t, err)
	assert.Equal(t, []Head{{Src: base(ownA[0]), Dst: dst}}, heads)
	_, heads, err = a.b.Tick(now)
	require.NoError(t, err)
	assert.Empty(t, heads, "a head goes out in one Tick")

	require.NoError(t, a.b.SetDirect(a.direct, ownB, ownB[:1]))
	assert.Nil(t, a.b.TakeHead(a.l, dst, now.Add(time.Minute)), "the head of the own list goes direct now")
	// The head stays for a later NoRoute of its flow: the route goes out first.
	require.NoError(t, a.b.SetDirect(a.direct, ownB, nil))
	assert.Equal(t, fromList, a.b.TakeHead(a.l, dst, now.Add(time.Minute)), "the head after the routes went out")

	// A head of a source outside the own list keeps its relay route and its ICMP error.
	require.NoError(t, a.b.SetDirect(a.direct, ownB, ownB[:1]))
	_, err = a.b.Send([][]byte{fromOther})
	require.NoError(t, err)
	assert.Equal(t, fromOther, a.b.TakeHead(a.l, dst, now.Add(2*time.Minute)), "the head of an advertised source")
}

// TestRemoveDirect removes the direct peers while packets go to them. After RemovePeer the
// packets take the relay route, and no packet goes to an SA of a removed peer.
func TestRemoveDirect(t *testing.T) {
	a, b := newDirect(t, directNoPipe, 0)
	direct(t, a, b)
	pkt := udp6(base(ownA[0]), base(ownB[0]), 1, 2)
	// Node a seals this packet with its direct SA before the removal.
	early := seal(a.node, channelPkt(ownA[0], ownB[0]))
	require.NotNil(t, early)

	// Packets go while a removes its direct peer. Each one goes direct, takes the relay route,
	// or has no route in the moment of the removal.
	stop := make(chan struct{})
	var sends sync.WaitGroup
	var unexpected error
	sends.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := a.b.Send([][]byte{pkt}); err != nil && !errors.Is(err, ErrNoRoute) {
				unexpected = err
				return
			}
		}
	})
	require.Eventually(t, func() bool { return rxCount(b.direct) > 0 }, 5*time.Second, time.Millisecond)
	a.b.RemovePeer(a.direct)
	close(stop)
	sends.Wait()
	require.NoError(t, unexpected)

	// The packets before the removal arrive. Then all go on the relay route.
	settle(t, func() uint64 { return counted(b.b.Stats()) })
	counts := rxCounts(b.direct, b.peer)
	for range 3 {
		_, err := a.b.Send([][]byte{pkt})
		require.NoError(t, err)
	}
	require.Eventually(t, func() bool { return rxCount(b.peer) == counts[1]+3 }, 5*time.Second, time.Millisecond)
	assert.Equal(t, counts[0], rxCount(b.direct), "packets on the direct peer after its removal")
	assert.ErrorIs(t, a.b.SetDirect(a.direct, ownB, ownB), ErrClosed)
	assert.ErrorIs(t, a.b.SendVia(a.direct, pkt, netip.AddrPort{}), ErrNoRoute)

	// b removes its direct peer: a packet on one of its SAs drops, also a channel packet.
	b.b.RemovePeer(b.direct)
	before := b.b.Stats()
	b.b.demux.Handle(early[addrLen:], net.UDPAddrFromAddrPort(addrOf(a.tr)))
	b.b.demux.BatchEnd()
	assert.Equal(t, Stats{RxDrops: 1}, sub(b.b.Stats(), before))
	noTake(t, b)
}

// TestSendVia sends packets to a peer with no route lookup, to the address of the peer or to
// another address, and as a data frame on a relay session.
func TestSendVia(t *testing.T) {
	a, b := newDirect(t, directNoPipe, MaxMTU)
	// Only b has direct routes: SendVia of a does not need them.
	require.NoError(t, b.b.SetDirect(b.direct, ownA, ownA))
	otherConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = otherConn.Close() })
	other := otherConn.LocalAddr().(*net.UDPAddr).AddrPort()

	t.Run("address of the peer", func(t *testing.T) {
		pkt := channelPkt(ownA[0], ownB[0])
		require.NoError(t, a.b.SendVia(a.direct, pkt, netip.AddrPort{}))
		got := takeOne(t, b)
		assert.Equal(t, pkt, got.pkt)
		assert.Equal(t, Source{Peer: b.direct, Addr: addrOf(a.tr)}, got.src)
	})

	t.Run("no route", func(t *testing.T) {
		pkt := udp6(base(ownA[0]), elsewhere, 1, 2)
		before := rxCount(b.direct)
		require.NoError(t, a.b.SendVia(a.direct, pkt, netip.AddrPort{}))
		require.Eventually(t, func() bool { return rxCount(b.direct) == before+1 }, 5*time.Second, time.Millisecond)
	})

	t.Run("other address", func(t *testing.T) {
		pkt := channelPkt(ownA[1], ownB[0])
		require.NoError(t, a.b.SendVia(a.direct, pkt, other))
		assert.Equal(t, addrOf(b.tr), a.direct.Addr(), "the address of the peer stays")
		require.NoError(t, otherConn.SetReadDeadline(time.Now().Add(5*time.Second)))
		buf := make([]byte, 2048)
		n, from, err := otherConn.ReadFromUDPAddrPort(buf)
		require.NoError(t, err)
		// The packet has the SA of the direct peer: b opens it as a packet from it.
		b.b.demux.Handle(buf[:n], net.UDPAddrFromAddrPort(from))
		b.b.demux.BatchEnd()
		got := takeOne(t, b)
		assert.Equal(t, pkt, got.pkt)
		assert.Same(t, b.direct, got.src.Peer)
		noTake(t, b)
	})

	t.Run("size", func(t *testing.T) {
		require.NoError(t, a.b.SetDirect(a.direct, ownB, ownB))
		defer func() { require.NoError(t, a.b.SetDirect(a.direct, nil, nil)) }()
		a.b.SetClampMTU(DefaultMTU)
		defer a.b.SetClampMTU(0)
		big := packet(base(ownA[0]), base(ownB[0]), 17, ChannelPort, ChannelPort, a.b.mtu)
		before := a.b.Stats()
		_, err := a.b.Send([][]byte{big})
		require.NoError(t, err)
		assert.Equal(t, Stats{TxDrops: 1, TxTooBig: 1}, sub(a.b.Stats(), before), "Send: above the clamp")
		require.NoError(t, a.b.SendVia(a.direct, big, netip.AddrPort{}), "SendVia: above the clamp, at the VPC MTU")
		assert.Equal(t, big, takeOne(t, b).pkt)
		tooBig := packet(base(ownA[0]), base(ownB[0]), 17, ChannelPort, ChannelPort, a.b.mtu+1)
		assert.Error(t, a.b.SendVia(a.direct, tooBig, netip.AddrPort{}), "above the VPC MTU")
		noTake(t, b)
	})

	t.Run("no SA", func(t *testing.T) {
		p, err := a.b.AddDirect(other)
		require.NoError(t, err)
		assert.ErrorIs(t, a.b.SendVia(p, channelPkt(ownA[0], ownB[0]), netip.AddrPort{}), ErrNoRoute)
	})

	t.Run("data frame", func(t *testing.T) {
		qa, qb := quicPair(t, a.tr, b.tr)
		pa, pb := peerconn.New(qa), peerconn.New(qb)
		t.Cleanup(func() { _ = pa.Close(); _ = pb.Close() })
		pb.HandleData(b.l)
		require.NoError(t, a.peer.UseQUIC(pa))
		pkt := channelPkt(ownA[0], ownB[1])
		require.NoError(t, a.b.SendVia(a.peer, pkt, netip.AddrPort{}))
		got := takeOne(t, b)
		assert.Equal(t, pkt, got.pkt)
		assert.Equal(t, Source{Link: b.l}, got.src)
	})
}

// TestSetDirect checks the direct table when two direct peers list one prefix, and the calls of
// link routes on a direct peer.
func TestSetDirect(t *testing.T) {
	a, b := newDirect(t, directNoPipe, 0)
	second, err := a.b.AddDirect(netip.MustParseAddrPort("192.0.2.1:1"))
	require.NoError(t, err)
	toB, toOther := udp6(base(ownA[0]), base(ownB[0]), 1, 2), udp6(base(ownA[0]), elsewhere, 1, 2)
	send := func(pkt []byte) error {
		_, err := a.b.Send([][]byte{pkt})
		return err
	}
	require.NoError(t, a.b.SetDirect(a.direct, ownB, ownB[:1]))
	require.NoError(t, b.b.SetDirect(b.direct, ownA, nil))
	err = a.b.SetDirect(second, nil, []netip.Prefix{netip.PrefixFrom(elsewhere, 96), ownB[0]})
	require.ErrorIs(t, err, engine.ErrRouteTaken)

	// The route of the first peer stays, and the second peer has no route.
	before := rxCounts(b.direct, b.peer)
	require.NoError(t, send(toB))
	require.NoError(t, send(toOther))
	require.Eventually(t, func() bool {
		c := rxCounts(b.direct, b.peer)
		return c[0] == before[0]+1 && c[1] == before[1]+1
	}, 5*time.Second, time.Millisecond)

	// The route moves: the first peer drops it, then the second peer adds it. The second peer
	// has no SA.
	require.NoError(t, a.b.SetDirect(a.direct, ownB, nil))
	require.NoError(t, a.b.SetDirect(second, nil, ownB[:1]))
	assert.ErrorIs(t, send(toB), ErrNoRoute)
	require.NoError(t, send(toOther))

	assert.Error(t, a.b.SetDirect(a.peer, nil, nil), "a relay peer")
	assert.ErrorIs(t, a.b.AddRoute(netip.PrefixFrom(elsewhere, 128), second), errDirect)
	assert.ErrorIs(t, second.UseQUIC(&peerconn.Conn{}), errDirect)
	assert.Error(t, a.b.SetDirect(second, nil, []netip.Prefix{{}}), "an invalid prefix")
}

// TestDirectRekey runs Tick after 3/4 of the SA life. The direct peer gets an Update, and a
// packet on its new SA goes to the take-out with the same peer.
func TestDirectRekey(t *testing.T) {
	a, b := newDirect(t, directNoPipe, 0)
	direct(t, a, b)
	senders := map[*Peer]*Peer{b.peer: a.peer, b.direct: a.direct}
	pkt := channelPkt(ownA[0], ownB[0])
	old := seal(a.node, pkt)
	require.NotNil(t, old)
	later := time.Now().Add(8 * time.Minute)
	ups, _, err := b.b.Tick(later)
	require.NoError(t, err)
	var got []*Peer
	for _, u := range ups {
		got = append(got, u.Peer)
		refused, err := senders[u.Peer].Apply(u.Request, later)
		require.NoError(t, err)
		require.Empty(t, refused)
	}
	assert.ElementsMatch(t, []*Peer{b.peer, b.direct}, got)
	f := seal(a.node, pkt)
	require.NotNil(t, f)
	assert.NotEqual(t, old[addrLen+4:addrLen+8], f[addrLen+4:addrLen+8], "the SPI of the new SA")
	b.b.demux.Handle(f[addrLen:], net.UDPAddrFromAddrPort(addrOf(a.tr)))
	b.b.demux.BatchEnd()
	assert.Same(t, b.direct, takeOne(t, b).src.Peer)
}
