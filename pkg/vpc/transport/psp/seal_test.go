// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"net/netip"
	"testing"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/apoxy-dev/softpsp/vtep/netstack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

// TestPrepareSeal reserves the send frames of packets in order and seals them in another
// order, as the send pipe does. The frames must carry the sequence numbers of Prepare, and
// the peer must accept all of them in send order.
func TestPrepareSeal(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	d := newDriver(a.b, nil)
	seal := func(f *netstack.TxFrame, pkt []byte) []byte {
		phy := make([]byte, 2048)
		n := d.Seal(f, pkt, phy)
		if n == 0 {
			return nil
		}
		return phy[:n]
	}

	t.Run("PSP sealed in reverse order", func(t *testing.T) {
		const n = 8
		pkts := make([][]byte, n)
		frames := make([]netstack.TxFrame, n)
		for i := range n {
			// One flow, so that one SA gives all sequence numbers.
			pkts[i] = packet(a.v4, b.v4, 17, 1, 2, 100+i)
			require.True(t, d.Prepare(pkts[i], &frames[i]))
			require.NotNil(t, frames[i].SA)
			assert.Equal(t, a.peer.Addr(), frames[i].Dst)
			if i > 0 {
				assert.Equal(t, frames[i-1].Seq+1, frames[i].Seq)
			}
		}
		phys := make([][]byte, n)
		for i := n - 1; i >= 0; i-- {
			phys[i] = seal(&frames[i], pkts[i])
			require.NotNil(t, phys[i])
			h, err := pspwire.ParseHeader(phys[i][addrLen:])
			require.NoError(t, err)
			assert.Equal(t, uint32(frames[i].Seq), h.Seq)
			assert.Equal(t, frames[i].Seq, h.IV)
			assert.Equal(t, frames[i].SA.SPI(), h.SPI)
		}
		before := b.b.Stats()
		for i := range n {
			assert.Equal(t, pkts[i], open(b.b, phys[i][addrLen:]), "packet %d", i)
		}
		assert.Equal(t, Stats{RxPackets: n}, sub(b.b.Stats(), before))
	})

	t.Run("QUIC data frame", func(t *testing.T) {
		qa, _ := quicPair(t, a.tr, b.tr)
		pc := peerconn.New(qa, a.v4)
		t.Cleanup(func() { _ = pc.Close() })
		a.b.UseQUIC(pc)
		defer a.b.relay.Store(nil)
		pkt := packet(a.v6, b.v6, 6, 1, 2, 500)
		var f netstack.TxFrame
		require.True(t, d.Prepare(pkt, &f))
		assert.Nil(t, f.SA)
		phy := make([]byte, 2048)
		n, err := a.b.frame(pkt, phy)
		require.NoError(t, err)
		assert.Equal(t, phy[:n], seal(&f, pkt))
	})

	t.Run("drops", func(t *testing.T) {
		far := netip.MustParseAddr("10.9.9.9")
		notIP := func(pkt []byte) []byte { pkt[0] = 0; return pkt }
		cases := []struct {
			name string
			pkt  []byte
			// prepare reports whether Prepare takes the packet. Then Seal drops it.
			prepare bool
			tripped bool // The breaker of the peer is tripped, so its limit drops the packet.
			want    Stats
		}{
			{"no route", packet(a.v4, far, 17, 1, 2, 100), false, false, Stats{TxNoRoute: 1}},
			{"too large", packet(a.v4, b.v4, 17, 1, 2, DefaultMTU+1), false, false, Stats{TxDrops: 1}},
			{"not IP", make([]byte, 100), false, false, Stats{TxDrops: 1}},
			{"tripped breaker", packet(a.v4, b.v4, 17, 1, 2, 100), false, true, Stats{TxLimitDrops: 1}},
			{"seal of a packet that is not IP", packet(a.v4, b.v4, 17, 1, 2, 100), true, false, Stats{TxDrops: 1}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				g := &a.peer.br.limiter
				if tc.tripped {
					// One byte per second: the first packet fills the queue of the breaker.
					g.rate.Store(1)
					var f netstack.TxFrame
					require.True(t, d.Prepare(packet(a.v4, b.v4, 17, 1, 2, 100), &f))
					defer func() { g.rate.Store(0); g.tat.Store(0) }()
				}
				before := a.b.Stats()
				var f netstack.TxFrame
				assert.Equal(t, tc.prepare, d.Prepare(tc.pkt, &f))
				if tc.prepare {
					assert.Nil(t, seal(&f, notIP(tc.pkt)))
				}
				assert.Equal(t, tc.want, sub(a.b.Stats(), before))
			})
		}
	})
}

// TestPrepareSegs reserves the send frames of the packets of one TCP packet with one call. A
// call that Prepare can drop reserves and counts nothing, so that Prepare gets each packet.
func TestPrepareSegs(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	d := newDriver(a.b, nil)
	hdr := packet(a.v4, b.v4, 6, 1, 2, 40)
	one := packet(a.v4, b.v4, 6, 1, 2, 100)
	g := &a.peer.br.limiter
	const n, size = 5, 1200

	t.Run("sequence numbers", func(t *testing.T) {
		var first, f, last netstack.TxFrame
		require.True(t, d.Prepare(one, &first))
		sent, before := g.sent.Load(), a.b.Stats()
		require.True(t, d.PrepareSegs(hdr, n, size, n*size-7, &f))
		require.True(t, d.Prepare(one, &last))
		assert.Same(t, first.SA, f.SA)
		assert.Equal(t, first.Seq+1, f.Seq)
		assert.Equal(t, f.Seq+n, last.Seq)
		assert.Equal(t, a.peer.Addr(), f.Dst)
		assert.Zero(t, f.Lane)
		assert.Equal(t, uint64(n*size-7+len(one)), g.sent.Load()-sent, "bytes of the breaker")
		assert.Equal(t, Stats{}, sub(a.b.Stats(), before))
		// The packets are sealed in reverse order. The peer accepts them in send order.
		pkts, phys := make([][]byte, n), make([][]byte, n)
		for i := n - 1; i >= 0; i-- {
			pkts[i] = packet(a.v4, b.v4, 6, 1, 2, size-i)
			fi := f
			fi.Seq += uint64(i)
			phy := make([]byte, 2048)
			m := d.Seal(&fi, pkts[i], phy)
			require.NotZero(t, m)
			phys[i] = phy[:m]
		}
		for i := range n {
			assert.Equal(t, pkts[i], open(b.b, phys[i][addrLen:]), "packet %d", i)
		}
	})

	t.Run("refused", func(t *testing.T) {
		far := netip.MustParseAddr("10.9.9.9")
		cases := []struct {
			name string
			hdr  []byte
			size int
			rate int64 // The limit of the breaker of the peer. Prepare takes a packet below it.
		}{
			{"no route", packet(a.v4, far, 6, 1, 2, 40), size, 0},
			{"too large", hdr, DefaultMTU + 1, 0},
			{"not IP", make([]byte, 40), size, 0},
			{"tripped breaker", hdr, size, 1 << 30},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				hooks := 0
				a.b.noRoute = func([]byte) { hooks++ }
				g.rate.Store(tc.rate)
				defer func() { a.b.noRoute = nil; g.rate.Store(0); g.tat.Store(0) }()
				var before, f, after netstack.TxFrame
				require.True(t, d.Prepare(one, &before))
				sent, stats := g.sent.Load(), a.b.Stats()
				assert.False(t, d.PrepareSegs(tc.hdr, n, tc.size, n*tc.size, &f))
				assert.Equal(t, Stats{}, sub(a.b.Stats(), stats))
				assert.Equal(t, sent, g.sent.Load())
				assert.Zero(t, hooks)
				// It took no sequence numbers.
				require.True(t, d.Prepare(one, &after))
				assert.Equal(t, before.Seq+1, after.Seq)
			})
		}
	})

	t.Run("no transmit SA", func(t *testing.T) {
		c, _ := newPair(t)
		var f netstack.TxFrame
		assert.False(t, newDriver(c.b, nil).PrepareSegs(hdr, n, size, n*size, &f))
		assert.Equal(t, Stats{}, c.b.Stats())
	})

	t.Run("last sequence numbers", func(t *testing.T) {
		c, e := newPair(t)
		offer(t, time.Now(), c, e)
		cd := newDriver(c.b, nil)
		sa, _ := c.peer.txSA(hdr)
		limit := uint64(pspwire.PacketLimit(c.b.mtu))
		_, err := sa.ReserveN(int(limit) - n)
		require.NoError(t, err)
		var f netstack.TxFrame
		require.True(t, cd.PrepareSegs(hdr, n, size, n*size, &f))
		assert.Equal(t, limit-n, f.Seq)
		assert.False(t, cd.PrepareSegs(hdr, 1, size, size, &f))
		assert.Equal(t, Stats{}, c.b.Stats())
	})

	t.Run("QUIC data frames", func(t *testing.T) {
		qa, _ := quicPair(t, a.tr, b.tr)
		pc := peerconn.New(qa, a.v4)
		t.Cleanup(func() { _ = pc.Close() })
		a.b.UseQUIC(pc)
		defer a.b.relay.Store(nil)
		q := &a.b.quic.limiter
		sent := q.sent.Load()
		f := netstack.TxFrame{Seq: 7}
		require.True(t, d.PrepareSegs(hdr, n, size, n*size, &f))
		assert.Equal(t, netstack.TxFrame{}, f)
		assert.Equal(t, uint64(n*size), q.sent.Load()-sent)
		q.rate.Store(1 << 30)
		defer q.rate.Store(0)
		assert.False(t, d.PrepareSegs(hdr, n, size, n*size, &f))
		assert.Equal(t, uint64(n*size), q.sent.Load()-sent)
	})
}
