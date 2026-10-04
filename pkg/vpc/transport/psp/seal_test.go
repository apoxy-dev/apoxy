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
