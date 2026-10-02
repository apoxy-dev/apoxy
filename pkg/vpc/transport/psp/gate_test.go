// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

func TestGate(t *testing.T) {
	const ms = int64(time.Millisecond)
	t0 := int64(time.Second)
	type step struct {
		n    int   // Packet size.
		now  int64 // Time of the packet.
		want bool
	}
	cases := []struct {
		name  string
		rate  int64 // Bytes per second.
		steps []step
	}{
		{"open", 0, []step{{1000, t0, true}, {1000, t0, true}, {1000, t0, true}}},
		{"a burst passes up to 2 ms of queue, then drops", 1_000_000, []step{
			{1000, t0, true},
			{1000, t0, true},
			{1000, t0, true},
			{1000, t0, false},
			{1000, t0 + ms, true},
			{1000, t0 + ms, false},
		}},
		{"a drop does not move the queue end", 1_000_000, []step{
			{3000, t0, true},
			{1000, t0, false},
			{1000, t0 + ms, true},
		}},
		{"a large packet at a low rate goes, the next one drops", breakFloor, []step{
			{1400, t0, true},
			{100, t0 + 9*ms, false},
			{100, t0 + 9500*int64(time.Microsecond), true},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var g gate
			g.rate.Store(tc.rate)
			var sent uint64
			for i, s := range tc.steps {
				ok := g.admitAt(s.n, s.now)
				assert.Equal(t, s.want, ok, "step %d", i)
				if ok {
					sent += uint64(s.n)
				}
			}
			assert.Equal(t, sent, g.sent.Load())
		})
	}
}

// TestGateDatapath checks that a closed gate drops the excess of a burst in
// VirtToPhy and in Send, and that the packets that pass arrive.
func TestGateDatapath(t *testing.T) {
	cases := []struct {
		name string
		quic bool
		send bool // Binding.Send, else VirtToPhy and WriteFrames.
	}{
		{"PSP driver", false, false},
		{"PSP Send", false, true},
		{"QUIC driver", true, false},
		{"QUIC Send", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPair(t)
			offer(t, time.Now(), a, b)
			got := &capture{}
			b.b.drv.Store(newDriver(b.b, got.deliver))
			g := &a.peer.br.gate
			if tc.quic {
				qa, qb := quicPair(t, a.tr, b.tr)
				pa, pb := peerconn.New(qa, a.v4), peerconn.New(qb, b.v4)
				t.Cleanup(func() { _ = pa.Close(); _ = pb.Close() })
				pb.HandleData(b.b.HandleData)
				a.b.UseQUIC(pa)
				g = &a.b.quic.gate
			}
			// 10 ms for each packet: the first packet of the burst passes, and the
			// next one only after 8 ms.
			g.rate.Store(100_000)
			pkts := slices.Repeat([][]byte{packet(a.v4, b.v4, 17, 1, 2, 1000)}, 10)
			before, frames := a.b.Stats(), a.b.stats.txFrames.Load()
			var sent int
			if tc.send {
				n, err := a.b.Send(pkts)
				require.NoError(t, err)
				sent = n
			} else {
				d := newDriver(a.b, nil)
				var out [][]byte
				for _, pkt := range pkts {
					phy := make([]byte, 2048)
					if n, _ := d.VirtToPhy(pkt, phy); n > 0 {
						out = append(out, phy[:n])
					}
				}
				n, err := d.WriteFrames(out)
				require.NoError(t, err)
				sent = n
			}
			require.GreaterOrEqual(t, sent, 1)
			require.LessOrEqual(t, sent, 2)
			want := Stats{TxPackets: uint64(sent), TxGateDrops: uint64(len(pkts) - sent)}
			assert.Equal(t, want, sub(a.b.Stats(), before))
			if tc.quic {
				assert.Equal(t, uint64(sent), a.b.stats.txFrames.Load()-frames)
			}
			require.Eventually(t, func() bool {
				got.mu.Lock()
				defer got.mu.Unlock()
				return len(got.got) == sent
			}, 5*time.Second, time.Millisecond)
		})
	}
}

// BenchmarkGate measures admit at an open gate and at a closed gate.
func BenchmarkGate(b *testing.B) {
	for _, rate := range []int64{0, 1 << 30} {
		b.Run(map[bool]string{true: "open", false: "closed"}[rate == 0], func(b *testing.B) {
			var g gate
			g.rate.Store(rate)
			b.ReportAllocs()
			for b.Loop() {
				g.admit(1280)
			}
		})
	}
}
