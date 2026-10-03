// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
)

// useNetstack gives the binding of n a netstack driver on ep with the inject workers,
// and with a receive pipe when pipe is set.
func useNetstack(t testing.TB, n *node, ep *channel.Endpoint, workers int, pipe bool) *driver {
	t.Helper()
	d := newDriver(n.b, func(buf []byte, off int) bool { return inject(ep, buf[off:]) })
	d.batch = newInjectBatch(ep, &n.b.stats, n.b.seed, workers, d.done, n.b.ctx.Done())
	if pipe {
		d.pipe = newRxPipe(d, d.done, n.b.ctx.Done())
	}
	require.True(t, n.b.drv.CompareAndSwap(nil, d))
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// TestPipe gives reads of PSP packets of many flows to the demux, as the QUIC read loop
// does. The netstack must get the packets of each flow once and in order, also when one
// read fills more than one set. Forged packets and copies drop.
func TestPipe(t *testing.T) {
	cases := []struct {
		name string
		pipe bool
		read int // Packets in one read.
	}{
		{"no pipe", false, 32},
		{"full sets", true, pipeSlots},
		{"small reads", true, 5},
		{"read larger than a set", true, 3*pipeSlots + 5},
	}
	const flows, perFlow = 8, 120
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPair(t)
			offer(t, time.Now(), a, b)
			r, ep := newRecorder(t)
			useNetstack(t, b, ep, 4, tc.pipe)
			var pkts [][]byte
			drops := 0
			for i := range flows * perFlow {
				pkt := seal(a, flowPacket(uint16(1+i%flows), uint32(i/flows)))[addrLen:]
				pkts = append(pkts, pkt)
				switch i % 37 {
				case 11:
					forged := bytes.Clone(pkt)
					forged[len(forged)-1] ^= 1
					pkts = append(pkts, forged)
					drops++
				case 23:
					pkts = append(pkts, bytes.Clone(pkt))
					drops++
				}
			}
			before := b.b.Stats()
			for i, pkt := range pkts {
				b.b.demux.Handle(pkt, nil)
				if (i+1)%tc.read == 0 {
					b.b.demux.BatchEnd()
				}
			}
			b.b.demux.BatchEnd()
			want := Stats{RxPackets: flows * perFlow, RxDrops: uint64(drops)}
			require.Eventually(t, func() bool { return sub(b.b.Stats(), before) == want },
				5*time.Second, time.Millisecond, "%d of %d packets", r.count(), want.RxPackets)
			r.mu.Lock()
			defer r.mu.Unlock()
			for f := range flows {
				assert.Equal(t, seqs(perFlow), r.got[uint16(1+f)], "flow %d", 1+f)
			}
		})
	}
}

// TestPipeClampMSS checks that the consumer of the pipe lowers the MSS of TCP SYN packets.
func TestPipeClampMSS(t *testing.T) {
	a, b := newPairMTU(t, 1400)
	offer(t, time.Now(), a, b)
	b.b.SetClampMTU(1280)
	r, ep := newRecorder(t)
	useNetstack(t, b, ep, 2, true)
	b.b.demux.Handle(seal(a, tcpSyn(a.v4, b.v4, header.TCPFlagSyn, 1360))[addrLen:], nil)
	b.b.demux.BatchEnd()
	require.Eventually(t, func() bool { return r.count() == 1 }, 5*time.Second, time.Millisecond)
	r.mu.Lock()
	defer r.mu.Unlock()
	assert.Equal(t, tcpSyn(a.v4, b.v4, header.TCPFlagSyn, 1240), r.last)
}

// TestPipeFull stops the netstack, so the inject queue and then all sets of the pipe
// fill. The read loop must wait and drop nothing. When the driver closes, the read loop
// stops waiting, and the packets in the pipe and in the queue drop.
func TestPipeFull(t *testing.T) {
	cases := []struct {
		name  string
		close bool // The driver closes while the read loop waits.
	}{
		{name: "netstack catches up"},
		{name: "driver closes", close: true},
	}
	// More packets than the inject queue and the sets can hold.
	const total = 2 * (injectQueue + 2) * maxInjectBatch
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPair(t)
			offer(t, time.Now(), a, b)
			r, ep := newRecorder(t)
			gate := make(chan struct{})
			r.gate = gate
			openGate := sync.OnceFunc(func() { close(gate) })
			defer openGate()
			d := useNetstack(t, b, ep, 1, true)
			pkts := make([][]byte, total)
			for i := range pkts {
				pkts[i] = seal(a, flowPacket(1, uint32(i)))[addrLen:]
			}

			// The read loop reads one packet at a time, until stop is set.
			var reads atomic.Int64
			var stop atomic.Bool
			loop := make(chan struct{})
			go func() {
				defer close(loop)
				for _, pkt := range pkts {
					if stop.Load() {
						return
					}
					b.b.demux.Handle(pkt, nil)
					b.b.demux.BatchEnd()
					reads.Add(1)
				}
			}()
			// The read loop waits when it reads no more and has no free set.
			last := int64(-1)
			require.Eventually(t, func() bool {
				n := reads.Load()
				waits := n == last && len(d.pipe.free) == 0
				last = n
				return waits
			}, 5*time.Second, 100*time.Millisecond, "the read loop did not wait")
			require.Less(t, last, int64(total), "the read loop did not wait for the pipe")
			// The consumer can hold one set.
			assert.GreaterOrEqual(t, len(d.pipe.full), pipeSets-1, "sets that wait for the consumer")

			if !tc.close {
				openGate()
				<-loop
				require.Eventually(t, func() bool { return b.b.Stats().RxPackets == total },
					5*time.Second, time.Millisecond, "%d of %d packets", r.count(), total)
				assert.Equal(t, Stats{RxPackets: total}, b.b.Stats())
				r.mu.Lock()
				defer r.mu.Unlock()
				assert.Equal(t, seqs(total), r.got[1])
				return
			}
			stop.Store(true)
			closed := make(chan struct{})
			go func() {
				defer close(closed)
				_ = d.Close()
			}()
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("Close waits for the netstack.")
			}
			<-loop
			assert.Empty(t, d.pipe.full, "sets that wait for the consumer")
			openGate()
			n := uint64(reads.Load())
			require.Eventually(t, func() bool {
				st := b.b.Stats()
				return st.RxPackets+st.RxDrops == n && len(d.batch.(*injectBatch).in[0]) == 0
			}, 5*time.Second, time.Millisecond, "%d packets: %+v", n, b.b.Stats())
			r.mu.Lock()
			defer r.mu.Unlock()
			assert.Equal(t, b.b.Stats().RxPackets, uint64(r.n))
			assert.Equal(t, seqs(r.n), r.got[1], "the packets before the close")
		})
	}
}

// BenchmarkPipe gives reads of 64 PSP packets of 1280 B in 16 flows to the demux, as the
// QUIC read loop does, and measures the time of each packet. The inject workers give the
// packets to an endpoint with no netstack, which drops them at once.
func BenchmarkPipe(b *testing.B) {
	for _, pipe := range []bool{false, true} {
		b.Run(fmt.Sprintf("pipe=%t", pipe), func(b *testing.B) {
			x, y := newPair(b)
			offer(b, time.Now(), x, y)
			useNetstack(b, y, channel.New(16, DefaultMTU, ""), 4, pipe)
			inner := make([][]byte, 16)
			for f := range inner {
				inner[f] = packet(x.v4, y.v4, 17, uint16(1+f), 2, DefaultMTU)
			}
			// Without the pipe the read loop opens the packets in place, so the packets
			// are sealed again after each use, with new sequence numbers.
			pkts := make([][]byte, 64*pipeSlots)
			sealAll := func() {
				for i := range pkts {
					pkts[i] = seal(x, inner[i%len(inner)])[addrLen:]
				}
			}
			sealAll()
			b.SetBytes(pipeSlots * DefaultMTU)
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				if i == len(pkts) {
					b.StopTimer()
					sealAll()
					i = 0
					b.StartTimer()
				}
				for _, p := range pkts[i : i+pipeSlots] {
					y.b.demux.Handle(p, nil)
				}
				y.b.demux.BatchEnd()
				i += pipeSlots
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*pipeSlots), "ns/pkt")
		})
	}
}
