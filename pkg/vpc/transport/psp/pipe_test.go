// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
)

// noPipe is the opens of useNetstack for a driver with no receive pipe.
const noPipe = -1

// useNetstack gives the binding of n a netstack driver on ep with the inject workers,
// and with a receive pipe of opens open workers. Zero opens means that the consumer
// opens the packets, and noPipe means no pipe.
func useNetstack(t testing.TB, n *node, ep *channel.Endpoint, workers, opens int) *driver {
	t.Helper()
	d := newDriver(n.b, func(buf []byte, off int) bool { return inject(ep, buf[off:]) })
	j := newInjectBatch(ep, &n.b.stats, n.b.seed, workers, d.done, n.b.ctx.Done())
	d.batch = j
	if opens >= 0 {
		d.pipe = newRxPipe(d, j, opens, d.done, n.b.ctx.Done())
	}
	require.True(t, n.b.drv.CompareAndSwap(nil, d))
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestOpenWorkers(t *testing.T) {
	for procs, want := range map[int]int{1: 0, 2: 0, 3: 0, 4: 2, 5: 2, 6: 3, 8: 4, 64: 4} {
		assert.Equal(t, want, openWorkers(procs), "procs %d", procs)
	}
}

// TestPipe gives reads of PSP packets of many flows to the demux, as the QUIC read loop
// does. The netstack must get the packets of each flow once and in order, also when the
// open workers finish the sets in another order and when one read fills more than one
// set. Forged packets fail Open and copies fail the replay window in Accept.
func TestPipe(t *testing.T) {
	cases := []struct {
		name  string
		opens int // Open workers, or noPipe.
		read  int // Packets in one read.
	}{
		{"no pipe", noPipe, 32},
		{"consumer opens full sets", 0, pipeSlots},
		{"one worker small reads", 1, 5},
		{"two workers reads of one", 2, 1},
		{"four workers small reads", 4, 5},
		{"four workers read larger than a set", 4, 3*pipeSlots + 5},
	}
	const flows, perFlow = 8, 120
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPair(t)
			offer(t, time.Now(), a, b)
			r, ep := newRecorder(t)
			useNetstack(t, b, ep, 4, tc.opens)
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
				case 31:
					// A copy of an older packet, which is in another set.
					pkts = append(pkts, bytes.Clone(pkts[len(pkts)-20]))
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

// TestPipeOrder gives the consumer two sets in read order, and the one open worker the
// same sets in another order. The netstack must get the packets in read order.
func TestPipeOrder(t *testing.T) {
	cases := []struct {
		name string
		work []int // The order of the sets for the open worker.
	}{
		{"opened in read order", []int{0, 1}},
		{"opened in reverse order", []int{1, 0}},
	}
	const perSet = 5
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPair(t)
			offer(t, time.Now(), a, b)
			r, ep := newRecorder(t)
			d := useNetstack(t, b, ep, 1, 1)
			sets := make([]*rxSet, 2)
			for i := range sets {
				s := <-d.pipe.free
				for j := range perSet {
					pkt := seal(a, flowPacket(1, uint32(i*perSet+j)))[addrLen:]
					s.slots[j] = append(s.slots[j][:0], pkt...)
				}
				s.n = perSet
				sets[i] = s
			}
			for _, i := range tc.work {
				d.pipe.work <- sets[i]
			}
			for _, s := range sets {
				d.pipe.full <- s
			}
			require.Eventually(t, func() bool { return r.count() == 2*perSet }, 5*time.Second, time.Millisecond)
			assert.Equal(t, Stats{RxPackets: 2 * perSet}, b.b.Stats())
			r.mu.Lock()
			defer r.mu.Unlock()
			assert.Equal(t, seqs(2*perSet), r.got[1])
		})
	}
}

// TestPipeSet gives one read of 9 packets with a bad packet in the middle. Open drops a
// forged packet or a packet with no SA, and Accept drops a copy. The packets after the
// bad one must arrive.
func TestPipeSet(t *testing.T) {
	cases := []struct {
		name    string
		bad     func(pkts [][]byte) []byte // The packet at index 4.
		icv     uint64                     // Packets that fail to authenticate.
		replays uint64                     // Packets that the replay window drops.
	}{
		{name: "all good"},
		{
			name: "forged",
			bad: func(pkts [][]byte) []byte {
				p := bytes.Clone(pkts[4])
				p[len(p)-1] ^= 1
				return p
			},
			icv: 1,
		},
		{
			name: "unknown SA",
			bad: func(pkts [][]byte) []byte {
				p := bytes.Clone(pkts[4])
				p[4] ^= 0xff
				return p
			},
		},
		{
			name:    "copy",
			bad:     func(pkts [][]byte) []byte { return bytes.Clone(pkts[2]) },
			replays: 1,
		},
	}
	for _, opens := range []int{0, 1, 3} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("opens=%d/%s", opens, tc.name), func(t *testing.T) {
				a, b := newPair(t)
				offer(t, time.Now(), a, b)
				r, ep := newRecorder(t)
				useNetstack(t, b, ep, 2, opens)
				var pkts [][]byte
				for i := range 9 {
					pkts = append(pkts, seal(a, flowPacket(1, uint32(i)))[addrLen:])
				}
				h, err := pspwire.ParseHeader(pkts[0])
				require.NoError(t, err)
				want := seqs(9)
				drops := uint64(0)
				if tc.bad != nil {
					pkts[4] = tc.bad(pkts)
					want = append(want[:4:4], want[5:]...)
					drops = 1
				}
				for _, pkt := range pkts {
					b.b.demux.Handle(pkt, nil)
				}
				b.b.demux.BatchEnd()
				require.Eventually(t, func() bool {
					st := b.b.Stats()
					return st.RxPackets+st.RxDrops == 9
				}, 5*time.Second, time.Millisecond)
				assert.Equal(t, Stats{RxPackets: 9 - drops, RxDrops: drops}, b.b.Stats())
				sa, ok := b.b.table.Stats(h.SPI)
				require.True(t, ok)
				assert.Equal(t, tc.icv, sa.ICVFailures)
				assert.Equal(t, tc.replays, sa.Replays)
				r.mu.Lock()
				defer r.mu.Unlock()
				assert.Equal(t, want, r.got[1])
			})
		}
	}
}

// TestPipeClampMSS checks that the consumer of the pipe lowers the MSS of TCP SYN packets.
func TestPipeClampMSS(t *testing.T) {
	a, b := newPairMTU(t, 1400)
	offer(t, time.Now(), a, b)
	b.b.SetClampMTU(1280)
	r, ep := newRecorder(t)
	useNetstack(t, b, ep, 2, 1)
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
		opens int
		close bool // The driver closes while the read loop waits.
	}{
		{name: "netstack catches up", opens: 0},
		{name: "netstack catches up with one worker", opens: 1},
		{name: "netstack catches up with three workers", opens: 3},
		{name: "driver closes", opens: 0, close: true},
		{name: "driver closes with three workers", opens: 3, close: true},
	}
	// More packets than the inject queue and the sets can hold.
	const total = 2 * (injectQueue + 2) * maxInjectBatch
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPair(t)
			offer(t, time.Now(), a, b)
			r, ep := newRecorder(t)
			hold := make(chan struct{})
			r.hold = hold
			release := sync.OnceFunc(func() { close(hold) })
			defer release()
			d := useNetstack(t, b, ep, 1, tc.opens)
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
			assert.GreaterOrEqual(t, len(d.pipe.full), cap(d.pipe.full)-1, "sets that wait for the consumer")

			if !tc.close {
				release()
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
			release()
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

// openSlot opens the PSP packet in slot i of s as an open worker does, and returns the
// result with a packet buffer that the test also references.
func openSlot(t *testing.T, b *Binding, j *injectBatch, s *rxSet, i int) openResult {
	t.Helper()
	inner, o, err := b.rxq.Open(s.slots[i])
	require.NoError(t, err)
	pkb, w := j.make(inner)
	require.NotNil(t, pkb)
	pkb.IncRef()
	return openResult{o: o, pkb: pkb, w: w}
}

// released waits until the pipe released the packet buffers of res, so that only the
// reference of the test is left, and gives that reference back.
func released(t *testing.T, res []openResult) {
	t.Helper()
	for _, r := range res {
		require.Eventually(t, func() bool { return r.pkb.ReadRefs() == 1 }, 5*time.Second, time.Millisecond,
			"the pipe did not release the packet buffer")
		r.pkb.DecRef()
	}
}

// TestPipeAcceptDrop gives the consumer a set with two results of the same packet. The
// replay window drops the second one, and the pipe must release its packet buffer.
func TestPipeAcceptDrop(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	r, ep := newRecorder(t)
	d := useNetstack(t, b, ep, 1, 1)
	s := <-d.pipe.free
	pkt := seal(a, flowPacket(1, 7))[addrLen:]
	var mine []openResult
	for i := range 2 {
		s.slots[i] = append(s.slots[i][:0], pkt...)
		s.res[i] = openSlot(t, b.b, d.pipe.j, s, i)
		mine = append(mine, s.res[i])
	}
	s.n = 2
	// The test is the open worker of the set.
	s.opened <- struct{}{}
	d.pipe.full <- s
	require.Eventually(t, func() bool {
		st := b.b.Stats()
		return st.RxPackets+st.RxDrops == 2
	}, 5*time.Second, time.Millisecond)
	assert.Equal(t, Stats{RxPackets: 1, RxDrops: 1}, b.b.Stats())
	released(t, mine)
	r.mu.Lock()
	defer r.mu.Unlock()
	assert.Equal(t, []uint32{7}, r.got[1])
}

// TestPipeCloseWhileOpen gives the consumer sets that are in no work channel, so the
// consumer waits for the first one. Close must stop the pipe and wait for the token of
// each set, which the test sends as a slow open worker after Close started. The packets
// of all sets count as drops, and the pipe releases the packet buffers of the first set.
func TestPipeCloseWhileOpen(t *testing.T) {
	cases := []struct {
		name string
		sets []int // Packets in each set. The first set has packet buffers.
	}{
		{"one set", []int{5}},
		{"sets wait after it", []int{5, pipeSlots, 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPair(t)
			offer(t, time.Now(), a, b)
			_, ep := newRecorder(t)
			d := useNetstack(t, b, ep, 1, 2)
			var sets []*rxSet
			var mine []openResult
			total := 0
			for si, n := range tc.sets {
				s := <-d.pipe.free
				for i := range n {
					pkt := seal(a, flowPacket(1, uint32(total+i)))[addrLen:]
					s.slots[i] = append(s.slots[i][:0], pkt...)
					s.res[i] = openResult{}
					if si == 0 {
						s.res[i] = openSlot(t, b.b, d.pipe.j, s, i)
						mine = append(mine, s.res[i])
					}
				}
				s.n = n
				total += n
				sets = append(sets, s)
				d.pipe.full <- s
			}
			require.Eventually(t, func() bool { return len(d.pipe.full) == len(tc.sets)-1 },
				5*time.Second, time.Millisecond, "the consumer did not take the first set")
			closed := make(chan struct{})
			go func() {
				defer close(closed)
				_ = d.Close()
			}()
			// The consumer stops waiting for the first set, then closes the work channel.
			require.Eventually(t, func() bool {
				d.pipe.mu.Lock()
				defer d.pipe.mu.Unlock()
				return d.pipe.closing
			}, 5*time.Second, time.Millisecond, "the consumer did not stop")
			for _, s := range sets {
				s.opened <- struct{}{}
			}
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("Close waits for the open workers.")
			}
			assert.Equal(t, Stats{RxDrops: uint64(total)}, b.b.Stats())
			released(t, mine)
		})
	}
}

// BenchmarkPipe gives reads of 64 PSP packets of 1280 B in 16 flows to the demux, as the
// QUIC read loop does, and measures the time of each packet. The inject workers give the
// packets to an endpoint with no netstack, which drops them at once.
func BenchmarkPipe(b *testing.B) {
	for _, opens := range []int{noPipe, 0, 1, 2, 4} {
		name := fmt.Sprintf("opens=%d", opens)
		if opens == noPipe {
			name = "no pipe"
		}
		b.Run(name, func(b *testing.B) {
			x, y := newPair(b)
			offer(b, time.Now(), x, y)
			useNetstack(b, y, channel.New(16, DefaultMTU, ""), 4, opens)
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
