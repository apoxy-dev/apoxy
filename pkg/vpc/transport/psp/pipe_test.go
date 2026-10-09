// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"fmt"
	"maps"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
)

// noPipe is the opens of useNetstack for a driver with no receive pipe.
const noPipe = -1

// useNetstack gives n a netstack driver on ep with workers inject workers and opens open
// workers. With zero opens the consumer opens the packets, and noPipe means no pipe.
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

// TestPipeRules checks the open workers of a pipe by CPU count, and the most sets of the
// pipe when 1, 4 and 16 read loops use it.
func TestPipeRules(t *testing.T) {
	cases := []struct {
		procs   int
		workers int
		sets    [3]int // With 1, 4 and 16 read loops.
	}{
		{1, 0, [3]int{8, 8, 8}},
		{2, 0, [3]int{8, 8, 8}},
		{3, 0, [3]int{8, 8, 8}},
		{4, 2, [3]int{12, 12, 12}},
		{5, 2, [3]int{12, 12, 12}},
		{6, 3, [3]int{14, 14, 14}},
		{7, 3, [3]int{14, 14, 14}},
		{8, 4, [3]int{16, 16, 16}},
		{16, 4, [3]int{16, 16, 16}},
		{19, 4, [3]int{16, 16, 16}},
		{20, 5, [3]int{16, 16, 64}},
		{24, 6, [3]int{16, 16, 64}},
		{31, 7, [3]int{16, 16, 64}},
		{32, 8, [3]int{16, 16, 64}},
		{64, 8, [3]int{16, 16, 64}},
		{192, 8, [3]int{16, 16, 64}},
	}
	for _, tc := range cases {
		w := openWorkers(tc.procs)
		assert.Equal(t, tc.workers, w, "procs %d", tc.procs)
		for i, lanes := range []int{1, 4, 16} {
			assert.Equal(t, tc.sets[i], maxSets(w, lanes), "procs %d, lanes %d", tc.procs, lanes)
		}
	}
}

// sealLanes seals perFlow packets of each of flows flows from a, and returns the PSP
// packets by the lane that sends them.
func sealLanes(t testing.TB, a *node, flows, perFlow int) [keys.MaxLanes][][]byte {
	t.Helper()
	var byLane [keys.MaxLanes][][]byte
	for i := range flows * perFlow {
		f := seal(a, flowPacket(uint16(1+i%flows), uint32(i/flows)))
		require.NotNil(t, f)
		byLane[f[laneOff]] = append(byLane[f[laneOff]], bytes.Clone(f[addrLen:]))
	}
	return byLane
}

// lanesUsed returns the number of lanes with packets.
func lanesUsed(byLane [keys.MaxLanes][][]byte) int {
	n := 0
	for _, pkts := range byLane {
		if len(pkts) > 0 {
			n++
		}
	}
	return n
}

// allFree checks that the pipe has all its sets again, and not more than maxSets for
// lanes read loops.
func allFree(t *testing.T, p *rxPipe, lanes int) {
	t.Helper()
	require.Eventually(t, func() bool { return len(p.free) == int(p.made.Load()) }, 5*time.Second, time.Millisecond,
		"%d of %d sets are free", len(p.free), p.made.Load())
	assert.Empty(t, p.full, "sets that wait for the consumer")
	assert.Equal(t, int32(lanes), p.readers.Load(), "read loops that use the pipe")
	assert.LessOrEqual(t, int(p.made.Load()), maxSets(p.workers, lanes), "sets of the pipe")
}

// TestPipe gives reads of PSP packets of many flows, with forged packets and copies, to the
// demux. The netstack must get the packets of each flow once and in order.
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

// TestPipeReaders gives the PSP packets of each SA lane to the read loop of that lane, as
// the relay does with lane ports. The read loops run at the same time. For each count of
// open workers, the netstack must get the packets of each flow as it gets them with no pipe.
func TestPipeReaders(t *testing.T) {
	const perFlow, read = 100, 7
	run := func(t *testing.T, lanes, opens int) map[uint16][]uint32 {
		a, b := newPairLanes(t, 0, lanes)
		offer(t, time.Now(), a, b)
		a.peer.SetLaneSockets(lanes)
		r, ep := newRecorder(t)
		d := useNetstack(t, b, ep, 4, opens)
		flows := 4 * lanes
		byLane := sealLanes(t, a, flows, perFlow)
		used := lanesUsed(byLane)
		require.Greater(t, used, lanes/2, "the flows use too few SA lanes")

		var readers sync.WaitGroup
		for lane, pkts := range byLane {
			readers.Go(func() {
				for i, pkt := range pkts {
					b.b.receive(lane, pkt)
					if (i+1)%read == 0 {
						b.b.batchEnd(lane)
					}
				}
				b.b.batchEnd(lane)
			})
		}
		readers.Wait()
		want := Stats{RxPackets: uint64(flows * perFlow)}
		require.Eventually(t, func() bool { return b.b.Stats() == want },
			5*time.Second, time.Millisecond, "%d of %d packets", r.count(), want.RxPackets)
		rx := b.b.RxLanePackets()
		for lane, pkts := range byLane {
			got := uint64(0)
			if lane < len(rx) {
				got = rx[lane]
			}
			assert.Equal(t, uint64(len(pkts)), got, "lane %d", lane)
		}
		if d.pipe != nil {
			allFree(t, d.pipe, used)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		return maps.Clone(r.got)
	}
	for _, lanes := range []int{1, 4, 16} {
		t.Run(fmt.Sprintf("lanes=%d", lanes), func(t *testing.T) {
			want := run(t, lanes, noPipe)
			require.Len(t, want, 4*lanes)
			for f, got := range want {
				require.Equal(t, seqs(perFlow), got, "flow %d with no pipe", f)
			}
			for _, opens := range []int{0, 1, 4, 8} {
				t.Run(fmt.Sprintf("opens=%d", opens), func(t *testing.T) {
					assert.Equal(t, want, run(t, lanes, opens))
				})
			}
		})
	}
}

// TestPipeSets checks that the pipe makes sets only while the read loops find none free,
// up to maxSets, and that all sets are free after the run. With hold, the netstack waits.
func TestPipeSets(t *testing.T) {
	cases := []struct {
		name  string
		lanes int
		opens int
		hold  bool
		close bool // The driver closes while the read loops wait.
	}{
		{name: "one lane, consumer opens", lanes: 1, opens: 0},
		{name: "one lane", lanes: 1, opens: 4},
		{name: "four lanes", lanes: 4, opens: 4},
		{name: "sixteen lanes", lanes: 16, opens: 8},
		{name: "netstack waits, one lane", lanes: 1, opens: 2, hold: true},
		{name: "netstack waits, four lanes", lanes: 4, opens: 4, hold: true},
		{name: "netstack waits, sixteen lanes", lanes: 16, opens: 8, hold: true},
		{name: "netstack waits, sixteen lanes, few open workers", lanes: 16, opens: 4, hold: true},
		{name: "netstack waits, sixteen lanes, consumer opens", lanes: 16, opens: 0, hold: true},
		{name: "driver closes, one lane, consumer opens", lanes: 1, opens: 0, hold: true, close: true},
		{name: "driver closes, four lanes", lanes: 4, opens: 4, hold: true, close: true},
		{name: "driver closes, sixteen lanes", lanes: 16, opens: 8, hold: true, close: true},
	}
	// More packets than the inject queue and the sets of 16 lanes can hold.
	const total = (injectQueue+2)*maxInjectBatch + 2*laneSets*keys.MaxLanes*pipeSlots
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPairLanes(t, 0, tc.lanes)
			offer(t, time.Now(), a, b)
			a.peer.SetLaneSockets(tc.lanes)
			r, ep := newRecorder(t)
			hold := make(chan struct{})
			release := sync.OnceFunc(func() { close(hold) })
			defer release()
			if tc.hold {
				r.hold = hold
			}
			d := useNetstack(t, b, ep, 1, tc.opens)
			p := d.pipe
			assert.Zero(t, p.made.Load(), "sets of a pipe that no read loop used")
			flows := 4 * tc.lanes
			byLane := sealLanes(t, a, flows, total/flows)
			used := lanesUsed(byLane)

			// Each read loop gives reads of one full set and a part of a set.
			var reads atomic.Int64
			var readers sync.WaitGroup
			for lane, pkts := range byLane {
				readers.Go(func() {
					for i, pkt := range pkts {
						b.b.receive(lane, pkt)
						if (i+1)%(pipeSlots+pipeSlots/2) == 0 {
							b.b.batchEnd(lane)
						}
						reads.Add(1)
					}
					b.b.batchEnd(lane)
				})
			}
			if tc.hold {
				// The read loops wait when they read no more and the pipe has all its sets.
				last := int64(-1)
				require.Eventually(t, func() bool {
					n := reads.Load()
					waits := n == last && len(p.free) == 0 && int(p.made.Load()) == maxSets(tc.opens, used)
					last = n
					return waits
				}, 10*time.Second, 100*time.Millisecond, "the read loops did not wait: %d sets", p.made.Load())
				require.Less(t, last, int64(total), "the read loops did not wait for the pipe")
			}
			if tc.close {
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
			}
			release()
			done := make(chan struct{})
			go func() {
				defer close(done)
				readers.Wait()
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("A read loop waits for a set.")
			}
			require.Eventually(t, func() bool {
				st := b.b.Stats()
				return st.RxPackets+st.RxDrops+st.RxNoDriver == total && len(d.batch.(*injectBatch).in[0]) == 0
			}, 10*time.Second, time.Millisecond, "%d packets: %+v", total, b.b.Stats())
			allFree(t, p, used)
			if !tc.close {
				assert.Equal(t, Stats{RxPackets: total}, b.b.Stats())
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			assert.Equal(t, b.b.Stats().RxPackets, uint64(r.n))
			for f, got := range r.got {
				assert.Equal(t, seqs(len(got)), got, "flow %d", f)
			}
		})
	}
}

// TestPipeCloseBusy closes the driver while sets always wait for the consumer. The replay
// window drops the packets after the first reads. Close must return.
func TestPipeCloseBusy(t *testing.T) {
	const lanes = 4
	for _, opens := range []int{0, 4} {
		t.Run(fmt.Sprintf("opens=%d", opens), func(t *testing.T) {
			a, b := newPairLanes(t, 0, lanes)
			offer(t, time.Now(), a, b)
			a.peer.SetLaneSockets(lanes)
			_, ep := newRecorder(t)
			d := useNetstack(t, b, ep, 1, opens)
			byLane := sealLanes(t, a, 4*lanes, pipeSlots)
			used := lanesUsed(byLane)
			var stop atomic.Bool
			var reads atomic.Int64
			var readers sync.WaitGroup
			for lane, pkts := range byLane {
				if len(pkts) == 0 {
					continue
				}
				readers.Go(func() {
					for !stop.Load() {
						for _, pkt := range pkts {
							b.b.receive(lane, pkt)
						}
						b.b.batchEnd(lane)
						reads.Add(1)
					}
				})
			}
			defer func() {
				stop.Store(true)
				readers.Wait()
			}()
			require.Eventually(t, func() bool { return reads.Load() > 100 && len(d.pipe.full) > 0 },
				5*time.Second, time.Millisecond, "the read loops gave %d reads", reads.Load())
			closed := make(chan struct{})
			go func() {
				defer close(closed)
				_ = d.Close()
			}()
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("Close waits for the consumer.")
			}
			stop.Store(true)
			readers.Wait()
			assert.Empty(t, d.pipe.full, "sets that wait for the consumer")
			// A read loop can keep the set that it filled at the close.
			assert.GreaterOrEqual(t, len(d.pipe.free), int(d.pipe.made.Load())-used, "free sets")
		})
	}
}

// TestPipeNoAllocs checks that reads through a pipe that has its sets do not allocate.
// The packets fail Open, so that the pipe makes no packet buffer for the netstack.
func TestPipeNoAllocs(t *testing.T) {
	for _, opens := range []int{0, 1, 4} {
		t.Run(fmt.Sprintf("opens=%d", opens), func(t *testing.T) {
			a, b := newPair(t)
			offer(t, time.Now(), a, b)
			_, ep := newRecorder(t)
			d := useNetstack(t, b, ep, 1, opens)
			pkts := make([][]byte, pipeSlots)
			for i := range pkts {
				pkts[i] = seal(a, flowPacket(1, uint32(i)))[addrLen:]
				pkts[i][len(pkts[i])-1] ^= 1
			}
			drops := uint64(0)
			read := func() {
				for _, pkt := range pkts {
					b.b.receive(0, pkt)
				}
				b.b.batchEnd(0)
				drops += pipeSlots
				// The consumer counts the drops, then frees the set.
				for b.b.Stats().RxDrops != drops || len(d.pipe.free) != int(d.pipe.made.Load()) {
					runtime.Gosched()
				}
			}
			assert.Zero(t, testing.AllocsPerRun(200, read))
			assert.Equal(t, Stats{RxDrops: drops}, b.b.Stats())
			assert.Equal(t, int32(1), d.pipe.made.Load(), "sets of the pipe")
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
				s := d.pipe.get()
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

// TestPipeSet gives one read of 9 packets with a bad packet in the middle. Only the bad
// packet must drop.
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
	a, b := newPairMTU(t, MaxMTU)
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

// TestPipeFull stops the netstack until all queues fill. The read loop must wait and drop
// nothing, and when the driver closes, it must stop waiting.
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
			// The read loop waits when it reads no more and the pipe has all its sets.
			sets := maxSets(tc.opens, 1)
			last := int64(-1)
			require.Eventually(t, func() bool {
				n := reads.Load()
				waits := n == last && len(d.pipe.free) == 0 && int(d.pipe.made.Load()) == sets
				last = n
				return waits
			}, 5*time.Second, 100*time.Millisecond, "the read loop did not wait")
			require.Less(t, last, int64(total), "the read loop did not wait for the pipe")
			// The consumer can hold one set.
			assert.GreaterOrEqual(t, len(d.pipe.full), sets-1, "sets that wait for the consumer")

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
			allFree(t, d.pipe, 1)
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

// openSlots opens the PSP packets of s and makes their packets for the netstack as an open
// worker does. It returns the packets, with a reference of the test on each packet buffer.
func openSlots(t *testing.T, b *Binding, j *injectBatch, s *rxSet) []rxPacket {
	t.Helper()
	for i, pkt := range s.slots[:s.n] {
		inner, o, err := b.rxq.Open(pkt)
		require.NoError(t, err)
		s.res[i] = openResult{o: o, inner: inner, ok: true}
	}
	s.nout = j.join(s.res[:s.n], s.out)
	mine := slices.Clone(s.out[:s.nout])
	for _, r := range mine {
		r.pkb.IncRef()
	}
	return mine
}

// released waits until the pipe released the packet buffers of pkts, so that only the
// reference of the test is left, and gives that reference back.
func released(t *testing.T, pkts []rxPacket) {
	t.Helper()
	for _, r := range pkts {
		require.Eventually(t, func() bool { return r.pkb.ReadRefs() == 1 }, 5*time.Second, time.Millisecond,
			"the pipe did not release the packet buffer")
		r.pkb.DecRef()
	}
}

// TestPipeAcceptDrop gives the consumer a set with two copies of the same packet. The
// replay window drops the second one, and the pipe must release its packet buffer.
func TestPipeAcceptDrop(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	r, ep := newRecorder(t)
	d := useNetstack(t, b, ep, 1, 1)
	s := d.pipe.get()
	pkt := seal(a, flowPacket(1, 7))[addrLen:]
	for i := range 2 {
		s.slots[i] = append(s.slots[i][:0], pkt...)
	}
	s.n = 2
	mine := openSlots(t, b.b, d.pipe.j, s)
	require.Len(t, mine, 2)
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

// TestPipeCloseWhileOpen closes the driver while the consumer waits for a slow open worker.
// Close must wait for the worker, and all packets must drop and release their buffers.
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
			var mine []rxPacket
			total := 0
			for si, n := range tc.sets {
				s := d.pipe.get()
				for i := range n {
					pkt := seal(a, flowPacket(1, uint32(total+i)))[addrLen:]
					s.slots[i] = append(s.slots[i][:0], pkt...)
				}
				s.n = n
				if si == 0 {
					mine = openSlots(t, b.b, d.pipe.j, s)
				}
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

// BenchmarkPipe gives reads to the demux: 64 PSP packets of 1280 B, UDP of 16 flows or TCP
// of 4 flows in runs of 16, or 2 TCP packets with no payload. No netstack takes them.
func BenchmarkPipe(b *testing.B) {
	for _, kind := range []string{"tcp=false", "tcp=true", "acks"} {
		for _, opens := range []int{noPipe, 0, 1, 2, 4, 8} {
			name := fmt.Sprintf("%s/opens=%d", kind, opens)
			if opens == noPipe {
				name = kind + "/no pipe"
			}
			b.Run(name, func(b *testing.B) {
				x, y := newPair(b)
				offer(b, time.Now(), x, y)
				useNetstack(b, y, channel.New(16, DefaultMTU, ""), 4, opens)
				const mss, perRun = DefaultMTU - header.IPv4MinimumSize - header.TCPMinimumSize - tcpOpts, 16
				data := pattern(perRun * mss)
				read := pipeSlots
				inner := make([][]byte, 64)
				for i := range inner {
					switch kind {
					case "tcp=true":
						off := i % perRun * mss
						inner[i] = tcpPacket(x.v4, y.v4, uint16(1+i/perRun), uint32(off), 7, header.TCPFlagAck, data[off:off+mss])
					case "acks":
						read = 2
						inner[i] = tcpPacket(x.v4, y.v4, uint16(1+i/perRun), 7, uint32(i%perRun*mss), header.TCPFlagAck, nil)
					default:
						inner[i] = packet(x.v4, y.v4, 17, uint16(1+i%16), 2, DefaultMTU)
					}
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
				b.SetBytes(int64(read * len(inner[0])))
				b.ReportAllocs()
				i := 0
				for b.Loop() {
					if i == len(pkts) {
						b.StopTimer()
						sealAll()
						i = 0
						b.StartTimer()
					}
					for _, p := range pkts[i : i+read] {
						y.b.demux.Handle(p, nil)
					}
					y.b.demux.BatchEnd()
					i += read
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*read), "ns/pkt")
			})
		}
	}
}

// BenchmarkPipeLanes gives reads of 64 PSP packets of 1280 B from 16 read loops at the same
// time. A read loop gives its packets again, and the replay window drops them then.
func BenchmarkPipeLanes(b *testing.B) {
	const lanes, sets = 16, 8
	for _, opens := range []int{0, 2, 4, 8} {
		b.Run(fmt.Sprintf("opens=%d", opens), func(b *testing.B) {
			x, y := newPairLanes(b, 0, lanes)
			offer(b, time.Now(), x, y)
			x.peer.SetLaneSockets(lanes)
			useNetstack(b, y, channel.New(16, DefaultMTU, ""), 4, opens)
			var byLane [lanes][][]byte
			for left, round := lanes*sets*pipeSlots, 0; left > 0; round++ {
				if round > 4*sets*pipeSlots {
					b.Fatal("a lane gets no flow")
				}
				for flow := range 4 * lanes {
					f := seal(x, packet(x.v4, y.v4, 17, uint16(1+flow), 2, DefaultMTU))
					if lane := f[laneOff]; len(byLane[lane]) < sets*pipeSlots {
						byLane[lane] = append(byLane[lane], bytes.Clone(f[addrLen:]))
						left--
					}
				}
			}
			before := y.b.Stats()
			var left atomic.Int64
			left.Store(int64(b.N))
			b.SetBytes(pipeSlots * DefaultMTU)
			b.ReportAllocs()
			b.ResetTimer()
			var readers sync.WaitGroup
			for lane, pkts := range byLane {
				readers.Go(func() {
					for i := 0; left.Add(-1) >= 0; i = (i + pipeSlots) % len(pkts) {
						for _, p := range pkts[i : i+pipeSlots] {
							y.b.receive(lane, p)
						}
						y.b.batchEnd(lane)
					}
				})
			}
			readers.Wait()
			// The run ends when the consumer has given or dropped all packets.
			for want := uint64(b.N) * pipeSlots; ; runtime.Gosched() {
				st := sub(y.b.Stats(), before)
				if st.RxPackets+st.RxDrops == want {
					break
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*pipeSlots), "ns/pkt")
		})
	}
}
