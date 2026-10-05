// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"fmt"
	"hash/maphash"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/apoxy-dev/softpsp/vtep/netstack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/flow"
)

// laneBinding returns a binding with no transport. Each lane has a socket
// that sends nothing, so that each lane has its own packet count.
func laneBinding(t testing.TB) *Binding {
	t.Helper()
	send, err := keys.NewSender(DefaultMTU)
	require.NoError(t, err)
	b := &Binding{mtu: DefaultMTU, send: send, seed: maphash.MakeSeed()}
	for i := 1; i < keys.MaxLanes; i++ {
		b.laneConns[i].Store(new(net.UDPConn))
	}
	return b
}

// laneSPI returns the SPI of the transmit SA of a lane of peer id.
func laneSPI(id byte, lane int) uint32 { return uint32(id)<<8 | uint32(lane+1) }

// laneDst returns an address in the route of peer id.
func laneDst(id byte) netip.Addr { return netip.AddrFrom4([4]byte{10, 0, id, 2}) }

// lanePeer adds peer id to b, with a transmit SA on each of n lanes and the
// route 10.0.id.0/24.
func lanePeer(t testing.TB, b *Binding, id byte, n int) *Peer {
	t.Helper()
	p := &Peer{b: b, tx: b.send.NewPeer()}
	p.sockets.Store(keys.MaxLanes)
	p.SetAddr(netip.MustParseAddrPort("192.0.2.1:443"))
	for lane := range n {
		offerLane(t, p, id, lane)
	}
	require.NoError(t, b.routes.Add(netip.PrefixFrom(laneDst(id), 24).Masked(), p))
	return p
}

// offerLane gives peer id a transmit SA on the lane.
func offerLane(t testing.TB, p *Peer, id byte, lane int) {
	t.Helper()
	sa := keys.SA{SPI: laneSPI(id, lane), Key: make([]byte, 16), VNI: testVNI, ExpiresIn: time.Hour, Lane: lane}
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	refused, err := p.tx.Apply(keys.Request{Op: keys.OpOffer, SAs: []keys.SA{sa}}, time.Now())
	require.NoError(t, err)
	require.Empty(t, refused)
	p.updateLanes()
}

// revokeLane removes the transmit SA of the lane of peer id.
func revokeLane(t testing.TB, p *Peer, id byte, lane int) {
	t.Helper()
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	_, err := p.tx.Apply(keys.Request{Op: keys.OpRevoke, SPIs: []uint32{laneSPI(id, lane)}}, time.Now())
	require.NoError(t, err)
	p.updateLanes()
}

// laneTicks moves the lane clock of b by n intervals.
func laneTicks(b *Binding, n int) {
	for range n {
		b.load.advance(b.load.start.Add(flowTick), &b.stats.txLanes)
	}
}

// flowMaker makes the packets of new flows. Each flow has its own slot in the
// flow table of a peer.
type flowMaker struct {
	b    *Binding
	port uint16
	used map[uint64]bool
}

func newFlowMaker(b *Binding) *flowMaker { return &flowMaker{b: b, used: map[uint64]bool{}} }

// next returns a packet of a new flow to peer id.
func (m *flowMaker) next(id byte) []byte {
	for {
		m.port++
		pkt := packet(netip.AddrFrom4([4]byte{10, 0, 0, 1}), laneDst(id), 6, m.port, 443, 100)
		if s := flow.Hash(m.b.seed, pkt) & (flowSlots - 1); !m.used[s] {
			m.used[s] = true
			return pkt
		}
	}
}

// TestFlowLanes starts flows together on a binding with no load. They use as
// many lanes as they can, and no lane has more than its share of the flows.
func TestFlowLanes(t *testing.T) {
	for _, lanes := range []int{2, 4, 6, 8, 16} {
		for _, flows := range []int{1, 2, 4, 8, 16} {
			t.Run(fmt.Sprintf("flows=%d/lanes=%d", flows, lanes), func(t *testing.T) {
				b := laneBinding(t)
				p := lanePeer(t, b, 1, lanes)
				m := newFlowMaker(b)
				used := map[int]int{}
				most := 0
				for range flows {
					sa, lane := p.txSA(m.next(1))
					require.NotNil(t, sa)
					require.Equal(t, laneSPI(1, lane), sa.SPI(), "lane of the SA")
					used[lane]++
					most = max(most, used[lane])
				}
				assert.Len(t, used, min(flows, lanes), "flows of each lane: %v", used)
				assert.Equal(t, (flows+lanes-1)/lanes, most, "flows of each lane: %v", used)
			})
		}
	}
}

// TestFlowLaneLife gives 4 flows the 4 lanes of a peer, changes something, and
// sends a packet of the flow of one lane again.
func TestFlowLaneLife(t *testing.T) {
	const lanes = 4
	ticks := func(n int) func(*testing.T, *Peer, []byte) {
		return func(_ *testing.T, p *Peer, _ []byte) { laneTicks(p.b, n) }
	}
	revoke := func(lane int) func(*testing.T, *Peer, []byte) {
		return func(t *testing.T, p *Peer, _ []byte) { revokeLane(t, p, 1, lane) }
	}
	cases := []struct {
		name  string
		act   func(t *testing.T, p *Peer, pkt []byte)
		lane  int  // The lane of the flow before act.
		keeps bool // The flow keeps its lane.
		gone  int  // A lane that no flow can get after act, or -1.
	}{
		{"many packets", func(t *testing.T, p *Peer, pkt []byte) {
			for range 1000 {
				_, lane := p.txSA(pkt)
				require.Equal(t, 2, lane)
			}
		}, 2, true, -1},
		{"a pause shorter than the time-out", ticks(flowIdle), 2, true, -1},
		{"two pauses shorter than the time-out", func(_ *testing.T, p *Peer, pkt []byte) {
			laneTicks(p.b, flowIdle)
			p.txSA(pkt)
			laneTicks(p.b, flowIdle)
		}, 2, true, -1},
		{"a pause longer than the time-out", ticks(flowIdle + 1), 2, false, -1},
		{"the lane count goes down", revoke(3), 3, false, 3},
		{"the lane count goes down, flow on a lower lane", revoke(3), 2, true, 3},
		{"the lane has no SA", revoke(1), 1, false, 1},
		{"another lane has no SA", revoke(1), 2, true, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := laneBinding(t)
			p := lanePeer(t, b, 1, lanes)
			m := newFlowMaker(b)
			var pkts [lanes][]byte
			for i := range pkts {
				pkts[i] = m.next(1)
				_, lane := p.txSA(pkts[i])
				require.Equal(t, i, lane)
			}
			tc.act(t, p, pkts[tc.lane])
			// The old lane now has the highest load, so a new choice gives another lane.
			b.stats.txLanes[tc.lane].Add(1000)
			sa, lane := p.txSA(pkts[tc.lane])
			require.NotNil(t, sa)
			require.Equal(t, laneSPI(1, lane), sa.SPI(), "lane of the SA")
			assert.Equal(t, tc.keeps, lane == tc.lane, "lane %d", lane)
			_, again := p.txSA(pkts[tc.lane])
			assert.Equal(t, lane, again, "the flow keeps the lane that it has now")
			for range 64 {
				sa, lane := p.txSA(m.next(1))
				require.NotNil(t, sa)
				require.NotEqual(t, tc.gone, lane)
				require.Less(t, lane, int(p.lanes.Load()))
			}
		})
	}
}

// TestFlowLaneLoad starts flows together on lanes that have load. sent has the
// packets that each lane socket sent, and ticks the intervals that start after that.
func TestFlowLaneLoad(t *testing.T) {
	cases := []struct {
		name    string
		peers   int // The flows go to the peers in turn.
		sockets int // SA lanes at or above this number send from the agent socket.
		sent    []uint64
		ticks   int
		flows   int
		want    []int // New flows of each lane socket.
	}{
		{"no load", 1, 4, nil, 0, 4, []int{1, 1, 1, 1}},
		{"the lane with the fewest packets", 1, 4, []uint64{500, 20, 300, 400}, 0, 1, []int{0, 1, 0, 0}},
		{"light lanes with different loads", 1, 4, []uint64{50, 200, 0, 3}, 0, 4, []int{1, 1, 1, 1}},
		{"one light flow on the last lane", 1, 4, []uint64{0, 0, 0, 400}, 0, 4, []int{1, 1, 1, 1}},
		{"two lanes with a heavy flow", 1, 4, []uint64{10000, 10000, 0, 0}, 0, 2, []int{0, 0, 1, 1}},
		{"more flows than lanes with no heavy flow", 1, 4, []uint64{10000, 10000, 0, 0}, 0, 6, []int{1, 1, 2, 2}},
		{"one lane with many heavy flows", 1, 4, []uint64{30000, 0, 0, 0}, 0, 4, []int{0, 2, 1, 1}},
		{"packets of the interval before", 1, 4, []uint64{5000, 0, 0, 0}, 1, 1, []int{0, 1, 0, 0}},
		{"packets of older intervals", 1, 4, []uint64{5000, 0, 0, 0}, 2, 1, []int{1, 0, 0, 0}},
		{"lanes that share the agent socket", 1, 2, nil, 0, 4, []int{2, 2}},
		{"each peer has one flow", 4, 4, nil, 0, 4, []int{1, 1, 1, 1}},
		{"each peer has two flows", 4, 4, nil, 0, 8, []int{2, 2, 2, 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const lanes = 4
			b := laneBinding(t)
			peers := make([]*Peer, tc.peers)
			for i := range peers {
				peers[i] = lanePeer(t, b, byte(i+1), lanes)
				peers[i].SetLaneSockets(tc.sockets)
			}
			for i, n := range tc.sent {
				b.stats.txLanes[i].Add(n)
			}
			laneTicks(b, tc.ticks)
			m := newFlowMaker(b)
			got := make([]int, len(tc.want))
			for i := range tc.flows {
				id := i % tc.peers
				sa, lane := peers[id].txSA(m.next(byte(id + 1)))
				require.NotNil(t, sa)
				got[peers[id].SendLane(lane)]++
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestLaneClock gives times to Tick. An interval of the lane clock starts only
// when the present one is flowTick old.
func TestLaneClock(t *testing.T) {
	cases := []struct {
		name string
		at   []time.Duration // Times of the calls after the first one.
		want uint32          // Intervals that started.
	}{
		{"one call", nil, 1},
		{"a call too soon", []time.Duration{flowTick - 1}, 1},
		{"a call after one interval", []time.Duration{flowTick}, 2},
		{"a call each second", []time.Duration{time.Second, 2 * time.Second, 3 * time.Second}, 4},
		{"two calls at the same time", []time.Duration{time.Second, time.Second}, 2},
		{"a time in the past", []time.Duration{-time.Hour}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := newPair(t)
			start := time.Now()
			_, err := a.b.Tick(start)
			require.NoError(t, err)
			for _, d := range tc.at {
				_, err := a.b.Tick(start.Add(d))
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, a.b.load.tick.Load())
		})
	}
}

// TestFlowLaneParallel calls prepare for the flows of 8 goroutines at the same
// time, with a steady peer and with a peer whose clock and SAs change.
func TestFlowLaneParallel(t *testing.T) {
	const (
		lanes   = 8
		workers = 8
		flows   = 16 // Flows of each worker.
		rounds  = 200
	)
	cases := []struct {
		name string
		// change runs until stop closes. Nil keeps the peer steady, and each flow
		// must keep its lane.
		change func(t *testing.T, p *Peer, stop <-chan struct{})
	}{
		{name: "steady"},
		{"the clock moves and a lane loses its SA", func(t *testing.T, p *Peer, stop <-chan struct{}) {
			for {
				select {
				case <-stop:
					return
				default:
				}
				laneTicks(p.b, 1)
				revokeLane(t, p, 1, lanes-1)
				laneTicks(p.b, 1)
				offerLane(t, p, 1, lanes-1)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := laneBinding(t)
			p := lanePeer(t, b, 1, lanes)
			m := newFlowMaker(b)
			var pkts [workers][flows][]byte
			for w := range pkts {
				for i := range pkts[w] {
					pkts[w][i] = m.next(1)
				}
			}
			stop, changed := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(changed)
				if tc.change != nil {
					tc.change(t, p, stop)
				}
			}()
			var used [lanes]atomic.Int32
			var wg sync.WaitGroup
			for w := range pkts {
				wg.Add(1)
				go func() {
					defer wg.Done()
					var first [flows]int
					for r := range rounds {
						for i, pkt := range pkts[w] {
							var f netstack.TxFrame
							if err := b.prepare(pkt, &f); err != nil || f.SA == nil {
								t.Errorf("prepare: %v", err)
								return
							}
							if f.SA.SPI() != laneSPI(1, f.Lane) {
								t.Errorf("SPI %#x on lane %d", f.SA.SPI(), f.Lane)
								return
							}
							if r == 0 {
								first[i] = f.Lane
								used[f.Lane].Add(1)
							} else if tc.change == nil && f.Lane != first[i] {
								t.Errorf("flow moved from lane %d to lane %d", first[i], f.Lane)
								return
							}
						}
					}
				}()
			}
			wg.Wait()
			close(stop)
			<-changed
			if tc.change == nil {
				for i := range used {
					assert.Equal(t, int32(workers*flows/lanes), used[i].Load(), "flows of lane %d", i)
				}
			}
		})
	}
}

// BenchmarkTxSA chooses the lane of a packet: for flows that send in turn, for
// 8 goroutines with one flow each, and for flows that are all new.
func BenchmarkTxSA(b *testing.B) {
	flowPackets := func(n int) [][]byte {
		pkts := make([][]byte, n)
		for i := range pkts {
			pkts[i] = packet(netip.AddrFrom4([4]byte{10, 0, 0, 1}), laneDst(1), 6, uint16(1024+i), 443, 100)
		}
		return pkts
	}
	for _, bc := range []struct{ lanes, flows int }{{1, 1}, {4, 1}, {8, 1}, {8, 256}, {16, 256}} {
		b.Run(fmt.Sprintf("lanes=%d/flows=%d", bc.lanes, bc.flows), func(b *testing.B) {
			p := lanePeer(b, laneBinding(b), 1, bc.lanes)
			pkts := flowPackets(bc.flows)
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				if sa, _ := p.txSA(pkts[i]); sa == nil {
					b.Fatal("no SA")
				}
				if i++; i == len(pkts) {
					i = 0
				}
			}
		})
	}
	b.Run("lanes=8/parallel", func(b *testing.B) {
		p := lanePeer(b, laneBinding(b), 1, 8)
		var port atomic.Uint32
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			pkt := packet(netip.AddrFrom4([4]byte{10, 0, 0, 1}), laneDst(1), 6, uint16(1024+port.Add(1)), 443, 100)
			for pb.Next() {
				if sa, _ := p.txSA(pkt); sa == nil {
					b.Error("no SA")
					return
				}
			}
		})
	})
	b.Run("lanes=8/new", func(b *testing.B) {
		bind := laneBinding(b)
		p := lanePeer(b, bind, 1, 8)
		m := newFlowMaker(bind)
		pkts := make([][]byte, flowSlots)
		for i := range pkts {
			pkts[i] = m.next(1)
		}
		b.ReportAllocs()
		i := 0
		for b.Loop() {
			if sa, _ := p.txSA(pkts[i]); sa == nil {
				b.Fatal("no SA")
			}
			if i++; i == len(pkts) {
				// All slots are idle after this, so each packet is of a new flow.
				i = 0
				laneTicks(bind, flowIdle+1)
			}
		}
	})
}
