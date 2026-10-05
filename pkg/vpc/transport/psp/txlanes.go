// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
)

const (
	// flowSlots is the size of the flow table of a peer. Flows with the same
	// slot use the same lane.
	flowSlots = 1024
	// flowTick is the shortest interval of the lane clock. Tick starts an
	// interval, and an agent calls Tick each second.
	flowTick = 500 * time.Millisecond
	// flowIdle is the highest age in intervals at which a slot keeps its lane.
	// A slot gets a new lane after 1 to 2 intervals with no packet.
	flowIdle = 1
	// newFlowLoad is the lowest load, in packets, of a flow that is too new to
	// show in the packet counts. A lane with less load than this is light.
	newFlowLoad = 1024

	// A slot holds the lane plus one in its low 8 bits, and the interval of
	// the last packet in the other 24 bits. Zero is an empty slot.
	slotLane = 1<<8 - 1
	slotTick = 1<<24 - 1
)

// laneLoad is the recent load of the send lanes of a binding. A new flow gets
// the lane with the lowest load.
type laneLoad struct {
	tick atomic.Uint32 // Number of the present interval.

	mu    sync.Mutex
	start time.Time // Start of the present interval.
	// sent is the packet count of each lane at the start of the present
	// interval and of the one before.
	sent [2][keys.MaxLanes]uint64
	// flows is the count of flows that got each lane in the present interval
	// and in the one before.
	flows [2][keys.MaxLanes]uint32
	next  int // The lane after the last choice. Equal lanes take turns.
}

// advance starts a new interval when the present one is flowTick old. sent has
// the packets that each lane sent.
func (l *laneLoad) advance(now time.Time, sent *[keys.MaxLanes]atomic.Uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.start.IsZero() && now.Sub(l.start) < flowTick {
		return
	}
	l.start = now
	l.sent[1] = l.sent[0]
	for i := range sent {
		l.sent[0][i] = sent[i].Load()
	}
	l.flows[1], l.flows[0] = l.flows[0], [keys.MaxLanes]uint32{}
	l.tick.Add(1)
}

// loadLane returns the lane whose socket sends the packets of the SA lane.
func (p *Peer) loadLane(lane int) int {
	if sock := p.SendLane(lane); p.b.laneConn(byte(sock)) != nil {
		return sock
	}
	return 0
}

// newLane gives the slot the lane with a transmit SA and the lowest load: the packets
// that its socket sent in the last 1 to 2 intervals, plus the flows that got it then.
func (p *Peer) newLane(s *atomic.Uint32, n int) (*engine.TxSA, int) {
	l := &p.b.load
	l.mu.Lock()
	defer l.mu.Unlock()
	v := s.Load()
	now := l.tick.Load() & slotTick
	// Another caller gave the slot a lane.
	if lane := int(v&slotLane) - 1; lane >= 0 && lane < n && (now-v>>8)&slotTick <= flowIdle {
		if sa := p.tx.SA(lane); sa != nil {
			return sa, lane
		}
	}
	var load [keys.MaxLanes]uint64
	var top uint64
	for i := range n {
		load[i] = p.b.stats.txLanes[i].Load() - l.sent[1][i]
		top = max(top, load[i])
	}
	// A new flow counts as half of the load of the busiest lane, because that
	// lane can have more than one flow.
	unit := max(newFlowLoad, top/2)
	var sa *engine.TxSA
	lane, low := 0, uint64(0)
	for i := range n {
		c := (l.next + i) % n
		x := p.tx.SA(c)
		if x == nil {
			continue
		}
		sock := p.loadLane(c)
		score := load[sock] + uint64(l.flows[0][sock]+l.flows[1][sock])*unit
		if sa == nil || score < low {
			sa, lane, low = x, c, score
		}
	}
	if sa == nil {
		return nil, 0
	}
	l.flows[0][p.loadLane(lane)]++
	l.next = lane + 1
	s.Store(uint32(lane+1) | now<<8)
	return sa, lane
}
