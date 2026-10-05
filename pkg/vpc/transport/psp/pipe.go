// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"sync"
	"sync/atomic"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"golang.org/x/sys/cpu"
)

const (
	// pipeSets is the most packet sets of a receive pipe with no open workers. Each
	// open worker adds two sets, up to twice this number.
	pipeSets = 8
	// laneSets is the number of sets for each read loop of a pipe with many open workers:
	// the set that it fills, and the sets of it that wait for the next stages.
	laneSets = 4
	// pipeSlots is the most PSP packets in one set. A read of quic-go with GRO can fill
	// many sets.
	pipeSlots = 64
	// fewOpenWorkers is the most open workers of a host with fewer than 20 CPUs.
	fewOpenWorkers = 4
	// maxOpenWorkers is the most open workers of a receive pipe.
	maxOpenWorkers = 8
)

// openWorkers returns the open workers of a receive pipe for procs CPUs: half of the CPUs
// up to 4, then a quarter of them. Zero means that the consumer opens the packets itself.
func openWorkers(procs int) int {
	if procs < 4 {
		return 0
	}
	return max(min(procs/2, fewOpenWorkers), min(procs/4, maxOpenWorkers))
}

// maxSets returns the most sets of a pipe with workers open workers that lanes read loops
// use. A host with few CPUs keeps few sets: more sets make its pipe slower.
func maxSets(workers, lanes int) int {
	sets := min(pipeSets+2*workers, 2*pipeSets)
	if workers <= fewOpenWorkers {
		return sets
	}
	return max(sets, laneSets*lanes)
}

// rxPipe copies the PSP packets of each read into a set. Open workers open and join the
// sets, and one consumer checks the replay window and injects the sets in read order.
// The read loop of the agent socket and of each lane socket has its own set. The pipe
// makes a set when a read loop finds no free set, up to maxSets.
type rxPipe struct {
	d       *driver
	j       *injectBatch
	workers int
	size    int         // The bytes of one slot.
	work    chan *rxSet // Sets for the open workers. Nil when the consumer opens the sets.
	full    chan *rxSet // Sets for the consumer, in read order.
	free    chan *rxSet // Empty sets for the read loops.
	done    <-chan struct{}
	closed  <-chan struct{}
	exited  chan struct{} // Closes when the consumer and the open workers stop.

	readers atomic.Int32 // Read loops that added a packet.
	made    atomic.Int32 // Sets that the pipe made.

	mu      sync.Mutex // Guards closing and the sends of flush.
	closing bool       // Set when the consumer stops. Then flush drops the sets.

	// lanes is the state of the read loop of each socket, by lane.
	lanes [keys.MaxLanes]rxLane
}

// rxLane is the state of the read loop of one socket. Only that read loop uses it.
type rxLane struct {
	_    cpu.CacheLinePad // Two read loops do not have a cache line in common.
	cur  *rxSet           // The set of this read. Nil until the read loop adds a packet.
	used bool             // The read loop is one of the readers of the pipe.
}

// rxSet is the PSP packets of one read. The first n slots hold packets.
type rxSet struct {
	slots  [][]byte
	n      int
	res    []openResult // The result of Open for each slot.
	out    []rxPacket   // The packets for the netstack, in slot order. The first nout are set.
	nout   int
	opened chan struct{} // Gets one token when an open worker finished the set.
}

// openResult is the result of Open for one slot. ok is false when Open failed.
type openResult struct {
	o     engine.Opened
	inner []byte // The inner packet, in the slot.
	ok    bool
}

// newRxPipe starts the consumer of d and workers open workers. They give the packets to
// j. They stop when done or closed closes. The pipe has no sets until a read loop adds a
// packet.
func newRxPipe(d *driver, j *injectBatch, workers int, done, closed <-chan struct{}) *rxPipe {
	// The channels have space for all sets that the pipe can make.
	sets := maxSets(workers, keys.MaxLanes)
	p := &rxPipe{
		d:       d,
		j:       j,
		workers: workers,
		size:    pspwire.Overhead + d.b.mtu,
		full:    make(chan *rxSet, sets),
		free:    make(chan *rxSet, sets),
		done:    done,
		closed:  closed,
		exited:  make(chan struct{}),
	}
	if workers > 0 {
		p.work = make(chan *rxSet, sets)
	}
	var wg sync.WaitGroup
	for range workers {
		wg.Go(p.open)
	}
	wg.Go(p.run)
	go func() {
		wg.Wait()
		close(p.exited)
	}()
	return p
}

// newSet makes an empty set.
func (p *rxPipe) newSet() *rxSet {
	s := &rxSet{slots: make([][]byte, pipeSlots), res: make([]openResult, pipeSlots), out: make([]rxPacket, pipeSlots)}
	if p.work != nil {
		s.opened = make(chan struct{}, 1)
	}
	slab := make([]byte, pipeSlots*p.size)
	for i := range s.slots {
		s.slots[i], slab = slab[:0:p.size], slab[p.size:]
	}
	return s
}

// add copies the PSP packet pkt into the set of this read of the socket of lane. It drops
// pkt when the pipe stops. Only the read loop of that socket calls it.
func (p *rxPipe) add(lane int, pkt []byte) {
	l := &p.lanes[lane]
	if l.cur == nil {
		if !l.used {
			// The pipe can have more sets from now on.
			l.used = true
			p.readers.Add(1)
		}
		if l.cur = p.get(); l.cur == nil {
			p.d.b.stats.rxDrops.Add(1)
			return
		}
	}
	s := l.cur
	s.slots[s.n] = append(s.slots[s.n][:0], pkt...)
	if s.n++; s.n == len(s.slots) {
		p.flush(lane)
	}
}

// get returns a free set, or a new set while the pipe has fewer sets than maxSets. Else
// it waits for a free set. It returns nil when the pipe stops.
func (p *rxPipe) get() *rxSet {
	var s *rxSet
	select {
	case s = <-p.free:
	default:
		if s = p.grow(); s == nil {
			select {
			case s = <-p.free:
			case <-p.done:
				return nil
			case <-p.closed:
				return nil
			}
		}
	}
	if p.stopped() {
		p.free <- s
		return nil
	}
	return s
}

// grow makes a set, or returns nil when the pipe has maxSets sets for its readers.
func (p *rxPipe) grow() *rxSet {
	limit := int32(maxSets(p.workers, int(p.readers.Load())))
	if p.made.Add(1) > limit {
		p.made.Add(-1)
		return nil
	}
	return p.newSet()
}

// flush gives the set of this read of the socket of lane to the open workers and the
// consumer, or drops it when the consumer stopped. Only the read loop of that socket
// calls it.
func (p *rxPipe) flush(lane int) {
	l := &p.lanes[lane]
	s := l.cur
	if s == nil {
		return
	}
	l.cur = nil
	p.d.b.stats.rxLanes[lane].Add(uint64(s.n))
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		p.d.b.stats.rxDrops.Add(uint64(s.n))
		s.n = 0
		p.free <- s
		return
	}
	// The channels hold all sets, so these sends do not wait.
	if p.work != nil {
		p.work <- s
	}
	p.full <- s
}

// open opens the sets of the work channel until the consumer closes it. Each open worker
// runs it. After the pipe stops, it gives each set back with no packets.
func (p *rxPipe) open() {
	for s := range p.work {
		if p.stopped() {
			s.nout = 0
		} else {
			p.openSet(s)
		}
		s.opened <- struct{}{}
	}
}

// openSet opens the packets of s in place, and makes the packets for the netstack from
// the ones that passed. It keeps the result of each slot and the packets in s.
func (p *rxPipe) openSet(s *rxSet) {
	b := p.d.b
	quic := b.relay.Load() != nil
	for i, pkt := range s.slots[:s.n] {
		inner, o, err := b.rxq.Open(pkt)
		if err != nil {
			s.res[i] = openResult{}
			continue
		}
		b.clampMSS(inner, quic)
		s.res[i] = openResult{o: o, inner: inner, ok: true}
	}
	s.nout = p.j.join(s.res[:s.n], s.out)
}

// run gives the sets to the netstack in read order until the pipe stops. Then it drops
// the sets that wait.
func (p *rxPipe) run() {
	b := p.d.b
	for {
		select {
		case s := <-p.full:
			if p.work == nil {
				p.openSet(s)
			} else if !p.wait(s) {
				p.stop(s)
				return
			}
			drops := s.n
			for _, r := range s.out[:s.nout] {
				if p.accept(s.res[r.first : r.first+r.n]) {
					p.j.push(r.pkb, r.w, r.n)
					drops -= r.n
				} else {
					r.pkb.DecRef()
				}
			}
			if drops > 0 {
				b.stats.rxDrops.Add(uint64(drops))
			}
			// A free set must hold no packet buffer, because release drops all it holds.
			clear(s.out[:s.nout])
			s.n, s.nout = 0, 0
			p.free <- s
			// When more sets wait, their packets go in the same inject batches.
			if len(p.full) == 0 {
				p.j.flush()
			}
		case <-p.done:
			p.stop(nil)
			return
		case <-p.closed:
			p.stop(nil)
			return
		}
	}
}

// accept gives the PSP packets of one packet for the netstack to the replay window, in
// order. The packet drops when the window drops one of them.
func (p *rxPipe) accept(res []openResult) bool {
	ok := true
	for i := range res {
		if p.d.b.rxq.Accept(res[i].o) != nil {
			ok = false
		}
	}
	return ok
}

// wait waits until an open worker finished s. It returns false when the pipe stops first.
func (p *rxPipe) wait(s *rxSet) bool {
	select {
	case <-s.opened:
		return true
	case <-p.done:
	case <-p.closed:
	}
	return false
}

// stop closes the work channel, so that the open workers finish the sets in it and exit.
// Then it drops the packets in the inject batches, in s and in the sets that wait.
func (p *rxPipe) stop(s *rxSet) {
	p.mu.Lock()
	p.closing = true
	if p.work != nil {
		close(p.work)
	}
	p.mu.Unlock()
	p.j.flush()
	if s != nil {
		p.release(s)
	}
	// After closing is set, flush adds no set, so this loop drops all sets that wait.
	for {
		select {
		case s := <-p.full:
			p.release(s)
		default:
			return
		}
	}
}

// release waits until an open worker finished s, drops the packets of s and frees s. The
// open workers finish every set of the work channel, so the wait ends.
func (p *rxPipe) release(s *rxSet) {
	if p.work != nil {
		<-s.opened
	}
	for _, r := range s.out[:s.nout] {
		r.pkb.DecRef()
	}
	clear(s.out[:s.nout])
	p.d.b.stats.rxDrops.Add(uint64(s.n))
	s.n, s.nout = 0, 0
	p.free <- s
}

// stopped reports whether the driver or the binding closed.
func (p *rxPipe) stopped() bool {
	select {
	case <-p.done:
		return true
	case <-p.closed:
		return true
	default:
		return false
	}
}
