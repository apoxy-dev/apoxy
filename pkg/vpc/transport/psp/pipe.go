// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"sync"

	"github.com/apoxy-dev/softpsp/engine"
	pspwire "github.com/apoxy-dev/softpsp/psp"
)

const (
	// pipeSets is the number of packet sets in a receive pipe with no open workers.
	// Each open worker adds two sets.
	pipeSets = 8
	// pipeSlots is the most PSP packets in one set. A read of quic-go with GRO can fill
	// many sets.
	pipeSlots = 64
	// maxOpenWorkers is the most open workers of a receive pipe.
	maxOpenWorkers = 4
)

// openWorkers returns the number of open workers of a receive pipe for procs CPUs. Zero
// means that the consumer opens the packets itself.
func openWorkers(procs int) int {
	if procs < 4 {
		return 0
	}
	return min(procs/2, maxOpenWorkers)
}

// rxPipe copies the PSP packets of each read into a set. Open workers open and join the
// sets, and one consumer checks the replay window and injects the sets in read order.
type rxPipe struct {
	d      *driver
	j      *injectBatch
	cur    *rxSet      // The set of this read. Nil until the read loop adds a packet.
	work   chan *rxSet // Sets for the open workers. Nil when the consumer opens the sets.
	full   chan *rxSet // Sets for the consumer, in read order.
	free   chan *rxSet // Empty sets for the read loop.
	done   <-chan struct{}
	closed <-chan struct{}
	exited chan struct{} // Closes when the consumer and the open workers stop.

	mu      sync.Mutex // Guards closing and the sends of flush.
	closing bool       // Set when the consumer stops. Then flush drops the sets.
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
// j. They stop when done or closed closes.
func newRxPipe(d *driver, j *injectBatch, workers int, done, closed <-chan struct{}) *rxPipe {
	sets := pipeSets + 2*workers
	p := &rxPipe{
		d:      d,
		j:      j,
		full:   make(chan *rxSet, sets),
		free:   make(chan *rxSet, sets),
		done:   done,
		closed: closed,
		exited: make(chan struct{}),
	}
	if workers > 0 {
		p.work = make(chan *rxSet, sets)
	}
	size := pspwire.Overhead + d.b.mtu
	slab := make([]byte, sets*pipeSlots*size)
	for range sets {
		s := &rxSet{slots: make([][]byte, pipeSlots), res: make([]openResult, pipeSlots), out: make([]rxPacket, pipeSlots)}
		if workers > 0 {
			s.opened = make(chan struct{}, 1)
		}
		for i := range s.slots {
			s.slots[i], slab = slab[:0:size], slab[size:]
		}
		p.free <- s
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

// add copies the PSP packet pkt into the set of this read. It drops pkt when the pipe
// stops. Only the read loop calls it.
func (p *rxPipe) add(pkt []byte) {
	if p.cur == nil {
		if p.cur = p.get(); p.cur == nil {
			p.d.b.stats.rxDrops.Add(1)
			return
		}
	}
	s := p.cur
	s.slots[s.n] = append(s.slots[s.n][:0], pkt...)
	if s.n++; s.n == len(s.slots) {
		p.flush()
	}
}

// get returns a free set. It waits while no set is free, and returns nil when the pipe
// stops.
func (p *rxPipe) get() *rxSet {
	select {
	case s := <-p.free:
		if !p.stopped() {
			return s
		}
	case <-p.done:
	case <-p.closed:
	}
	return nil
}

// flush gives the set of this read to the open workers and the consumer, or drops it
// when the consumer stopped. Only the read loop calls it.
func (p *rxPipe) flush() {
	s := p.cur
	if s == nil {
		return
	}
	p.cur = nil
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		p.d.b.stats.rxDrops.Add(uint64(s.n))
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

// release waits until an open worker finished s, and drops the packets of s. The open
// workers finish every set of the work channel, so the wait ends.
func (p *rxPipe) release(s *rxSet) {
	if p.work != nil {
		<-s.opened
	}
	for _, r := range s.out[:s.nout] {
		r.pkb.DecRef()
	}
	clear(s.out[:s.nout])
	s.nout = 0
	p.d.b.stats.rxDrops.Add(uint64(s.n))
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
