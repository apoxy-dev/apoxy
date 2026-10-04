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
	// pipeSlots is the most PSP packets in one set, as in one read of quic-go.
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

// rxPipe moves the PSP packets of the netstack driver from the QUIC read loop to a
// consumer goroutine. The read loop only copies the packets of each read into a set.
// Open workers decrypt the sets, each worker one set at a time. The consumer takes the
// sets in read order, waits until a worker opened each one, checks the replay window and
// gives the packets to the inject workers. Thus the packets of a flow stay in order, and
// only the consumer writes the replay window. When all sets wait, the read loop waits,
// and the socket buffer keeps the next packets.
type rxPipe struct {
	d      *driver
	cur    *rxSet      // The set of this read. Nil until the read loop adds a packet.
	work   chan *rxSet // Sets for the open workers. Nil when the consumer opens the sets.
	full   chan *rxSet // Sets for the consumer, in read order.
	free   chan *rxSet // Empty sets for the read loop.
	done   <-chan struct{}
	closed <-chan struct{}
	exited chan struct{} // Closes when the consumer and the open workers stop.
}

// rxSet is the PSP packets of one read. The first n slots hold packets.
type rxSet struct {
	slots  [][]byte
	n      int
	res    []openResult  // The result of Open for each slot.
	opened chan struct{} // Gets one token when an open worker finished the set.
}

// openResult is the result of Open for one packet.
type openResult struct {
	o engine.Opened
	n int // The length of the inner packet, or -1 when Open failed.
}

// newRxPipe starts the consumer of d and workers open workers. They stop when done or
// closed closes.
func newRxPipe(d *driver, workers int, done, closed <-chan struct{}) *rxPipe {
	sets := pipeSets + 2*workers
	p := &rxPipe{
		d:      d,
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
		s := &rxSet{slots: make([][]byte, pipeSlots), res: make([]openResult, pipeSlots)}
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

// flush gives the set of this read to the open workers and the consumer. Only the read
// loop calls it.
func (p *rxPipe) flush() {
	s := p.cur
	if s == nil {
		return
	}
	p.cur = nil
	// The channels hold all sets, so these sends do not wait.
	if p.work != nil {
		p.work <- s
	}
	p.full <- s
	// The consumer can stop before it gets s.
	if p.stopped() {
		p.drain()
	}
}

// open opens the sets of the work channel until the pipe stops. Each open worker runs it.
func (p *rxPipe) open() {
	for {
		select {
		case s := <-p.work:
			p.openSet(s)
			s.opened <- struct{}{}
		case <-p.done:
			return
		case <-p.closed:
			return
		}
	}
}

// openSet opens the packets of s in place and keeps the result of each one in s.
func (p *rxPipe) openSet(s *rxSet) {
	q := p.d.b.rxq
	for i, pkt := range s.slots[:s.n] {
		inner, o, err := q.Open(pkt)
		if err != nil {
			s.res[i] = openResult{n: -1}
			continue
		}
		s.res[i] = openResult{o: o, n: len(inner)}
	}
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
			for i, pkt := range s.slots[:s.n] {
				if r := s.res[i]; r.n < 0 {
					b.stats.rxDrops.Add(1)
				} else {
					b.accept(p.d, pkt, r.o, r.n)
				}
			}
			s.n = 0
			p.free <- s
			// When more sets wait, their packets go in the same inject batches.
			if len(p.full) == 0 {
				p.d.batch.flush()
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

// wait waits until an open worker opened s. It returns false when the pipe stops first.
func (p *rxPipe) wait(s *rxSet) bool {
	select {
	case <-s.opened:
		return true
	case <-p.done:
	case <-p.closed:
	}
	return false
}

// stop drops the packets in the inject batches, in s and in the sets that wait.
func (p *rxPipe) stop(s *rxSet) {
	p.d.batch.flush()
	if s != nil {
		p.d.b.stats.rxDrops.Add(uint64(s.n))
	}
	p.drain()
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

// drain drops the sets that wait for the consumer. It does not change them, because an
// open worker can still read them.
func (p *rxPipe) drain() {
	for {
		select {
		case s := <-p.full:
			p.d.b.stats.rxDrops.Add(uint64(s.n))
		default:
			return
		}
	}
}
