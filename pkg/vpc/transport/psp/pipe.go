// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	pspwire "github.com/apoxy-dev/softpsp/psp"
)

const (
	// pipeSets is the number of packet sets in a receive pipe.
	pipeSets = 8
	// pipeSlots is the most PSP packets in one set, as in one read of quic-go.
	pipeSlots = 64
)

// rxPipe moves the PSP packets of the netstack driver from the QUIC read loop to a
// consumer goroutine. The read loop only copies the packets of each read into a set.
// The consumer opens the sets in order and gives the packets to the inject workers, so
// the packets of a flow stay in order and only the consumer uses the receive queue.
// When all sets wait for the consumer, the read loop waits, and the socket buffer keeps
// the next packets.
type rxPipe struct {
	d      *driver
	cur    *rxSet      // The set of this read. Nil until the read loop adds a packet.
	full   chan *rxSet // Sets for the consumer, in order.
	free   chan *rxSet // Empty sets for the read loop.
	done   <-chan struct{}
	closed <-chan struct{}
	exited chan struct{} // Closes when the consumer stops.
}

// rxSet is the PSP packets of one read. The first n slots hold packets.
type rxSet struct {
	slots [][]byte
	n     int
}

// newRxPipe starts the consumer of d. It stops when done or closed closes.
func newRxPipe(d *driver, done, closed <-chan struct{}) *rxPipe {
	p := &rxPipe{
		d:      d,
		full:   make(chan *rxSet, pipeSets),
		free:   make(chan *rxSet, pipeSets),
		done:   done,
		closed: closed,
		exited: make(chan struct{}),
	}
	size := pspwire.Overhead + d.b.mtu
	slab := make([]byte, pipeSets*pipeSlots*size)
	for range pipeSets {
		s := &rxSet{slots: make([][]byte, pipeSlots)}
		for i := range s.slots {
			s.slots[i], slab = slab[:0:size], slab[size:]
		}
		p.free <- s
	}
	go p.run()
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

// flush gives the set of this read to the consumer. Only the read loop calls it.
func (p *rxPipe) flush() {
	s := p.cur
	if s == nil {
		return
	}
	p.cur = nil
	// There are pipeSets sets, so this does not wait.
	p.full <- s
	// The consumer can stop before it gets s.
	if p.stopped() {
		p.drain()
	}
}

// run opens the sets in order until the pipe stops. Then it drops the sets that wait.
func (p *rxPipe) run() {
	defer close(p.exited)
	for {
		select {
		case s := <-p.full:
			for _, pkt := range s.slots[:s.n] {
				p.d.b.open(p.d, pkt)
			}
			s.n = 0
			p.free <- s
			// When more sets wait, their packets go in the same inject batches.
			if len(p.full) == 0 {
				p.d.batch.flush()
			}
		case <-p.done:
			p.stop()
			return
		case <-p.closed:
			p.stop()
			return
		}
	}
}

// stop drops the packets in the inject batches and in the sets that wait.
func (p *rxPipe) stop() {
	p.d.batch.flush()
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

// drain drops the sets that wait for the consumer.
func (p *rxPipe) drain() {
	for {
		select {
		case s := <-p.full:
			p.d.b.stats.rxDrops.Add(uint64(s.n))
			s.n = 0
		default:
			return
		}
	}
}
