// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/udpbatch"
)

const (
	// fwdSets is the most packet sets of each sender of a forward pipe. They hold
	// two reads of the largest size: 64 GRO messages of 64 packets.
	fwdSets = 128
	// maxSend is the most packets in one sendmmsg call of a sender.
	maxSend = 4 * maxFwd
	// maxFwdSenders is the most senders of a forward pipe.
	maxFwdSenders = 4
)

// fwdSenders returns the number of senders of a forward pipe for procs CPUs: at
// most half of the CPUs, and at most maxFwdSenders, because one read loop feeds them.
func fwdSenders(procs int) int {
	if procs < 4 {
		return 1
	}
	return min(procs/2, maxFwdSenders)
}

// forwarder sends the PSP packets that one read of the QUIC read loop forwards.
// Only the read loop calls it.
type forwarder interface {
	// add copies b to dst into the forwarder.
	add(b []byte, dst netip.AddrPort)
	// flush sends the packets of the read, or gives them to the senders.
	flush()
}

// fwdPipe moves the PSP packets that the read loop forwards to sender goroutines.
// A destination always has the same sender, so its packets stay in order. The read
// loop does not wait: a packet for a sender with no free set drops.
type fwdPipe struct {
	tr      *quic.Transport
	addrs   addrCache
	senders []*fwdSender
	// slots holds 1 plus the sender index of each hash slot, or 0. Only the read
	// loop uses slots and next.
	slots [1 << addrSlotBits]uint8
	next  int
	done  <-chan struct{}
	c     fwdCounters
}

// fwdCounters are the counters of a forward pipe.
type fwdCounters struct {
	closed *atomic.Uint64 // Packets that drop because the pipe stopped.
	queue  *atomic.Uint64 // Packets that drop because their sender has no free set.
	sends  *sendStats
}

// fwdSender sends the packets of its destinations with one socket batch.
type fwdSender struct {
	b    *udpbatch.Batch // Only the sender goroutine uses it.
	cur  *fwdSet         // The set of this read. Only the read loop uses it.
	full chan *fwdSet    // Sets for the sender goroutine, in order.
	made int             // The sets of the sender. Only the read loop uses it.

	mu   sync.Mutex
	free []*fwdSet // Empty sets. The last one was in use most recently.
}

// fwdSet is the forwarded packets of one read for one sender. The first n slots
// hold packets.
type fwdSet struct {
	pkts [][]byte
	dsts []netip.AddrPort
	n    int
}

// newFwdPipe returns a pipe for tr with n senders that stops when done closes, or
// nil when the socket of tr cannot send batches. The caller calls start.
func newFwdPipe(tr *quic.Transport, n int, done <-chan struct{}, c fwdCounters) *fwdPipe {
	uc, ok := tr.Conn.(*net.UDPConn)
	if !ok {
		return nil
	}
	p := &fwdPipe{tr: tr, done: done, c: c}
	for range n {
		// The senders send at the same time, so a send must not wait for the others.
		b := udpbatch.NewShared(uc, maxSend)
		if b == nil {
			return nil
		}
		sd := &fwdSender{b: b, full: make(chan *fwdSet, fwdSets), free: make([]*fwdSet, 0, fwdSets)}
		p.senders = append(p.senders, sd)
	}
	return p
}

// newFwdSet returns an empty set with room for maxFwd packets.
func newFwdSet() *fwdSet {
	s := &fwdSet{pkts: make([][]byte, maxFwd), dsts: make([]netip.AddrPort, maxFwd)}
	slab := make([]byte, maxFwd*maxUDP)
	for i := range s.pkts {
		s.pkts[i], slab = slab[:0:maxUDP], slab[maxUDP:]
	}
	return s
}

// start runs the sender goroutines.
func (p *fwdPipe) start() {
	for _, sd := range p.senders {
		go p.run(sd)
	}
}

// senderOf returns the sender of the destination dst. The first packet to a hash
// slot gives the slot the next sender in turn, and the slot keeps that sender.
func (p *fwdPipe) senderOf(dst netip.AddrPort) *fwdSender {
	if len(p.senders) == 1 {
		return p.senders[0]
	}
	slot := &p.slots[addrSlot(dst)]
	if *slot == 0 {
		p.next = p.next%len(p.senders) + 1
		*slot = uint8(p.next)
	}
	return p.senders[*slot-1]
}

// add copies b to dst into the set of this read for the sender of dst. It drops b
// when that sender has no free set, or when the pipe stopped.
func (p *fwdPipe) add(b []byte, dst netip.AddrPort) {
	if len(b) > maxUDP {
		_, _ = p.tr.WriteTo(b, p.addrs.get(dst))
		return
	}
	sd := p.senderOf(dst)
	s := sd.cur
	if s == nil {
		if s = sd.take(); s == nil {
			if p.stopped() {
				p.c.closed.Add(1)
			} else {
				p.c.queue.Add(1)
			}
			return
		}
		sd.cur = s
	}
	s.pkts[s.n] = append(s.pkts[s.n][:0], b...)
	s.dsts[s.n] = dst
	if s.n++; s.n == len(s.pkts) {
		p.give(sd)
	}
}

// take returns the free set of sd that was in use most recently. With no free set
// it makes a set, so an idle sender holds no memory. With fwdSets sets it returns nil.
func (sd *fwdSender) take() *fwdSet {
	sd.mu.Lock()
	if n := len(sd.free); n > 0 {
		s := sd.free[n-1]
		sd.free = sd.free[:n-1]
		sd.mu.Unlock()
		return s
	}
	sd.mu.Unlock()
	if sd.made == fwdSets {
		return nil
	}
	sd.made++
	return newFwdSet()
}

// put empties the sets and makes them free.
func (sd *fwdSender) put(sets []*fwdSet) {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	for _, s := range sets {
		s.n = 0
		sd.free = append(sd.free, s)
	}
}

// flush gives the sets of this read to the senders.
func (p *fwdPipe) flush() {
	for _, sd := range p.senders {
		if sd.cur != nil {
			p.give(sd)
		}
	}
}

// give gives the set of this read of sd to its sender goroutine.
func (p *fwdPipe) give(sd *fwdSender) {
	s := sd.cur
	sd.cur = nil
	// The sender has fwdSets sets, so this does not wait.
	sd.full <- s
	// The sender goroutine can stop before it gets s.
	if p.stopped() {
		p.drain(sd)
	}
}

// run sends the sets of sd in order until the pipe stops. Then it drops the sets
// that wait. One sendmmsg call sends the sets that wait, up to maxSend packets.
func (p *fwdPipe) run(sd *fwdSender) {
	held := make([]*fwdSet, 0, fwdSets)
	for {
		var s *fwdSet
		select {
		case s = <-sd.full:
		case <-p.done:
		}
		if p.stopped() {
			if s != nil {
				p.drop(s)
			}
			p.drain(sd)
			return
		}
		for s != nil {
			if sd.b.Len()+s.n > maxSend {
				held = p.send(sd, held)
			}
			for i := range s.n {
				sd.b.Add(s.pkts[i], s.dsts[i])
			}
			held = append(held, s)
			select {
			case s = <-sd.full:
			default:
				s = nil
			}
		}
		held = p.send(sd, held)
	}
}

// send sends the batch of sd and makes its sets free. It returns held with no sets.
func (p *fwdPipe) send(sd *fwdSender, held []*fwdSet) []*fwdSet {
	p.c.sends.flush(sd.b)
	sd.put(held)
	clear(held)
	return held[:0]
}

// stopped reports whether the pipe stopped.
func (p *fwdPipe) stopped() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// drain drops the sets that wait for the sender goroutine of sd.
func (p *fwdPipe) drain(sd *fwdSender) {
	for {
		select {
		case s := <-sd.full:
			p.drop(s)
		default:
			return
		}
	}
}

// drop counts the packets of s as drops and empties s.
func (p *fwdPipe) drop(s *fwdSet) {
	p.c.closed.Add(uint64(s.n))
	s.n = 0
}
