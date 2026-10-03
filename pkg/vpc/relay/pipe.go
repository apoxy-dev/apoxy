// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/udpbatch"
)

// fwdSets is the number of packet sets in a forward pipe.
const fwdSets = 8

// forwarder sends the PSP packets that one read of the QUIC read loop forwards.
// Only the read loop calls it.
type forwarder interface {
	// add copies b to dst into the forwarder.
	add(b []byte, dst netip.AddrPort)
	// flush sends the packets of the read, or gives them to the sender.
	flush()
}

// fwdPipe moves the PSP packets that the read loop forwards to a sender goroutine.
// The loop only copies the packets of each read into a set. The sender sends the
// sets in order, each with one sendmmsg call, so the packets to each destination
// stay in order. When all sets wait for the sender, the loop waits, and the socket
// buffer keeps the next packets.
type fwdPipe struct {
	tr    *quic.Transport
	b     *udpbatch.Batch // Only the sender uses it.
	addrs addrCache
	cur   *fwdSet      // The set of this read. Nil until the loop adds a packet.
	full  chan *fwdSet // Sets for the sender, in order.
	free  chan *fwdSet // Empty sets for the loop.
	done  <-chan struct{}
	drops *atomic.Uint64 // Packets that drop because the pipe stopped.
}

// fwdSet is the forwarded packets of one read. The first n slots hold packets.
type fwdSet struct {
	pkts [][]byte
	dsts []netip.AddrPort
	n    int
}

// newFwdPipe returns a pipe for tr that stops when done closes, or nil when the
// socket of tr cannot send batches. The caller runs run.
func newFwdPipe(tr *quic.Transport, done <-chan struct{}, drops *atomic.Uint64) *fwdPipe {
	uc, ok := tr.Conn.(*net.UDPConn)
	if !ok {
		return nil
	}
	b := udpbatch.New(uc, maxFwd)
	if b == nil {
		return nil
	}
	p := &fwdPipe{
		tr:    tr,
		b:     b,
		full:  make(chan *fwdSet, fwdSets),
		free:  make(chan *fwdSet, fwdSets),
		done:  done,
		drops: drops,
	}
	slab := make([]byte, fwdSets*maxFwd*maxUDP)
	for range fwdSets {
		s := &fwdSet{pkts: make([][]byte, maxFwd), dsts: make([]netip.AddrPort, maxFwd)}
		for i := range s.pkts {
			s.pkts[i], slab = slab[:0:maxUDP], slab[maxUDP:]
		}
		p.free <- s
	}
	return p
}

// add copies b to dst into the set of this read. It drops b when the pipe stops.
func (p *fwdPipe) add(b []byte, dst netip.AddrPort) {
	if len(b) > maxUDP {
		_, _ = p.tr.WriteTo(b, p.addrs.get(dst))
		return
	}
	if p.cur == nil {
		if p.cur = p.get(); p.cur == nil {
			p.drops.Add(1)
			return
		}
	}
	s := p.cur
	s.pkts[s.n] = append(s.pkts[s.n][:0], b...)
	s.dsts[s.n] = dst
	if s.n++; s.n == len(s.pkts) {
		p.flush()
	}
}

// get returns a free set. It waits while no set is free, and returns nil when the pipe
// stops.
func (p *fwdPipe) get() *fwdSet {
	select {
	case s := <-p.free:
		if !p.stopped() {
			return s
		}
	case <-p.done:
	}
	return nil
}

// flush gives the set of this read to the sender.
func (p *fwdPipe) flush() {
	s := p.cur
	if s == nil {
		return
	}
	p.cur = nil
	// There are fwdSets sets, so this does not wait.
	p.full <- s
	// The sender can stop before it gets s.
	if p.stopped() {
		p.drain()
	}
}

// run sends the sets in order until the pipe stops. Then it drops the sets that wait.
func (p *fwdPipe) run() {
	for {
		var s *fwdSet
		select {
		case s = <-p.full:
		case <-p.done:
		}
		if p.stopped() {
			if s != nil {
				p.drop(s)
			}
			p.drain()
			return
		}
		for i := range s.n {
			p.b.Add(s.pkts[i], s.dsts[i])
		}
		// A packet that the socket refuses drops, as in fwdBatch.
		_, _, _ = p.b.Flush()
		s.n = 0
		p.free <- s
	}
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

// drain drops the sets that wait for the sender.
func (p *fwdPipe) drain() {
	for {
		select {
		case s := <-p.full:
			p.drop(s)
		default:
			return
		}
	}
}

// drop counts the packets of s as drops and empties s.
func (p *fwdPipe) drop(s *fwdSet) {
	p.drops.Add(uint64(s.n))
	s.n = 0
}
