// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/atoonk/packetio"
	"github.com/quic-go/quic-go"
)

// quicQueue is how many received datagrams wait for quic-go. A datagram that does not fit drops
// (quic_full). The datagrams stay in their RX frames, so each RX queue has frames for a full queue
// (see frameOptions).
const quicQueue = 4096

// quicConn is the UDP 443 socket of the relay on the dedicated interface. It reads and writes the ECN
// bits of each packet, with DF, and WriteToGSO sends a batch of datagrams in one TX send.
type quicConn struct {
	d      *Device
	local  netip.AddrPort
	in     chan *quicTurn // The QUIC turns of the RX goroutines.
	queued atomic.Int64   // The datagrams that quic-go did not read, at most quicQueue.

	// mu keeps one read at a time, and the turn that it reads. Close takes it, so that no read
	// copies from an RX frame after Close.
	mu   sync.Mutex
	turn *quicTurn
	next int // The next datagram of turn.

	closeOnce sync.Once
	closed    chan struct{}
	deadline  deadline
}

var _ quic.GSOPacketConn = (*quicConn)(nil)

func newQUICConn(d *Device, local netip.AddrPort) *quicConn {
	c := &quicConn{d: d, local: local, in: make(chan *quicTurn, quicQueue), closed: make(chan struct{})}
	c.deadline.init()
	return c
}

// reserve takes room in the queue for at most n datagrams. It returns the number it took.
func (c *quicConn) reserve(n int) int {
	for {
		q := c.queued.Load()
		k := min(int64(n), quicQueue-q)
		if k <= 0 {
			return 0
		}
		if c.queued.CompareAndSwap(q, q+k) {
			return int(k)
		}
	}
}

// quicTurn is the QUIC datagrams of one RX turn, in their RX frames. quic-go copies each datagram
// one time, from its frame. quic-go owns the turn from give until read is true.
type quicTurn struct {
	dgs   []datagram
	descs []packetio.Desc // The RX frame of each datagram.
	read  atomic.Bool     // quic-go read all datagrams, and the RX goroutine owns the turn again.
}

// quicTurns is the QUIC turns of one RX goroutine. Only that goroutine uses it.
type quicTurns struct {
	given []*quicTurn // The turns that quic-go has, oldest first. It reads them in this order.
	free  []*quicTurn
	done  []packetio.Desc
}

// next returns an empty turn.
func (s *quicTurns) next() *quicTurn {
	if n := len(s.free); n > 0 {
		t := s.free[n-1]
		s.free = s.free[:n-1]
		return t
	}
	return &quicTurn{}
}

func (s *quicTurns) release(t *quicTurn) {
	t.dgs, t.descs = t.dgs[:0], t.descs[:0]
	t.read.Store(false)
	s.free = append(s.free, t)
}

// give gives the datagrams of t to c, as one item. It never waits. The datagrams that do not fit in
// the queue drop (quic_full), and give appends their frames to free.
func (s *quicTurns) give(c *quicConn, t *quicTurn, free []packetio.Desc) []packetio.Desc {
	k := 0
	if len(t.dgs) > 0 {
		k = c.reserve(len(t.dgs))
	}
	for _, dg := range t.dgs[k:] {
		c.d.p.drop(ReasonQUICFull, len(dg.payload))
	}
	free = append(free, t.descs[k:]...)
	if k == 0 {
		s.release(t)
		return free
	}
	t.dgs, t.descs = t.dgs[:k], t.descs[:k]
	s.given = append(s.given, t)
	// The send does not wait: each turn in c.in has datagrams that reserve counts, at most quicQueue.
	c.in <- t
	return free
}

// read returns the frames of the turns that quic-go read, and takes these turns back.
func (s *quicTurns) read() []packetio.Desc {
	s.done = s.done[:0]
	n := 0
	for ; n < len(s.given) && s.given[n].read.Load(); n++ {
		s.done = append(s.done, s.given[n].descs...)
		s.release(s.given[n])
	}
	if n > 0 {
		s.given = append(s.given[:0], s.given[n:]...)
	}
	return s.done
}

func (c *quicConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, _, err := c.ReadFromECN(b)
	return n, addr, err
}

// ReadFromECN reads a datagram and the ECN bits of its IP header. It takes a turn in one wake, and
// gives its datagrams one by one.
func (c *quicConn) ReadFromECN(b []byte) (int, net.Addr, uint8, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return 0, nil, 0, net.ErrClosed
	default:
	}
	if c.turn == nil {
		select {
		case c.turn = <-c.in:
			c.next = 0
		case <-c.closed:
			return 0, nil, 0, net.ErrClosed
		case <-c.deadline.wait():
			return 0, nil, 0, os.ErrDeadlineExceeded
		}
	}
	dg := c.turn.dgs[c.next]
	n := copy(b, dg.payload)
	c.queued.Add(-1)
	if c.next++; c.next == len(c.turn.dgs) {
		c.turn.read.Store(true)
		c.turn = nil
	}
	return n, net.UDPAddrFromAddrPort(dg.from), dg.ecn, nil
}

func (c *quicConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.WriteToECN(b, addr, 0)
}

// WriteToECN sends a datagram with the ECN bits ecn and DF. With no next-hop MAC, or a full
// transmit ring, it drops the datagram; it never waits.
func (c *quicConn) WriteToECN(b []byte, addr net.Addr, ecn uint8) (int, error) {
	return c.write(b, addr, 0, ecn)
}

// WriteToGSO sends the datagrams of b, each gsoSize bytes except the last, as WriteToECN sends one,
// with one TX send for the batch. It returns len(b) also when it drops datagrams.
func (c *quicConn) WriteToGSO(b []byte, addr net.Addr, gsoSize uint16, ecn uint8) (int, error) {
	return c.write(b, addr, int(gsoSize), ecn)
}

func (c *quicConn) write(b []byte, addr net.Addr, seg int, ecn uint8) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("not a UDP address")
	}
	c.d.sendUDP(portQUIC, ua.AddrPort(), ecn, segments{b: b, seg: seg})
	return len(b), nil
}

func (c *quicConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		// A read that runs now ends before Close returns: the device closes the RX frames after Close.
		c.mu.Lock()
		c.mu.Unlock()
	})
	return nil
}

func (c *quicConn) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(c.local) }

func (c *quicConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *quicConn) SetReadDeadline(t time.Time) error {
	c.deadline.set(t)
	return nil
}

// SetWriteDeadline does nothing: a write never waits.
func (c *quicConn) SetWriteDeadline(time.Time) error { return nil }

// SetReadBuffer and SetWriteBuffer do nothing: the queue sizes are fixed. quic-go calls them.
func (c *quicConn) SetReadBuffer(int) error  { return nil }
func (c *quicConn) SetWriteBuffer(int) error { return nil }

// deadline is a read deadline: wait gives a channel that is closed when the deadline passes.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	passed chan struct{}
}

func (d *deadline) init() { d.passed = make(chan struct{}) }

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		// The timer closed the channel already, or it is about to; start a new one.
		<-d.passed
		d.passed = make(chan struct{})
	}
	d.timer = nil
	select {
	case <-d.passed:
		d.passed = make(chan struct{})
	default:
	}
	if t.IsZero() {
		return
	}
	if dur := time.Until(t); dur > 0 {
		passed := d.passed
		d.timer = time.AfterFunc(dur, func() { close(passed) })
		return
	}
	close(d.passed)
}

func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.passed
}
