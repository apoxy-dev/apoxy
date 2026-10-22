// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// quicQueue is how many received datagrams wait for quic-go. A full queue drops the datagram
// (quic_full).
const quicQueue = 1024

// quicConn is the UDP 443 socket of the relay on the dedicated interface. quic-go reads and
// writes the ECN bits of the IP header through ReadFromECN and WriteToECN; each packet has DF.
type quicConn struct {
	d     *Device
	local netip.AddrPort
	in    chan *inDatagram
	pool  sync.Pool

	closeOnce sync.Once
	closed    chan struct{}
	deadline  deadline
}

var _ quic.ECNPacketConn = (*quicConn)(nil)

type inDatagram struct {
	buf  []byte
	n    int
	from netip.AddrPort
	ecn  uint8
}

func newQUICConn(d *Device, local netip.AddrPort, size int) *quicConn {
	c := &quicConn{d: d, local: local, in: make(chan *inDatagram, quicQueue), closed: make(chan struct{})}
	c.pool.New = func() any { return &inDatagram{buf: make([]byte, size)} }
	c.deadline.init()
	return c
}

// deliver queues a received datagram. It copies the payload and never waits.
func (c *quicConn) deliver(dg datagram) {
	in := c.pool.Get().(*inDatagram)
	if len(dg.payload) > len(in.buf) {
		c.pool.Put(in)
		return
	}
	in.n, in.from, in.ecn = copy(in.buf, dg.payload), dg.from, dg.ecn
	select {
	case c.in <- in:
	default:
		c.pool.Put(in)
		c.d.p.drop(ReasonQUICFull, len(dg.payload))
	}
}

func (c *quicConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, _, err := c.ReadFromECN(b)
	return n, addr, err
}

// ReadFromECN reads a datagram and the ECN bits of its IP header.
func (c *quicConn) ReadFromECN(b []byte) (int, net.Addr, uint8, error) {
	select {
	case <-c.closed:
		return 0, nil, 0, net.ErrClosed
	default:
	}
	select {
	case in := <-c.in:
		n := copy(b, in.buf[:in.n])
		from, ecn := in.from, in.ecn
		c.pool.Put(in)
		return n, net.UDPAddrFromAddrPort(from), ecn, nil
	case <-c.closed:
		return 0, nil, 0, net.ErrClosed
	case <-c.deadline.wait():
		return 0, nil, 0, os.ErrDeadlineExceeded
	}
}

func (c *quicConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.WriteToECN(b, addr, 0)
}

// WriteToECN sends a datagram with the ECN bits ecn and DF. With no next-hop MAC, or a full
// transmit ring, it drops the datagram; it never waits.
func (c *quicConn) WriteToECN(b []byte, addr net.Addr, ecn uint8) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("not a UDP address")
	}
	c.d.sendUDP(portQUIC, ua.AddrPort(), ecn, b)
	return len(b), nil
}

func (c *quicConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
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
