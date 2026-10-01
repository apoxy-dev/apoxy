// SPDX-License-Identifier: AGPL-3.0-only

// Package peerconn has the frames of the QUIC datagrams on agent sessions. Conn
// carries peer sessions in them and gives data frames to a handler.
package peerconn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// queueLen is the number of received packets that wait for ReadFrom.
const queueLen = 1024

// ErrAddr is the error for a WriteTo address that is not an overlay IP.
var ErrAddr = errors.New("peerconn: address is not a *net.UDPAddr with an IP")

// Conn is a net.PacketConn whose addresses are overlay IPs with port 0.
type Conn struct {
	src   netip.Addr
	laddr *net.UDPAddr
	rq    chan rxPkt
	done  chan struct{}
	rd    *deadline
	wd    *deadline
	sess  atomic.Pointer[session]
	bufs  sync.Pool

	mu     sync.Mutex // Guards closed and session changes.
	closed bool

	data atomic.Pointer[func([]byte)]

	readDrops, writeDrops, otherDrops atomic.Uint64
}

type session struct {
	qc   quic.Connection
	stop context.CancelFunc
}

type rxPkt struct {
	pkt  []byte
	addr *net.UDPAddr
}

// Stats counts dropped packets.
type Stats struct {
	// ReadDrops are packets from the relay that found the read queue full.
	ReadDrops uint64
	// WriteDrops are packets that the relay session did not take.
	WriteDrops uint64
	// OtherDrops are frames that are not peer frames and that no handler took.
	OtherDrops uint64
}

// New returns a *Conn on the relay session qc. src is the local overlay
// address. qc must have datagrams on.
func New(qc quic.Connection, src netip.Addr) net.PacketConn {
	src = src.Unmap()
	c := &Conn{
		src:   src,
		laddr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(src, 0)),
		rq:    make(chan rxPkt, queueLen),
		done:  make(chan struct{}),
		rd:    newDeadline(),
		wd:    newDeadline(),
	}
	c.bufs.New = func() any { return new([]byte) }
	c.SetConn(qc)
	return c
}

// SetConn moves c to a new relay session, for example after a reconnect.
// Peer sessions on c continue if they do not time out first.
func (c *Conn) SetConn(qc quic.Connection) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	ctx, stop := context.WithCancel(context.Background())
	if old := c.sess.Swap(&session{qc: qc, stop: stop}); old != nil {
		old.stop()
	}
	go c.receive(ctx, qc)
}

// HandleData gives the data frames of the relay session to h. h runs on the
// reader goroutine and must not block. It owns the frame. Nil stops it.
func (c *Conn) HandleData(h func(frame []byte)) {
	if h == nil {
		c.data.Store(nil)
		return
	}
	c.data.Store(&h)
}

// receive reads the frames of qc until ctx ends or qc closes. Peer frames go
// to the read queue, and data frames to the data handler.
func (c *Conn) receive(ctx context.Context, qc quic.Connection) {
	var src netip.Addr
	var addr *net.UDPAddr
	for {
		b, err := qc.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(b) > 0 && b[0] == TypeData {
			if h := c.data.Load(); h != nil {
				(*h)(b)
				continue
			}
		}
		s, pkt, err := DecodeFromRelay(b)
		if err != nil {
			c.otherDrops.Add(1)
			continue
		}
		if addr == nil || s != src {
			// Peer sessions use one address for a long time, so keep it.
			src, addr = s, net.UDPAddrFromAddrPort(netip.AddrPortFrom(s, 0))
		}
		select {
		case c.rq <- rxPkt{pkt: pkt, addr: addr}:
		default:
			c.readDrops.Add(1)
		}
	}
}

// ReadFrom returns the next packet from the relay. Callers must not change
// the returned address.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-c.rd.wait():
		return 0, nil, os.ErrDeadlineExceeded
	default:
	}
	select {
	case r := <-c.rq:
		return copy(p, r.pkt), r.addr, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-c.rd.wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

// WriteTo sends p to the peer at addr. It drops p with no error if the relay
// session does not take it, because quic-go closes on write errors.
func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	case <-c.wd.wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, ErrAddr
	}
	dst, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return 0, ErrAddr
	}
	bp := c.bufs.Get().(*[]byte)
	*bp = EncodeToRelay((*bp)[:0], dst, c.src, p)
	// SendDatagram copies the frame.
	if err := c.sess.Load().qc.SendDatagram(*bp); err != nil {
		c.writeDrops.Add(1)
	}
	c.bufs.Put(bp)
	return len(p), nil
}

// Close ends ReadFrom and WriteTo. It does not close the relay session.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.closed = true
	close(c.done)
	c.sess.Load().stop()
	return nil
}

func (c *Conn) LocalAddr() net.Addr { return c.laddr }

func (c *Conn) SetDeadline(t time.Time) error {
	c.rd.set(t)
	c.wd.set(t)
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.rd.set(t)
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.wd.set(t)
	return nil
}

// SetReadBuffer and SetWriteBuffer do nothing. With them, quic-go does not
// log a warning about the socket buffer size.
func (c *Conn) SetReadBuffer(int) error  { return nil }
func (c *Conn) SetWriteBuffer(int) error { return nil }

// Stats returns the drop counters.
func (c *Conn) Stats() Stats {
	return Stats{ReadDrops: c.readDrops.Load(), WriteDrops: c.writeDrops.Load(), OtherDrops: c.otherDrops.Load()}
}
