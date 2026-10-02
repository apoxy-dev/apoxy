// SPDX-License-Identifier: AGPL-3.0-only

// Package peerconn has the frames of the QUIC datagrams on agent sessions. Conn
// carries peer sessions in them and carries data frames on the shards of a
// relay session.
package peerconn

import (
	"context"
	"errors"
	"hash/maphash"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/flow"
)

const (
	// queueLen is the number of received packets that wait for ReadFrom.
	queueLen = 1024
	// MaxShards is the most QUIC connections that carry the data of one
	// relay session. Shard 0 is the session connection.
	MaxShards = 4
)

var (
	// ErrAddr is the error for a WriteTo address that is not an overlay IP.
	ErrAddr = errors.New("peerconn: address is not a *net.UDPAddr with an IP")
	// ErrShard is the error for a shard index that is not from 1 to MaxShards-1.
	ErrShard = errors.New("peerconn: shard index is not from 1 to MaxShards-1")
)

// Conn is a net.PacketConn whose addresses are overlay IPs with port 0. Its
// data frames go on the shards of the relay session, one shard for each flow.
type Conn struct {
	src   netip.Addr
	laddr *net.UDPAddr
	rq    chan rxPkt
	done  chan struct{}
	rd    *deadline
	wd    *deadline
	sess  atomic.Pointer[session]
	bufs  sync.Pool

	mu     sync.Mutex // Guards closed, stops and session and shard changes.
	closed bool
	stops  [MaxShards]context.CancelFunc // Stop the readers of shards 1 and up.

	seed   maphash.Seed
	shards atomic.Pointer[shardTable]
	data   atomic.Pointer[func([]byte)]

	readDrops, writeDrops, otherDrops atomic.Uint64
}

type session struct {
	qc   quic.Connection
	stop context.CancelFunc
}

// shardTable is the shards of a session. It does not change after Conn
// publishes it.
type shardTable struct {
	conns [MaxShards]quic.Connection // Nil for a shard that is down.
	n     int                        // 1 + the highest shard set since SetConn.
	live  []quic.Connection
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

// New returns a Conn on the relay session qc. src is the local overlay
// address. qc must have datagrams on.
func New(qc quic.Connection, src netip.Addr) *Conn {
	src = src.Unmap()
	c := &Conn{
		src:   src,
		laddr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(src, 0)),
		rq:    make(chan rxPkt, queueLen),
		done:  make(chan struct{}),
		rd:    newDeadline(),
		wd:    newDeadline(),
		seed:  maphash.MakeSeed(),
	}
	c.bufs.New = func() any { return new([]byte) }
	c.SetConn(qc)
	return c
}

// SetConn moves c to a new relay session, for example after a reconnect.
// Peer sessions on c continue if they do not time out first. The shards of
// the old session stop.
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
	c.stopShards()
	c.publish(shardTable{conns: [MaxShards]quic.Connection{qc}, n: 1})
	go c.receive(ctx, qc)
}

// SetShard makes qc shard i of the relay session, or removes shard i if qc
// is nil. When a shard closes, the flows on it move to the other shards.
func (c *Conn) SetShard(i int, qc quic.Connection) error {
	if i < 1 || i >= MaxShards {
		return ErrShard
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if stop := c.stops[i]; stop != nil {
		stop()
		c.stops[i] = nil
	}
	t := *c.shards.Load()
	t.conns[i] = qc
	if qc != nil {
		t.n = max(t.n, i+1)
		ctx, stop := context.WithCancel(context.Background())
		c.stops[i] = stop
		go func() {
			c.receive(ctx, qc)
			c.shardDown(i, qc)
		}()
	}
	c.publish(t)
	return nil
}

// shardDown removes shard i if it is still qc.
func (c *Conn) shardDown(i int, qc quic.Connection) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := *c.shards.Load()
	if t.conns[i] != qc {
		return
	}
	t.conns[i] = nil
	c.publish(t)
}

// stopShards stops the readers of shards 1 and up. c.mu must be held.
func (c *Conn) stopShards() {
	for i, stop := range c.stops {
		if stop != nil {
			stop()
			c.stops[i] = nil
		}
	}
}

// publish makes t the shard table. c.mu must be held.
func (c *Conn) publish(t shardTable) {
	t.live = nil
	for _, qc := range t.conns[:t.n] {
		if qc != nil {
			t.live = append(t.live, qc)
		}
	}
	c.shards.Store(&t)
}

// SendData sends a data frame on the shard of its flow. A flow whose shard is
// down goes to another shard. SendDatagram copies the frame.
func (c *Conn) SendData(frame []byte) error {
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	t := c.shards.Load()
	var h uint64
	if len(frame) > DataLen {
		h = flow.Hash(c.seed, frame[DataLen:])
	}
	n := uint64(t.n)
	qc := t.conns[h%n]
	if qc == nil {
		qc = t.live[(h/n)%uint64(len(t.live))]
	}
	return qc.SendDatagram(frame)
}

// Shards returns the number of live shards, with the session.
func (c *Conn) Shards() int { return len(c.shards.Load().live) }

// HandleData gives the data frames of the relay session to h. h runs on the
// reader goroutine of each shard, so calls can run at the same time. h must
// not block, and it owns the frame. Nil stops it.
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
	c.stopShards()
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
