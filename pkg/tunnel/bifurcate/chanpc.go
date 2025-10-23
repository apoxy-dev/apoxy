package bifurcate

import (
	"net"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
)

type chanPacketConn struct {
	pc batchpc.BatchPacketConn
	// Incoming batches from the bifurcator goroutine.
	ch     chan []*batchpc.Message
	closed chan struct{}
	// Locally pending batch from the last receive (not yet fully consumed).
	pending      []*batchpc.Message
	pendingIndex int
}

func newChanPacketConn(pc batchpc.BatchPacketConn) *chanPacketConn {
	return &chanPacketConn{
		ch:     make(chan []*batchpc.Message, 1024),
		pc:     pc,
		closed: make(chan struct{}),
	}
}

func (pc *chanPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if err := pc.ensurePendingBlocking(); err != nil {
		return 0, nil, err
	}
	msg := pc.popOne()
	defer messagePool.Put(msg)

	n := copy(p, msg.Buf)
	return n, msg.Addr, nil
}

func (pc *chanPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return pc.pc.WriteTo(p, addr)
}

func (pc *chanPacketConn) Close() error {
	select {
	case <-pc.closed:
		return nil
	default:
		close(pc.closed)
		return nil
	}
}

func (pc *chanPacketConn) LocalAddr() net.Addr {
	return pc.pc.LocalAddr()
}

func (pc *chanPacketConn) SetDeadline(t time.Time) error {
	return pc.pc.SetDeadline(t)
}

func (pc *chanPacketConn) SetReadDeadline(t time.Time) error {
	return pc.pc.SetReadDeadline(t)
}

func (pc *chanPacketConn) SetWriteDeadline(t time.Time) error {
	return pc.pc.SetWriteDeadline(t)
}

func (pc *chanPacketConn) ReadBatch(msgs []batchpc.Message, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}

	n := 0
	// 1) Ensure at least one packet (blocking once).
	if err := pc.ensurePendingBlocking(); err != nil {
		return 0, err
	}

	// 2) Fill from pending, then non-blocking drain of further batches.
	fill := func() {
		for n < len(msgs) && len(pc.pending) > 0 {
			msg := pc.popOne()
			copied := copy(msgs[n].Buf, msg.Buf)
			msgs[n].Buf = msgs[n].Buf[:copied]
			msgs[n].Addr = msg.Addr
			messagePool.Put(msg)
			n++
		}
	}

	fill() // consume current pending

	for n < len(msgs) {
		if !pc.tryFillPendingNonBlocking() {
			break
		}
		fill()
	}

	return n, nil
}

func (pc *chanPacketConn) WriteBatch(msgs []batchpc.Message, flags int) (int, error) {
	return pc.pc.WriteBatch(msgs, flags)
}

// popOne pulls one message from pending; assumes pending not empty.
func (pc *chanPacketConn) popOne() *batchpc.Message {
	m := pc.pending[pc.pendingIndex]
	pc.pendingIndex++
	if pc.pendingIndex >= len(pc.pending) {
		// batch fully consumed
		pc.pending = nil
		pc.pendingIndex = 0
	}
	return m
}

func (pc *chanPacketConn) ensurePendingBlocking() error {
	if len(pc.pending) > 0 {
		return nil
	}
	select {
	case batch := <-pc.ch:
		pc.pending = batch
		pc.pendingIndex = 0
		return nil
	case <-pc.closed:
		return net.ErrClosed
	}
}

func (pc *chanPacketConn) tryFillPendingNonBlocking() bool {
	if len(pc.pending) > 0 {
		return true
	}
	select {
	case batch := <-pc.ch:
		pc.pending = batch
		pc.pendingIndex = 0
		return true
	default:
		return false
	}
}
