package bifurcate

import (
	"net"
	"sync"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
)

type chanPacketConn struct {
	pc            batchpc.BatchPacketConn
	closeConnOnce *sync.Once
	// Incoming batches from the bifurcator goroutine.
	ch         chan []*batchpc.Message
	closedOnce sync.Once
	closed     chan struct{}
	// Locally pending batch from the last receive (not yet fully consumed).
	pendingMu    sync.Mutex
	pending      []*batchpc.Message
	pendingIndex int
	// Last transient error to be surfaced on next Read/ReadBatch.
	errMu   sync.Mutex
	lastErr error
}

func newChanPacketConn(pc batchpc.BatchPacketConn, closeConnOnce *sync.Once) *chanPacketConn {
	return &chanPacketConn{
		ch:            make(chan []*batchpc.Message, 1024),
		pc:            pc,
		closeConnOnce: closeConnOnce,
		closed:        make(chan struct{}),
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
	pc.closedOnce.Do(func() {
		close(pc.closed)
	})

	var err error
	pc.closeConnOnce.Do(func() {
		err = pc.pc.Close()
	})
	return err
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

	fill := func() {
		for n < len(msgs) {
			msg := pc.popOne()
			if msg == nil {
				// nothing pending anymore
				break
			}
			copied := copy(msgs[n].Buf, msg.Buf)
			msgs[n].Buf = msgs[n].Buf[:copied]
			msgs[n].Addr = msg.Addr
			messagePool.Put(msg)
			n++
		}
	}

	// consume current pending
	fill()

	// 2) Then non-blocking drain of further batches.
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

// pendingLenLocked returns len(pending). pendingMu MUST be held by caller.
func (pc *chanPacketConn) pendingLenLocked() int {
	return len(pc.pending)
}

// setPendingLocked sets the pending batch + resets index. pendingMu MUST be held.
func (pc *chanPacketConn) setPendingLocked(batch []*batchpc.Message) {
	pc.pending = batch
	pc.pendingIndex = 0
}

// popOne pulls one message from pending.
// Returns nil if pending is empty.
// Takes the lock internally.
func (pc *chanPacketConn) popOne() *batchpc.Message {
	pc.pendingMu.Lock()
	defer pc.pendingMu.Unlock()

	if len(pc.pending) == 0 {
		return nil
	}

	m := pc.pending[pc.pendingIndex]
	pc.pendingIndex++
	if pc.pendingIndex >= len(pc.pending) {
		// batch fully consumed
		pc.pending = nil
		pc.pendingIndex = 0
	}
	return m
}

// ensurePendingBlocking guarantees there's at least one message in pending,
// blocking on pc.ch if needed. Surfaces transient errors first.
func (pc *chanPacketConn) ensurePendingBlocking() error {
	// Fast path: already have pending locally.
	pc.pendingMu.Lock()
	if pc.pendingLenLocked() > 0 {
		pc.pendingMu.Unlock()
		return nil
	}
	pc.pendingMu.Unlock()

	// Check if there's a transient error waiting to be reported.
	if err := pc.takeErr(); err != nil {
		return err
	}

	select {
	case batch, ok := <-pc.ch:
		if !ok {
			// ch closed -> treat as connection closed
			return net.ErrClosed
		}
		pc.pendingMu.Lock()
		pc.setPendingLocked(batch)
		pc.pendingMu.Unlock()
		return nil
	case <-pc.closed:
		return net.ErrClosed
	}
}

// tryFillPendingNonBlocking tries to pull a new batch into pending without blocking.
// Returns true if pending now has data.
func (pc *chanPacketConn) tryFillPendingNonBlocking() bool {
	// Check fast path first.
	pc.pendingMu.Lock()
	if pc.pendingLenLocked() > 0 {
		pc.pendingMu.Unlock()
		return true
	}
	pc.pendingMu.Unlock()

	select {
	case batch, ok := <-pc.ch:
		if !ok {
			return false
		}
		pc.pendingMu.Lock()
		pc.setPendingLocked(batch)
		hasData := pc.pendingLenLocked() > 0
		pc.pendingMu.Unlock()
		return hasData
	default:
		return false
	}
}

// setErr records a transient error to be surfaced on the next Read/ReadBatch call.
func (pc *chanPacketConn) setErr(err error) {
	if err == nil {
		return
	}
	pc.errMu.Lock()
	pc.lastErr = err
	pc.errMu.Unlock()
}

// takeErr returns (and clears) the currently stored transient error.
// If there's no pending transient error it returns nil.
func (pc *chanPacketConn) takeErr() error {
	pc.errMu.Lock()
	defer pc.errMu.Unlock()
	err := pc.lastErr
	pc.lastErr = nil
	return err
}
