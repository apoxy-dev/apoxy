package bifurcate

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
)

// chanPacketConn is one side of a bifurcated conn.
type chanPacketConn struct {
	pc batchpc.BatchPacketConn
	// open is the number of sides that are not closed. The last Close closes pc.
	open *atomic.Int32
	// The batches from the bifurcator goroutine.
	ch       chan []*batchpc.Message
	isClosed atomic.Bool
	closed   chan struct{}
	rd       atomic.Pointer[readDeadline]
	// The batch from the last receive that is not fully read.
	pendingMu    sync.Mutex
	pending      []*batchpc.Message
	pendingIndex int
	// The last temporary error. The next read returns it.
	errMu   sync.Mutex
	lastErr error
}

// readDeadline is the read deadline of one side. changed closes when a new
// deadline replaces it.
type readDeadline struct {
	t       time.Time
	changed chan struct{}
}

func newChanPacketConn(pc batchpc.BatchPacketConn, open *atomic.Int32) *chanPacketConn {
	c := &chanPacketConn{
		ch:     make(chan []*batchpc.Message, 1024),
		pc:     pc,
		open:   open,
		closed: make(chan struct{}),
	}
	c.rd.Store(&readDeadline{changed: make(chan struct{})})
	return c
}

func (pc *chanPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		if err := pc.ensurePendingBlocking(); err != nil {
			return 0, nil, err
		}

		// Another reader or a close can empty the pending batch before the pop.
		msg := pc.popOne()
		if msg == nil {
			continue
		}
		defer messagePool.Put(msg)

		n := copy(p, msg.Buf)
		return n, msg.Addr, nil
	}
}

func (pc *chanPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if pc.isClosed.Load() {
		return 0, net.ErrClosed
	}
	return pc.pc.WriteTo(p, addr)
}

func (pc *chanPacketConn) Close() error {
	if !pc.isClosed.CompareAndSwap(false, true) {
		return nil
	}
	close(pc.closed)
	if pc.open.Add(-1) == 0 {
		return pc.pc.Close()
	}
	return nil
}

func (pc *chanPacketConn) LocalAddr() net.Addr {
	return pc.pc.LocalAddr()
}

func (pc *chanPacketConn) SetDeadline(t time.Time) error {
	_ = pc.SetReadDeadline(t)
	return pc.pc.SetWriteDeadline(t)
}

// SetReadDeadline sets the read deadline of this side only. A read that waits
// gets the new deadline.
func (pc *chanPacketConn) SetReadDeadline(t time.Time) error {
	close(pc.rd.Swap(&readDeadline{t: t, changed: make(chan struct{})}).changed)
	return nil
}

func (pc *chanPacketConn) SetWriteDeadline(t time.Time) error {
	return pc.pc.SetWriteDeadline(t)
}

func (pc *chanPacketConn) ReadBatch(msgs []batchpc.Message, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}

	n := 0
	// Wait for one packet.
	if err := pc.ensurePendingBlocking(); err != nil {
		return 0, err
	}

	fill := func() {
		for n < len(msgs) {
			msg := pc.popOne()
			if msg == nil {
				break
			}
			copied := copy(msgs[n].Buf, msg.Buf)
			msgs[n].Buf = msgs[n].Buf[:copied]
			msgs[n].Addr = msg.Addr
			messagePool.Put(msg)
			n++
		}
	}

	fill()

	// Then read the batches that are ready, without a wait.
	for n < len(msgs) {
		if !pc.tryFillPendingNonBlocking() {
			break
		}
		fill()
	}

	return n, nil
}

func (pc *chanPacketConn) WriteBatch(msgs []batchpc.Message, flags int) (int, error) {
	if pc.isClosed.Load() {
		return 0, net.ErrClosed
	}
	return pc.pc.WriteBatch(msgs, flags)
}

// pendingLenLocked returns len(pending). The caller holds pendingMu.
func (pc *chanPacketConn) pendingLenLocked() int {
	return len(pc.pending)
}

// setPendingLocked sets the pending batch. The caller holds pendingMu.
func (pc *chanPacketConn) setPendingLocked(batch []*batchpc.Message) {
	pc.pending = batch
	pc.pendingIndex = 0
}

// popOne removes one message from pending. It returns nil if pending is empty.
func (pc *chanPacketConn) popOne() *batchpc.Message {
	pc.pendingMu.Lock()
	defer pc.pendingMu.Unlock()

	if len(pc.pending) == 0 {
		return nil
	}

	m := pc.pending[pc.pendingIndex]
	pc.pendingIndex++
	if pc.pendingIndex >= len(pc.pending) {
		pc.pending = nil
		pc.pendingIndex = 0
	}
	return m
}

// ensurePendingBlocking waits until pending has a message. It returns a
// temporary error first.
func (pc *chanPacketConn) ensurePendingBlocking() error {
	for {
		rd := pc.rd.Load()
		if !rd.t.IsZero() && !time.Now().Before(rd.t) {
			return os.ErrDeadlineExceeded
		}

		pc.pendingMu.Lock()
		if pc.pendingLenLocked() > 0 {
			pc.pendingMu.Unlock()
			return nil
		}
		pc.pendingMu.Unlock()

		if err := pc.takeErr(); err != nil {
			return err
		}
		if done, err := pc.waitBatch(rd); done {
			return err
		}
	}
}

// waitBatch waits for a batch until the side closes or the deadline rd ends.
// It returns false when a new deadline replaces rd.
func (pc *chanPacketConn) waitBatch(rd *readDeadline) (bool, error) {
	// A batch that is ready does not need the timer and the full select.
	select {
	case batch, ok := <-pc.ch:
		return true, pc.setBatch(batch, ok)
	default:
	}
	var expired <-chan time.Time
	if !rd.t.IsZero() {
		timer := time.NewTimer(time.Until(rd.t))
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case batch, ok := <-pc.ch:
		return true, pc.setBatch(batch, ok)
	case <-pc.closed:
		return true, net.ErrClosed
	case <-expired:
		return true, os.ErrDeadlineExceeded
	case <-rd.changed:
		return false, nil
	}
}

// setBatch makes batch the pending batch. ok is false when ch is closed.
func (pc *chanPacketConn) setBatch(batch []*batchpc.Message, ok bool) error {
	if !ok {
		return net.ErrClosed
	}
	pc.pendingMu.Lock()
	pc.setPendingLocked(batch)
	pc.pendingMu.Unlock()
	return nil
}

// tryFillPendingNonBlocking gets a batch that is ready into pending, without a
// wait. It returns true if pending has data.
func (pc *chanPacketConn) tryFillPendingNonBlocking() bool {
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

// setErr keeps a temporary error for the next read.
func (pc *chanPacketConn) setErr(err error) {
	if err == nil {
		return
	}
	pc.errMu.Lock()
	pc.lastErr = err
	pc.errMu.Unlock()
}

// takeErr returns and clears the temporary error. It returns nil if there is none.
func (pc *chanPacketConn) takeErr() error {
	pc.errMu.Lock()
	defer pc.errMu.Unlock()
	err := pc.lastErr
	pc.lastErr = nil
	return err
}
