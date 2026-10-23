// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/atoonk/packetio"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeTx is a packetio.TxQueue and the kernel side of its rings. A kick sends at most budget
// descriptors from the TX ring. The kernel completes a sent frame at once, or at finish with hold.
type fakeTx struct {
	mu      sync.Mutex
	mem     []byte
	ring    int
	free    []packetio.Desc // The pool.
	txr     []packetio.Desc // On the TX ring.
	held    []packetio.Desc // Sent, and not completed yet.
	cq      []packetio.Desc // On the completion ring.
	wire    [][]byte        // The frames that the kernel sent, in order.
	kicks   int
	budget  func(kick int) int
	kickErr func(kick int) error
	hold    bool
	scratch []packetio.Desc
}

const fakeFrameSize = 64

func newFakeTx(frames, ring int) *fakeTx {
	f := &fakeTx{mem: make([]byte, frames*fakeFrameSize), ring: ring, budget: func(int) int { return 32 }}
	for i := range frames {
		f.free = append(f.free, packetio.Desc{Addr: uint64(i * fakeFrameSize)})
	}
	return f
}

func (f *fakeTx) port() txPort {
	return txPort{publish: f.publish, kick: f.kick, pending: f.pending, counts: f.counts}
}

// counts gives one sendto for each kick, as a socket with no EAGAIN.
func (f *fakeTx) counts() KickCounts {
	f.mu.Lock()
	defer f.mu.Unlock()
	return KickCounts{Sendto: uint64(f.kicks)}
}

func (f *fakeTx) publish(descs []packetio.Desc) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := min(len(descs), f.ring-len(f.txr))
	f.txr = append(f.txr, descs[:k]...)
	return k
}

func (f *fakeTx) kick() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kicks++
	if f.kickErr != nil {
		if err := f.kickErr(f.kicks); err != nil {
			return err
		}
	}
	n := min(f.budget(f.kicks), len(f.txr))
	for _, d := range f.txr[:n] {
		f.wire = append(f.wire, bytes.Clone(f.mem[d.Addr:d.Addr+uint64(d.Len)]))
	}
	if f.hold {
		f.held = append(f.held, f.txr[:n]...)
	} else {
		f.cq = append(f.cq, f.txr[:n]...)
	}
	f.txr = append(f.txr[:0], f.txr[n:]...)
	return nil
}

func (f *fakeTx) pending() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.txr)
}

// finish completes the frames that the kernel sent and holds.
func (f *fakeTx) finish() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cq, f.held = append(f.cq, f.held...), f.held[:0]
}

// sent returns the frames that the kernel sent.
func (f *fakeTx) sent() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wire
}

// frames returns all frames of the queue, wherever they are.
func (f *fakeTx) frames() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.free) + len(f.txr) + len(f.held) + len(f.cq)
}

func (f *fakeTx) Region() packetio.Region { return fakeRegion{f} }

func (f *fakeTx) Alloc(n int) []packetio.Desc {
	f.mu.Lock()
	defer f.mu.Unlock()
	n = min(n, len(f.free), f.ring-len(f.txr))
	f.scratch = append(f.scratch[:0], f.free[len(f.free)-n:]...)
	f.free = f.free[:len(f.free)-n]
	return f.scratch
}

func (f *fakeTx) Transmit(descs []packetio.Desc) int { return f.publish(descs) }
func (f *fakeTx) Err() error                         { return nil }

func (f *fakeTx) Complete(max int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := min(max, len(f.cq))
	f.free = append(f.free, f.cq[:n]...)
	f.cq = append(f.cq[:0], f.cq[n:]...)
	return n
}

func (f *fakeTx) Reclaim(max int, out []packetio.Desc) []packetio.Desc {
	f.Complete(max)
	return out
}

func (f *fakeTx) Free(descs []packetio.Desc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range descs {
		f.free = append(f.free, packetio.Desc{Addr: d.Addr - d.Addr%fakeFrameSize})
	}
}

func (f *fakeTx) NumCompleted() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cq)
}

func (f *fakeTx) NumInFlight() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.txr) + len(f.held) + len(f.cq)
}

func (f *fakeTx) NumFreeSlots() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ring - len(f.txr)
}

func (f *fakeTx) NumFreeFrames() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.free)
}

func (f *fakeTx) SendFunc(int, func(int, []byte) int) (int, error) {
	return 0, errors.New("the fake has no SendFunc")
}

func (f *fakeTx) Stats() (packetio.TxStats, error) { return packetio.TxStats{}, nil }
func (f *fakeTx) Close() error                     { return nil }

type fakeRegion struct{ f *fakeTx }

func (r fakeRegion) Bytes() []byte                { return r.f.mem }
func (r fakeRegion) Frame(d packetio.Desc) []byte { return r.f.mem[d.Addr : d.Addr+uint64(d.Len)] }
func (r fakeRegion) FrameSize() int               { return fakeFrameSize }
func (r fakeRegion) NumFrames() int               { return len(r.f.mem) / fakeFrameSize }
func (r fakeRegion) Writable(d packetio.Desc) []byte {
	return r.f.mem[d.Addr : d.Addr-d.Addr%fakeFrameSize+fakeFrameSize]
}

// numbered returns a build that writes first+i into the frame of packet i.
func numbered(first uint64) func(i int, frame []byte) int {
	return func(i int, frame []byte) int {
		binary.BigEndian.PutUint64(frame, first+uint64(i))
		return 8
	}
}

// TestTxQueueSend sends one packet with an empty pool and frames on the completion ring. The send
// takes back all completed frames, not only one batch.
func TestTxQueueSend(t *testing.T) {
	const frames = 4096
	cases := []struct {
		name      string
		completed int // Frames on the completion ring. The kernel holds the others.
		sent      int
		free      int // Free frames after the send.
	}{
		{name: "no completed frame", completed: 0, sent: 0, free: 0},
		{name: "one batch", completed: 64, sent: 1, free: 63},
		{name: "one more than a batch", completed: 65, sent: 1, free: 64},
		{name: "many batches", completed: 300, sent: 1, free: 299},
		{name: "all frames", completed: frames, sent: 1, free: frames - 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTx(frames, frames)
			f.cq = append([]packetio.Desc(nil), f.free[:tc.completed]...)
			f.held = append([]packetio.Desc(nil), f.free[tc.completed:]...)
			f.free = nil
			q := newTxQueue(f, f.port())
			sent, full := q.send(1, numbered(0))
			assert.Equal(t, tc.sent, sent)
			assert.Equal(t, uint64(1-tc.sent), full, "the packet with no frame is full")
			assert.Zero(t, f.NumCompleted(), "all completed frames are back in the pool")
			assert.Equal(t, tc.free, f.NumFreeFrames())
			assert.Equal(t, frames, f.frames())
		})
	}
}

// TestTxQueueKicker sends one batch and no more. The kicker kicks until the TX ring is empty, also
// when a kick sends only part of the ring, sends nothing, or fails and the queue continues. A kick
// error that ends the queue stops the kicker, and a send after it sends nothing. When the kicker
// stops, its activations are all its kick calls, with the kicks after a backoff and the failed ones.
func TestTxQueueKicker(t *testing.T) {
	cases := []struct {
		name    string
		ring    int
		budget  func(kick int) int
		kickErr func(kick int) error
		err     error // The error of the kicker.
	}{
		{name: "a kick sends 32 descriptors", ring: 4096, budget: func(int) int { return 32 }},
		{name: "a full ring, 16 descriptors for each kick", ring: rxBatch, budget: func(int) int { return 16 }},
		{name: "the first kicks send nothing, as with a full send buffer", ring: 4096, budget: func(k int) int {
			if k <= 5 {
				return 0
			}
			return 32
		}},
		{name: "the first kicks fail with a link that is down", ring: 4096, budget: func(int) int { return 32 }, kickErr: func(k int) error {
			if k <= 3 {
				return syscall.ENETDOWN
			}
			return nil
		}},
		{name: "a closed socket ends the queue", ring: 4096, budget: func(int) int { return 32 },
			kickErr: func(int) error { return net.ErrClosed }, err: net.ErrClosed},
		{name: "an unbound socket ends the queue", ring: 4096, budget: func(int) int { return 32 },
			kickErr: func(int) error { return fmt.Errorf("sendto: %w", syscall.ENXIO) }, err: syscall.ENXIO},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTx(256, tc.ring)
			f.budget, f.kickErr = tc.budget, tc.kickErr
			q := newTxQueue(f, f.port())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			kicked := make(chan error, 1)
			go func() { kicked <- q.kicker(ctx) }()

			sent, full := q.send(rxBatch, numbered(100))
			require.Equal(t, rxBatch, sent)
			require.Zero(t, full)
			if tc.err != nil {
				select {
				case err := <-kicked:
					assert.ErrorIs(t, err, tc.err)
				case <-time.After(2 * time.Second):
					t.Fatal("the kicker did not stop")
				}
				sent, full := q.send(1, numbered(0))
				assert.Zero(t, sent, "a failed queue sends nothing")
				assert.Zero(t, full, "a failed queue counts no tx_full")
				assert.Equal(t, KickCounts{Activations: 1, Sendto: 1}, q.kickCounts())
				return
			}
			require.Eventually(t, func() bool { return len(f.sent()) == rxBatch && f.pending() == 0 },
				2*time.Second, time.Millisecond, "the kicker did not empty the TX ring")
			for i, b := range f.sent() {
				assert.Equal(t, uint64(100+i), binary.BigEndian.Uint64(b), "frame %d", i)
			}
			cancel()
			assert.NoError(t, <-kicked)
			kicks := uint64(f.kicks)
			assert.Equal(t, KickCounts{Activations: kicks, Sendto: kicks}, q.kickCounts())
		})
	}
}

// TestTxQueueWriters runs receive loops that send batches and QUIC writers that send one packet at a
// time, on one queue. Each packet is sent or full, and no frame is lost.
func TestTxQueueWriters(t *testing.T) {
	const frames, ring, loops, quic, turns = 256, 128, 4, 2, 400
	f := newFakeTx(frames, ring)
	f.hold = true
	q := newTxQueue(f, f.port())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	kicked := make(chan error, 1)
	go func() { kicked <- q.kicker(ctx) }()
	// The kernel completes the frames that it sent a short time after the kick.
	kernel := make(chan struct{})
	go func() {
		defer close(kernel)
		for ctx.Err() == nil {
			f.finish()
			time.Sleep(50 * time.Microsecond)
		}
	}()

	var sent, full atomic.Int64
	send := func(n int) {
		s, fl := q.send(n, numbered(0))
		assert.Equal(t, n, s+bits.OnesCount64(fl), "each packet is sent or full")
		sent.Add(int64(s))
		full.Add(int64(bits.OnesCount64(fl)))
	}
	var wg sync.WaitGroup
	for range loops {
		wg.Go(func() {
			for range turns {
				send(rxBatch)
			}
		})
	}
	for range quic {
		wg.Go(func() {
			for range 4 * turns {
				send(1)
			}
		})
	}
	wg.Wait()
	// No send comes after this, so only the kicker empties the TX ring.
	require.Eventually(t, func() bool { return f.pending() == 0 }, 2*time.Second, time.Millisecond)
	cancel()
	<-kernel
	require.NoError(t, <-kicked)
	f.finish()

	assert.Equal(t, int(sent.Load()), len(f.sent()), "the kernel sent each published frame one time")
	assert.Equal(t, frames, f.frames(), "no frame is lost")
	assert.Equal(t, frames, f.NumFreeFrames()+f.NumCompleted(), "the kernel gave back all frames")
	t.Logf("sent %d, full %d", sent.Load(), full.Load())
}
