// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/vtep/netstack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests of this file use the lane senders and their queues. A driver has
// them only with a batch send, which only Linux has.

// TestSendLanesClose closes a binding whose lane 1 has a sender. The sender
// stops and the lane socket closes.
func TestSendLanesClose(t *testing.T) {
	for _, kept := range []bool{false, true} {
		t.Run(fmt.Sprintf("kept=%t", kept), func(t *testing.T) {
			a, b := newPairLanes(t, 0, 2)
			offer(t, time.Now(), a, b)
			frames := make([][]byte, 16)
			for i := range frames {
				frames[i] = seal(a, packet(a.v4, b.v4, 17, uint16(1000+i), 9, 200))
			}
			d := fakeDriver(a.b, nil)
			w1, _, err := write(d, frames, kept)
			require.NoError(t, err)
			l, c := d.lanes[1], a.b.laneConn(1)
			require.NotNil(t, l, "16 flows use lane 1")
			require.NoError(t, a.b.Close())
			select {
			case <-l.exited:
			case <-time.After(5 * time.Second):
				t.Fatal("the lane sender did not stop")
			}
			w2, _, err := write(d, frames, kept)
			assert.ErrorIs(t, err, net.ErrClosed)
			_, err = c.WriteToUDPAddrPort([]byte{1}, addrOf(b.tr))
			assert.ErrorIs(t, err, net.ErrClosed)
			allReleased(t, w1, w2)
		})
	}
}

// TestLaneQueue fills the queue of lane 1, which has no sender. The driver
// waits and does not drop, lane 2 sends its frame, and a close ends the wait.
// After the end, the driver keeps no frame.
func TestLaneQueue(t *testing.T) {
	cases := []struct {
		name string
		// end ends the wait. Nil takes one batch from the queue of lane 1.
		end func(d *driver, n *node, l *laneSender)
		err error
		// stopped runs the sender of lane 1 after the end. It must return at once.
		stopped bool
	}{
		{name: "the lane has space again"},
		{"the driver closes", func(d *driver, _ *node, _ *laneSender) { _ = d.Close() }, net.ErrClosed, true},
		{"the binding closes", func(_ *driver, n *node, _ *laneSender) { _ = n.b.Close() }, net.ErrClosed, true},
		// A sender that stops closes exited and then drops its queue.
		{"the lane sender stops", func(_ *driver, _ *node, l *laneSender) { close(l.exited); l.drain() }, net.ErrClosed, false},
	}
	for _, tc := range cases {
		for _, kept := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/kept=%t", tc.name, kept), func(t *testing.T) {
				a, b := newPairLanes(t, 0, 3)
				offer(t, time.Now(), a, b)
				sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				require.NoError(t, err)
				defer sink.Close()
				a.peer.SetAddr(sink.LocalAddr().(*net.UDPAddr).AddrPort())
				flows := laneFlows(t, a, 3)
				frame := func(lane int) []byte { return seal(a, packet(a.v4, b.v4, 17, flows[lane], 9, 100)) }
				buf := make([]byte, 2048)
				read := func(want []byte) {
					t.Helper()
					require.NoError(t, sink.SetReadDeadline(time.Now().Add(5*time.Second)))
					m, err := sink.Read(buf)
					require.NoError(t, err)
					require.Equal(t, want[addrLen:], buf[:m])
				}

				// A frame of lane 2 starts the senders of lanes 0 and 2.
				d := fakeDriver(a.b, nil)
				defer d.Close()
				first := frame(2)
				w, _, err := write(d, [][]byte{first}, kept)
				require.NoError(t, err)
				writes := []*keptWrite{w}
				read(first)
				l := d.newLane(1, nil)
				d.lanes[1] = l
				var want [][]byte
				take := func() {
					t.Helper()
					select {
					case q := <-l.work:
						require.LessOrEqual(t, len(q.frames), len(want))
						for i, f := range q.frames {
							require.Equal(t, want[i], f, "frame %d", i)
						}
						want = want[len(q.frames):]
						q.done()
						l.free <- q
					case <-time.After(5 * time.Second):
						t.Fatal("no batch for lane 1")
					}
				}

				for range laneBatches {
					full := make([][]byte, laneFrames)
					for i := range full {
						full[i] = frame(1)
					}
					want = append(want, full...)
					w, n, err := write(d, full, kept)
					require.NoError(t, err)
					require.Equal(t, laneFrames, n)
					writes = append(writes, w)
				}
				// The queue of lane 1 is full, so the frame of lane 1 waits.
				last := [][]byte{frame(2), frame(1), frame(2)}
				want = append(want, last[1])
				type result struct {
					w   *keptWrite
					n   int
					err error
				}
				done := make(chan result, 1)
				go func() {
					w, n, err := write(d, last, kept)
					done <- result{w, n, err}
				}()
				read(last[0])
				select {
				case r := <-done:
					t.Fatalf("the driver did not wait: %+v", r)
				case <-time.After(20 * time.Millisecond):
				}

				if tc.end == nil {
					take()
				} else {
					tc.end(d, a, l)
				}
				var r result
				select {
				case r = <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("the driver waits after the end")
				}
				writes = append(writes, r.w)
				if tc.err != nil {
					assert.ErrorIs(t, r.err, tc.err)
					assert.Zero(t, r.n)
				} else {
					require.NoError(t, r.err)
					assert.Equal(t, len(last), r.n)
					read(last[2])
					for len(want) > 0 {
						take()
					}
					assert.Zero(t, a.b.Stats().TxDrops)
				}
				if tc.stopped {
					l.run(d.done)
				}
				if tc.err != nil {
					// The sender counts the frames of its queue as drops.
					assert.Equal(t, uint64(laneBatches*laneFrames), a.b.Stats().TxDrops)
				}
				d.lanes[1] = nil // It has no goroutine.
				exits(t, d)
				allReleased(t, writes...)
			})
		}
	}
}

// TestLaneStopped gives frames to a lane whose sender stopped. The driver
// drops the frames, counts them and keeps none.
func TestLaneStopped(t *testing.T) {
	for _, kept := range []bool{false, true} {
		t.Run(fmt.Sprintf("kept=%t", kept), func(t *testing.T) {
			a, b := newPairLanes(t, 0, 3)
			offer(t, time.Now(), a, b)
			flows := laneFlows(t, a, 3)
			frame := func(lane int) []byte { return seal(a, packet(a.v4, b.v4, 17, flows[lane], 9, 100)) }
			d := fakeDriver(a.b, nil)
			defer d.Close()
			for i := range 3 {
				d.lanes[i] = d.newLane(i, nil)
			}
			l := d.lanes[1]
			close(l.exited)

			// The driver filled a batch before the sender stopped, and gives it after.
			var writes []*keptWrite
			w := &keptWrite{frames: [][]byte{frame(1), frame(1)}}
			w.k = netstack.NewKept(func() { w.freed.Add(1) })
			l.cur = <-l.free
			l.cur.frames = append(l.cur.frames, w.frames...)
			if kept {
				w.k.Keep()
				l.cur.kept = w.k
				writes = append(writes, w)
			}
			l.give()
			assert.Nil(t, l.cur)
			assert.Empty(t, l.work)
			assert.Equal(t, uint64(2), a.b.Stats().TxDrops)

			// A write finds a free batch, or it finds that the sender stopped.
			for i := range 20 {
				before := a.b.Stats().TxDrops
				w, n, err := write(d, [][]byte{frame(2), frame(1), frame(2)}, kept)
				writes = append(writes, w)
				if err != nil {
					require.ErrorIs(t, err, net.ErrClosed, "write %d", i)
					assert.Zero(t, n)
					// The frame of lane 2 that no sender got.
					assert.Equal(t, before+1, a.b.Stats().TxDrops, "write %d", i)
					assert.Empty(t, d.lanes[2].work)
					continue
				}
				assert.Equal(t, 3, n)
				assert.Equal(t, before+1, a.b.Stats().TxDrops, "write %d", i)
				assert.Empty(t, l.work)
				// Lane 2 has no goroutine, so the test is its sender.
				q := <-d.lanes[2].work
				assert.Len(t, q.frames, 2)
				q.done()
				d.lanes[2].free <- q
			}
			allReleased(t, writes...)
		})
	}
}

// TestWriteNoAllocs gives the frames of one set to the queues of 4 lanes, and
// takes the batches as the senders do. The driver must not allocate, with
// frames that it copies and with frames that it keeps.
func TestWriteNoAllocs(t *testing.T) {
	const lanes = 4
	a, b := newPairLanes(t, 0, lanes)
	offer(t, time.Now(), a, b)
	flows := laneFlows(t, a, lanes)
	frames := make([][]byte, laneFrames)
	for i := range frames {
		// The flows of laneFlows, so that frame i is on lane i%lanes.
		frames[i] = seal(a, packet(a.v4, b.v4, 17, flows[i%lanes], 9, DefaultMTU))
	}
	for _, kept := range []bool{false, true} {
		t.Run(fmt.Sprintf("kept=%t", kept), func(t *testing.T) {
			d := fakeDriver(a.b, nil)
			defer d.Close()
			// The lanes have no goroutine, so the test is their sender.
			for i := range lanes {
				d.lanes[i] = d.newLane(i, nil)
			}
			freed := 0
			k := netstack.NewKept(func() { freed++ })
			run := func() {
				k.Keep()
				var err error
				if kept {
					_, err = d.WriteKept(frames, k)
				} else {
					_, err = d.WriteFrames(frames)
				}
				k.Release()
				if err != nil {
					t.Fatal(err)
				}
				for _, l := range d.lanes[:lanes] {
					q := <-l.work
					if len(q.frames) != laneFrames/lanes || kept != (q.kept == k) || kept != (&q.frames[0][0] == &frames[l.lane][0]) {
						t.Fatalf("lane %d: %d frames, kept %t", l.lane, len(q.frames), q.kept == k)
					}
					q.done()
					l.free <- q
				}
			}
			// Each batch makes its buffer at the first frame that it copies.
			for range laneBatches {
				run()
			}
			freed = 0
			assert.Zero(t, testing.AllocsPerRun(100, run))
			// The frames had no user left after each run.
			assert.Equal(t, 101, freed)
			for _, l := range d.lanes[:lanes] {
				for range laneBatches {
					assert.Equal(t, kept, (<-l.free).buf == nil, "lane %d: a batch has a buffer only for copies", l.lane)
				}
			}
		})
	}
}
