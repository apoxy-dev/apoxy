// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"context"
	"encoding/binary"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/atoonk/packetio"
)

// The handoff of the device. The RX goroutine of each queue does the demux and gives the UDP 1000
// packets of each turn up to the worker of their session: one item for each worker in each turn,
// in their RX frames. The worker runs the pipeline on them and sends on its own TX queue. It marks
// each item done, and the RX goroutine takes back the frames of the done items.

const (
	// workerQueue is the most items that wait for one worker. An item that does not fit drops
	// (worker_full).
	workerQueue = 4096
	// frameAllowance is the most RX frames of one RX queue at the workers. An item over it drops
	// (worker_allowance). It holds about 25 ms of one 7 Gbps flow of 1500-byte packets.
	frameAllowance = 16384
	// defaultWorker gets the packets with no SPI in the steering map.
	defaultWorker = 0
)

// The names of the OS threads of the RX goroutines and of the workers, as /proc/PID/task/TID/comm
// shows them.
const (
	RxThread     = "relay-rx"
	WorkerThread = "relay-wk"
)

// workItem is the UDP 1000 packets of one RX turn for one worker, in their RX frames. The worker
// owns the item from the send until done is true.
type workItem struct {
	rx    []RxPacket
	descs []packetio.Desc
	done  atomic.Bool
}

// worker runs the pipeline on the items of its channel, and sends on its own TX queue.
type worker struct {
	idx  int
	in   chan *workItem
	tx   *TxBatch
	cpu  int          // The CPU of the plan, or -1.
	busy atomic.Int64 // Nanoseconds.
}

func newWorker(idx int, t *txQueue) *worker {
	return &worker{idx: idx, in: make(chan *workItem, workerQueue), tx: &TxBatch{txq: t, hops: hopCache{}}, cpu: -1}
}

// rxOut is the items of one RX goroutine at one worker, oldest first. Only the RX goroutine uses
// it. The worker takes the items of one RX goroutine in order, so the done items are at the head.
type rxOut struct {
	given []*workItem
	free  []*workItem
}

func (o *rxOut) next() *workItem {
	if n := len(o.free); n > 0 {
		it := o.free[n-1]
		o.free = o.free[:n-1]
		return it
	}
	return &workItem{}
}

func (o *rxOut) release(it *workItem) {
	clear(it.rx)
	it.rx, it.descs = it.rx[:0], it.descs[:0]
	it.done.Store(false)
	o.free = append(o.free, it)
}

// read appends the frames of the done items at the head to back, and takes these items back. It
// returns back and the number of frames.
func (o *rxOut) read(back []packetio.Desc) ([]packetio.Desc, int) {
	n, frames := 0, 0
	for ; n < len(o.given) && o.given[n].done.Load(); n++ {
		back = append(back, o.given[n].descs...)
		frames += len(o.given[n].descs)
		o.release(o.given[n])
	}
	if n > 0 {
		k := copy(o.given, o.given[n:])
		clear(o.given[k:])
		o.given = o.given[:k]
	}
	return back, frames
}

// rxPending is a UDP 1000 packet of the turn, its frame and its worker.
type rxPending struct {
	pkt  RxPacket
	desc packetio.Desc
	w    int
}

// rxHandoff is the handoff state of one RX goroutine. Only that goroutine uses it.
type rxHandoff struct {
	outs  []rxOut
	items []*workItem // The item of each worker in this turn, or nil.
	pend  []rxPending
	out   int // The frames of this RX queue at the workers.
}

func (d *Device) newRxHandoff() *rxHandoff {
	return &rxHandoff{outs: make([]rxOut, len(d.workers)), items: make([]*workItem, len(d.workers)),
		pend: make([]rxPending, 0, rxBatch)}
}

// reclaim appends the frames of the items that the workers are done with to back.
func (h *rxHandoff) reclaim(back []packetio.Desc) []packetio.Desc {
	for w := range h.outs {
		var n int
		back, n = h.outs[w].read(back)
		h.out -= n
	}
	return back
}

// steer sets the worker of each pending packet from the map sm, and reports whether a packet had
// no SPI in it.
func (d *Device) steer(pend []rxPending, sm *steerMap) (miss bool) {
	for i := range pend {
		w, ok := 0, false
		if b := pend[i].pkt.Payload; sm != nil && len(b) >= 8 {
			w, ok = (*sm)[binary.BigEndian.Uint32(b[4:8])]
		}
		if !ok || w >= len(d.workers) {
			w, miss = defaultWorker, true
		}
		pend[i].w = w
	}
	return miss
}

// handoff gives the pending packets of the turn to their workers, one item for each worker, in
// order. sm is the steering map that the RX goroutine read after it took the frames of the turn.
// Before a packet goes to the default worker, it reads the map again. The frames of a dropped item
// go to free.
func (d *Device) handoff(h *rxHandoff, sm *steerMap, free []packetio.Desc) []packetio.Desc {
	if d.steer(h.pend, sm) {
		if sm2 := d.p.steering.Load(); sm2 != sm {
			d.steer(h.pend, sm2)
		}
	}
	for _, p := range h.pend {
		it := h.items[p.w]
		if it == nil {
			it = h.outs[p.w].next()
			h.items[p.w] = it
		}
		it.rx, it.descs = append(it.rx, p.pkt), append(it.descs, p.desc)
	}
	clear(h.pend)
	h.pend = h.pend[:0]
	for w, it := range h.items {
		if it == nil {
			continue
		}
		h.items[w] = nil
		free = d.give(d.workers[w], &h.outs[w], it, &h.out, free)
	}
	return free
}

// give sends it to w with no wait. An item over the frame allowance of its RX queue, or with no
// room in the channel of w, drops: each packet counts, and the frames go to free.
func (d *Device) give(w *worker, o *rxOut, it *workItem, out *int, free []packetio.Desc) []packetio.Desc {
	reason := ReasonWorkerAllowance
	if *out+len(it.descs) <= frameAllowance {
		select {
		case w.in <- it:
			o.given = append(o.given, it)
			*out += len(it.descs)
			return free
		default:
			reason = ReasonWorkerFull
		}
	}
	for _, p := range it.rx {
		d.p.drop(reason, len(p.Payload))
	}
	free = append(free, it.descs...)
	o.release(it)
	return free
}

// work is the loop of worker w until ctx is done. It takes all items that wait, up to rxBatch
// packets, runs the pipeline on them as one part, and marks them done. The wait for an item is
// idle; the rest of each pass adds to the busy time of w. It returns an error only when it cannot
// pin its thread.
func (d *Device) work(ctx context.Context, w *worker) error {
	runtime.LockOSThread()
	defer nameThread(nameThread(WorkerThread))
	if w.cpu >= 0 {
		if err := pinThread("worker", w.cpu); err != nil {
			return err
		}
	}
	rx := make([]RxPacket, 0, rxBatch)
	items := make([]*workItem, 0, rxBatch)
	var next *workItem // An item that did not fit in the last part.
	for {
		it, start := next, time.Now()
		if it == nil {
			select {
			case <-ctx.Done():
				return nil
			case it = <-w.in:
			}
			start = time.Now()
		}
		items, rx, next = w.part(it, items[:0], rx[:0])
		d.forward(rx, w.tx)
		for _, it := range items {
			it.done.Store(true)
		}
		clear(items)
		clear(rx)
		w.busy.Add(int64(time.Since(start)))
	}
}

// part appends first and the items that wait in w.in, up to rxBatch packets, to items, and their
// packets to rx. It returns the first item that did not fit, or nil.
func (w *worker) part(first *workItem, items []*workItem, rx []RxPacket) ([]*workItem, []RxPacket, *workItem) {
	items, rx = append(items, first), append(rx, first.rx...)
	for len(rx) < rxBatch {
		select {
		case it := <-w.in:
			if len(rx)+len(it.rx) > rxBatch {
				return items, rx, it
			}
			items, rx = append(items, it), append(rx, it.rx...)
		default:
			return items, rx, nil
		}
	}
	return items, rx, nil
}

// forward runs the pipeline on rx, at most rxBatch packets, with one TX frame of tx for each
// packet: the pipeline seals a packet into its frame, and Send sends it there. The frames that no
// packet used go back to the TX queue.
func (d *Device) forward(rx []RxPacket, tx *TxBatch) {
	tx.frames = tx.txq.take(len(rx), tx.frames[:0])
	d.p.Receive(rx, tx)
	if len(tx.frames) > 0 {
		tx.txq.put(tx.frames, 0)
		tx.frames = tx.frames[:0]
	}
}
