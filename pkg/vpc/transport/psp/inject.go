// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"hash/maphash"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/flow"
)

const (
	// maxInjectWorkers is the most inject workers of a netstack driver.
	maxInjectWorkers = 8
	// injectQueue is the most batches that wait for one inject worker.
	injectQueue = 32
	// maxInjectBatch is the most packets in one batch for one worker.
	maxInjectBatch = 64
)

// injectBatch gives the PSP packets of one read of the QUIC read loop to
// inject workers, which give them to the netstack. All packets of a flow go
// to one worker, so they stay in order. When the queue of a worker is full,
// the read loop waits, and the socket buffer keeps the next packets.
type injectBatch struct {
	ep     *channel.Endpoint
	st     *counters
	seed   maphash.Seed
	done   <-chan struct{}
	closed <-chan struct{}
	in     []chan []inbound // The queue of each worker.
	pend   [][]inbound      // The packets of this read for each worker.
	free   chan []inbound   // Empty batches to use again.
}

// inbound is a packet for the netstack.
type inbound struct {
	proto tcpip.NetworkProtocolNumber
	pkb   *stack.PacketBuffer
}

// newInjectBatch starts n workers. They stop when done or closed closes.
func newInjectBatch(ep *channel.Endpoint, st *counters, seed maphash.Seed, n int, done, closed <-chan struct{}) *injectBatch {
	j := &injectBatch{
		ep:     ep,
		st:     st,
		seed:   seed,
		done:   done,
		closed: closed,
		in:     make([]chan []inbound, n),
		pend:   make([][]inbound, n),
		free:   make(chan []inbound, n*(injectQueue+1)),
	}
	for i := range j.in {
		j.in[i] = make(chan []inbound, injectQueue)
		go j.run(j.in[i])
	}
	return j
}

func (j *injectBatch) add(pkt []byte) {
	proto, ok := ipProto(pkt)
	if !ok {
		j.st.rxDrops.Add(1)
		return
	}
	w := 0
	if len(j.in) > 1 {
		w = int(flow.Hash(j.seed, pkt) % uint64(len(j.in)))
	}
	if j.pend[w] == nil {
		j.pend[w] = j.get()
	}
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	j.pend[w] = append(j.pend[w], inbound{proto, pkb})
	if len(j.pend[w]) == maxInjectBatch {
		j.send(w)
	}
}

func (j *injectBatch) flush() {
	for w, p := range j.pend {
		if len(p) > 0 {
			j.send(w)
		}
	}
}

// send gives the packets for worker w to its queue. It waits while the queue
// is full, and drops the packets when the driver closes.
func (j *injectBatch) send(w int) {
	p := j.pend[w]
	j.pend[w] = nil
	select {
	case j.in[w] <- p:
		// The worker can stop before it gets p.
		if j.stopped() {
			j.drain(j.in[w])
		}
		return
	case <-j.done:
	case <-j.closed:
	}
	j.st.rxDrops.Add(uint64(len(p)))
	j.release(p)
}

func (j *injectBatch) run(in <-chan []inbound) {
	for {
		select {
		case p := <-in:
			for _, x := range p {
				j.ep.InjectInbound(x.proto, x.pkb)
			}
			j.st.rxPackets.Add(uint64(len(p)))
			j.release(p)
		case <-j.done:
			j.drain(in)
			return
		case <-j.closed:
			j.drain(in)
			return
		}
	}
}

// stopped reports whether the driver or the binding closed.
func (j *injectBatch) stopped() bool {
	select {
	case <-j.done:
		return true
	case <-j.closed:
		return true
	default:
		return false
	}
}

// drain drops the batches in the queue in.
func (j *injectBatch) drain(in <-chan []inbound) {
	for {
		select {
		case p := <-in:
			j.st.rxDrops.Add(uint64(len(p)))
			j.release(p)
		default:
			return
		}
	}
}

// release frees the packets of p, and keeps p to use again.
func (j *injectBatch) release(p []inbound) {
	for i := range p {
		p[i].pkb.DecRef()
		p[i] = inbound{}
	}
	select {
	case j.free <- p[:0]:
	default:
	}
}

func (j *injectBatch) get() []inbound {
	select {
	case p := <-j.free:
		return p
	default:
		return make([]inbound, 0, rxBatch)
	}
}
