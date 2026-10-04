// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"hash/maphash"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/stack/gro"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/flow"
)

const (
	// maxInjectWorkers is the most inject workers of a netstack driver.
	maxInjectWorkers = 8
	// injectQueue is the most batches that wait for one inject worker.
	injectQueue = 32
	// maxInjectBatch is the most PSP packets in one batch for one worker. A packet that
	// holds more of them can go above it.
	maxInjectBatch = 64
)

// injectBatch gives packets to inject workers, which give them to the netstack with GRO.
// A flow uses one worker, and the caller waits while the queue of the worker is full.
type injectBatch struct {
	ep     *channel.Endpoint
	st     *counters
	seed   maphash.Seed
	done   <-chan struct{}
	closed <-chan struct{}
	in     []chan []injected // The queue of each worker.
	pend   [][]injected      // The packets of this read for each worker.
	npend  []int             // The PSP packets in pend for each worker.
	free   chan []injected   // Empty batches to use again.
}

// injected is a packet buffer for the netstack and the number of PSP packets in it.
type injected struct {
	pkb *stack.PacketBuffer
	n   int
}

// pspPackets returns the number of PSP packets in p.
func pspPackets(p []injected) uint64 {
	n := 0
	for _, it := range p {
		n += it.n
	}
	return uint64(n)
}

// newInjectBatch starts n workers. They stop when done or closed closes.
func newInjectBatch(ep *channel.Endpoint, st *counters, seed maphash.Seed, n int, done, closed <-chan struct{}) *injectBatch {
	j := &injectBatch{
		ep:     ep,
		st:     st,
		seed:   seed,
		done:   done,
		closed: closed,
		in:     make([]chan []injected, n),
		pend:   make([][]injected, n),
		npend:  make([]int, n),
		free:   make(chan []injected, n*(injectQueue+1)),
	}
	for i := range j.in {
		j.in[i] = make(chan []injected, injectQueue)
		go j.run(j.in[i])
	}
	return j
}

// make returns the packet buffer of the inner packet pkt and the index of its inject
// worker, or nil when pkt is not IP. Many goroutines can call it.
func (j *injectBatch) make(pkt []byte) (*stack.PacketBuffer, int) {
	proto, ok := ipProto(pkt)
	if !ok {
		return nil, 0
	}
	return j.wrap(buffer.MakeWithData(pkt), proto, pkt)
}

// wrap returns the packet buffer of buf, which holds the IP packet pkt, and the index of
// its inject worker.
func (j *injectBatch) wrap(buf buffer.Buffer, proto tcpip.NetworkProtocolNumber, pkt []byte) (*stack.PacketBuffer, int) {
	w := 0
	if len(j.in) > 1 {
		w = int(flow.Hash(j.seed, pkt) % uint64(len(j.in)))
	}
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buf})
	pkb.NetworkProtocolNumber = proto
	// PSP open authenticated the packet, so GRO and the netstack do not check
	// its checksums.
	pkb.RXChecksumValidated = true
	return pkb, w
}

// push adds pkb, which holds n PSP packets, to the batch of worker w, and sends a full
// batch. Only the goroutine that gives the packets to the workers calls it.
func (j *injectBatch) push(pkb *stack.PacketBuffer, w, n int) {
	if j.pend[w] == nil {
		j.pend[w] = j.get()
	}
	j.pend[w] = append(j.pend[w], injected{pkb: pkb, n: n})
	if j.npend[w] += n; j.npend[w] >= maxInjectBatch {
		j.send(w)
	}
}

// add makes the packet buffer of pkt and pushes it.
func (j *injectBatch) add(pkt []byte) {
	pkb, w := j.make(pkt)
	if pkb == nil {
		j.st.rxDrops.Add(1)
		return
	}
	j.push(pkb, w, 1)
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
	j.pend[w], j.npend[w] = nil, 0
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
	j.st.rxDrops.Add(pspPackets(p))
	j.release(p)
}

func (j *injectBatch) run(in <-chan []injected) {
	g := &gro.GRO{Dispatcher: injector{j.ep}}
	g.Init(true)
	for {
		select {
		case p := <-in:
			for _, it := range p {
				g.Enqueue(it.pkb)
			}
			g.Flush()
			j.st.rxPackets.Add(pspPackets(p))
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
func (j *injectBatch) drain(in <-chan []injected) {
	for {
		select {
		case p := <-in:
			j.st.rxDrops.Add(pspPackets(p))
			j.release(p)
		default:
			return
		}
	}
}

// release frees the packets of p, and keeps p to use again.
func (j *injectBatch) release(p []injected) {
	for i := range p {
		p[i].pkb.DecRef()
		p[i] = injected{}
	}
	select {
	case j.free <- p[:0]:
	default:
	}
}

func (j *injectBatch) get() []injected {
	select {
	case p := <-j.free:
		return p
	default:
		return make([]injected, 0, rxBatch)
	}
}

// injector gives the packets of GRO to the netstack of ep.
type injector struct{ ep *channel.Endpoint }

func (i injector) DeliverNetworkPacket(proto tcpip.NetworkProtocolNumber, pkb *stack.PacketBuffer) {
	i.ep.InjectInbound(proto, pkb)
}

func (injector) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}
