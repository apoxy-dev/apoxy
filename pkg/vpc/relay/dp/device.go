// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/bits"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/atoonk/packetio"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// rxBatch is the most frames that a receive loop takes in one turn, and the most packets of a
// TxBatch.
const rxBatch = 64

// Device is the dedicated interface of the relay. Its demux gives UDP 1000 to the workers of the
// pipeline, UDP 443 to the QUIC conn, ARP, ICMP, ICMPv6 and NDP to the netstack, and drops all
// else.
type Device struct {
	ifc  Interface
	dev  packetio.Device
	p    *Pipeline
	ns   *netstack
	conn *quicConn
	tx   []*txQueue

	// workers run the pipeline (handoff.go): worker w sends on TX queue w. plan is the CPU of each
	// thread, and restore puts back the interrupt affinities that the plan changed, or is nil.
	workers []*worker
	plan    cpuPlan
	restore func()
	rxBusy  []atomic.Int64 // The busy time of each RX goroutine in nanoseconds.

	src4, src6 netip.Addr

	// impair reads the impair map, and delays is the copy of it that the send path reads. delays is
	// nil when no entry delays a packet.
	impair impairReader
	delays atomic.Pointer[delayTable]

	hops sync.Pool // The next-hop caches of sendUDP. A send takes one, so no other goroutine uses it.

	// kicks are the kick counts that Run read before it closed the sockets, nil before. The lock
	// keeps a read of the open sockets before the close.
	kicksMu sync.Mutex
	kicks   []KickCounts
}

// txQueue is a transmit queue. The receive loops, quic-go and the netstack send from many
// goroutines, so a lock keeps the queue to one at a time. A send only publishes: its kicker kicks.
type txQueue struct {
	mu     sync.Mutex
	q      packetio.TxQueue
	closed bool
	err    error // The kick error that ended the queue.

	txPort
	wake        chan struct{} // Size 1. A send after a publish asks the kicker for a kick.
	activations atomic.Uint64 // Kick calls of the kicker.
	cpu         int           // The CPU of the kicker in the plan, or -1.
	busy        atomic.Int64  // The busy time of the kicker in nanoseconds.
}

// txPort is how the device sends on one TX queue. The kicker calls kick and pending without the
// queue lock.
type txPort struct {
	publish func(descs []packetio.Desc) int // Puts descriptors on the TX ring, with no kick.
	kick    func() error                    // Tells the kernel about them, when it asks for it.
	pending func() int                      // TX descriptors that the kernel did not take.
	counts  func() KickCounts               // The sendto counts of the socket, with no Activations. Can be nil.
}

// KickCounts are the kick counts of one TX queue. Activations counts kick calls; the other fields
// count the sendto calls of those kicks and their results. None of them counts packets.
type KickCounts struct {
	Activations uint64 // Kick calls of the kicker, with the kicks after a backoff.
	Sendto      uint64 // sendto calls, with the retries of a kick.
	EAGAIN      uint64 // sendto calls that returned EAGAIN. The kick then tries again.
	Exhausted   uint64 // Kicks that used all their EAGAIN retries.
	EBUSY       uint64 // sendto calls that returned EBUSY: the kernel completed a frame and did not send it.
}

// The backoff of a kicker while descriptors stay on its TX ring doubles from kickWaitMin to
// kickWaitMax.
const (
	kickWaitMin = 20 * time.Microsecond
	kickWaitMax = 200 * time.Microsecond
)

// impairReader reads the entries of the impair map. On the relay interface it is the Impair of the
// pinned map.
type impairReader interface {
	Show() ([]Impairment, error)
	Close() error
}

// newDevice builds the pipeline, the workers, the netstack and the QUIC conn on dev. ports has the
// port of each TX queue of dev. mtu is the IP MTU of the link, impair the impair map, and aead the
// AEAD of the pipeline.
func newDevice(ifc Interface, dev packetio.Device, ports []txPort, mtu uint32, impair impairReader, aead AEAD) (*Device, error) {
	d := &Device{ifc: ifc, dev: dev, impair: impair}
	for _, p := range ifc.Own {
		switch a := p.Addr(); {
		case a.Is4() && !d.src4.IsValid():
			d.src4 = a
		case a.Is6() && !d.src6.IsValid():
			d.src6 = a
		}
	}
	if !d.src4.IsValid() && !d.src6.IsValid() {
		return nil, errors.New("the relay interface has no own address")
	}
	if len(ports) != dev.NumTxQueues() {
		return nil, fmt.Errorf("the relay interface has %d TX queues and %d TX ports", dev.NumTxQueues(), len(ports))
	}
	for i := range dev.NumTxQueues() {
		d.tx = append(d.tx, newTxQueue(dev.TxQueue(i), ports[i]))
	}
	if len(d.tx) == 0 || dev.NumRxQueues() == 0 {
		return nil, errors.New("the relay interface has no queues")
	}
	ns, err := newNetstack(ifc, mtu, d.sendPacket)
	if err != nil {
		return nil, err
	}
	d.ns = ns
	d.p = New(deviceSender{d}, aead)
	for i, t := range d.tx {
		d.workers = append(d.workers, newWorker(i, t))
	}
	d.p.setWorkers(len(d.workers))
	d.rxBusy = make([]atomic.Int64, dev.NumRxQueues())
	d.hops.New = func() any { return hopCache{} }
	local := d.src4
	if !local.IsValid() {
		local = d.src6
	}
	d.conn = newQUICConn(d, netip.AddrPortFrom(local, portQUIC))
	return d, nil
}

// Target is the pipeline of the device.
func (d *Device) Target() *Pipeline { return d.p }

// PacketConn is the UDP 443 conn of the device, for a quic.Transport. It also implements
// quic.GSOPacketConn: ReadFromECN, WriteToECN and WriteToGSO.
func (d *Device) PacketConn() net.PacketConn { return d.conn }

// Interface is the interface of the device and its addresses.
func (d *Device) Interface() Interface { return d.ifc }

// KickCounts returns the kick counts of each TX queue. The counts only increase. After Run closes
// the sockets, it returns the counts that Run read before the close.
func (d *Device) KickCounts() []KickCounts {
	d.kicksMu.Lock()
	defer d.kicksMu.Unlock()
	if d.kicks != nil {
		return slices.Clone(d.kicks)
	}
	c := make([]KickCounts, len(d.tx))
	for i, t := range d.tx {
		c[i] = t.kickCounts()
	}
	return c
}

// ThreadBusy is the busy time of one thread of the device: the elapsed time of its loop passes
// minus their idle waits. Kind is "rx" with the RX queue as Index, "worker" with the worker, or
// "kick" with the TX queue.
type ThreadBusy struct {
	Kind  string
	Index int
	Busy  time.Duration
}

// Busy returns the busy time of each RX goroutine, worker and kicker. The times only increase.
func (d *Device) Busy() []ThreadBusy {
	var out []ThreadBusy
	for i := range d.rxBusy {
		out = append(out, ThreadBusy{Kind: "rx", Index: i, Busy: time.Duration(d.rxBusy[i].Load())})
	}
	for _, w := range d.workers {
		out = append(out, ThreadBusy{Kind: "worker", Index: w.idx, Busy: time.Duration(w.busy.Load())})
	}
	for i, t := range d.tx {
		out = append(out, ThreadBusy{Kind: "kick", Index: i, Busy: time.Duration(t.busy.Load())})
	}
	return out
}

// Run receives on all queues, runs the workers, kicks each TX queue on its own OS thread, and
// reads the impair map each second, until ctx is done, a TX queue fails or a thread cannot get its
// CPU of the plan. Then it closes the QUIC conn, the netstack, the interface and the impair map,
// and puts back the interrupt affinities of the CPU plan. The close frees all frames, also the RX
// frames of the items that no worker did.
func (d *Device) Run(ctx context.Context) error {
	rxMem := d.setMemories()
	// A worker that cannot start stops the RX goroutines and the kickers with its error.
	rctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	// The workers start first and stop after the RX goroutines, so that each item that an RX
	// goroutine gives goes to a worker that runs.
	wctx, wcancel := context.WithCancel(context.Background())
	defer wcancel()
	var wg sync.WaitGroup
	for _, w := range d.workers {
		wg.Go(func() {
			if err := d.work(wctx, w); err != nil {
				stop(err)
			}
		})
	}
	g, gctx := errgroup.WithContext(rctx)
	for i := range d.dev.NumRxQueues() {
		q := d.dev.RxQueue(i)
		g.Go(func() error { return d.receive(gctx, i, q, rxMem[i]) })
	}
	for _, t := range d.tx {
		g.Go(func() error { return t.kicker(gctx) })
	}
	g.Go(func() error {
		d.readDelays(gctx)
		return nil
	})
	err := g.Wait()
	wcancel()
	wg.Wait()
	if errors.Is(err, context.Canceled) && ctx.Err() == nil {
		err = context.Cause(rctx) // A worker stopped Run.
	}
	// The counts of a closed socket are 0, so read them while the sockets are open.
	kicks := d.KickCounts()
	d.kicksMu.Lock()
	d.kicks = kicks
	d.kicksMu.Unlock()
	d.conn.Close()
	for _, t := range d.tx {
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()
	}
	d.ns.close()
	if cerr := d.dev.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if d.restore != nil {
		d.restore()
	}
	d.impair.Close()
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return nil
	}
	return err
}

// setMemories gives the batch of each worker the memories of the queues: the TX frames of its TX
// queue and the RX frames of each RX queue. It returns the memory of each RX queue. With AF_XDP an
// RX queue and the TX queue of the same index are one socket, with one memory.
func (d *Device) setMemories() (rxMem []int) {
	var mems [][]byte
	index := func(m []byte) int {
		for i, x := range mems {
			if len(x) == len(m) && unsafe.SliceData(x) == unsafe.SliceData(m) {
				return i
			}
		}
		mems = append(mems, m)
		return len(mems) - 1
	}
	txMem := make([]int, len(d.tx))
	for i, t := range d.tx {
		txMem[i] = index(t.q.Region().Bytes())
	}
	for i := range d.dev.NumRxQueues() {
		rxMem = append(rxMem, index(d.dev.RxQueue(i).Region().Bytes()))
	}
	for _, w := range d.workers {
		w.tx.mems, w.tx.txMem = mems, txMem[w.idx]
	}
	return rxMem
}

// receive is the receive loop of RX queue qi, with its frames in memory mem of the workers. It
// gives the UDP 1000 packets of each turn to the workers of their sessions (handoff.go), and takes
// back the frames of the items that the workers are done with. The QUIC datagrams of a turn go to
// quic-go as one item, in their RX frames. The goroutine is the only user of the RX and fill rings.
// The poll for frames is idle; the rest of each pass adds to the busy time of the queue.
func (d *Device) receive(ctx context.Context, qi int, q packetio.RxQueue, mem int) error {
	runtime.LockOSThread()
	defer nameThread(nameThread(RxThread))
	if cpu := d.plan.rxCPU(qi); cpu >= 0 {
		if err := pinThread("rx", cpu); err != nil {
			return err
		}
	}
	busy := &d.rxBusy[qi]
	free := make([]packetio.Desc, 0, rxBatch)
	var back []packetio.Desc
	var qt quicTurns
	h := d.newRxHandoff()
	for ctx.Err() == nil {
		start := time.Now()
		back = h.reclaim(append(back[:0], qt.read()...))
		q.Recycle(back)
		q.Fill(q.NumFreeFillSlots())
		descs := q.Receive(rxBatch)
		if len(descs) == 0 {
			busy.Add(int64(time.Since(start)))
			// Poll only when no frame waits: in copy mode a poll also sends the TX ring of the socket,
			// on this core.
			if _, err := q.Poll(100 * time.Millisecond); err != nil {
				return fmt.Errorf("failed to receive on the relay interface: %w", err)
			}
			continue
		}
		// The steering map comes after the frames of the turn: a packet with a new SPI comes after
		// the table change that published its worker.
		sm := d.p.steering.Load()
		free = free[:0]
		turn := qt.next()
		for _, desc := range descs {
			frame := q.Region().Frame(desc)
			switch to, dg := demux(frame, d.own); to {
			case toPipeline:
				h.pend = append(h.pend, rxPending{pkt: RxPacket{From: dg.from, Payload: dg.payload, mem: mem}, desc: desc})
				continue // The frame goes to a worker.
			case toQUIC:
				turn.dgs, turn.descs = append(turn.dgs, dg), append(turn.descs, desc)
				continue // The frame stays with the datagram until quic-go reads it.
			case toNetstack:
				d.ns.link.deliver(frame)
			default:
				// The drops counter is atomic. The drops of the packet I/O do not take the pipeline
				// lock, because a send runs with or without it.
				d.p.drop(ReasonDemux, len(frame))
			}
			free = append(free, desc)
		}
		free = qt.give(d.conn, turn, free)
		if len(h.pend) > 0 {
			free = d.handoff(h, sm, free)
		}
		q.Recycle(free)
		busy.Add(int64(time.Since(start)))
	}
	return ctx.Err()
}

// readDelays reads the impair map into the delay table now and then each second, until ctx is
// done. When it cannot read the map, it keeps the last table.
func (d *Device) readDelays(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		entries, err := d.impair.Show()
		if err != nil {
			slog.Warn("Failed to read the impair map", "error", err)
		} else if t := newDelayTable(entries); t != nil {
			d.delays.Store(&t)
		} else {
			d.delays.Store(nil)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (d *Device) own(a netip.Addr) bool {
	for _, p := range d.ifc.Own {
		if p.Addr() == a {
			return true
		}
	}
	return false
}

// udpFrame is a UDP datagram from the own address, with its next-hop MAC.
type udpFrame struct {
	from, to netip.AddrPort
	mac      tcpip.LinkAddress
	ecn      uint8
	payload  []byte
}

// route returns the frame header of a UDP datagram from the own address and port, or false with no
// next-hop MAC in hops or gVisor. Call it before a TX queue lock: a miss sends ARP or NDP.
func (d *Device) route(port uint16, to netip.AddrPort, ecn uint8, hops hopCache, now time.Time) (udpFrame, bool) {
	to = netip.AddrPortFrom(to.Addr().Unmap(), to.Port())
	src := d.src4
	if to.Addr().Is6() {
		src = d.src6
	}
	mac, ok := hops.mac(d.ns, to.Addr(), now)
	if !src.IsValid() || !ok {
		return udpFrame{}, false
	}
	return udpFrame{from: netip.AddrPortFrom(src, port), to: to, mac: mac, ecn: ecn}, true
}

// hopTTL is the time that an RX goroutine uses a MAC from gVisor. Each new ask keeps the neighbor
// checks of gVisor going, so a new MAC of a next hop applies within about hopTTL.
const hopTTL = time.Second

// hopCache is the next-hop MACs of one sending goroutine, with the time it asked gVisor for each.
// Only that goroutine uses it, so it has no lock.
type hopCache map[netip.Addr]hopEntry

type hopEntry struct {
	mac tcpip.LinkAddress
	at  time.Time
}

// mac returns the MAC of the next hop to dst. A miss, or an entry older than hopTTL, asks gVisor
// one time.
func (c hopCache) mac(ns *netstack, dst netip.Addr, now time.Time) (tcpip.LinkAddress, bool) {
	hop := ns.nextHop(dst)
	if e, ok := c[hop]; ok && now.Sub(e.at) < hopTTL {
		return e.mac, true
	}
	mac, ok := ns.neighbor(hop)
	if ok {
		// There are few next hops, so a full cache is cleared. An LRU would write on each hit.
		if len(c) >= stack.NeighborCacheSize {
			clear(c)
		}
		c[hop] = hopEntry{mac: mac, at: now}
	}
	return mac, ok
}

// encode writes f into frame. It returns the frame length, or 0 and counts a drop (mtu) when frame
// is too small.
func (d *Device) encode(f *udpFrame, frame []byte) int {
	n := encodeUDP(frame, tcpip.LinkAddress(d.ifc.MAC), f.mac, f.from, f.to, f.ecn, f.payload)
	if n == 0 {
		d.p.drop(ReasonMTU, len(f.payload))
	}
	return n
}

// deviceSender gives the batches of the pipeline to the device.
type deviceSender struct{ d *Device }

// Send sends the packets of b on the TX queue of its worker, in one publish. Each packet is in its
// TX frame, and Send writes its headers in front of it there. It gives the other frames back. A
// batch with no worker (PacketOut) sends each packet alone and asks gVisor for each MAC. It never
// waits.
func (s deviceSender) Send(b *TxBatch) {
	d := s.d
	if b.txq == nil {
		for i := range b.Len() {
			to, payload := b.Packet(i)
			d.sendUDP(PortData, to, 0, segments{b: payload})
		}
		return
	}
	var sizes [rxBatch]int // The size of each packet to send, for a tx_full drop.
	n := 0
	mem := b.mems[b.txMem]
	t, now := d.delays.Load(), time.Now()
	for i := range b.Len() {
		to, payload := b.Packet(i)
		f, ok := d.route(PortData, to, 0, b.hops, now)
		if !ok {
			d.p.drop(ReasonNoNeighbor, len(payload))
			continue
		}
		if t != nil {
			if w := t.wait(PortData, f.to.Addr()); w > 0 {
				d.sendLater(w, b.txq, f, segments{b: payload})
				continue
			}
		}
		start := b.starts[i] - udpHeaderLen(f.from)
		putUDP(mem[start:b.ends[i]], tcpip.LinkAddress(d.ifc.MAC), f.mac, f.from, f.to, f.ecn)
		fr := b.frames[i]
		fr.Addr, fr.Len = uint64(start), uint32(b.ends[i]-start)
		// The packets to send come first; the frames of the other packets move after them.
		b.frames[i], b.frames[n] = b.frames[n], fr
		sizes[n] = len(payload)
		n++
	}
	sent := b.txq.put(b.frames, n)
	for _, size := range sizes[sent:n] {
		d.p.drop(ReasonTXFull, size)
	}
	b.frames = b.frames[:0]
}

// segments is UDP datagrams back to back in b, seg bytes each; the last can be shorter. With seg 0,
// b is one datagram.
type segments struct {
	b   []byte
	seg int
}

func (s segments) len() int {
	if s.seg <= 0 || s.seg >= len(s.b) {
		return 1
	}
	return (len(s.b) + s.seg - 1) / s.seg
}

// at returns datagram i.
func (s segments) at(i int) []byte {
	if s.seg <= 0 || s.seg >= len(s.b) {
		return s.b
	}
	return s.b[i*s.seg : min((i+1)*s.seg, len(s.b))]
}

// sendUDP sends the datagrams of s from the own address and port to one destination. It never
// waits: a datagram with no next-hop MAC drops (no_neighbor), and the impair map can delay all.
func (d *Device) sendUDP(port uint16, to netip.AddrPort, ecn uint8, s segments) {
	hops := d.hops.Get().(hopCache)
	f, ok := d.route(port, to, ecn, hops, time.Now())
	d.hops.Put(hops)
	if !ok {
		for i := range s.len() {
			d.p.drop(ReasonNoNeighbor, len(s.at(i)))
		}
		return
	}
	h := f.to.Addr().As16()
	q := d.tx[(uint32(h[15])|uint32(f.to.Port())<<8)%uint32(len(d.tx))]
	if t := d.delays.Load(); t != nil {
		if w := t.wait(port, f.to.Addr()); w > 0 {
			d.sendLater(w, q, f, s)
			return
		}
	}
	d.sendSegments(q, f, s)
}

// sendSegments sends the datagrams of s with the header of f on q, one send for each rxBatch
// datagrams. A datagram with no room in the ring drops (tx_full).
func (d *Device) sendSegments(q *txQueue, f udpFrame, s segments) {
	n := s.len()
	for first := 0; first < n; first += rxBatch {
		_, full := q.send(min(n-first, rxBatch), func(i int, frame []byte) int {
			f.payload = s.at(first + i)
			return d.encode(&f, frame)
		})
		for ; full != 0; full &= full - 1 {
			d.p.drop(ReasonTXFull, len(s.at(first+bits.TrailingZeros64(full))))
		}
	}
}

// sendLater sends a copy of the datagrams of s with the header of f on q after w.
func (d *Device) sendLater(w time.Duration, q *txQueue, f udpFrame, s segments) {
	s.b = bytes.Clone(s.b)
	time.AfterFunc(w, func() { d.sendSegments(q, f, s) })
}

// sendPacket sends a packet of the netstack, with its Ethernet header.
func (d *Device) sendPacket(pkt *stack.PacketBuffer) bool {
	return d.transmit(d.tx[0], pkt.Size(), func(frame []byte) int {
		if pkt.Size() > len(frame) {
			return 0
		}
		n := 0
		for _, s := range pkt.AsSlices() {
			n += copy(frame[n:], s)
		}
		return n
	})
}

// transmit builds one frame on t and transmits it. A full ring drops the frame (tx_full); size is
// the size that the drop counts.
func (d *Device) transmit(t *txQueue, size int, build func(frame []byte) int) bool {
	sent, full := t.send(1, func(_ int, frame []byte) int { return build(frame) })
	if full != 0 {
		d.p.drop(ReasonTXFull, size)
	}
	return sent == 1
}

func newTxQueue(q packetio.TxQueue, p txPort) *txQueue {
	return &txQueue{q: q, txPort: p, wake: make(chan struct{}, 1), cpu: -1}
}

// send builds the frames of n packets (at most rxBatch) and publishes them in one call. build
// returns 0 to skip packet i. Bit i of full tells that packet i had no room in the ring.
func (t *txQueue) send(n int, build func(i int, frame []byte) int) (sent int, full uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.err != nil {
		return 0, 0
	}
	// Take back all completed frames, not only n: one kick can complete thousands.
	t.q.Complete(t.q.NumCompleted())
	descs := t.q.Alloc(n)
	var pkts [rxBatch]int // The packet of each frame.
	k, i := 0, 0
	for ; i < n && k < len(descs); i++ {
		if l := build(i, t.q.Region().Writable(descs[k])); l > 0 {
			descs[k].Len, pkts[k] = uint32(l), i
			k++
		}
	}
	t.q.Free(descs[k:])
	sent = t.publish(descs[:k])
	if sent > 0 {
		t.wakeKicker()
	}
	t.q.Free(descs[sent:k])
	for _, j := range pkts[sent:k] {
		full |= 1 << j
	}
	for ; i < n; i++ {
		full |= 1 << i
	}
	return sent, full
}

// take takes back the completed frames of t, and appends up to n free TX frames to out. The caller
// writes them with no lock, and gives them all back to put.
func (t *txQueue) take(n int, out []packetio.Desc) []packetio.Desc {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.err != nil {
		return out
	}
	t.q.Complete(t.q.NumCompleted())
	return append(out, t.q.Alloc(n)...)
}

// put publishes descs[:n], frames of take with their packets, in one call, and gives the other
// frames of descs back to the pool. It returns how many it published: a prefix of descs.
func (t *txQueue) put(descs []packetio.Desc, n int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	sent := 0
	if n > 0 && !t.closed && t.err == nil {
		sent = t.publish(descs[:n])
	}
	if sent > 0 {
		t.wakeKicker()
	}
	t.q.Free(descs[sent:])
	return sent
}

// wakeKicker asks the kicker of t for a kick after a publish.
func (t *txQueue) wakeKicker() {
	select {
	case t.wake <- struct{}{}:
	default: // The kicker has a wake that it did not take yet. Its next kick sends these frames too.
	}
}

// KickThread is the name of the OS thread of each kicker, as /proc/PID/task/TID/comm shows it.
const KickThread = "relay-kick"

// kicker kicks t on its own OS thread, so that in copy mode the kernel copies the frames on a second
// core. One kick covers all wakes since the last kick. While descriptors stay on the ring, it kicks
// again after a backoff: no frame waits for the next send. It runs until ctx is done or a kick error
// ends the queue. The thread has the name KickThread, and the goroutine ends with it locked, so the
// Go runtime ends the named thread too. The wait for a wake or a backoff is idle; the rest of each
// pass adds to the busy time of t.
func (t *txQueue) kicker(ctx context.Context) error {
	runtime.LockOSThread()
	// The Go runtime keeps the main thread when its locked goroutine ends, so it gets its old name back.
	defer nameThread(nameThread(KickThread))
	if t.cpu >= 0 {
		if err := pinThread("kicker", t.cpu); err != nil {
			return err
		}
	}
	retry := time.NewTimer(kickWaitMax)
	retry.Stop()
	var backoff time.Duration
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.wake:
			backoff = 0
		case <-retry.C:
		}
		start := time.Now()
		t.activations.Add(1)
		// Other kick errors, as a link that is down, keep the frames on the ring for the next kick.
		if err := t.kick(); kickEnds(err) {
			t.fail(err)
			return fmt.Errorf("failed to kick a TX queue of the relay interface: %w", err)
		}
		if t.pending() == 0 {
			retry.Stop()
		} else {
			backoff = min(max(2*backoff, kickWaitMin), kickWaitMax)
			retry.Reset(backoff)
		}
		t.busy.Add(int64(time.Since(start)))
	}
}

// kickCounts returns the kick counts of t.
func (t *txQueue) kickCounts() KickCounts {
	var c KickCounts
	if t.counts != nil {
		c = t.counts()
	}
	c.Activations = t.activations.Load()
	return c
}

// kickEnds tells if a kick error ends the TX queue: the socket is closed, or the kernel removed its
// binding to the interface (ENXIO).
func kickEnds(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, packetio.ErrClosed) ||
		errors.Is(err, syscall.ENXIO)
}

// fail ends t with the kick error err. A send after it sends nothing.
func (t *txQueue) fail(err error) {
	t.mu.Lock()
	t.err = err
	t.mu.Unlock()
}
