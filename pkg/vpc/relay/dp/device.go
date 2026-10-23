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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/atoonk/packetio"
	"github.com/cilium/ebpf"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// rxBatch is the most frames that a receive loop takes in one turn, and the most packets of a
// TxBatch.
const rxBatch = 64

// Device is the dedicated interface of the relay. Its demux gives UDP 1000 to the pipeline, UDP
// 443 to the QUIC conn, ARP, ICMP, ICMPv6 and NDP to the netstack, and drops all else.
type Device struct {
	ifc  Interface
	dev  packetio.Device
	p    *Pipeline
	ns   *netstack
	conn *quicConn
	tx   []*txQueue

	src4, src6 netip.Addr

	// impair is the impair map, and delays the copy of it that the send path reads. delays is nil
	// when no entry delays a packet.
	impair *ebpf.Map
	delays atomic.Pointer[delayTable]

	hops sync.Pool // The next-hop caches of sendUDP. A send takes one, so no other goroutine uses it.
}

// txQueue is a transmit queue. The receive loops, quic-go and the netstack send from many
// goroutines, so a lock keeps the queue to one at a time. A send only publishes: its kicker kicks.
type txQueue struct {
	mu     sync.Mutex
	q      packetio.TxQueue
	closed bool
	err    error // The kick error that ended the queue.

	txPort
	wake chan struct{} // Size 1. A send after a publish asks the kicker for a kick.
}

// txPort is how the device sends on one TX queue. The kicker calls kick and pending without the
// queue lock.
type txPort struct {
	publish func(descs []packetio.Desc) int // Puts descriptors on the TX ring, with no kick.
	kick    func() error                    // Tells the kernel about them, when it asks for it.
	pending func() int                      // TX descriptors that the kernel did not take.
}

// The backoff of a kicker while descriptors stay on its TX ring doubles from kickWaitMin to
// kickWaitMax.
const (
	kickWaitMin = 20 * time.Microsecond
	kickWaitMax = 200 * time.Microsecond
)

// newDevice builds the pipeline, the netstack and the QUIC conn on dev. ports has the port of each
// TX queue of dev. mtu is the IP MTU of the link, and impair the impair map.
func newDevice(ifc Interface, dev packetio.Device, ports []txPort, mtu uint32, impair *ebpf.Map) (*Device, error) {
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
	d.p = New(deviceSender{d})
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
// ReadFromECN and WriteToECN.
func (d *Device) PacketConn() net.PacketConn { return d.conn }

// Interface is the interface of the device and its addresses.
func (d *Device) Interface() Interface { return d.ifc }

// Run receives on all queues, kicks each TX queue on its own OS thread, and reads the impair map
// each second, until ctx is done or a TX queue fails. Then it closes the QUIC conn, the netstack,
// the interface and the impair map.
func (d *Device) Run(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)
	for i := range d.dev.NumRxQueues() {
		q := d.dev.RxQueue(i)
		tx := &TxBatch{txq: d.tx[i%len(d.tx)], hops: hopCache{}}
		g.Go(func() error { return d.receive(gctx, q, tx) })
	}
	for _, t := range d.tx {
		g.Go(func() error { return t.kicker(gctx) })
	}
	g.Go(func() error {
		d.readDelays(gctx)
		return nil
	})
	err := g.Wait()
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
	d.impair.Close()
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return nil
	}
	return err
}

// receive is the receive loop of one queue. The pipeline sends the packets of each turn in tx. The
// QUIC datagrams of a turn go to quic-go as one item, in their RX frames.
func (d *Device) receive(ctx context.Context, q packetio.RxQueue, tx *TxBatch) error {
	rx := make([]RxPacket, 0, rxBatch)
	free := make([]packetio.Desc, 0, rxBatch)
	var qt quicTurns
	for ctx.Err() == nil {
		q.Recycle(qt.read())
		q.Fill(q.NumFreeFillSlots())
		descs := q.Receive(rxBatch)
		if len(descs) == 0 {
			// Poll only when no frame waits: in copy mode a poll also sends the TX ring of the socket,
			// on this core.
			if _, err := q.Poll(100 * time.Millisecond); err != nil {
				return fmt.Errorf("failed to receive on the relay interface: %w", err)
			}
			continue
		}
		rx, free = rx[:0], free[:0]
		turn := qt.next()
		for _, desc := range descs {
			frame := q.Region().Frame(desc)
			switch to, dg := demux(frame, d.own); to {
			case toPipeline:
				rx = append(rx, RxPacket{From: dg.from, Payload: dg.payload})
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
		d.p.Receive(rx, tx)
		q.Recycle(free)
	}
	return ctx.Err()
}

// readDelays reads the impair map into the delay table now and then each second, until ctx is
// done. When it cannot read the map, it keeps the last table.
func (d *Device) readDelays(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		entries, err := impairments(d.impair)
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

// route returns the frame of a UDP datagram from the own address and port. With no next-hop MAC in
// hops or gVisor it drops it (no_neighbor). Call it before a TX queue lock: a miss sends ARP or NDP.
func (d *Device) route(port uint16, to netip.AddrPort, ecn uint8, b []byte, hops hopCache, now time.Time) (udpFrame, bool) {
	to = netip.AddrPortFrom(to.Addr().Unmap(), to.Port())
	src := d.src4
	if to.Addr().Is6() {
		src = d.src6
	}
	mac, ok := hops.mac(d.ns, to.Addr(), now)
	if !src.IsValid() || !ok {
		d.p.drop(ReasonNoNeighbor, len(b))
		return udpFrame{}, false
	}
	return udpFrame{from: netip.AddrPortFrom(src, port), to: to, mac: mac, ecn: ecn, payload: b}, true
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

// encode writes f into frame. It returns the frame length, or 0 when frame is too small.
func (d *Device) encode(f *udpFrame, frame []byte) int {
	return encodeUDP(frame, tcpip.LinkAddress(d.ifc.MAC), f.mac, f.from, f.to, f.ecn, f.payload)
}

// deviceSender gives the batches of the pipeline to the device.
type deviceSender struct{ d *Device }

// Send sends the packets of b on the TX queue of its RX queue, in one publish. A batch with no
// RX queue (PacketOut) sends each packet alone and asks gVisor for each MAC. It never waits.
func (s deviceSender) Send(b *TxBatch) {
	d := s.d
	if b.txq == nil {
		for i := range b.Len() {
			to, payload := b.Packet(i)
			d.sendUDP(PortData, to, 0, payload)
		}
		return
	}
	var fs [rxBatch]udpFrame
	n := 0
	t, now := d.delays.Load(), time.Now()
	for i := range b.Len() {
		to, payload := b.Packet(i)
		f, ok := d.route(PortData, to, 0, payload, b.hops, now)
		if !ok {
			continue
		}
		if t != nil {
			if w := t.wait(PortData, f.to.Addr()); w > 0 {
				d.sendLater(w, b.txq, f)
				continue
			}
		}
		fs[n] = f
		n++
	}
	if n == 0 {
		return
	}
	_, full := b.txq.send(n, func(i int, frame []byte) int { return d.encode(&fs[i], frame) })
	for ; full != 0; full &= full - 1 {
		d.p.drop(ReasonTXFull, len(fs[bits.TrailingZeros64(full)].payload))
	}
}

// sendUDP sends a UDP datagram from the own address and port. With no next-hop MAC it drops the
// datagram (no_neighbor). It never waits: when the impair map delays the datagram, a timer sends a
// copy of it.
func (d *Device) sendUDP(port uint16, to netip.AddrPort, ecn uint8, b []byte) {
	hops := d.hops.Get().(hopCache)
	f, ok := d.route(port, to, ecn, b, hops, time.Now())
	d.hops.Put(hops)
	if !ok {
		return
	}
	h := f.to.Addr().As16()
	q := d.tx[(uint32(h[15])|uint32(f.to.Port())<<8)%uint32(len(d.tx))]
	if t := d.delays.Load(); t != nil {
		if w := t.wait(port, f.to.Addr()); w > 0 {
			d.sendLater(w, q, f)
			return
		}
	}
	d.transmit(q, len(b), func(frame []byte) int { return d.encode(&f, frame) })
}

// sendLater sends a copy of f on q after w.
func (d *Device) sendLater(w time.Duration, q *txQueue, f udpFrame) {
	f.payload = bytes.Clone(f.payload)
	time.AfterFunc(w, func() {
		d.transmit(q, len(f.payload), func(frame []byte) int { return d.encode(&f, frame) })
	})
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
	return &txQueue{q: q, txPort: p, wake: make(chan struct{}, 1)}
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
		select {
		case t.wake <- struct{}{}:
		default: // The kicker has a wake that it did not take yet. Its next kick sends these frames too.
		}
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

// KickThread is the name of the OS thread of each kicker, as /proc/PID/task/TID/comm shows it.
const KickThread = "relay-kick"

// kicker kicks t on its own OS thread, so that in copy mode the kernel copies the frames on a second
// core. One kick covers all wakes since the last kick. While descriptors stay on the ring, it kicks
// again after a backoff: no frame waits for the next send. It runs until ctx is done or a kick error
// ends the queue. The thread has the name KickThread, and the goroutine ends with it locked, so the
// Go runtime ends the named thread too.
func (t *txQueue) kicker(ctx context.Context) error {
	runtime.LockOSThread()
	// The Go runtime keeps the main thread when its locked goroutine ends, so it gets its old name back.
	defer nameThread(nameThread(KickThread))
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
		// Other kick errors, as a link that is down, keep the frames on the ring for the next kick.
		if err := t.kick(); kickEnds(err) {
			t.fail(err)
			return fmt.Errorf("failed to kick a TX queue of the relay interface: %w", err)
		}
		if t.pending() == 0 {
			retry.Stop()
			continue
		}
		backoff = min(max(2*backoff, kickWaitMin), kickWaitMax)
		retry.Reset(backoff)
	}
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
