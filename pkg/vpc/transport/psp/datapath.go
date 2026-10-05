// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"

	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/apoxy-dev/softpsp/vtep"
	"github.com/apoxy-dev/softpsp/vtep/netstack"
	"github.com/apoxy-dev/softpsp/vtep/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/udpbatch"
)

const (
	// A send frame is the destination address (16 B and the port), the send
	// lane (1 B), then the PSP packet. Port 0 marks a QUIC data frame for the
	// relay session.
	laneOff = 18
	addrLen = 19
	// maxBatch is the most packets in one send batch.
	maxBatch = 128
	// laneFrames is the most frames in one batch of a lane queue.
	laneFrames = 64
	// laneBatches is the number of batches in a lane queue.
	laneBatches = 6
	// tunOffset is the space that the TUN device needs before each packet.
	tunOffset = 16
	// rxBatch is the most packets in one TUN write. A full batch is written at once.
	rxBatch = 8
	// rxSlot is the space for one packet of a tunBatch. The device can coalesce up to 64 KiB into it.
	rxSlot = tunOffset + 1<<16
)

// driver is the engine and the underlay of a softpsp vtep driver, for sends only. The QUIC
// read loop and the relay session reader give the received packets to deliver.
type driver struct {
	b *Binding
	// deliver gives the inner packet buf[off:] to the netstack or the TUN
	// device. It returns false when it drops the packet.
	deliver func(buf []byte, off int) bool
	// batch collects the PSP packets of one read of the QUIC read loop.
	batch readBatch
	done  chan struct{}
	once  sync.Once
	// pipe moves the PSP packets from the QUIC read loop to a goroutine that opens them.
	// Nil when the read loop opens them.
	pipe *rxPipe

	// Send state. Only the send goroutine of the vtep driver uses it.
	tx *udpbatch.Batch // Nil when the socket cannot send batches.
	// lanes are the lane senders. A lane 1 or up gets one at its first frame, and
	// then lane 0 gets one too and its sender owns tx.
	lanes [keys.MaxLanes]*laneSender
	ua    net.UDPAddr // The address of a frame that goes alone.
}

func newDriver(b *Binding, deliver func([]byte, int) bool) *driver {
	d := &driver{
		b:       b,
		deliver: deliver,
		done:    make(chan struct{}),
		ua:      net.UDPAddr{IP: make(net.IP, net.IPv6len)},
	}
	if uc, ok := b.tr.Conn.(*net.UDPConn); ok {
		d.tx = udpbatch.New(uc, maxBatch)
	}
	return d
}

var (
	_ vtep.EngineXfrm   = (*driver)(nil)
	_ netstack.Sealer   = (*driver)(nil)
	_ netstack.Underlay = (*driver)(nil)
	_ netstack.Keeper   = (*driver)(nil)
	_ tun.Underlay      = (*driver)(nil)
)

// Netstack returns a netstack driver that connects ep to the binding. Make ep
// with the inner MTU. The caller runs the driver. A binding has one driver.
func (b *Binding) Netstack(ep *channel.Endpoint) (*netstack.Datapath, error) {
	d := newDriver(b, func(buf []byte, off int) bool { return inject(ep, buf[off:]) })
	procs := runtime.GOMAXPROCS(0)
	j := newInjectBatch(ep, &b.stats, b.seed, min(procs, maxInjectWorkers), d.done, b.ctx.Done())
	d.batch = j
	if procs > 1 {
		d.pipe = newRxPipe(d, j, openWorkers(procs), d.done, b.ctx.Done())
	}
	if !b.drv.CompareAndSwap(nil, d) {
		_ = d.Close()
		return nil, errors.New("psp: binding already has a driver")
	}
	nd, err := netstack.New(netstack.Config{Engine: d, Endpoint: ep, Underlay: d})
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	return nd, nil
}

// Tun connects dev, from wireguard-go tun.CreateTUN with the offloads on, to the binding.
// The caller runs the driver, and the driver closes dev. A binding has one driver.
func (b *Binding) Tun(dev tun.Device) (*tun.Datapath, error) {
	w := &tunWriter{dev: dev, bufs: make([][]byte, 1), scratch: make([]byte, tunOffset+b.mtu)}
	d := newDriver(b, w.write)
	d.batch = newTunBatch(w, &b.stats)
	if !b.drv.CompareAndSwap(nil, d) {
		return nil, errors.New("psp: binding already has a driver")
	}
	// TODO: use the link MTU of the agent when it has one.
	td, err := tun.New(tun.Config{Engine: d, Device: dev, Underlay: d, DeviceOffset: tunOffset, InnerMTU: b.mtu})
	if err != nil {
		b.drv.CompareAndSwap(d, nil)
		return nil, err
	}
	return td, nil
}

// inject gives an inner IP packet to the netstack, which copies it.
func inject(ep *channel.Endpoint, pkt []byte) bool {
	proto, ok := ipProto(pkt)
	if !ok {
		return false
	}
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	ep.InjectInbound(proto, pkb)
	pkb.DecRef()
	return true
}

// ipProto returns the network protocol of an IPv4 or IPv6 packet.
func ipProto(pkt []byte) (tcpip.NetworkProtocolNumber, bool) {
	switch {
	case len(pkt) > 0 && pkt[0]>>4 == header.IPv4Version:
		return header.IPv4ProtocolNumber, true
	case len(pkt) > 0 && pkt[0]>>4 == header.IPv6Version:
		return header.IPv6ProtocolNumber, true
	}
	return 0, false
}

// readBatch collects the PSP packets of one read of the QUIC read loop. Only
// the goroutine that opens the PSP packets calls it.
type readBatch interface {
	// add copies pkt into the batch.
	add(pkt []byte)
	// flush gives the batch to the device or the netstack.
	flush()
}

// tunWriter writes received packets to a TUN device. The PSP path and the
// QUIC path both use it.
type tunWriter struct {
	dev     tun.Device
	mu      sync.Mutex
	bufs    [][]byte
	scratch []byte
}

// write writes the packet buf[off:]. The device writes its header before the
// packet, so a packet with less than tunOffset bytes before it is copied first.
func (w *tunWriter) write(buf []byte, off int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if off < tunOffset {
		if len(buf)-off > len(w.scratch)-tunOffset {
			return false
		}
		n := copy(w.scratch[tunOffset:], buf[off:])
		buf, off = w.scratch[:tunOffset+n], tunOffset
	}
	w.bufs[0] = buf[off-tunOffset:]
	_, err := w.dev.Write(w.bufs, tunOffset)
	return err == nil
}

// tunBatch copies the PSP packets of one read of the QUIC read loop, and writes them to the TUN
// device in one call, so that the device can coalesce them. Only the QUIC read loop uses it.
type tunBatch struct {
	w    *tunWriter
	st   *counters
	bufs [][]byte // rxBatch slots of rxSlot bytes.
	out  [][]byte // The packets in bufs.
}

func newTunBatch(w *tunWriter, st *counters) *tunBatch {
	slab := make([]byte, rxBatch*rxSlot)
	t := &tunBatch{w: w, st: st, bufs: make([][]byte, rxBatch), out: make([][]byte, 0, rxBatch)}
	for i := range t.bufs {
		t.bufs[i] = slab[i*rxSlot : (i+1)*rxSlot : (i+1)*rxSlot]
	}
	return t
}

// add copies pkt into the batch. It writes the batch when the batch is full.
func (t *tunBatch) add(pkt []byte) {
	b := t.bufs[len(t.out)][:tunOffset+len(pkt)]
	copy(b[tunOffset:], pkt)
	t.out = append(t.out, b)
	if len(t.out) == cap(t.out) {
		t.flush()
	}
}

// flush writes the packets of the batch to the device. A failed write counts all of them as drops.
func (t *tunBatch) flush() {
	n := uint64(len(t.out))
	if n == 0 {
		return
	}
	t.w.mu.Lock()
	_, err := t.w.dev.Write(t.out, tunOffset)
	t.w.mu.Unlock()
	t.out = t.out[:0]
	if err != nil {
		t.st.rxDrops.Add(n)
	} else {
		t.st.rxPackets.Add(n)
	}
}

// VirtToPhy makes the send frame of an inner packet for the peer that routes its destination:
// a PSP packet, or a QUIC data frame after UseQUIC. It can lower the MSS of a TCP SYN in virt.
func (d *driver) VirtToPhy(virt, phy []byte) (int, bool) {
	n, err := d.b.frame(virt, phy)
	if err != nil {
		d.countTx(virt, err)
	}
	return n, false
}

// Overhead returns the bytes that a send frame adds to the inner packet.
func (d *driver) Overhead() int { return addrLen + pspwire.Overhead }

// Prepare reserves the send frame of an inner packet: the transmit SA and its next sequence
// number, and the address of the peer that routes the destination. The send pump calls it in
// send order, so that the peer gets the sequence numbers in order.
func (d *driver) Prepare(virt []byte, f *netstack.TxFrame) bool {
	err := d.b.prepare(virt, f)
	if err != nil {
		d.countTx(virt, err)
	}
	return err == nil
}

// PrepareSegs reserves the send frames of the n packets of one TCP packet in one call: one lane
// and n sequence numbers in a row. It returns false and reserves nothing when Prepare must run.
func (d *driver) PrepareSegs(hdr []byte, n, size, total int, f *netstack.TxFrame) bool {
	return d.b.prepareSegs(hdr, n, size, total, f)
}

// Seal writes the send frame that Prepare reserved to phy. Many goroutines can call it at once.
func (d *driver) Seal(f *netstack.TxFrame, virt, phy []byte) int {
	n, err := d.b.seal(f, virt, phy)
	if err != nil {
		d.b.stats.txDrops.Add(1)
	}
	return n
}

// countTx counts a send frame of virt that failed with err.
func (d *driver) countTx(virt []byte, err error) {
	b := d.b
	switch err {
	case ErrNoRoute:
		b.stats.txNoRoute.Add(1)
		if b.noRoute != nil {
			b.noRoute(virt)
		}
	case errLimit:
		b.stats.txLimitDrops.Add(1)
	default:
		b.stats.txDrops.Add(1)
	}
}

// frame writes the send frame of the inner packet virt to phy and returns its length.
// The limiter of a tripped breaker can drop the packet with errLimit.
func (b *Binding) frame(virt, phy []byte) (int, error) {
	var f netstack.TxFrame
	if err := b.prepare(virt, &f); err != nil {
		return 0, err
	}
	return b.seal(&f, virt, phy)
}

// prepare reserves the send frame of virt in f: the transmit SA with its next sequence
// number and the address of the peer, or no SA for a QUIC data frame after UseQUIC.
func (b *Binding) prepare(virt []byte, f *netstack.TxFrame) error {
	dst, ok := innerDst(virt)
	if !ok || len(virt) > b.mtu {
		return errDrop
	}
	p, ok := b.routes.Lookup(dst)
	if !ok {
		return ErrNoRoute
	}
	if b.relay.Load() != nil {
		if !b.quic.limiter.admit(len(virt)) {
			return errLimit
		}
		*f = netstack.TxFrame{}
		return nil
	}
	sa, lane := p.txSA(virt)
	if sa == nil {
		return ErrNoRoute
	}
	if !p.br.limiter.admit(len(virt)) {
		return errLimit
	}
	seq, err := sa.Reserve()
	if err != nil {
		return err
	}
	*f = netstack.TxFrame{SA: sa, Seq: seq, Dst: *p.addr.Load(), Lane: p.SendLane(lane)}
	return nil
}

// prepareSegs is prepare for n packets with the headers hdr. It refuses the packets that prepare
// can drop: no route, no SA, a breaker limit, or too few sequence numbers.
func (b *Binding) prepareSegs(hdr []byte, n, size, total int, f *netstack.TxFrame) bool {
	dst, ok := innerDst(hdr)
	if !ok || size > b.mtu {
		return false
	}
	p, ok := b.routes.Lookup(dst)
	if !ok {
		return false
	}
	if b.relay.Load() != nil {
		if b.quic.limiter.rate.Load() != 0 {
			return false
		}
		b.quic.limiter.sent.Add(uint64(total))
		*f = netstack.TxFrame{}
		return true
	}
	sa, lane := p.txSA(hdr)
	if sa == nil || p.br.limiter.rate.Load() != 0 {
		return false
	}
	seq, err := sa.ReserveN(n)
	if err != nil {
		return false
	}
	p.br.limiter.sent.Add(uint64(total))
	*f = netstack.TxFrame{SA: sa, Seq: seq, Dst: *p.addr.Load(), Lane: p.SendLane(lane)}
	return true
}

// seal writes the send frame that prepare reserved in f to phy and returns its length. It
// can lower the MSS of a TCP SYN in virt.
func (b *Binding) seal(f *netstack.TxFrame, virt, phy []byte) (int, error) {
	if len(phy) < addrLen+pspwire.Overhead+len(virt) {
		return 0, errDrop
	}
	quic := f.SA == nil
	b.clampMSS(virt, quic)
	if quic {
		clear(phy[:addrLen])
		return addrLen + len(peerconn.EncodeData(phy[addrLen:addrLen], b.vni, virt)), nil
	}
	n, err := f.SA.SealSeq(f.Seq, phy[addrLen:], virt)
	if err != nil {
		return 0, err
	}
	ip := f.Dst.Addr().As16()
	copy(phy, ip[:])
	binary.BigEndian.PutUint16(phy[16:laneOff], f.Dst.Port())
	phy[laneOff] = byte(f.Lane)
	return addrLen + n, nil
}

// Send sends inner packets outside the driver, for example the packets that waited for a
// peer session. It stops at the first packet with ErrNoRoute, and returns the number sent.
func (b *Binding) Send(pkts [][]byte) (int, error) {
	if b.ctx.Err() != nil {
		return 0, ErrClosed
	}
	phy := make([]byte, addrLen+pspwire.Overhead+b.mtu)
	ua := &net.UDPAddr{IP: make(net.IP, net.IPv6len)}
	sent := 0
	for _, pkt := range pkts {
		n, err := b.frame(pkt, phy)
		if err == ErrNoRoute {
			return sent, err
		}
		if err == errLimit {
			b.stats.txLimitDrops.Add(1)
			continue
		}
		if err == nil {
			err = b.write(phy[:n], ua)
		}
		if err != nil {
			b.stats.txDrops.Add(1)
			continue
		}
		b.stats.txPackets.Add(1)
		sent++
	}
	return sent, nil
}

// Deliver gives an inner packet from the agent, for example an ICMP error, to the driver.
// It writes at once and not into the TUN batch, so do not call it on the QUIC read loop.
func (b *Binding) Deliver(pkt []byte) bool {
	d := b.drv.Load()
	return d != nil && d.deliver(pkt, 0)
}

// PhyToVirt opens nothing: ReadFrame gives no frames to the vtep driver.
func (d *driver) PhyToVirt([]byte, []byte) int { return 0 }

// ToPhy has no frames to send.
func (d *driver) ToPhy([]byte) int { return 0 }

// ReadFrame blocks until the driver or the binding closes.
func (d *driver) ReadFrame([]byte) (int, error) {
	select {
	case <-d.done:
	case <-d.b.ctx.Done():
	}
	return 0, net.ErrClosed
}

// Close stops ReadFrame and removes the driver from the binding. The tun
// driver calls it when it stops.
func (d *driver) Close() error {
	d.once.Do(func() {
		close(d.done)
		if d.pipe != nil {
			// The next driver can open packets only after the pipe stops.
			<-d.pipe.exited
		}
		d.b.drv.CompareAndSwap(d, nil)
	})
	return nil
}

// WriteFrames sends the PSP packets in batches and the data frames on the
// relay session. It drops and counts a packet that fails.
func (d *driver) WriteFrames(frames [][]byte) (int, error) {
	return d.WriteKept(frames, nil)
}

// WriteKept is WriteFrames for frames that do not change while k has a user.
// The lane senders send these frames with no copy, and then release k.
func (d *driver) WriteKept(frames [][]byte, k *netstack.Kept) (int, error) {
	if d.closed() {
		return 0, net.ErrClosed
	}
	for i := 0; i < len(frames); i += maxBatch {
		if err := d.send(frames[i:min(i+maxBatch, len(frames))], k); err != nil {
			return i, err
		}
	}
	return len(frames), nil
}

// send sends at most maxBatch frames. While no lane has a sender, the caller
// sends the PSP packets in one batch. After that, send adds each PSP packet to
// the queue of its lane, and the lane senders send them in parallel. The queue
// gets the packet itself when k keeps it, or a copy.
func (d *driver) send(frames [][]byte, k *netstack.Kept) error {
	st := &d.b.stats
	for _, f := range frames {
		port := binary.BigEndian.Uint16(f[16:laneOff])
		if port == 0 || d.tx == nil {
			if d.b.write(f, &d.ua) != nil {
				st.txDrops.Add(1)
			} else {
				st.txPackets.Add(1)
			}
			continue
		}
		l := d.lane(f[laneOff])
		if l == nil {
			d.tx.Add(f[addrLen:], frameDst(f))
			continue
		}
		if err := d.queue(l, f, k); err != nil {
			d.drop()
			return err
		}
	}
	if d.lanes[0] == nil {
		return d.b.flush(d.tx, 0)
	}
	d.push()
	return nil
}

// queue adds the frame f to the queue of a lane: f itself when k keeps it, or
// a copy. It waits while the queue is full, and returns net.ErrClosed when the
// sender stopped.
func (d *driver) queue(l *laneSender, f []byte, k *netstack.Kept) error {
	if len(f) > l.slot {
		d.b.stats.txDrops.Add(1)
		return nil
	}
	q := l.cur
	if q == nil {
		select {
		case q = <-l.free:
		case <-l.exited:
			return net.ErrClosed
		default:
			// The other lanes get their frames before the wait.
			d.push()
			select {
			case q = <-l.free:
			case <-l.exited:
				return net.ErrClosed
			case <-d.done:
				return net.ErrClosed
			case <-d.b.ctx.Done():
				return net.ErrClosed
			}
		}
		l.cur = q
		if k != nil {
			// The batch is one user of the frames of this write.
			k.Keep()
			q.kept = k
		}
	}
	if k != nil {
		q.frames = append(q.frames, f)
	} else {
		if q.buf == nil {
			q.buf = make([]byte, laneFrames*l.slot)
		}
		i := len(q.frames) * l.slot
		q.frames = append(q.frames, q.buf[i:i+copy(q.buf[i:], f)])
	}
	if len(q.frames) == laneFrames {
		l.give()
	}
	return nil
}

// push gives the frames that queue added to the lane senders.
func (d *driver) push() {
	for _, l := range d.lanes {
		if l != nil && l.cur != nil {
			l.give()
		}
	}
}

// drop drops the frames that queue added and no sender got, after a send that
// failed.
func (d *driver) drop() {
	for _, l := range d.lanes {
		if l != nil && l.cur != nil {
			d.b.stats.txDrops.Add(uint64(len(l.cur.frames)))
			l.cur.done()
			l.free <- l.cur
			l.cur = nil
		}
	}
}

// closed reports whether the driver or the binding closed. Then the lane
// senders stop.
func (d *driver) closed() bool {
	select {
	case <-d.done:
		return true
	default:
		return d.b.ctx.Err() != nil
	}
}

// frameDst returns the destination address of a send frame.
func frameDst(f []byte) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16([16]byte(f[:16])), binary.BigEndian.Uint16(f[16:laneOff]))
}

// lane returns the sender of a send lane. A lane with no socket uses the sender
// of lane 0. It returns nil while no lane has a sender: the caller sends then.
func (d *driver) lane(lane byte) *laneSender {
	if lane == 0 || int(lane) >= len(d.lanes) {
		return d.lanes[0]
	}
	if l := d.lanes[lane]; l != nil {
		return l
	}
	uc := d.b.laneConn(lane)
	if uc == nil {
		return d.lanes[0]
	}
	var tx *udpbatch.Batch
	if s := d.b.laneSends[lane].Load(); s != nil {
		// The kernel wakes no waiter for the packets that a send socket sent.
		tx = udpbatch.NewSend(s, maxBatch)
	} else {
		tx = udpbatch.New(uc, maxBatch)
	}
	if tx == nil {
		return d.lanes[0]
	}
	if d.lanes[0] == nil {
		// The frames that the caller has for lane 0 go before the frames of its sender.
		_ = d.b.flush(d.tx, 0)
		d.lanes[0] = d.newLane(0, d.tx)
		go d.lanes[0].run(d.done)
	}
	l := d.newLane(int(lane), tx)
	d.lanes[lane] = l
	go l.run(d.done)
	return l
}

// newLane returns the sender of a lane, with an empty queue. It does not run.
func (d *driver) newLane(lane int, tx *udpbatch.Batch) *laneSender {
	l := &laneSender{
		b: d.b, lane: lane, tx: tx, slot: d.Overhead() + d.b.mtu,
		free: make(chan *laneBatch, laneBatches), work: make(chan *laneBatch, laneBatches),
		exited: make(chan struct{}),
	}
	for range laneBatches {
		l.free <- &laneBatch{frames: make([][]byte, 0, laneFrames)}
	}
	return l
}

// laneSender sends the frames of one send lane on its own goroutine, so that
// the kernel send work of each lane runs on its own CPU. Its queue has
// laneBatches batches: each one is in free, in cur, in work or with run. A
// batch in free keeps no frames.
type laneSender struct {
	b      *Binding
	lane   int
	tx     *udpbatch.Batch
	slot   int             // The most bytes of one send frame.
	cur    *laneBatch      // The batch that the driver fills. Only the driver uses it.
	free   chan *laneBatch // Empty batches for the driver.
	work   chan *laneBatch // Batches for the sender, in send order.
	exited chan struct{}   // Closed when run returns.
}

// laneBatch holds at most laneFrames send frames of one lane: copies in buf,
// or frames of one write that kept keeps.
type laneBatch struct {
	buf    []byte         // laneFrames slots for copies. Nil until the first copy.
	frames [][]byte       // The frames, in send order.
	kept   *netstack.Kept // Not nil while the batch is a user of kept frames.
}

// done empties q after its frames went out or dropped, and releases the
// frames that it kept.
func (q *laneBatch) done() {
	q.frames = q.frames[:0]
	if q.kept != nil {
		q.kept.Release()
		q.kept = nil
	}
}

// give gives the batch that the driver filled to the sender. A sender that
// stopped takes no batch, so the driver drops the batches that wait.
func (l *laneSender) give() {
	l.work <- l.cur
	l.cur = nil
	select {
	case <-l.exited:
		l.drain()
	default:
	}
}

// drain drops the batches that wait for the sender, which stopped, and counts
// their frames as drops. The sender and the driver can call it at one time.
func (l *laneSender) drain() {
	n := 0
	for {
		select {
		case q := <-l.work:
			n += len(q.frames)
			q.done()
		default:
			l.b.stats.txDrops.Add(uint64(n))
			return
		}
	}
}

// run sends the batches of the lane in order until the driver or the binding
// closes, or the socket closes. Batches that wait go in one send of at most
// maxBatch frames. It counts the frames that it did not send as drops.
func (l *laneSender) run(stop <-chan struct{}) {
	var next *laneBatch // A batch that did not fit in the last send.
	defer func() {
		if next != nil {
			l.b.stats.txDrops.Add(uint64(len(next.frames)))
			next.done()
		}
		l.drain()
		// The driver can give a batch until it sees the close, so drain again.
		close(l.exited)
		l.drain()
	}()
	var held [laneBatches]*laneBatch
	for {
		select {
		case <-stop:
			return
		case <-l.b.ctx.Done():
			return
		default:
		}
		q := next
		next = nil
		if q == nil {
			select {
			case q = <-l.work:
			case <-stop:
				return
			case <-l.b.ctx.Done():
				return
			}
		}
		n := 0
		for q != nil {
			for _, f := range q.frames {
				l.tx.Add(f[addrLen:], frameDst(f))
			}
			held[n] = q
			n++
			select {
			case q = <-l.work:
				if l.tx.Len()+len(q.frames) > maxBatch {
					next, q = q, nil
				}
			default:
				q = nil
			}
		}
		err := l.b.flush(l.tx, l.lane)
		for _, q := range held[:n] {
			q.done()
			l.free <- q
		}
		if err != nil {
			return
		}
	}
}

// flush sends the batch of a lane and counts its packets.
func (b *Binding) flush(tx *udpbatch.Batch, lane int) error {
	if tx == nil || tx.Len() == 0 {
		return nil
	}
	sent, dropped, err := tx.Flush()
	b.stats.txPackets.Add(uint64(sent))
	b.stats.txLanes[lane].Add(uint64(sent))
	b.stats.txDrops.Add(uint64(dropped))
	return err
}

// write sends one send frame: a data frame on the relay session shard of its flow, or a
// PSP packet to the address in the frame from the socket of its lane. ua must have a
// 16-byte IP.
func (b *Binding) write(f []byte, ua *net.UDPAddr) error {
	port := binary.BigEndian.Uint16(f[16:laneOff])
	if port == 0 {
		pc := b.relay.Load()
		if pc == nil {
			return errNoRelay
		}
		if err := pc.SendData(f[addrLen:]); err != nil {
			return err
		}
		b.stats.txFrames.Add(1)
		return nil
	}
	copy(ua.IP, f[:16])
	ua.Port = int(port)
	lane := f[laneOff]
	var err error
	if c := b.laneConn(lane); c != nil {
		_, err = c.WriteTo(f[addrLen:], ua)
	} else {
		lane = 0
		_, err = b.tr.WriteTo(f[addrLen:], ua)
	}
	if err == nil {
		b.stats.txLanes[lane].Add(1)
	}
	return err
}

// innerDst returns the destination address of an IPv4 or IPv6 packet.
func innerDst(pkt []byte) (netip.Addr, bool) {
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4:
		return netip.AddrFrom4([4]byte(pkt[16:20])), true
	case len(pkt) >= 40 && pkt[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(pkt[24:40])), true
	}
	return netip.Addr{}, false
}
