// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/atoonk/packetio"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// rxBatch is the most frames that a receive loop takes in one turn.
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
}

// txQueue is a transmit queue. The pipeline, quic-go and the netstack send from many goroutines,
// so a lock keeps the queue to one at a time.
type txQueue struct {
	mu     sync.Mutex
	q      packetio.TxQueue
	closed bool
}

// newDevice builds the pipeline, the netstack and the QUIC conn on dev. mtu is the IP MTU of the
// link.
func newDevice(ifc Interface, dev packetio.Device, mtu uint32) (*Device, error) {
	d := &Device{ifc: ifc, dev: dev}
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
	for i := range dev.NumTxQueues() {
		d.tx = append(d.tx, &txQueue{q: dev.TxQueue(i)})
	}
	if len(d.tx) == 0 || dev.NumRxQueues() == 0 {
		return nil, errors.New("the relay interface has no queues")
	}
	ns, err := newNetstack(ifc, mtu, d.sendPacket)
	if err != nil {
		return nil, err
	}
	d.ns = ns
	d.p = New(func(to netip.AddrPort, b []byte) { d.sendUDP(PortData, to, 0, b) })
	local := d.src4
	if !local.IsValid() {
		local = d.src6
	}
	d.conn = newQUICConn(d, netip.AddrPortFrom(local, portQUIC), dev.TxQueue(0).Region().FrameSize())
	return d, nil
}

// Target is the pipeline of the device.
func (d *Device) Target() *Pipeline { return d.p }

// PacketConn is the UDP 443 conn of the device, for a quic.Transport. It also implements
// ReadFromECN and WriteToECN.
func (d *Device) PacketConn() net.PacketConn { return d.conn }

// Interface is the interface of the device and its addresses.
func (d *Device) Interface() Interface { return d.ifc }

// Run receives on all queues until ctx is done. Then it closes the QUIC conn, the netstack and
// the interface.
func (d *Device) Run(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)
	for i := range d.dev.NumRxQueues() {
		q := d.dev.RxQueue(i)
		g.Go(func() error { return d.receive(gctx, q) })
	}
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
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return nil
	}
	return err
}

// receive is the receive loop of one queue.
func (d *Device) receive(ctx context.Context, q packetio.RxQueue) error {
	q.Fill(q.NumFreeFillSlots())
	for ctx.Err() == nil {
		n, err := q.Poll(100 * time.Millisecond)
		if err != nil {
			return fmt.Errorf("failed to receive on the relay interface: %w", err)
		}
		if n == 0 {
			continue
		}
		descs := q.Receive(min(n, rxBatch))
		for _, desc := range descs {
			d.input(q.Region().Frame(desc))
		}
		q.Recycle(descs)
		q.Fill(q.NumFreeFillSlots())
	}
	return ctx.Err()
}

// input is the demux of one received frame.
func (d *Device) input(frame []byte) {
	switch to, dg := demux(frame, d.own); to {
	case toPipeline:
		d.p.Receive(dg.from, dg.payload)
	case toQUIC:
		d.conn.deliver(dg)
	case toNetstack:
		d.ns.link.deliver(frame)
	default:
		// The drops counter is atomic. The drops of the packet I/O do not take the pipeline lock,
		// because a send runs with or without it.
		d.p.drop(ReasonDemux, len(frame))
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

// sendUDP sends a UDP datagram from the own address and port. With no next-hop MAC it drops the
// datagram (no_neighbor). It never waits.
func (d *Device) sendUDP(port uint16, to netip.AddrPort, ecn uint8, b []byte) {
	to = netip.AddrPortFrom(to.Addr().Unmap(), to.Port())
	src := d.src4
	if to.Addr().Is6() {
		src = d.src6
	}
	mac, ok := d.ns.neighbor(to.Addr())
	if !src.IsValid() || !ok {
		d.p.drop(ReasonNoNeighbor, len(b))
		return
	}
	from := netip.AddrPortFrom(src, port)
	h := to.Addr().As16()
	d.transmit(d.tx[(uint32(h[15])|uint32(to.Port())<<8)%uint32(len(d.tx))], len(b), func(frame []byte) int {
		return encodeUDP(frame, tcpip.LinkAddress(d.ifc.MAC), mac, from, to, ecn, b)
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
	sent, full := t.send(build)
	if full {
		d.p.drop(ReasonTXFull, size)
	}
	return sent
}

// send builds one frame and transmits it. full tells that the ring had no room for it.
func (t *txQueue) send(build func(frame []byte) int) (sent, full bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false, false
	}
	t.q.Complete(rxBatch)
	descs := t.q.Alloc(1)
	if len(descs) == 0 {
		return false, true
	}
	desc := descs[0]
	n := build(t.q.Region().Writable(desc))
	if n <= 0 {
		t.q.Free(descs)
		return false, false
	}
	desc.Len = uint32(n)
	if t.q.Transmit([]packetio.Desc{desc}) != 1 {
		t.q.Free([]packetio.Desc{desc})
		return false, true
	}
	return true, false
}
