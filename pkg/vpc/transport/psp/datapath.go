// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/apoxy-dev/softpsp/vtep"
	"github.com/apoxy-dev/softpsp/vtep/netstack"
	"github.com/apoxy-dev/softpsp/vtep/tun"
	"golang.org/x/net/ipv4"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

const (
	// A send frame is the destination address (16 B and the port), then the
	// PSP packet. Port 0 marks a QUIC data frame for the relay session.
	addrLen = 18
	// maxBatch is the largest number of packets in one sendmmsg call.
	maxBatch = 128
	// tunOffset is the space that the TUN device needs before each packet.
	tunOffset = 16
	// rxBatch is the most packets in one TUN write: the recvmmsg batch of quic-go on Linux.
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
	// batch collects the PSP packets of one read for the TUN device. It is nil for the netstack.
	batch *tunBatch
	done  chan struct{}
	once  sync.Once

	// Send state. Only the send goroutine of the vtep driver uses it.
	pc    *ipv4.PacketConn // Nil when the socket cannot send with sendmmsg.
	msgs  []ipv4.Message
	addrs []net.UDPAddr
}

func newDriver(b *Binding, deliver func([]byte, int) bool) *driver {
	d := &driver{
		b:       b,
		deliver: deliver,
		done:    make(chan struct{}),
		msgs:    make([]ipv4.Message, maxBatch),
		addrs:   make([]net.UDPAddr, maxBatch),
	}
	// x/net sends a batch only on Linux.
	if uc, ok := b.tr.Conn.(*net.UDPConn); ok && runtime.GOOS == "linux" {
		d.pc = ipv4.NewPacketConn(uc)
	}
	for i := range d.msgs {
		d.addrs[i].IP = make(net.IP, net.IPv6len)
		d.msgs[i].Buffers = make([][]byte, 1)
		d.msgs[i].Addr = &d.addrs[i]
	}
	return d
}

var (
	_ vtep.EngineXfrm   = (*driver)(nil)
	_ netstack.Underlay = (*driver)(nil)
	_ tun.Underlay      = (*driver)(nil)
)

// Netstack returns a netstack driver that connects ep to the binding. Make ep
// with the inner MTU. The caller runs the driver. A binding has one driver.
func (b *Binding) Netstack(ep *channel.Endpoint) (*netstack.Datapath, error) {
	d := newDriver(b, func(buf []byte, off int) bool { return inject(ep, buf[off:]) })
	if !b.drv.CompareAndSwap(nil, d) {
		return nil, errors.New("psp: binding already has a driver")
	}
	nd, err := netstack.New(netstack.Config{Engine: d, Endpoint: ep, Underlay: d})
	if err != nil {
		b.drv.CompareAndSwap(d, nil)
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
	var proto tcpip.NetworkProtocolNumber
	switch {
	case len(pkt) > 0 && pkt[0]>>4 == header.IPv4Version:
		proto = header.IPv4ProtocolNumber
	case len(pkt) > 0 && pkt[0]>>4 == header.IPv6Version:
		proto = header.IPv6ProtocolNumber
	default:
		return false
	}
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	ep.InjectInbound(proto, pkb)
	pkb.DecRef()
	return true
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
	b := d.b
	dst, ok := innerDst(virt)
	if !ok || len(virt) > b.mtu || len(phy) < addrLen+pspwire.Overhead+len(virt) {
		b.stats.txDrops.Add(1)
		return 0, false
	}
	p, ok := b.routes.Lookup(dst)
	if !ok {
		b.stats.txNoRoute.Add(1)
		return 0, false
	}
	quic := b.relay.Load() != nil
	b.clampMSS(virt, quic)
	if quic {
		clear(phy[:addrLen])
		return addrLen + len(peerconn.EncodeData(phy[addrLen:addrLen], b.vni, virt)), false
	}
	sa := p.txSA(virt)
	if sa == nil {
		b.stats.txNoRoute.Add(1)
		return 0, false
	}
	n, err := sa.Seal(phy[addrLen:], virt)
	if err != nil {
		b.stats.txDrops.Add(1)
		return 0, false
	}
	a := p.addr.Load()
	ip := a.Addr().As16()
	copy(phy, ip[:])
	binary.BigEndian.PutUint16(phy[16:addrLen], a.Port())
	return addrLen + n, false
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
		d.b.drv.CompareAndSwap(d, nil)
	})
	return nil
}

// WriteFrames sends the PSP packets with sendmmsg and the data frames on the
// relay session. It drops and counts a packet that fails.
func (d *driver) WriteFrames(frames [][]byte) (int, error) {
	if d.b.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	for i := 0; i < len(frames); i += maxBatch {
		if err := d.send(frames[i:min(i+maxBatch, len(frames))]); err != nil {
			return i, err
		}
	}
	return len(frames), nil
}

// send sends at most maxBatch frames.
func (d *driver) send(frames [][]byte) error {
	st := &d.b.stats
	n := 0
	for _, f := range frames {
		port := binary.BigEndian.Uint16(f[16:addrLen])
		if port == 0 {
			d.sendData(f[addrLen:])
			continue
		}
		a := &d.addrs[n]
		copy(a.IP, f[:16])
		a.Port = int(port)
		if d.pc == nil {
			if _, err := d.b.tr.WriteTo(f[addrLen:], a); err != nil {
				st.txDrops.Add(1)
			} else {
				st.txPackets.Add(1)
			}
			continue
		}
		d.msgs[n].Buffers[0] = f[addrLen:]
		n++
	}
	for msgs := d.msgs[:n]; len(msgs) > 0; {
		sent, err := d.pc.WriteBatch(msgs, 0)
		sent = max(sent, 0) // It is -1 when the first message fails.
		st.txPackets.Add(uint64(sent))
		msgs = msgs[sent:]
		if errors.Is(err, net.ErrClosed) {
			return err
		}
		if err != nil && len(msgs) > 0 {
			// The kernel refused the first message that is left.
			st.txDrops.Add(1)
			msgs = msgs[1:]
		}
	}
	return nil
}

// sendData sends a data frame on the relay session shard of its flow.
func (d *driver) sendData(frame []byte) {
	st := &d.b.stats
	pc := d.b.relay.Load()
	if pc == nil || pc.SendData(frame) != nil {
		st.txDrops.Add(1)
		return
	}
	st.txPackets.Add(1)
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
