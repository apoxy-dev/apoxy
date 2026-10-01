// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"encoding/binary"
	"errors"
	"hash/maphash"
	"net"
	"net/netip"

	"github.com/apoxy-dev/softpsp/engine"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/apoxy-dev/softpsp/vtep"
	"github.com/apoxy-dev/softpsp/vtep/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
)

const (
	// A send frame is the destination address (16 B and the port), then the PSP packet.
	addrLen = 18
	// rxSlots is the number of received PSP packets that can wait for the driver.
	rxSlots = 1024
	slotLen = MaxMTU + pspwire.Overhead
)

// driver is the engine and the underlay of a softpsp vtep driver.
type driver struct {
	b *Binding

	// The write address. Only the send goroutine of the driver uses it.
	wa net.UDPAddr
	ip [16]byte

	// Receive slots. push fills them on the QUIC read loop, and ReadFrame empties them.
	slots []byte
	free  chan int32
	full  chan rxPkt
}

type rxPkt struct{ slot, n int32 }

func newDriver(b *Binding) *driver {
	d := &driver{
		b:     b,
		slots: make([]byte, rxSlots*slotLen),
		free:  make(chan int32, rxSlots),
		full:  make(chan rxPkt, rxSlots),
	}
	d.wa.IP = d.ip[:]
	for i := range int32(rxSlots) {
		d.free <- i
	}
	return d
}

var (
	_ vtep.EngineXfrm   = (*driver)(nil)
	_ netstack.Underlay = (*driver)(nil)
)

// Netstack returns a netstack driver that connects ep to the binding. The caller
// runs it. A binding has one driver.
func (b *Binding) Netstack(ep *channel.Endpoint) (*netstack.Datapath, error) {
	d := newDriver(b)
	if !b.drv.CompareAndSwap(nil, d) {
		return nil, errors.New("psp: binding already has a driver")
	}
	nd, err := netstack.New(netstack.Config{Engine: d, Endpoint: ep, Underlay: d})
	if err != nil {
		b.drv.Store(nil)
		return nil, err
	}
	return nd, nil
}

// VirtToPhy seals an inner packet with an SA of the peer that routes its
// destination.
func (d *driver) VirtToPhy(virt, phy []byte) (int, bool) {
	b := d.b
	dst, ok := innerDst(virt)
	if !ok || len(virt) > b.mtu {
		b.stats.txDrops.Add(1)
		return 0, false
	}
	var sa *engine.TxSA
	p, ok := b.routes.Lookup(dst)
	if ok {
		sa = p.txSA(virt)
	}
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

// PhyToVirt opens a PSP packet in place and copies the inner packet to virt.
func (d *driver) PhyToVirt(phy, virt []byte) int {
	inner, _, err := d.b.rxq.Receive(phy)
	if err != nil {
		d.b.stats.rxDrops.Add(1)
		return 0
	}
	d.b.stats.rxPackets.Add(1)
	return copy(virt, inner)
}

// ToPhy has no frames to send.
func (d *driver) ToPhy([]byte) int { return 0 }

// push copies a PSP packet to a free slot. It does not block, and returns
// false when no slot is free.
func (d *driver) push(pkt []byte) bool {
	select {
	case slot := <-d.free:
		n := copy(d.slot(slot), pkt)
		d.full <- rxPkt{slot, int32(n)} // Never blocks: full holds all slots.
		return true
	default:
		return false
	}
}

func (d *driver) slot(i int32) []byte {
	return d.slots[int(i)*slotLen : int(i+1)*slotLen]
}

// ReadFrame returns the next PSP packet.
func (d *driver) ReadFrame(buf []byte) (int, error) {
	select {
	case p := <-d.full:
		n := copy(buf, d.slot(p.slot)[:p.n])
		d.free <- p.slot
		return n, nil
	case <-d.b.ctx.Done():
		return 0, net.ErrClosed
	}
}

// WriteFrames sends each PSP packet to its address. A failed write drops only its packet.
func (d *driver) WriteFrames(frames [][]byte) (int, error) {
	if d.b.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	for _, f := range frames {
		copy(d.ip[:], f[:16])
		d.wa.Port = int(binary.BigEndian.Uint16(f[16:addrLen]))
		if _, err := d.b.tr.WriteTo(f[addrLen:], &d.wa); err != nil {
			d.b.stats.txDrops.Add(1)
			continue
		}
		d.b.stats.txPackets.Add(1)
	}
	return len(frames), nil
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

// flowHash returns a keyed hash of the addresses, protocol and ports of a packet.
// Fragments and IPv6 packets with extension headers hash without ports.
func flowHash(seed maphash.Seed, pkt []byte) uint64 {
	var k [37]byte
	n := 0
	if pkt[0]>>4 == 4 {
		n = copy(k[:], pkt[12:20])
		proto := pkt[9]
		k[n] = proto
		n++
		hl := int(pkt[0]&0x0f) * 4
		frag := binary.BigEndian.Uint16(pkt[6:8]) & 0x3fff // MF and the offset.
		if hasPorts(proto) && frag == 0 && len(pkt) >= hl+4 {
			n += copy(k[n:], pkt[hl:hl+4])
		}
	} else {
		n = copy(k[:], pkt[8:40])
		next := pkt[6]
		k[n] = next
		n++
		if hasPorts(next) && len(pkt) >= 44 {
			n += copy(k[n:], pkt[40:44])
		}
	}
	return maphash.Bytes(seed, k[:n])
}

// hasPorts reports whether the protocol is TCP, UDP or SCTP.
func hasPorts(proto byte) bool { return proto == 6 || proto == 17 || proto == 132 }
