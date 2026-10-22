// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"bytes"
	"cmp"
	"net/netip"
	"time"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/apoxy-dev/softpsp/psp"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

// maxPacket is the size of a send buffer: the largest UDP payload.
const maxPacket = 65535

// meta is the packet metadata of one pass (meta_t).
type meta struct {
	port    uint64
	session uint64 // The session of the RX entry, or of the FRAME in.
	spi     uint32 // The SPI of the RX entry.
	lane    uint8
	vni     uint32
	from    netip.AddrPort
	psp     bool // A PSP packet, not a FRAME in.
	size    int  // The bytes that the meters and the drops count.
}

// Receive runs the pipeline on all packets of rx, and changes their payloads. Then it gives the
// sealed PSP and RAW packets to one Send(tx), and resets tx. Probes and keepalives go to the root.
func (p *Pipeline) Receive(rx []RxPacket, tx *TxBatch) {
	// Each packet sends at most one packet, so a part of rxBatch packets keeps tx to rxBatch.
	for len(rx) > 0 {
		n := min(len(rx), rxBatch)
		p.mu.RLock()
		for _, pkt := range rx[:n] {
			p.receive(pkt.From, pkt.Payload, tx)
		}
		p.mu.RUnlock()
		p.flush(tx)
		rx = rx[n:]
	}
}

// flush gives tx to the Sender when it has packets, and resets it.
func (p *Pipeline) flush(tx *TxBatch) {
	if tx.Len() > 0 {
		p.send.Send(tx)
	}
	tx.reset()
}

// receive runs the pipeline on one UDP payload b of port 1000 from the outer address from.
func (p *Pipeline) receive(from netip.AddrPort, b []byte, tx *TxBatch) {
	if _, ok := p2p.ProbeSID(b); ok || (len(b) == 1 && b[0] == p2p.TypeKeepalive) {
		p.toRoot(PacketInMeta{Kind: KindPunt, From: from}, 0, len(b), b)
		return
	}
	h, err := psp.ParseTrunkHeader(b)
	if err != nil {
		p.drop(ReasonMalformed, len(b))
		return
	}
	// open_psp: the RX entry of the SPI.
	sa := p.st.rx[h.SPI]
	if sa == nil {
		p.drop(ReasonUnknownSPI, len(b))
		return
	}
	payload, ok := sa.open(h, b)
	if !ok {
		p.drop(ReasonOpen, len(b))
		return
	}
	p.apply(&meta{port: sa.port, session: sa.session, spi: sa.spi, lane: sa.lane, vni: h.VNI, from: from, psp: true, size: len(b)}, payload, tx)
}

// PacketOut takes FRAME in, SEAL and RAW, and sends its packet in a batch of one. An error is only
// for a bad request; a packet that the pipeline drops is counted in drops.
func (p *Pipeline) PacketOut(po *p4.PacketOut) error {
	md, err := DecodePacketOutMeta(po.GetMetadata())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	tx := p.batches.Get().(*TxBatch)
	defer p.batches.Put(tx)
	p.mu.RLock()
	err = p.packetOut(md, po.GetPayload(), tx)
	p.mu.RUnlock()
	p.flush(tx)
	return err
}

func (p *Pipeline) packetOut(md PacketOutMeta, b []byte, tx *TxBatch) error {
	switch md.Kind {
	case KindFrame:
		vni, inner, err := peerconn.DecodeData(b)
		if err != nil {
			p.drop(ReasonMalformed, len(b))
			return nil
		}
		p.apply(&meta{port: md.Port, session: md.Session, vni: vni, size: len(b)}, inner, tx)
	case KindSeal:
		// SEAL skips apply: M's trunk messages and probes, with tag 0.
		o, ok := p.port(md.Port)
		if !ok || !o.Addr.IsValid() {
			p.drop(ReasonNoTarget, len(b))
			return nil
		}
		if o.Session != md.Session {
			p.drop(ReasonOldSession, len(b))
			return nil
		}
		p.seal(md.Port, o, 0, 0, b, 0, tx)
	case KindRaw:
		if !md.To.IsValid() {
			return status.Error(codes.InvalidArgument, "RAW has no outer address")
		}
		tx.add(md.To, copy(tx.room(len(b)), b))
	default:
		return status.Errorf(codes.InvalidArgument, "packet_out kind %d is not FRAME, SEAL or RAW", md.Kind)
	}
	return nil
}

// port returns the port action of the ports entry of id.
func (p *Pipeline) port(id uint64) (PortAction, bool) {
	if e := p.st.ports[id]; e != nil {
		a, ok := e.action.(PortAction)
		return a, ok
	}
	return PortAction{}, false
}

// apply is the apply block of the Relay control, from ports to send_out.
func (p *Pipeline) apply(m *meta, pkt []byte, tx *TxBatch) {
	// ports.
	var act Action = p.defaults[TablePorts]
	if e := p.st.ports[m.port]; e != nil {
		act = e.action
	}
	pa, ok := act.(PortAction)
	if !ok {
		p.dropAction(act, m.size, 0)
		return
	}

	// check_in.
	if m.session != pa.Session {
		p.dropIn(pa.MeterIndex, ReasonOldSession, m.size)
		return
	}
	if m.psp {
		if !fromPort(pa, m.from) {
			p.dropIn(pa.MeterIndex, ReasonUnknownSource, m.size)
			return
		}
		if !p.meter(MeterLane, 4*pa.MeterIndex+uint32(m.lane), m.size) {
			p.dropIn(pa.MeterIndex, ReasonMeter, m.size)
			return
		}
	}
	if !p.meter(MeterPort, pa.MeterIndex, m.size) {
		p.dropIn(pa.MeterIndex, ReasonMeter, m.size)
		return
	}
	if m.psp {
		p.st.count(m.spi)
	}

	// read_tag: a trunk packet carries the sender's session tag in the VNI field. Tag 0 is for M.
	var tag uint32
	if pa.Trunk {
		tag = m.vni
		if tag == 0 {
			p.toRoot(PacketInMeta{Kind: KindPunt, Port: m.port, Session: pa.Session, From: m.from}, pa.MeterIndex, m.size, pkt)
			return
		}
	}
	src, dst, ok := innerAddrs(pkt)
	if !ok {
		p.dropIn(pa.MeterIndex, ReasonMalformed, m.size)
		return
	}

	// classify.
	act = p.defaults[TableClassify]
	var vpc uint32
	if e := p.st.classify[ClassifyKey{Port: m.port, Session: pa.Session, Tag: tag}]; e != nil {
		act, vpc = e.action, e.vpc
	}
	c, ok := act.(ContextAction)
	if !ok {
		p.dropAction(act, m.size, pa.MeterIndex)
		return
	}
	if !pa.Trunk && m.vni != c.VNI {
		p.dropIn(pa.MeterIndex, ReasonNoContext, m.size)
		return
	}
	p.cells[2*c.Cell].add(len(pkt))

	// source.
	act = p.defaults[TableSource]
	if l := p.st.source[setKey{m.port, pa.Session, tag}]; l != nil {
		if e, ok := l.lookup(src); ok {
			act = e.action
		}
	}
	var localOnly bool
	switch a := act.(type) {
	case NoAction:
	case LocalOnlyAction:
		localOnly = true
	default:
		p.dropAction(a, m.size, pa.MeterIndex)
		return
	}

	// route and route_end.
	hash := flowHash(pkt)
	act = p.defaults[TableRoute]
	if l := p.st.route[vpc]; l != nil {
		if e, ok := l.lookup(dst); ok {
			act = e.action
		}
	}
	var out uint64
	var cell uint32
	switch a := act.(type) {
	case ForwardAction:
		out, cell = a.Port, a.Cell
		if pa.Trunk || localOnly {
			out, cell = a.LocalPort, a.LocalCell
		}
		if out == 0 {
			p.dropIn(pa.MeterIndex, ReasonNoRoute, m.size)
			return
		}
	case NoAction:
		if pa.Trunk {
			p.dropIn(pa.MeterIndex, ReasonNoRoute, m.size)
			return
		}
		p.toRoot(PacketInMeta{Kind: KindMiss, Port: m.port, Session: pa.Session, Hash: hash, From: m.from}, pa.MeterIndex, m.size, pkt)
		return
	default:
		p.dropAction(a, m.size, pa.MeterIndex)
		return
	}

	// send_out. After the ports entry of the out port, a drop counts at its meter index
	// (out_meter_index).
	o, ok := p.port(out)
	if !ok {
		p.dropIn(pa.MeterIndex, ReasonNoTarget, m.size)
		return
	}
	mo := cmp.Or(o.MeterIndex, pa.MeterIndex)
	switch {
	case pa.Trunk && o.Trunk:
		p.dropIn(mo, ReasonTrunkToTrunk, m.size)
		return
	case localOnly && o.Trunk:
		p.dropIn(mo, ReasonLocalOnly, m.size)
		return
	case o.MTU != 0 && len(pkt) > int(o.MTU):
		p.dropIn(mo, ReasonMTU, m.size)
		return
	}
	if o.Addr.IsValid() {
		vni := c.VNI
		if o.Trunk {
			vni = pa.Tag
		}
		if !p.seal(out, o, vni, hash, pkt, mo, tx) {
			return
		}
	} else {
		w := p.writers[out]
		if w == nil {
			p.dropIn(mo, ReasonNoTarget, m.size)
			return
		}
		bp := p.bufs.Get().(*[]byte)
		err := w(peerconn.EncodeData((*bp)[:0], c.VNI, pkt))
		p.bufs.Put(bp)
		if err != nil {
			p.dropIn(mo, ReasonDatagramFull, m.size)
			return
		}
	}
	p.cells[2*cell+1].add(len(pkt))
}

// seal seals payload with a TX entry of the port session of o on a lane by hash, and sends it to
// the address of that lane. Lane i of 1 to 3 goes to the port address until bit i-1 of seen is set
// (a keepalive from the lane port). It counts the drop when it fails, also in port_drops at the
// meter index mi (0: none).
func (p *Pipeline) seal(port uint64, o PortAction, vni, hash uint32, payload []byte, mi uint32, tx *TxBatch) bool {
	sa := p.st.tx[portSession{port, o.Session}].pick(hash)
	if sa == nil || len(payload)+psp.Overhead > maxPacket {
		p.dropIn(mi, ReasonNoKeys, len(payload))
		return false
	}
	n, err := sa.seal(tx.room(len(payload)+psp.Overhead), vni, payload)
	if err != nil {
		p.dropIn(mi, ReasonNoKeys, len(payload))
		return false
	}
	to := o.Addr
	if sa.lane > 0 && o.Seen&(1<<(sa.lane-1)) != 0 {
		to = laneAddr(o, sa.lane)
	}
	tx.add(to, n)
	return true
}

// toRoot gives a PacketIn to the root's callback, within punt meter i: the meter index of the port
// of the packet, or 0 for a probe.
func (p *Pipeline) toRoot(md PacketInMeta, i uint32, size int, payload []byte) {
	if !p.meter(MeterPunt, i, size) {
		p.dropIn(i, ReasonMeter, size)
		return
	}
	fn := p.packetIn.Load()
	if fn == nil || !(*fn)(&p4.PacketIn{Payload: bytes.Clone(payload), Metadata: md.Metadata()}) {
		p.dropIn(i, ReasonPuntFull, size)
	}
}

func (p *Pipeline) drop(reason uint8, size int) {
	p.drops[reason].add(size)
}

// dropIn counts a drop, also in port_drops at (mi << 5) | reason when the meter index mi is not 0:
// the out port in send_out (tx), else the in port (rx).
func (p *Pipeline) dropIn(mi uint32, reason uint8, size int) {
	p.drop(reason, size)
	if mi != 0 {
		p.portDrops[mi<<5|uint32(reason)].packets.Add(1)
	}
}

// dropAction runs a drop action of a packet whose in port has meter index mi. Each table entry
// action that is not the expected one is a drop.
func (p *Pipeline) dropAction(a Action, size int, mi uint32) {
	if d, ok := a.(DropAction); ok {
		p.dropIn(mi, d.Reason, size)
	}
}

// meter reports whether the packet is green in meter index i. An index with no configuration has
// no limit.
func (p *Pipeline) meter(id, i uint32, size int) bool {
	b := p.st.meters[meterKey{id, i}]
	if b == nil {
		return true
	}
	if meterPackets[id] {
		size = 1
	}
	return b.take(size, time.Now())
}

// fromPort reports whether a PSP packet from the outer address a is from the port: its address,
// its previous address or a lane port at its address.
func fromPort(pa PortAction, a netip.AddrPort) bool {
	switch {
	case !a.IsValid():
		return false
	case a == pa.Addr || a == pa.Prev:
		return true
	case !pa.Addr.IsValid() || a.Addr() != pa.Addr.Addr():
		return false
	}
	for lane := uint8(1); lane < lanes; lane++ {
		if laneAddr(pa, lane) == a {
			return true
		}
	}
	return false
}

// laneAddr returns the outer address of a lane of the port: lane 0 is its address, and lanes 1 to
// 3 are the 16-bit ports of lanes, from the high bits, at its IP address. A port 0 is its address.
func laneAddr(pa PortAction, lane uint8) netip.AddrPort {
	if lane == 0 {
		return pa.Addr
	}
	port := uint16(pa.Lanes >> (48 - 16*uint(lane)))
	if port == 0 {
		return pa.Addr
	}
	return netip.AddrPortFrom(pa.Addr.Addr(), port)
}

// innerAddrs returns the source and destination of an IPv4 or IPv6 packet as 128-bit addresses.
func innerAddrs(pkt []byte) (src, dst netip.Addr, ok bool) {
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4:
		s, d := netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20]))
		return netip.AddrFrom16(s.As16()), netip.AddrFrom16(d.As16()), true
	case len(pkt) >= 40 && pkt[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40])), true
	}
	return netip.Addr{}, netip.Addr{}, false
}

// flowHash hashes the addresses, the protocol and the first 4 bytes of a TCP, UDP or SCTP header
// (the ports) of an IP packet, with FNV-1a.
func flowHash(pkt []byte) uint32 {
	var addrs []byte
	var proto byte
	l4 := -1
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4:
		addrs, proto, l4 = pkt[12:20], pkt[9], int(pkt[0]&0x0f)*4
	case len(pkt) >= 40 && pkt[0]>>4 == 6:
		addrs, proto, l4 = pkt[8:40], pkt[6], 40
	default:
		return 0
	}
	h := uint32(2166136261)
	mix := func(b []byte) {
		for _, x := range b {
			h ^= uint32(x)
			h *= 16777619
		}
	}
	mix(addrs)
	mix([]byte{proto})
	if (proto == 6 || proto == 17 || proto == 132) && l4 >= 20 && len(pkt) >= l4+4 {
		mix(pkt[l4 : l4+4])
	}
	return h
}
