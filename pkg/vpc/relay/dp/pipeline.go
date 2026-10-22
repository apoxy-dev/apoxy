// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"bytes"
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
	lane    uint8
	vni     uint32
	from    netip.AddrPort
	psp     bool // A PSP packet, not a FRAME in.
	size    int  // The bytes that the meters and the drops count.
}

// Receive runs the pipeline on one UDP payload b of port 1000 from the outer address from. It
// changes b. Keepalives drop with no count, and probes go to the root.
func (p *Pipeline) Receive(from netip.AddrPort, b []byte) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(b) == 1 && b[0] == p2p.TypeKeepalive {
		return
	}
	if _, ok := p2p.ProbeSID(b); ok {
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
	p.apply(&meta{port: sa.port, session: sa.session, lane: sa.lane, vni: h.VNI, from: from, psp: true, size: len(b)}, payload)
}

// PacketOut takes FRAME in, SEAL and RAW. An error is only for a bad request; a packet that the
// pipeline drops is counted in drops.
func (p *Pipeline) PacketOut(po *p4.PacketOut) error {
	md, err := DecodePacketOutMeta(po.GetMetadata())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	b := po.GetPayload()
	p.mu.RLock()
	defer p.mu.RUnlock()
	switch md.Kind {
	case KindFrame:
		vni, inner, err := peerconn.DecodeData(b)
		if err != nil {
			p.drop(ReasonMalformed, len(b))
			return nil
		}
		p.apply(&meta{port: md.Port, session: md.Session, vni: vni, size: len(b)}, inner)
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
		p.seal(md.Port, o, 0, 0, b)
	case KindRaw:
		if !md.To.IsValid() {
			return status.Error(codes.InvalidArgument, "RAW has no outer address")
		}
		p.send(md.To, b)
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
func (p *Pipeline) apply(m *meta, pkt []byte) {
	// ports.
	var act Action = p.defaults[TablePorts]
	if e := p.st.ports[m.port]; e != nil {
		act = e.action
	}
	pa, ok := act.(PortAction)
	if !ok {
		p.dropAction(act, m.size)
		return
	}

	// check_in.
	if m.session != pa.Session {
		p.drop(ReasonOldSession, m.size)
		return
	}
	if m.psp {
		if !fromPort(pa, m.from) {
			p.drop(ReasonUnknownSource, m.size)
			return
		}
		if !p.meter(MeterLane, 4*pa.MeterIndex+uint32(m.lane), m.size) {
			p.drop(ReasonMeter, m.size)
			return
		}
	}
	if !p.meter(MeterPort, pa.MeterIndex, m.size) {
		p.drop(ReasonMeter, m.size)
		return
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
		p.drop(ReasonMalformed, m.size)
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
		p.dropAction(act, m.size)
		return
	}
	if !pa.Trunk && m.vni != c.VNI {
		p.drop(ReasonNoContext, m.size)
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
		p.dropAction(a, m.size)
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
			p.drop(ReasonNoRoute, m.size)
			return
		}
	case NoAction:
		if pa.Trunk {
			p.drop(ReasonNoRoute, m.size)
			return
		}
		p.toRoot(PacketInMeta{Kind: KindMiss, Port: m.port, Session: pa.Session, Hash: hash, From: m.from}, pa.MeterIndex, m.size, pkt)
		return
	default:
		p.dropAction(a, m.size)
		return
	}

	// send_out.
	o, ok := p.port(out)
	switch {
	case !ok:
		p.drop(ReasonNoTarget, m.size)
		return
	case pa.Trunk && o.Trunk:
		p.drop(ReasonTrunkToTrunk, m.size)
		return
	case localOnly && o.Trunk:
		p.drop(ReasonLocalOnly, m.size)
		return
	case o.MTU != 0 && len(pkt) > int(o.MTU):
		p.drop(ReasonMTU, m.size)
		return
	}
	if o.Addr.IsValid() {
		vni := c.VNI
		if o.Trunk {
			vni = pa.Tag
		}
		if !p.seal(out, o, vni, hash, pkt) {
			return
		}
	} else {
		w := p.writers[out]
		if w == nil {
			p.drop(ReasonNoTarget, m.size)
			return
		}
		bp := p.bufs.Get().(*[]byte)
		err := w(peerconn.EncodeData((*bp)[:0], c.VNI, pkt))
		p.bufs.Put(bp)
		if err != nil {
			p.drop(ReasonDatagramFull, m.size)
			return
		}
	}
	p.cells[2*cell+1].add(len(pkt))
}

// seal seals payload with a TX entry of the port session of o on a lane by hash, and sends it to
// the address of that lane. It counts the drop when it fails.
func (p *Pipeline) seal(port uint64, o PortAction, vni, hash uint32, payload []byte) bool {
	sa := p.st.tx[portSession{port, o.Session}].pick(hash)
	if sa == nil || len(payload)+psp.Overhead > maxPacket {
		p.drop(ReasonNoKeys, len(payload))
		return false
	}
	bp := p.bufs.Get().(*[]byte)
	defer p.bufs.Put(bp)
	n, err := sa.seal(*bp, vni, payload)
	if err != nil {
		p.drop(ReasonNoKeys, len(payload))
		return false
	}
	p.send(laneAddr(o, sa.lane), (*bp)[:n])
	return true
}

// toRoot gives a PacketIn to the root's callback, within punt meter i.
func (p *Pipeline) toRoot(md PacketInMeta, i uint32, size int, payload []byte) {
	if !p.meter(MeterPunt, i, size) {
		p.drop(ReasonMeter, size)
		return
	}
	fn := p.packetIn.Load()
	if fn == nil || !(*fn)(&p4.PacketIn{Payload: bytes.Clone(payload), Metadata: md.Metadata()}) {
		p.drop(ReasonPuntFull, size)
	}
}

func (p *Pipeline) drop(reason uint8, size int) {
	p.drops[reason].add(size)
}

// dropAction runs a drop action. Each table entry action that is not the expected one is a drop.
func (p *Pipeline) dropAction(a Action, size int) {
	if d, ok := a.(DropAction); ok {
		p.drop(d.Reason, size)
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
