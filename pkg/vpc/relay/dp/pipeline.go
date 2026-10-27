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
	mem     int  // The memory of the packet in the batch.
}

// rxState is the parse result of one RX packet of a part of Receive.
type rxState struct {
	drop uint8 // A drop reason, or 0.
	sa   *rxSA // The RX entry. nil with drop 0: a probe or a keepalive, for the root.
	h    psp.Header
	op   int // The open op of the packet in the opens of the batch.
}

// Receive runs the pipeline on all packets of rx. It gives the sealed PSP and RAW packets of each
// part of rxBatch packets to one Send(tx), and resets tx. Probes and keepalives go to the root. A
// part has five steps: under one read lock and one read of cur, parse each packet, open the PSP
// packets with one AEAD call, apply each packet in RX order, and seal the packets out with one AEAD
// call; then Send.
func (p *Pipeline) Receive(rx []RxPacket, tx *TxBatch) {
	// Each packet sends at most one packet, so a part of rxBatch packets keeps tx to rxBatch.
	for len(rx) > 0 {
		n := min(len(rx), rxBatch)
		p.mu.RLock()
		st := p.cur
		for _, pkt := range rx[:n] {
			p.parse(st, pkt, tx)
		}
		if len(tx.opens) > 0 {
			p.aead.Open(tx.memories(), tx.opens)
		}
		for i, pkt := range rx[:n] {
			p.receive(st, pkt, &tx.rx[i], tx)
		}
		if len(tx.seals) > 0 {
			p.aead.Seal(tx.memories(), tx.seals)
		}
		p.mu.RUnlock()
		p.flush(tx)
		rx = rx[n:]
	}
}

// parse is the parser and open_psp up to the AEAD, for one UDP payload of port 1000, with the tables
// st. It adds the result to tx.rx: a punt, a drop reason, or an open op of the PSP packet in the
// memory of tx. It counts nothing, so that receive counts in RX order.
func (p *Pipeline) parse(st *state, pkt RxPacket, tx *TxBatch) {
	rs := rxState{op: -1}
	b := pkt.Payload
	if _, ok := p2p.ProbeSID(b); !ok && !(len(b) == 1 && b[0] == p2p.TypeKeepalive) {
		h, err := psp.ParseTrunkHeader(b)
		var sa *rxSA
		if err == nil {
			sa = st.rx[h.SPI]
		}
		switch {
		case err != nil:
			rs.drop = ReasonMalformed
		case sa == nil:
			rs.drop = ReasonUnknownSPI
		case !sa.accepts(h):
			rs.drop = ReasonOpen
		default:
			mem, off := tx.in(pkt.mem, b)
			rs.sa, rs.h, rs.op = sa, h, len(tx.opens)
			tx.opens = append(tx.opens, AEADOp{Key: sa.key, Mem: mem, Off: off, Len: len(b)})
		}
	}
	tx.rx = append(tx.rx, rs)
}

// flush gives tx to the Sender when it has packets, and resets it.
func (p *Pipeline) flush(tx *TxBatch) {
	if tx.Len() > 0 {
		p.send.Send(tx)
	}
	tx.reset()
}

// receive runs the rest of the pipeline on one UDP payload of port 1000 with its parse result rs,
// after the open call.
func (p *Pipeline) receive(st *state, pkt RxPacket, rs *rxState, tx *TxBatch) {
	b := pkt.Payload
	switch {
	case rs.drop != 0:
		p.drop(rs.drop, len(b))
		return
	case rs.sa == nil:
		p.toRoot(st, PacketInMeta{Kind: KindPunt, From: pkt.From}, 0, len(b), b)
		return
	}
	// open_psp: the result of the open call, Next Header and the replay window.
	sa, op := rs.sa, &tx.opens[rs.op]
	payload, ok := sa.opened(rs.h, tx.memories()[op.Mem][op.Off:op.Off+op.Len], op.OK)
	if !ok {
		p.drop(ReasonOpen, len(b))
		return
	}
	p.apply(st, &meta{port: sa.port, session: sa.session, spi: sa.spi, lane: sa.lane, vni: rs.h.VNI, from: pkt.From, psp: true, size: len(b), mem: op.Mem}, payload, tx)
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
	err = p.packetOut(p.cur, md, po.GetPayload(), tx)
	if len(tx.seals) > 0 {
		p.aead.Seal(tx.memories(), tx.seals)
	}
	p.mu.RUnlock()
	p.flush(tx)
	return err
}

func (p *Pipeline) packetOut(st *state, md PacketOutMeta, b []byte, tx *TxBatch) error {
	switch md.Kind {
	case KindFrame:
		vni, inner, err := peerconn.DecodeData(b)
		if err != nil {
			p.drop(ReasonMalformed, len(b))
			return nil
		}
		// The AEAD reads only the memories of the batch, so the inner packet goes there first.
		_, off := tx.in(0, inner)
		p.apply(st, &meta{port: md.Port, session: md.Session, vni: vni, size: len(b)}, tx.buf[off:off+len(inner)], tx)
	case KindSeal:
		// SEAL skips apply: M's trunk messages and probes, with tag 0. A message is never IP.
		o, ok := st.port(md.Port)
		if !ok || !o.Addr.IsValid() {
			p.drop(ReasonNoTarget, len(b))
			return nil
		}
		if o.Session != md.Session {
			p.drop(ReasonOldSession, len(b))
			return nil
		}
		_, off := tx.in(0, b)
		p.seal(st, md.Port, o, psp.NextHdrMessage, 0, 0, tx.buf[off:off+len(b)], 0, 0, tx)
	case KindRaw:
		if !md.To.IsValid() {
			return status.Error(codes.InvalidArgument, "RAW has no outer address")
		}
		off := tx.slot(len(b))
		tx.add(md.To, off, copy(tx.buf[off:], b))
	default:
		return status.Errorf(codes.InvalidArgument, "packet_out kind %d is not FRAME, SEAL or RAW", md.Kind)
	}
	return nil
}

// port returns the port action of the ports entry of id.
func (s *state) port(id uint64) (PortAction, bool) {
	if e := s.ports[id]; e != nil {
		a, ok := e.action.(PortAction)
		return a, ok
	}
	return PortAction{}, false
}

// apply is the apply block of the Relay control, from ports to send_out, with the tables st.
func (p *Pipeline) apply(st *state, m *meta, pkt []byte, tx *TxBatch) {
	// ports.
	var act Action = p.defaults[TablePorts]
	if e := st.ports[m.port]; e != nil {
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
		if !st.meter(MeterLane, 4*pa.MeterIndex+uint32(m.lane), m.size) {
			p.dropIn(pa.MeterIndex, ReasonMeter, m.size)
			return
		}
	}
	if !st.meter(MeterPort, pa.MeterIndex, m.size) {
		p.dropIn(pa.MeterIndex, ReasonMeter, m.size)
		return
	}
	if m.psp {
		st.count(m.spi)
	}

	// read_tag: a trunk packet carries the sender's session tag in the VNI field. Tag 0 is for M.
	var tag uint32
	if pa.Trunk {
		tag = m.vni
		if tag == 0 {
			p.toRoot(st, PacketInMeta{Kind: KindPunt, Port: m.port, Session: pa.Session, From: m.from}, pa.MeterIndex, m.size, pkt)
			return
		}
	}
	src, dst, nh, ok := innerAddrs(pkt)
	if !ok {
		p.dropIn(pa.MeterIndex, ReasonMalformed, m.size)
		return
	}

	// classify.
	act = p.defaults[TableClassify]
	var vpc uint32
	if e := st.classify[ClassifyKey{Port: m.port, Session: pa.Session, Tag: tag}]; e != nil {
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
	if l := st.source[setKey{m.port, pa.Session, tag}]; l != nil {
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
	if l := st.route[vpc]; l != nil {
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
		p.toRoot(st, PacketInMeta{Kind: KindMiss, Port: m.port, Session: pa.Session, Hash: hash, From: m.from}, pa.MeterIndex, m.size, pkt)
		return
	default:
		p.dropAction(a, m.size, pa.MeterIndex)
		return
	}

	// send_out. After the ports entry of the out port, a drop counts at its meter index
	// (out_meter_index).
	o, ok := st.port(out)
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
		if !p.seal(st, out, o, nh, vni, hash, pkt, m.mem, mo, tx) {
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

// seal seals payload with the Next Header nh and a TX entry of the port session of o on a lane by
// hash, and sends it to the address of that lane. Lane i of 1 to 3 goes to the port address until bit i-1 of seen is set
// (a keepalive from the lane port). payload is in memory mem of tx. seal writes the PSP header into
// the room of the next packet (the next TX frame of a batch of a worker) and adds a seal op; the
// seal call encrypts later. It counts no_keys when it fails, also in port_drops at the meter index
// mi (0: none). With no room, the packet counts tx_full, and seal reports true, as for a full TX
// ring.
func (p *Pipeline) seal(st *state, port uint64, o PortAction, nh uint8, vni, hash uint32, payload []byte, mem int, mi uint32, tx *TxBatch) bool {
	sa := st.tx[portSession{port, o.Session}].pick(hash)
	n := len(payload) + psp.Overhead
	if sa == nil || n > maxPacket {
		p.dropIn(mi, ReasonNoKeys, len(payload))
		return false
	}
	// The offset first: room can move the buf of a batch with no mems.
	src := tx.offset(mem, payload)
	off, ok := tx.room(n)
	if !ok {
		p.drop(ReasonTXFull, n)
		return true
	}
	ms := tx.memories()
	if err := sa.put(ms[tx.txMem][off:off+psp.PrefixLen], nh, vni); err != nil {
		p.dropIn(mi, ReasonNoKeys, len(payload))
		return false
	}
	tx.seals = append(tx.seals, AEADOp{Key: sa.key, Mem: tx.txMem, Off: off, Len: n, SrcMem: mem, Src: src})
	to := o.Addr
	if sa.lane > 0 && o.Seen&(1<<(sa.lane-1)) != 0 {
		to = laneAddr(o, sa.lane)
	}
	tx.add(to, off, n)
	return true
}

// toRoot gives a PacketIn to the root's callback, within punt meter i: the meter index of the port
// of the packet, or 0 for a probe.
func (p *Pipeline) toRoot(st *state, md PacketInMeta, i uint32, size int, payload []byte) {
	if !st.meter(MeterPunt, i, size) {
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
func (s *state) meter(id, i uint32, size int) bool {
	b := s.meters[meterKey{id, i}]
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

// innerAddrs returns the source and destination of an IPv4 or IPv6 packet as 128-bit addresses,
// and its PSP Next Header: NextHdrV4 or NextHdrV6.
func innerAddrs(pkt []byte) (src, dst netip.Addr, nh uint8, ok bool) {
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4:
		s, d := netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20]))
		return netip.AddrFrom16(s.As16()), netip.AddrFrom16(d.As16()), psp.NextHdrV4, true
	case len(pkt) >= 40 && pkt[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40])), psp.NextHdrV6, true
	}
	return netip.Addr{}, netip.Addr{}, 0, false
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
