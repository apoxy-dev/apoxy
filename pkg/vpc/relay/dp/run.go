// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"bytes"
	"cmp"
	"slices"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/apoxy-dev/softpsp/psp"
)

// maxPacket is the size of a send buffer: the largest UDP payload.
const maxPacket = 65535

// part is one part of a batch in the generated pipeline (parse and apply of relay.gen.go): the
// tables of one read of cur, and the batch of the ops and of the packets out.
type part struct {
	p  *Pipeline
	st *state
	tx *TxBatch
}

// packet is one packet of a part: the pass of the generated pipeline, and the open op of Open.
type packet struct {
	pass
	mem int   // The memory of the packet in the batch.
	sa  *rxSA // The RX entry of Open.
	op  int   // The open op of Open in the opens of the batch.
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
		x := part{p: p, st: p.cur, tx: tx}
		// reset leaves the packets zero: no header is valid.
		tx.pkts = slices.Grow(tx.pkts[:0], n)[:n]
		for i, r := range rx[:n] {
			pkt := &tx.pkts[i]
			pkt.mem, pkt.in, pkt.m.from, pkt.sm.packetLength = r.mem, r.Payload, r.From, uint32(len(r.Payload))
			x.parse(pkt)
		}
		if len(tx.opens) > 0 {
			p.aead.Open(tx.memories(), tx.opens)
		}
		for i := range tx.pkts {
			x.run(&tx.pkts[i])
		}
		if len(tx.seals) > 0 {
			p.aead.Seal(tx.memories(), tx.seals)
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

// run runs apply on pkt. When apply ends with packet_in valid, it gives the root a PacketIn with
// the packet after the parsed headers.
func (x *part) run(pkt *packet) {
	x.apply(pkt)
	if !pkt.h.packetIn.valid {
		return
	}
	fn := x.p.packetIn.Load()
	if fn == nil || !(*fn)(&p4.PacketIn{Payload: bytes.Clone(pkt.data), Metadata: pkt.h.packetIn.metadata().Metadata()}) {
		x.drop(pkt, ReasonPuntFull)
	}
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
	x := part{p: p, st: st, tx: tx}
	switch md.Kind {
	case KindFrame:
		// A FRAME in starts at the parser on the CPU port. The AEAD reads only the memories of the
		// batch, so the frame goes there first.
		_, off := tx.in(0, b)
		tx.pkts = append(tx.pkts[:0], packet{})
		pkt := &tx.pkts[0]
		pkt.in, pkt.ctl = tx.buf[off:off+len(b)], md
		pkt.sm.ingressPort, pkt.sm.packetLength = cpuPort, uint32(len(b))
		x.parse(pkt)
		x.run(pkt)
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
		x.seal(md.Port, o, psp.NextHdrMessage, 0, 0, tx.buf[off:off+len(b)], 0, 0)
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

// countIndex counts pkt at index i of counter id. drops counts the length of the packet in, cells
// the inner length, and port_drops only packets.
func (x *part) countIndex(id, i uint32, pkt *packet) {
	cs, n := x.p.cells, len(pkt.data)
	switch id {
	case CounterDrops:
		cs, n = x.p.drops, int(pkt.sm.packetLength)
	case CounterPortDrops:
		if int(i) < len(x.p.portDrops) {
			x.p.portDrops[i].packets.Add(1)
		}
		return
	}
	if int(i) < len(cs) {
		cs[i].add(n)
	}
}

// executeMeter gives the color of pkt in index i of meter id: 0 (green), or meterRed. The meters
// take the length of the packet in.
func (x *part) executeMeter(id, i uint32, pkt *packet) uint8 {
	if x.st.meter(id, i, int(pkt.sm.packetLength)) {
		return 0
	}
	return meterRed
}

// drop counts pkt as count_drop of relay.p4 does: in drops, and in port_drops at the out meter index,
// or else at the meter index of the in port.
func (x *part) drop(pkt *packet, reason uint8) {
	x.p.dropIn(cmp.Or(pkt.m.outMeterIndex, pkt.m.p.meterIndex), reason, int(pkt.sm.packetLength))
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
