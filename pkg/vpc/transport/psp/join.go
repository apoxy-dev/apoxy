// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// maxJoined is the most bytes of a joined packet. The length fields of IPv4 and IPv6 have
// 16 bits.
const maxJoined = 1<<16 - 1

// headLen is the size of the first view of a joined packet. It holds all the bytes that the
// netstack and its receive filter read as headers, which are 112 at most.
const headLen = 128

// rxPacket is a packet for the netstack, made from the slots first to first+n-1 of a set.
type rxPacket struct {
	pkb      *stack.PacketBuffer
	w        int // The inject worker.
	first, n int
}

// tcpSeg is the headers of an inner TCP segment.
type tcpSeg struct {
	ipLen, hdrLen int // hdrLen is the length of the IP header and the TCP header.
	payload       int
	seq           uint32
	flags         header.TCPFlags
}

// tcpRun is TCP segments of one flow in consecutive slots, which join into one packet.
type tcpRun struct {
	first, n int
	hdr      []byte          // The first segment.
	seg      tcpSeg          // The headers of the first segment.
	size     int             // The bytes of the joined packet.
	next     uint32          // The sequence number of the next segment.
	flags    header.TCPFlags // The PSH and FIN flags of the segments.
	closed   bool            // A short segment or a segment with PSH or FIN ended the run.
}

// joiner makes the packets for the netstack of one set.
type joiner struct {
	j   *injectBatch
	res []openResult
	out []rxPacket
	n   int
	r   tcpRun
}

// join puts the packets of the opened slots res in out, in slot order, and returns their
// number. TCP segments of one flow in consecutive slots join into one packet, as in GRO.
func (j *injectBatch) join(res []openResult, out []rxPacket) int {
	jn := joiner{j: j, res: res, out: out}
	for i := range res {
		jn.add(i)
	}
	jn.flush()
	return jn.n
}

// add adds slot i to the run, or ends the run and starts a new one.
func (jn *joiner) add(i int) {
	if !jn.res[i].ok {
		jn.flush()
		return
	}
	pkt := jn.res[i].inner
	seg, ok := parseSeg(pkt)
	if !ok {
		jn.flush()
		if pkb, w := jn.j.make(pkt); pkb != nil {
			jn.emit(rxPacket{pkb: pkb, w: w, first: i, n: 1})
		}
		return
	}
	r := &jn.r
	if r.n > 0 && r.joins(pkt, &seg) {
		r.n++
		r.size += seg.payload
		r.next += uint32(seg.payload)
		r.flags |= seg.flags & (header.TCPFlagPsh | header.TCPFlagFin)
		r.closed = seg.payload < r.seg.payload || seg.flags&(header.TCPFlagPsh|header.TCPFlagFin) != 0
		return
	}
	jn.flush()
	*r = tcpRun{
		first: i, n: 1, hdr: pkt, seg: seg, size: len(pkt),
		next:   seg.seq + uint32(seg.payload),
		flags:  seg.flags & (header.TCPFlagPsh | header.TCPFlagFin),
		closed: seg.payload == 0 || seg.flags&(header.TCPFlagPsh|header.TCPFlagFin) != 0,
	}
}

// flush makes the packet of the run and ends the run.
func (jn *joiner) flush() {
	if jn.r.n == 0 {
		return
	}
	jn.emit(jn.j.packet(jn.res, &jn.r))
	jn.r.n = 0
}

func (jn *joiner) emit(p rxPacket) {
	jn.out[jn.n] = p
	jn.n++
}

// parseSeg parses an inner packet as a TCP segment that can join a run: IPv4 with no
// options and no fragment, or IPv6 with no extension header, with no SYN, RST, URG or CWR.
func parseSeg(pkt []byte) (tcpSeg, bool) {
	var s tcpSeg
	switch {
	case len(pkt) >= header.IPv4MinimumSize+header.TCPMinimumSize && pkt[0] == 0x45:
		if pkt[9] != uint8(header.TCPProtocolNumber) || binary.BigEndian.Uint16(pkt[6:])&0x3fff != 0 ||
			int(binary.BigEndian.Uint16(pkt[2:])) != len(pkt) {
			return s, false
		}
		s.ipLen = header.IPv4MinimumSize
	case len(pkt) >= header.IPv6MinimumSize+header.TCPMinimumSize && pkt[0]>>4 == 6:
		if pkt[6] != uint8(header.TCPProtocolNumber) ||
			int(binary.BigEndian.Uint16(pkt[4:]))+header.IPv6MinimumSize != len(pkt) {
			return s, false
		}
		s.ipLen = header.IPv6MinimumSize
	default:
		return s, false
	}
	t := pkt[s.ipLen:]
	s.hdrLen = s.ipLen + int(t[12]>>4)*4
	if s.hdrLen < s.ipLen+header.TCPMinimumSize || s.hdrLen > len(pkt) {
		return s, false
	}
	s.flags = header.TCPFlags(t[13])
	if s.flags&(header.TCPFlagSyn|header.TCPFlagRst|header.TCPFlagUrg|header.TCPFlagCwr) != 0 {
		return s, false
	}
	s.payload = len(pkt) - s.hdrLen
	s.seq = binary.BigEndian.Uint32(t[4:])
	return s, true
}

// joins reports whether pkt continues the run. Its headers can differ from the first
// segment only in lengths, IPv4 ID, checksums, sequence number, PSH and FIN.
func (r *tcpRun) joins(pkt []byte, seg *tcpSeg) bool {
	f := &r.seg
	if r.closed || seg.payload == 0 || seg.payload > f.payload || seg.hdrLen != f.hdrLen ||
		seg.seq != r.next || r.size+seg.payload > maxJoined {
		return false
	}
	h := r.hdr
	if f.ipLen == header.IPv4MinimumSize {
		if !bytes.Equal(pkt[:2], h[:2]) || !bytes.Equal(pkt[8:10], h[8:10]) || !bytes.Equal(pkt[12:20], h[12:20]) {
			return false
		}
	} else if !bytes.Equal(pkt[:4], h[:4]) || !bytes.Equal(pkt[6:40], h[6:40]) {
		return false
	}
	t, th := pkt[f.ipLen:f.hdrLen], h[f.ipLen:f.hdrLen]
	return bytes.Equal(t[:4], th[:4]) && bytes.Equal(t[8:13], th[8:13]) &&
		(t[13]^th[13])&^uint8(header.TCPFlagPsh|header.TCPFlagFin) == 0 &&
		bytes.Equal(t[14:16], th[14:16]) && bytes.Equal(t[20:], th[20:])
}

// packet makes the packet of the run r. The netstack copies the whole view that holds a
// header when the view is shared, thus the first view holds only the first headLen bytes.
func (j *injectBatch) packet(res []openResult, r *tcpRun) rxPacket {
	if r.n == 1 {
		pkb, w := j.make(r.hdr)
		return rxPacket{pkb: pkb, w: w, first: r.first, n: 1}
	}
	hl := r.seg.hdrLen
	hv := buffer.NewView(min(headLen, r.size))
	var pv *buffer.View
	if r.size > headLen {
		pv = buffer.NewView(r.size - headLen)
	}
	put := func(p []byte) {
		n := min(headLen-hv.Size(), len(p))
		_, _ = hv.Write(p[:n])
		if n < len(p) {
			_, _ = pv.Write(p[n:])
		}
	}
	put(r.hdr)
	for _, s := range res[r.first+1 : r.first+r.n] {
		put(s.inner[hl:])
	}
	b := hv.AsSlice()
	proto := header.IPv6ProtocolNumber
	if r.seg.ipLen == header.IPv4MinimumSize {
		proto = header.IPv4ProtocolNumber
		h := header.IPv4(b)
		h.SetTotalLength(uint16(r.size))
		h.SetChecksum(0)
		h.SetChecksum(^h.CalculateChecksum())
	} else {
		header.IPv6(b).SetPayloadLength(uint16(r.size - header.IPv6MinimumSize))
	}
	b[r.seg.ipLen+13] |= uint8(r.flags)
	buf := buffer.MakeWithView(hv)
	if pv != nil {
		payload := buffer.MakeWithView(pv)
		buf.Merge(&payload)
	}
	pkb, w := j.wrap(buf, proto, b)
	return rxPacket{pkb: pkb, w: w, first: r.first, n: r.n}
}
