// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"errors"
	"net"
	"net/netip"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/ipv4"
)

const (
	// maxFwd is the most packets in one batch, and thus in one GSO message.
	// A full batch is sent at once.
	maxFwd = 64
	// maxGSOBytes is the most bytes in one GSO message, less than 64 KiB.
	maxGSOBytes = 65000
)

// fwdBatch collects the PSP packets that one read of the QUIC read loop
// forwards, and sends them at the end of the read with one sendmmsg call.
// Packets to one address with the same size go in one message with UDP GSO.
// Only the read loop of the transport uses it.
type fwdBatch struct {
	tr    *quic.Transport
	pc    *ipv4.PacketConn // Nil when the socket cannot send batches.
	gso   bool             // False after the socket refuses UDP_SEGMENT.
	addrs addrCache

	slab []byte // maxFwd slots of maxUDP bytes.
	n    int    // Used slots.
	pend []fwdMsg
	msgs []ipv4.Message
	oob  [maxFwd][]byte
}

// fwdMsg is one message of a batch: packets to dst. All have the size seg,
// but the last one can be shorter.
type fwdMsg struct {
	dst   netip.AddrPort
	bufs  [][]byte
	seg   int
	bytes int
	full  bool // A shorter packet ends the message.
}

func newFwdBatch(tr *quic.Transport) *fwdBatch {
	f := &fwdBatch{tr: tr}
	if uc, ok := tr.Conn.(*net.UDPConn); ok && batchWrites {
		f.pc = ipv4.NewPacketConn(uc)
		f.gso = gsoSupported(uc)
		f.slab = make([]byte, maxFwd*maxUDP)
		f.pend = make([]fwdMsg, 0, maxFwd)
		f.msgs = make([]ipv4.Message, 0, maxFwd)
	}
	return f
}

// add copies b to the batch. A socket with no batches sends it at once.
func (f *fwdBatch) add(b []byte, dst netip.AddrPort) {
	if f.pc == nil || len(b) > maxUDP {
		_, _ = f.tr.WriteTo(b, f.addrs.get(dst))
		return
	}
	if f.n == maxFwd {
		f.flush()
	}
	p := f.slab[f.n*maxUDP : f.n*maxUDP+len(b) : (f.n+1)*maxUDP]
	copy(p, b)
	f.n++
	// The newest message to dst takes p if it can. The packets to one
	// address stay in order.
	for i := len(f.pend) - 1; i >= 0; i-- {
		m := &f.pend[i]
		if m.dst != dst {
			continue
		}
		if f.gso && !m.full && len(p) <= m.seg && m.bytes+len(p) <= maxGSOBytes {
			m.bufs = append(m.bufs, p)
			m.bytes += len(p)
			m.full = len(p) < m.seg
			return
		}
		break
	}
	f.pend = f.pend[:len(f.pend)+1]
	m := &f.pend[len(f.pend)-1]
	m.dst, m.bufs, m.seg, m.bytes, m.full = dst, append(m.bufs[:0], p), len(p), len(p), false
}

// flush sends the batch. It drops a message that the socket refuses. A bad
// packet, for example one larger than the MTU, does not stop GSO.
func (f *fwdBatch) flush() {
	if len(f.pend) == 0 {
		return
	}
	msgs := f.msgs[:0]
	for i := range f.pend {
		m := &f.pend[i]
		msg := ipv4.Message{Buffers: m.bufs, Addr: f.addrs.get(m.dst)}
		if len(m.bufs) > 1 {
			f.oob[i] = appendSegmentSize(f.oob[i][:0], uint16(m.seg))
			msg.OOB = f.oob[i]
		}
		msgs = append(msgs, msg)
	}
	for len(msgs) > 0 {
		n, err := f.pc.WriteBatch(msgs, 0)
		msgs = msgs[max(n, 0):]
		if err == nil || len(msgs) == 0 {
			continue
		}
		if errors.Is(err, net.ErrClosed) {
			break
		}
		if len(msgs[0].Buffers) > 1 && isGSOError(err) {
			// Send the rest one packet at a time. If the first packet goes, the
			// socket refuses GSO, so do not use GSO on it again.
			msgs = splitGSO(msgs)
			if n, _ := f.pc.WriteBatch(msgs[:1], 0); n == 1 {
				f.gso = false
			}
		}
		msgs = msgs[1:]
	}
	clear(f.msgs[:cap(f.msgs)])
	f.pend = f.pend[:0]
	f.n = 0
}

// splitGSO returns msgs with one message for each packet.
func splitGSO(msgs []ipv4.Message) []ipv4.Message {
	var out []ipv4.Message
	for _, m := range msgs {
		for _, b := range m.Buffers {
			out = append(out, ipv4.Message{Buffers: [][]byte{b}, Addr: m.Addr})
		}
	}
	return out
}
