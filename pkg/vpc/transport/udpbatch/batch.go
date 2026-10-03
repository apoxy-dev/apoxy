// SPDX-License-Identifier: AGPL-3.0-only

// Package udpbatch sends UDP packets in batches with one sendmmsg call.
// Packets to one address with the same size go in one UDP GSO message.
package udpbatch

import (
	"errors"
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"
)

const (
	// MaxSegments is the most packets in one GSO message.
	MaxSegments = 64
	// MaxGSOBytes is the most bytes in one GSO message, less than 64 KiB.
	MaxGSOBytes = 65000
)

// Batch collects packets and sends them with one sendmmsg call. Packets to
// one address with the same size go in one message with UDP_SEGMENT, and a
// shorter packet ends the message. The packets to one address stay in
// order. One goroutine at a time can use a Batch.
type Batch struct {
	pc    *ipv4.PacketConn
	gso   bool // False after the socket refuses UDP_SEGMENT.
	pend  []msg
	msgs  []ipv4.Message
	addrs []net.UDPAddr
	oob   [][]byte
	n     int // Packets in the batch.
}

// msg is one message of a batch: packets to dst. All have the size seg, but
// the last one can be shorter.
type msg struct {
	dst   netip.AddrPort
	bufs  [][]byte
	seg   int
	bytes int
	full  bool // A shorter packet ends the message.
}

// New returns a batch of at most size packets for uc. It returns nil when
// the system cannot send a batch with one call.
func New(uc *net.UDPConn, size int) *Batch {
	if !batchWrites {
		return nil
	}
	b := &Batch{
		pc:    ipv4.NewPacketConn(uc),
		gso:   gsoSupported(uc),
		pend:  make([]msg, 0, size),
		msgs:  make([]ipv4.Message, 0, size),
		addrs: make([]net.UDPAddr, size),
		oob:   make([][]byte, size),
	}
	for i := range b.addrs {
		b.addrs[i].IP = make(net.IP, net.IPv6len)
	}
	return b
}

// Len returns the number of packets in the batch. Flush the batch before it
// has more than size packets.
func (b *Batch) Len() int { return b.n }

// Add adds the packet p to dst. The batch keeps p until Flush returns.
func (b *Batch) Add(p []byte, dst netip.AddrPort) {
	b.n++
	// The newest message to dst takes p if it can.
	for i := len(b.pend) - 1; i >= 0; i-- {
		m := &b.pend[i]
		if m.dst != dst {
			continue
		}
		if b.gso && !m.full && len(m.bufs) < MaxSegments && len(p) <= m.seg && m.bytes+len(p) <= MaxGSOBytes {
			m.bufs = append(m.bufs, p)
			m.bytes += len(p)
			m.full = len(p) < m.seg
			return
		}
		break
	}
	b.pend = b.pend[:len(b.pend)+1]
	m := &b.pend[len(b.pend)-1]
	m.dst, m.bufs, m.seg, m.bytes, m.full = dst, append(m.bufs[:0], p), len(p), len(p), false
}

// Flush sends the batch and empties it. It returns the packets that the
// socket took and the packets that it refused. When the socket is closed,
// it returns net.ErrClosed and does not count the packets that are left.
// A bad packet, for example one larger than the MTU, does not stop GSO.
func (b *Batch) Flush() (sent, dropped int, err error) {
	msgs := b.msgs[:0]
	for i := range b.pend {
		m := &b.pend[i]
		a := &b.addrs[i]
		ip := m.dst.Addr().As16()
		copy(a.IP, ip[:])
		a.Port, a.Zone = int(m.dst.Port()), m.dst.Addr().Zone()
		msg := ipv4.Message{Buffers: m.bufs, Addr: a}
		if len(m.bufs) > 1 {
			b.oob[i] = appendSegmentSize(b.oob[i][:0], uint16(m.seg))
			msg.OOB = b.oob[i]
		}
		msgs = append(msgs, msg)
	}
	for len(msgs) > 0 {
		n, werr := b.pc.WriteBatch(msgs, 0)
		n = max(n, 0) // It is -1 when the first message fails.
		for _, m := range msgs[:n] {
			sent += len(m.Buffers)
		}
		msgs = msgs[n:]
		if werr == nil || len(msgs) == 0 {
			continue
		}
		if errors.Is(werr, net.ErrClosed) {
			err = werr
			break
		}
		if len(msgs[0].Buffers) > 1 && isGSOError(werr) {
			// Send the rest one packet at a time. If the first packet goes, the
			// socket refuses GSO, so do not use GSO on it again.
			msgs = splitGSO(msgs)
			if n, _ := b.pc.WriteBatch(msgs[:1], 0); n == 1 {
				b.gso = false
				sent++
				msgs = msgs[1:]
				continue
			}
		}
		dropped += len(msgs[0].Buffers)
		msgs = msgs[1:]
	}
	for i := range b.pend {
		clear(b.pend[i].bufs)
	}
	clear(b.msgs[:cap(b.msgs)])
	b.pend = b.pend[:0]
	b.n = 0
	return sent, dropped, err
}

// splitGSO returns msgs with one message for each packet.
func splitGSO(msgs []ipv4.Message) []ipv4.Message {
	var out []ipv4.Message
	for _, m := range msgs {
		for _, p := range m.Buffers {
			out = append(out, ipv4.Message{Buffers: [][]byte{p}, Addr: m.Addr})
		}
	}
	return out
}
