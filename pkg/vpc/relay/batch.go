// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/udpbatch"
)

// maxFwd is the most packets in one batch. A full batch is sent at once.
const maxFwd = 64

// sendStats counts the sendmmsg calls of the forwarders, their messages and the
// packets that the socket took.
type sendStats struct {
	calls, messages, packets atomic.Uint64
}

// flush sends the batch b and counts it.
func (s *sendStats) flush(b *udpbatch.Batch) {
	msgs := b.Messages()
	if msgs == 0 {
		return
	}
	// A packet that the socket refuses drops.
	sent, _, _ := b.Flush()
	s.calls.Add(1)
	s.messages.Add(uint64(msgs))
	s.packets.Add(uint64(sent))
}

// fwdBatch collects the PSP packets that one read of the QUIC read loop
// forwards, and sends them at the end of the read with one sendmmsg call.
// Only the read loop of the transport uses it. It is the forwarder with one CPU.
type fwdBatch struct {
	tr    *quic.Transport
	b     *udpbatch.Batch // Nil when the socket cannot send batches.
	stats *sendStats
	addrs addrCache
	slab  []byte // maxFwd slots of maxUDP bytes.
}

func newFwdBatch(tr *quic.Transport, stats *sendStats) *fwdBatch {
	f := &fwdBatch{tr: tr, stats: stats}
	if uc, ok := tr.Conn.(*net.UDPConn); ok {
		if f.b = udpbatch.New(uc, maxFwd); f.b != nil {
			f.slab = make([]byte, maxFwd*maxUDP)
		}
	}
	return f
}

// add copies b to the batch. A socket with no batches sends it at once.
func (f *fwdBatch) add(b []byte, dst netip.AddrPort) {
	if f.b == nil || len(b) > maxUDP {
		_, _ = f.tr.WriteTo(b, f.addrs.get(dst))
		return
	}
	if f.b.Len() == maxFwd {
		f.flush()
	}
	i := f.b.Len()
	p := f.slab[i*maxUDP : i*maxUDP+len(b) : (i+1)*maxUDP]
	copy(p, b)
	f.b.Add(p, dst)
}

// flush sends the batch. It drops a packet that the socket refuses.
func (f *fwdBatch) flush() {
	if f.b != nil {
		f.stats.flush(f.b)
	}
}
