// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net"
	"net/netip"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/udpbatch"
)

// maxFwd is the most packets in one batch. A full batch is sent at once.
const maxFwd = 64

// fwdBatch collects the PSP packets that one read of the QUIC read loop
// forwards, and sends them at the end of the read with one sendmmsg call.
// Only the read loop of the transport uses it.
type fwdBatch struct {
	tr    *quic.Transport
	b     *udpbatch.Batch // Nil when the socket cannot send batches.
	addrs addrCache
	slab  []byte // maxFwd slots of maxUDP bytes.
}

func newFwdBatch(tr *quic.Transport) *fwdBatch {
	f := &fwdBatch{tr: tr}
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
		_, _, _ = f.b.Flush()
	}
}
