// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/quic-go/quic-go"
)

// PacketHandler returns the NonQUICPacketHandler and the NonQUICBatchEnd of
// tr. The handler forwards PSP packets by SPI rows, and opens the PSP packets
// to the relay. The batch end sends the packets that the handler forwarded in
// one read. Relay sessions must use tr or another transport with these.
//
// With more than one CPU, a sender goroutine sends the forwarded packets, so the
// read loop does not wait for the sends. It stops when ctx ends, and then the
// forwarded packets drop.
func (r *Router) PacketHandler(ctx context.Context, tr *quic.Transport) (handle func(b []byte, from net.Addr), batchEnd func()) {
	br := r.startBridge(tr)
	var fwd forwarder
	if p := newFwdPipe(tr, ctx.Done(), &r.drops[dropClosed]); p != nil && runtime.GOMAXPROCS(0) > 1 {
		go p.run()
		fwd = p
	} else {
		fwd = newFwdBatch(tr)
	}
	return func(b []byte, from net.Addr) {
		h, err := pspwire.ParseHeader(b)
		if err != nil {
			if !r.answerProbe(tr, b, from) {
				r.drops[dropMalformed].Add(1)
			}
			return
		}
		now := time.Now()
		dst, v := r.Forward(addrPort(from), h.SPI, len(b), now)
		switch {
		case v != Pass:
		case dst.IsValid():
			fwd.add(b, dst)
		case br != nil:
			// A row to the relay has no address.
			r.receivePSP(br, b, h.SPI, now)
		}
	}, fwd.flush
}

// addrCache keeps the net.UDPAddr of recent destinations, so that a forward
// does not allocate one. Two destinations can use the same slot.
type addrCache [1024]atomic.Pointer[net.UDPAddr]

func (c *addrCache) get(a netip.AddrPort) *net.UDPAddr {
	b := a.Addr().As16()
	h := (binary.LittleEndian.Uint64(b[:8]) ^ binary.LittleEndian.Uint64(b[8:]) ^ uint64(a.Port())) * 0x9e3779b97f4a7c15
	slot := &c[h>>54]
	if u := slot.Load(); u != nil && u.AddrPort() == a {
		return u
	}
	u := net.UDPAddrFromAddrPort(a)
	slot.Store(u)
	return u
}
