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
// tr. The handler forwards PSP packets by SPI rows, seals the PSP packets for
// a receiver on another relay into trunk packets, and opens the PSP packets
// to the relay and the trunk packets of the mesh members. The batch end sends
// the packets that the handler forwarded in one read. Relay sessions must use
// tr or another transport with these.
//
// With more than one CPU, sender goroutines send the forwarded packets, so the
// read loop does not wait for the sends. A packet for a sender that is too slow
// drops. The senders stop when ctx ends, and then the forwarded packets drop.
func (r *Router) PacketHandler(ctx context.Context, tr *quic.Transport) (handle func(b []byte, from net.Addr), batchEnd func()) {
	br := r.startBridge(tr)
	var fwd forwarder
	if procs := runtime.GOMAXPROCS(0); procs > 1 {
		c := fwdCounters{closed: &r.drops[dropClosed], queue: &r.drops[dropSendQueue], sends: &r.sends}
		if p := newFwdPipe(tr, fwdSenders(procs), ctx.Done(), c); p != nil {
			p.start()
			fwd = p
		}
	}
	if fwd == nil {
		fwd = newFwdBatch(tr, &r.sends)
	}
	// Only the read loop calls the handler, and a forwarder copies or sends a
	// packet before it returns, so one buffer is enough for the trunk packets.
	sealed := make([]byte, maxUDP)
	return func(b []byte, from net.Addr) {
		if t := r.trunk.Load(); t != nil {
			// A mesh member sends only trunk packets, which have their own header check.
			if p := t.from(addrPort(from)); p != nil {
				if why, ok := t.receive(br, p, b, fwd, time.Now()); !ok {
					r.drops[why].Add(1)
				}
				return
			}
		}
		h, err := pspwire.ParseHeader(b)
		if err != nil {
			if !r.Keepalive(b, addrPort(from)) && !r.answerProbe(tr, b, from) {
				r.drops[dropMalformed].Add(1)
			}
			return
		}
		now := time.Now()
		dst, ts, v := r.forward(addrPort(from), h.SPI, len(b), now)
		switch {
		case v != Pass:
		case ts.sa != nil:
			// The whole packet goes to the other relay in one trunk packet.
			n, err := ts.sa.SealTrunkPSP(ts.tag, sealed, b)
			if err != nil {
				r.drops[dropTrunkKeys].Add(1)
				return
			}
			fwd.add(sealed[:n], dst)
		case dst.IsValid():
			fwd.add(b, dst)
		case br != nil:
			// A row to the relay has no address.
			r.receivePSP(br, b, h.SPI, now)
		}
	}, fwd.flush
}

// addrSlotBits is the number of hash bits that select a slot of a destination table.
const addrSlotBits = 10

// addrSlot returns the slot of the destination a in a table of 1<<addrSlotBits slots.
func addrSlot(a netip.AddrPort) uint64 {
	b := a.Addr().As16()
	h := (binary.LittleEndian.Uint64(b[:8]) ^ binary.LittleEndian.Uint64(b[8:]) ^ uint64(a.Port())) * 0x9e3779b97f4a7c15
	return h >> (64 - addrSlotBits)
}

// addrCache keeps the net.UDPAddr of recent destinations, so that a forward
// does not allocate one. Two destinations can use the same slot.
type addrCache [1 << addrSlotBits]atomic.Pointer[net.UDPAddr]

func (c *addrCache) get(a netip.AddrPort) *net.UDPAddr {
	slot := &c[addrSlot(a)]
	if u := slot.Load(); u != nil && u.AddrPort() == a {
		return u
	}
	u := net.UDPAddrFromAddrPort(a)
	slot.Store(u)
	return u
}
