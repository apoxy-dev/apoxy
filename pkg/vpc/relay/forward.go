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

// QUICSocketHandler returns the NonQUICPacketHandler of a QUIC socket. The
// socket carries only QUIC, so it drops and counts each packet.
func (r *Router) QUICSocketHandler() func(b []byte, from net.Addr) {
	return func([]byte, net.Addr) { r.drops[dropNotQUIC].Add(1) }
}

// PacketHandler returns the handler and batch end of the PSP socket tr, which
// needs Start. Forwarded packets drop at a slow sender or after ctx.
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
	// Only the read loop calls the handler, and each send copies or sends a
	// packet before it returns, so one buffer is enough for the sealed packets.
	sealed := make([]byte, maxUDP)
	return func(b []byte, from net.Addr) {
		src := addrPort(from)
		if t := r.trunk.Load(); t != nil {
			// A mesh member sends trunk packets and the PSP packets of its senders.
			if p := t.member(src, b); p != nil {
				if why, ok := t.receive(br, p, b, sealed, fwd, time.Now()); !ok {
					r.drops[why].Add(1)
				}
				return
			}
		}
		h, err := pspwire.ParseHeader(b)
		if err != nil {
			if !r.Keepalive(b, src) && !r.answerProbe(tr, b, from) {
				r.drops[dropMalformed].Add(1)
			}
			return
		}
		now := time.Now()
		dst, v := r.Forward(src, h.SPI, len(b), now)
		switch {
		case v != Pass:
			r.socket[socketDropped].Add(1)
		case dst.IsValid():
			r.socket[socketAgentRow].Add(1)
			fwd.add(b, dst)
		case br != nil:
			// A row to the relay has no address.
			r.socket[socketAgentRelay].Add(1)
			r.receivePSP(br, b, h.SPI, sealed, now)
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
