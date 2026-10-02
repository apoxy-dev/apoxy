// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/quic-go/quic-go"
)

// PacketHandler returns the NonQUICPacketHandler of tr. It forwards PSP
// packets by SPI rows on the read loop, and opens the PSP packets to the
// relay. Relay sessions must use tr or another transport with this handler.
func (r *Router) PacketHandler(tr *quic.Transport) func(b []byte, from net.Addr) {
	br := r.startBridge(tr)
	addrs := new(addrCache)
	return func(b []byte, from net.Addr) {
		h, err := pspwire.ParseHeader(b)
		if err != nil {
			return // A path probe or a bad packet.
		}
		now := time.Now()
		dst, v := r.Forward(addrPort(from), h.SPI, len(b), now)
		switch {
		case v != Pass:
		case dst.IsValid():
			_, _ = tr.WriteTo(b, addrs.get(dst))
		case br != nil:
			// A row to the relay has no address.
			r.receivePSP(br, b, h.SPI, now)
		}
	}
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
