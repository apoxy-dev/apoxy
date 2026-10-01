// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/quic-go/quic-go"
)

// PacketHandler returns the NonQUICPacketHandler of tr. It forwards PSP
// packets by SPI rows on the read loop. Relay sessions must use tr too.
func (r *Router) PacketHandler(tr *quic.Transport) func(b []byte, from net.Addr) {
	return func(b []byte, from net.Addr) {
		h, err := pspwire.ParseHeader(b)
		if err != nil {
			return // A path probe or a bad packet.
		}
		dst, v := r.Forward(addrPort(from), h.SPI, len(b), time.Now())
		if v != Pass {
			return
		}
		_, _ = tr.WriteTo(b, net.UDPAddrFromAddrPort(dst))
	}
}
