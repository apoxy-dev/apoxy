package netstack

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func ToFullAddress(addrPort netip.AddrPort) *tcpip.FullAddress {
	if addrPort.Addr().Is4() {
		addrv4 := addrPort.Addr().As4()
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4Slice(addrv4[:]),
			Port: uint16(addrPort.Port()),
		}
	} else {
		addrv6 := addrPort.Addr().As16()
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom16Slice(addrv6[:]),
			Port: uint16(addrPort.Port()),
		}
	}
}
