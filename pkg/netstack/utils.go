package netstack

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func ToFullAddress(addr *net.UDPAddr) *tcpip.FullAddress {
	if addr.IP.To4() != nil {
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4Slice(addr.IP.To4()[:]),
			Port: uint16(addr.Port),
		}
	} else {
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom16Slice(addr.IP.To16()[:]),
			Port: uint16(addr.Port),
		}
	}
}
