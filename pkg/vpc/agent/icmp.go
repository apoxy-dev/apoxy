// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

// maxICMPBody is the most bytes of the packet that an ICMP error carries.
const maxICMPBody = psp.MaxICMPv6 - header.IPv6MinimumSize - header.ICMPv6DstUnreachableMinimumSize

// unicastDst returns the destination of an IPv4 or IPv6 packet if it is a
// unicast address.
func unicastDst(pkt []byte) (netip.Addr, bool) {
	var dst netip.Addr
	switch {
	case len(pkt) >= header.IPv4MinimumSize && pkt[0]>>4 == 4:
		dst = netip.AddrFrom4([4]byte(pkt[16:20]))
	case len(pkt) >= header.IPv6MinimumSize && pkt[0]>>4 == 6:
		dst = netip.AddrFrom16([16]byte(pkt[24:40]))
	}
	return dst, dst.IsGlobalUnicast()
}

// unicastSrc returns the source of an IPv4 or IPv6 packet if it is a unicast
// address.
func unicastSrc(pkt []byte) (netip.Addr, bool) {
	var src netip.Addr
	switch {
	case len(pkt) >= header.IPv4MinimumSize && pkt[0]>>4 == 4:
		src = netip.AddrFrom4([4]byte(pkt[12:16]))
	case len(pkt) >= header.IPv6MinimumSize && pkt[0]>>4 == 6:
		src = netip.AddrFrom16([16]byte(pkt[8:24]))
	}
	return src, src.IsGlobalUnicast()
}

// unreachable returns an ICMP unreachable error for pkt, or nil for none.
// ICMPv6 comes from the address from, ICMPv4 from the destination of pkt.
func unreachable(pkt []byte, from netip.Addr, denied bool) []byte {
	switch {
	case len(pkt) >= header.IPv4MinimumSize && pkt[0]>>4 == 4:
		return unreachable4(pkt, denied)
	case len(pkt) >= header.IPv6MinimumSize && pkt[0]>>4 == 6 && from.Is6():
		return unreachable6(pkt, from, denied)
	}
	return nil
}

func unreachable6(pkt []byte, from netip.Addr, denied bool) []byte {
	src, dst := netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40]))
	if !src.IsGlobalUnicast() || !dst.IsGlobalUnicast() {
		return nil
	}
	// An ICMPv6 error (type below 128) gets no error.
	if header.IPv6(pkt).TransportProtocol() == header.ICMPv6ProtocolNumber &&
		(len(pkt) == header.IPv6MinimumSize || pkt[header.IPv6MinimumSize] < 128) {
		return nil
	}
	code := header.ICMPv6AddressUnreachable
	if denied {
		code = header.ICMPv6Prohibited
	}
	return psp.ICMPv6Error(pkt, from, header.ICMPv6DstUnreachable, code, 0)
}

func unreachable4(pkt []byte, denied bool) []byte {
	ip := header.IPv4(pkt)
	n := int(ip.HeaderLength())
	src, dst := netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20]))
	if n < header.IPv4MinimumSize || len(pkt) < n || ip.FragmentOffset() != 0 || !src.IsGlobalUnicast() || !dst.IsGlobalUnicast() {
		return nil
	}
	// Of the ICMP messages, only an echo request gets an error.
	if ip.Protocol() == uint8(header.ICMPv4ProtocolNumber) && (len(pkt) == n || pkt[n] != uint8(header.ICMPv4Echo)) {
		return nil
	}
	code := header.ICMPv4HostUnreachable
	if denied {
		code = header.ICMPv4AdminProhibited
	}
	return psp.ICMPv4Error(pkt, header.ICMPv4DstUnreachable, code, 0)
}
