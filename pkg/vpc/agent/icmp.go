// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	// An ICMPv6 error is at most the IPv6 minimum MTU, and an ICMPv4 error is at
	// most 576 B.
	maxICMPv6 = header.IPv6MinimumMTU
	maxICMPv4 = 576
	// maxICMPBody is the most bytes of the packet that an ICMP error carries.
	maxICMPBody = maxICMPv6 - header.IPv6MinimumSize - header.ICMPv6DstUnreachableMinimumSize
)

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

// unreachable returns an ICMP destination unreachable error for pkt, or nil
// when pkt must get no error. An ICMPv6 error comes from the address from, and
// an ICMPv4 error comes from the destination of pkt.
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
	const hdr = header.IPv6MinimumSize + header.ICMPv6DstUnreachableMinimumSize
	body := pkt[:min(len(pkt), maxICMPv6-hdr)]
	b := make([]byte, hdr+len(body))
	srcAddr, dstAddr := tcpip.AddrFrom16(from.As16()), tcpip.AddrFrom16(src.As16())
	header.IPv6(b).Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(b) - header.IPv6MinimumSize),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
	})
	icmp := header.ICMPv6(b[header.IPv6MinimumSize:])
	icmp.SetType(header.ICMPv6DstUnreachable)
	icmp.SetCode(header.ICMPv6AddressUnreachable)
	if denied {
		icmp.SetCode(header.ICMPv6Prohibited)
	}
	copy(icmp.Payload(), body)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmp[:header.ICMPv6DstUnreachableMinimumSize],
		Src:         srcAddr,
		Dst:         dstAddr,
		PayloadCsum: checksum.Checksum(body, 0),
		PayloadLen:  len(body),
	}))
	return b
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
	const hdr = header.IPv4MinimumSize + header.ICMPv4MinimumSize
	body := pkt[:min(len(pkt), maxICMPv4-hdr)]
	b := make([]byte, hdr+len(body))
	out := header.IPv4(b)
	out.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(dst.As4()),
		DstAddr:     tcpip.AddrFrom4(src.As4()),
	})
	out.SetChecksum(^out.CalculateChecksum())
	icmp := header.ICMPv4(b[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4DstUnreachable)
	icmp.SetCode(header.ICMPv4HostUnreachable)
	if denied {
		icmp.SetCode(header.ICMPv4AdminProhibited)
	}
	copy(icmp.Payload(), body)
	icmp.SetChecksum(header.ICMPv4Checksum(icmp[:header.ICMPv4MinimumSize], checksum.Checksum(body, 0)))
	return b
}
