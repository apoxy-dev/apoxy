// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"encoding/binary"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	// MaxICMPv6 and MaxICMPv4 are the most bytes of an ICMP error with its IP header:
	// the IPv6 minimum MTU (RFC 4443), and 576 B (RFC 1812).
	MaxICMPv6 = header.IPv6MinimumMTU
	MaxICMPv4 = 576
	// icmpErrLen is the length of the ICMP header of an error, before the quote.
	icmpErrLen = 8
)

// ICMPv4Error returns the ICMPv4 error of typ and code for the IPv4 packet pkt, from the
// destination of pkt to its source. rest is the 4 bytes after the checksum.
func ICMPv4Error(pkt []byte, typ header.ICMPv4Type, code header.ICMPv4Code, rest uint32) []byte {
	const hdr = header.IPv4MinimumSize + icmpErrLen
	body := pkt[:min(len(pkt), MaxICMPv4-hdr)]
	b := make([]byte, hdr+len(body))
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     header.IPv4(pkt).DestinationAddress(),
		DstAddr:     header.IPv4(pkt).SourceAddress(),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	icmp := header.ICMPv4(b[header.IPv4MinimumSize:])
	icmp.SetType(typ)
	icmp.SetCode(code)
	binary.BigEndian.PutUint32(icmp[4:], rest)
	copy(icmp[icmpErrLen:], body)
	icmp.SetChecksum(header.ICMPv4Checksum(icmp[:icmpErrLen], checksum.Checksum(body, 0)))
	return b
}

// ICMPv6Error returns the ICMPv6 error of typ and code for the IPv6 packet pkt, from the
// address from to the source of pkt. rest is the 4 bytes after the checksum.
func ICMPv6Error(pkt []byte, from netip.Addr, typ header.ICMPv6Type, code header.ICMPv6Code, rest uint32) []byte {
	const hdr = header.IPv6MinimumSize + icmpErrLen
	body := pkt[:min(len(pkt), MaxICMPv6-hdr)]
	b := make([]byte, hdr+len(body))
	src, dst := tcpip.AddrFrom16(from.As16()), header.IPv6(pkt).SourceAddress()
	header.IPv6(b).Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(b) - header.IPv6MinimumSize),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           src,
		DstAddr:           dst,
	})
	icmp := header.ICMPv6(b[header.IPv6MinimumSize:])
	icmp.SetType(typ)
	icmp.SetCode(code)
	binary.BigEndian.PutUint32(icmp[4:], rest)
	copy(icmp[icmpErrLen:], body)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmp[:icmpErrLen],
		Src:         src,
		Dst:         dst,
		PayloadCsum: checksum.Checksum(body, 0),
		PayloadLen:  len(body),
	}))
	return b
}
