// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"encoding/binary"
	"math"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

// The UDP ports of the relay on the dedicated interface. PortData carries PSP packets, probes and
// lane keep-alives; agents get it in Welcome.
const (
	PortData = 1000
	portQUIC = 443
)

// The places where the demux sends a frame.
const (
	toDrop = iota
	toPipeline
	toQUIC
	toNetstack
)

// datagram is a UDP datagram to the relay.
type datagram struct {
	from    netip.AddrPort
	ecn     uint8
	payload []byte
}

// demux returns where a received frame goes, and its datagram for the pipeline and for QUIC.
// UDP must go to an own address; IP fragments and IPv6 extension headers are dropped.
func demux(frame []byte, own func(netip.Addr) bool) (int, datagram) {
	if len(frame) < header.EthernetMinimumSize {
		return toDrop, datagram{}
	}
	var (
		src, dst netip.Addr
		proto    uint8
		ecn      uint8
		l4       []byte
	)
	b := frame[header.EthernetMinimumSize:]
	switch binary.BigEndian.Uint16(frame[12:]) {
	case uint16(header.ARPProtocolNumber):
		return toNetstack, datagram{}
	case uint16(header.IPv4ProtocolNumber):
		ip := header.IPv4(b)
		if len(b) < header.IPv4MinimumSize || ip.HeaderLength() < header.IPv4MinimumSize ||
			int(ip.HeaderLength()) > len(b) || int(ip.TotalLength()) > len(b) || int(ip.TotalLength()) < int(ip.HeaderLength()) {
			return toDrop, datagram{}
		}
		if ip.More() || ip.FragmentOffset() != 0 {
			return toDrop, datagram{}
		}
		src = netip.AddrFrom4([4]byte(ip.SourceAddressSlice()))
		dst = netip.AddrFrom4([4]byte(ip.DestinationAddressSlice()))
		tos, _ := ip.TOS()
		proto, ecn = ip.Protocol(), tos&0x3
		l4 = b[ip.HeaderLength():ip.TotalLength()]
		if proto == uint8(header.ICMPv4ProtocolNumber) {
			return toNetstack, datagram{}
		}
	case uint16(header.IPv6ProtocolNumber):
		ip := header.IPv6(b)
		if len(b) < header.IPv6MinimumSize || header.IPv6MinimumSize+int(ip.PayloadLength()) > len(b) {
			return toDrop, datagram{}
		}
		src = netip.AddrFrom16([16]byte(ip.SourceAddressSlice()))
		dst = netip.AddrFrom16([16]byte(ip.DestinationAddressSlice()))
		tc, _ := ip.TOS()
		proto, ecn = ip.NextHeader(), tc&0x3
		l4 = b[header.IPv6MinimumSize : header.IPv6MinimumSize+int(ip.PayloadLength())]
		if proto == uint8(header.ICMPv6ProtocolNumber) {
			return toNetstack, datagram{}
		}
	default:
		return toDrop, datagram{}
	}
	if proto != uint8(header.UDPProtocolNumber) || len(l4) < header.UDPMinimumSize || !own(dst) {
		return toDrop, datagram{}
	}
	udp := header.UDP(l4)
	if int(udp.Length()) < header.UDPMinimumSize || int(udp.Length()) > len(l4) {
		return toDrop, datagram{}
	}
	d := datagram{from: netip.AddrPortFrom(src, udp.SourcePort()), ecn: ecn, payload: l4[header.UDPMinimumSize:udp.Length()]}
	switch udp.DestinationPort() {
	case PortData:
		return toPipeline, d
	case portQUIC:
		return toQUIC, d
	}
	return toDrop, datagram{}
}

// encodeUDP writes an Ethernet, IP and UDP frame of payload into frame, with DF and the ECN bits set.
// It returns the frame length, or 0 when frame is too small.
func encodeUDP(frame []byte, srcMAC, dstMAC tcpip.LinkAddress, src, dst netip.AddrPort, ecn uint8, payload []byte) int {
	v4 := src.Addr().Is4()
	ipLen := header.IPv6MinimumSize
	if v4 {
		ipLen = header.IPv4MinimumSize
	}
	off := header.EthernetMinimumSize + ipLen
	n := off + header.UDPMinimumSize + len(payload)
	// A source and destination of two families cannot be one IP header.
	if n > len(frame) || header.UDPMinimumSize+len(payload) > math.MaxUint16 || v4 != dst.Addr().Is4() {
		return 0
	}
	copy(frame[off+header.UDPMinimumSize:], payload)
	udpLen := uint16(header.UDPMinimumSize + len(payload))
	// The addresses are copied from As4 and As16, because a tcpip.Address for each packet is slow.
	var addrs []byte // The pseudo-header sum uses the two addresses in the IP header.
	if v4 {
		header.Ethernet(frame).Encode(&header.EthernetFields{SrcAddr: srcMAC, DstAddr: dstMAC, Type: header.IPv4ProtocolNumber})
		ip := header.IPv4(frame[header.EthernetMinimumSize:off])
		setIPv4VersionIHL(ip)
		ip.SetTOS(ecn&0x3, 0)
		ip.SetTotalLength(uint16(ipLen) + udpLen)
		ip.SetID(0)
		ip.SetFlagsFragmentOffset(header.IPv4FlagDontFragment, 0)
		ip.SetTTL(ipv4.DefaultTTL)
		setIPv4Protocol(ip, header.UDPProtocolNumber)
		ip.SetChecksum(0)
		*(*[4]byte)(ip.SourceAddressSlice()) = src.Addr().As4()
		*(*[4]byte)(ip.DestinationAddressSlice()) = dst.Addr().As4()
		ip.SetChecksum(^ip.CalculateChecksum())
		// The two addresses are the last bytes of the header.
		addrs = ip[header.IPv4MinimumSize-2*header.IPv4AddressSize:]
	} else {
		// IPv6 routers never fragment, so DF has no field there.
		header.Ethernet(frame).Encode(&header.EthernetFields{SrcAddr: srcMAC, DstAddr: dstMAC, Type: header.IPv6ProtocolNumber})
		ip := header.IPv6(frame[header.EthernetMinimumSize:off])
		ip.SetTOS(ecn&0x3, 0) // It also writes version 6 and flow label 0.
		ip.SetPayloadLength(udpLen)
		ip.SetNextHeader(uint8(header.UDPProtocolNumber))
		ip.SetHopLimit(ipv6.DefaultTTL)
		*(*[16]byte)(ip.SourceAddressSlice()) = src.Addr().As16()
		*(*[16]byte)(ip.DestinationAddressSlice()) = dst.Addr().As16()
		addrs = ip[header.IPv6MinimumSize-2*header.IPv6AddressSize:]
	}
	udp := header.UDP(frame[off:n])
	udp.SetSourcePort(src.Port())
	udp.SetDestinationPort(dst.Port())
	udp.SetLength(udpLen)
	udp.SetChecksum(0)
	// The pseudo-header is the two addresses, the UDP length and the protocol (RFC 768, RFC 8200).
	sum := checksum.Combine(checksum.Checksum(addrs, 0), udpLen)
	sum = checksum.Checksum(udp, checksum.Combine(sum, uint16(header.UDPProtocolNumber)))
	// A sum of 0xffff gives checksum 0, which means no checksum, so it is sent as 0xffff.
	if sum != math.MaxUint16 {
		sum = ^sum
	}
	udp.SetChecksum(sum)
	return n
}

// setIPv4Protocol writes the protocol field of an IPv4 header (RFC 791). gVisor has no setter for it.
func setIPv4Protocol(ip header.IPv4, p tcpip.TransportProtocolNumber) {
	const protocolOffset = 9
	ip[protocolOffset] = uint8(p)
}

// setIPv4VersionIHL writes version 4 and a header length of 20 bytes. It does not use SetHeaderLength,
// because SetHeaderLength has a panic check that stops the compiler from inlining it.
func setIPv4VersionIHL(ip header.IPv4) {
	const (
		versionIHLOffset = 0
		versionShift     = 4 // The version is the high 4 bits of the byte.
	)
	ip[versionIHLOffset] = header.IPv4Version<<versionShift | header.IPv4MinimumSize/header.IPv4IHLStride
}
