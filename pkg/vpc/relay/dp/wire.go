// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"encoding/binary"
	"math"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
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
	ip := frame[header.EthernetMinimumSize:off]
	var addrs []byte // The source and destination addresses in ip, for the pseudo-header sum.
	if v4 {
		header.Ethernet(frame).Encode(&header.EthernetFields{SrcAddr: srcMAC, DstAddr: dstMAC, Type: header.IPv4ProtocolNumber})
		ip[0], ip[1] = 0x45, ecn&0x3 // Version 4, 20-byte header.
		binary.BigEndian.PutUint16(ip[2:], uint16(ipLen)+udpLen)
		binary.BigEndian.PutUint32(ip[4:], uint32(header.IPv4FlagDontFragment)<<13) // ID 0, DF.
		ip[8], ip[9] = 64, uint8(header.UDPProtocolNumber)
		binary.BigEndian.PutUint16(ip[10:], 0)
		*(*[4]byte)(ip[12:]) = src.Addr().As4()
		*(*[4]byte)(ip[16:]) = dst.Addr().As4()
		binary.BigEndian.PutUint16(ip[10:], ^checksum.Checksum(ip, 0))
		addrs = ip[12:20]
	} else {
		// IPv6 routers never fragment, so DF has no field there.
		header.Ethernet(frame).Encode(&header.EthernetFields{SrcAddr: srcMAC, DstAddr: dstMAC, Type: header.IPv6ProtocolNumber})
		binary.BigEndian.PutUint32(ip[0:], 6<<28|uint32(ecn&0x3)<<20)
		binary.BigEndian.PutUint16(ip[4:], udpLen)
		ip[6], ip[7] = uint8(header.UDPProtocolNumber), 64
		*(*[16]byte)(ip[8:]) = src.Addr().As16()
		*(*[16]byte)(ip[24:]) = dst.Addr().As16()
		addrs = ip[8:40]
	}
	udp := frame[off:n]
	binary.BigEndian.PutUint16(udp[0:], src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], udpLen)
	binary.BigEndian.PutUint16(udp[6:], 0)
	// The pseudo-header is the two addresses, the UDP length and the protocol (RFC 768, RFC 8200).
	sum := checksum.Combine(checksum.Checksum(addrs, 0), udpLen)
	sum = checksum.Checksum(udp, checksum.Combine(sum, uint16(header.UDPProtocolNumber)))
	// A sum of 0xffff gives checksum 0, which means no checksum, so it is sent as 0xffff.
	if sum != math.MaxUint16 {
		sum = ^sum
	}
	binary.BigEndian.PutUint16(udp[6:], sum)
	return n
}
