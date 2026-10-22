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

// encodeUDP writes an Ethernet, IP and UDP frame of payload into frame, as icx udp.Encode does,
// with DF and the ECN bits set. It returns the frame length, or 0 when frame is too small.
func encodeUDP(frame []byte, srcMAC, dstMAC tcpip.LinkAddress, src, dst netip.AddrPort, ecn uint8, payload []byte) int {
	hdr := header.EthernetMinimumSize + header.UDPMinimumSize
	if src.Addr().Is4() {
		hdr += header.IPv4MinimumSize
	} else {
		hdr += header.IPv6MinimumSize
	}
	n := hdr + len(payload)
	if n > len(frame) || header.UDPMinimumSize+len(payload) > math.MaxUint16 {
		return 0
	}
	copy(frame[hdr:], payload)
	srcIP, dstIP := tcpip.AddrFromSlice(src.Addr().AsSlice()), tcpip.AddrFromSlice(dst.Addr().AsSlice())
	udpLen := uint16(header.UDPMinimumSize + len(payload))
	eth := header.Ethernet(frame)
	off := header.EthernetMinimumSize
	if src.Addr().Is4() {
		eth.Encode(&header.EthernetFields{SrcAddr: srcMAC, DstAddr: dstMAC, Type: header.IPv4ProtocolNumber})
		ip := header.IPv4(frame[off:])
		ip.Encode(&header.IPv4Fields{
			TOS:         ecn & 0x3,
			TotalLength: header.IPv4MinimumSize + udpLen,
			Flags:       header.IPv4FlagDontFragment,
			TTL:         64,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     srcIP,
			DstAddr:     dstIP,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
		off += header.IPv4MinimumSize
	} else {
		// IPv6 routers never fragment, so DF has no field there.
		eth.Encode(&header.EthernetFields{SrcAddr: srcMAC, DstAddr: dstMAC, Type: header.IPv6ProtocolNumber})
		header.IPv6(frame[off:]).Encode(&header.IPv6Fields{
			TrafficClass:      ecn & 0x3,
			PayloadLength:     udpLen,
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          64,
			SrcAddr:           srcIP,
			DstAddr:           dstIP,
		})
		off += header.IPv6MinimumSize
	}
	udp := header.UDP(frame[off:])
	udp.Encode(&header.UDPFields{SrcPort: src.Port(), DstPort: dst.Port(), Length: udpLen})
	csum := udp.CalculateChecksum(checksum.Combine(
		header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcIP, dstIP, udpLen),
		checksum.Checksum(payload, 0),
	))
	if csum != math.MaxUint16 {
		csum = ^csum
	}
	udp.SetChecksum(csum)
	return n
}
