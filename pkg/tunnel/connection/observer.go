package connection

import (
	"net/netip"
	"time"
)

// Direction indicates whether a packet is inbound or outbound.
type Direction uint8

const (
	DirectionOutbound Direction = iota // TUN → Remote
	DirectionInbound                   // Remote → TUN
)

func (d Direction) String() string {
	switch d {
	case DirectionOutbound:
		return "OUT"
	case DirectionInbound:
		return "IN"
	default:
		return "?"
	}
}

// Protocol represents the transport layer protocol.
type Protocol uint8

const (
	ProtocolUnknown Protocol = iota
	ProtocolTCP
	ProtocolUDP
	ProtocolICMP
)

func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	case ProtocolICMP:
		return "ICMP"
	default:
		return "???"
	}
}

// TCPFlags represents TCP control flags.
type TCPFlags uint8

const (
	TCPFlagFIN TCPFlags = 0x01
	TCPFlagSYN TCPFlags = 0x02
	TCPFlagRST TCPFlags = 0x04
	TCPFlagPSH TCPFlags = 0x08
	TCPFlagACK TCPFlags = 0x10
	TCPFlagURG TCPFlags = 0x20
)

func (f TCPFlags) String() string {
	if f == 0 {
		return ""
	}
	var flags []byte
	if f&TCPFlagSYN != 0 {
		flags = append(flags, 'S')
	}
	if f&TCPFlagACK != 0 {
		flags = append(flags, 'A')
	}
	if f&TCPFlagFIN != 0 {
		flags = append(flags, 'F')
	}
	if f&TCPFlagRST != 0 {
		flags = append(flags, 'R')
	}
	if f&TCPFlagPSH != 0 {
		flags = append(flags, 'P')
	}
	if f&TCPFlagURG != 0 {
		flags = append(flags, 'U')
	}
	return string(flags)
}

// PacketInfo contains metadata extracted from a packet.
type PacketInfo struct {
	Timestamp time.Time
	Direction Direction
	Protocol  Protocol
	SrcIP     netip.Addr
	SrcPort   uint16
	DstIP     netip.Addr
	DstPort   uint16
	Size      int
	TCPFlags  TCPFlags
}

// PacketObserver is an interface for observing packets flowing through the tunnel.
type PacketObserver interface {
	OnPacket(info PacketInfo)
}

// ExtractPacketInfo parses an IP packet to extract metadata.
func ExtractPacketInfo(packet []byte, dir Direction) PacketInfo {
	info := PacketInfo{
		Timestamp: time.Now(),
		Direction: dir,
		Size:      len(packet),
	}

	if len(packet) < 20 {
		return info
	}

	version := packet[0] >> 4
	switch version {
	case 4: // IPv4
		info.SrcIP, _ = netip.AddrFromSlice(packet[12:16])
		info.DstIP, _ = netip.AddrFromSlice(packet[16:20])
		ihl := int(packet[0]&0x0F) * 4
		if ihl < 20 || len(packet) < ihl {
			return info
		}
		proto := packet[9]
		switch proto {
		case 6: // TCP
			info.Protocol = ProtocolTCP
			if len(packet) >= ihl+14 {
				info.SrcPort = uint16(packet[ihl])<<8 | uint16(packet[ihl+1])
				info.DstPort = uint16(packet[ihl+2])<<8 | uint16(packet[ihl+3])
				info.TCPFlags = TCPFlags(packet[ihl+13] & 0x3F)
			}
		case 17: // UDP
			info.Protocol = ProtocolUDP
			if len(packet) >= ihl+4 {
				info.SrcPort = uint16(packet[ihl])<<8 | uint16(packet[ihl+1])
				info.DstPort = uint16(packet[ihl+2])<<8 | uint16(packet[ihl+3])
			}
		case 1: // ICMP
			info.Protocol = ProtocolICMP
		}
	case 6: // IPv6
		if len(packet) >= 40 {
			info.SrcIP, _ = netip.AddrFromSlice(packet[8:24])
			info.DstIP, _ = netip.AddrFromSlice(packet[24:40])
			proto := packet[6] // Next Header
			switch proto {
			case 6: // TCP
				info.Protocol = ProtocolTCP
				if len(packet) >= 54 {
					info.SrcPort = uint16(packet[40])<<8 | uint16(packet[41])
					info.DstPort = uint16(packet[42])<<8 | uint16(packet[43])
					info.TCPFlags = TCPFlags(packet[53] & 0x3F)
				}
			case 17: // UDP
				info.Protocol = ProtocolUDP
				if len(packet) >= 44 {
					info.SrcPort = uint16(packet[40])<<8 | uint16(packet[41])
					info.DstPort = uint16(packet[42])<<8 | uint16(packet[43])
				}
			case 58: // ICMPv6
				info.Protocol = ProtocolICMP
			}
		}
	}
	return info
}
