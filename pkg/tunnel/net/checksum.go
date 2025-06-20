package net

import (
	"encoding/binary"
	"fmt"
	"net"
)

// RecalculateTCPChecksum manually recalculates and updates the TCP checksum in a raw packet
func RecalculateTCPChecksum(packetData []byte) error {
	if len(packetData) < 20 {
		return fmt.Errorf("packet too short")
	}

	// Determine IP version
	version := packetData[0] >> 4

	switch version {
	case 4:
		return recalculateTCPChecksumIPv4(packetData)
	case 6:
		return recalculateTCPChecksumIPv6(packetData)
	default:
		return fmt.Errorf("unsupported IP version: %d", version)
	}
}

// recalculateTCPChecksumIPv4 handles IPv4 TCP checksum recalculation
func recalculateTCPChecksumIPv4(packetData []byte) error {
	if len(packetData) < 20 {
		return fmt.Errorf("IPv4 packet too short")
	}

	// Parse IPv4 header
	ihl := int(packetData[0]&0x0F) * 4
	protocol := packetData[9]

	if protocol != 6 { // TCP protocol number
		return fmt.Errorf("not a TCP packet, protocol: %d", protocol)
	}

	if len(packetData) < ihl+20 {
		return fmt.Errorf("packet too short for TCP header")
	}

	srcIP := net.IP(packetData[12:16])
	dstIP := net.IP(packetData[16:20])
	tcpLength := len(packetData) - ihl

	// Calculate pseudo-header checksum
	pseudoSum := calculatePseudoHeaderIPv4(srcIP, dstIP, uint16(tcpLength))

	// Zero out existing checksum in TCP header
	tcpOffset := ihl
	binary.BigEndian.PutUint16(packetData[tcpOffset+16:tcpOffset+18], 0)

	// Calculate and set new checksum
	tcpData := packetData[tcpOffset:]
	checksum := finalizeChecksum(pseudoSum + calculateChecksum(tcpData))
	binary.BigEndian.PutUint16(packetData[tcpOffset+16:tcpOffset+18], checksum)

	return nil
}

// recalculateTCPChecksumIPv6 handles IPv6 TCP checksum recalculation
func recalculateTCPChecksumIPv6(packetData []byte) error {
	if len(packetData) < 60 { // IPv6 header (40) + min TCP header (20)
		return fmt.Errorf("IPv6 packet too short")
	}

	// Parse IPv6 header
	nextHeader := packetData[6]
	if nextHeader != 6 { // TCP protocol number
		return fmt.Errorf("not a TCP packet, next header: %d", nextHeader)
	}

	srcIP := net.IP(packetData[8:24])
	dstIP := net.IP(packetData[24:40])
	payloadLength := binary.BigEndian.Uint16(packetData[4:6])

	// Calculate pseudo-header checksum
	pseudoSum := calculatePseudoHeaderIPv6(srcIP, dstIP, uint32(payloadLength))

	// Zero out existing checksum in TCP header
	tcpOffset := 40
	binary.BigEndian.PutUint16(packetData[tcpOffset+16:tcpOffset+18], 0)

	// Calculate and set new checksum
	tcpData := packetData[tcpOffset:]
	checksum := finalizeChecksum(pseudoSum + calculateChecksum(tcpData))
	binary.BigEndian.PutUint16(packetData[tcpOffset+16:tcpOffset+18], checksum)

	return nil
}

// calculatePseudoHeaderIPv4 calculates the IPv4 TCP pseudo-header checksum
func calculatePseudoHeaderIPv4(srcIP, dstIP net.IP, tcpLength uint16) uint32 {
	var sum uint32

	// Source IP (4 bytes)
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))

	// Destination IP (4 bytes)
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))

	// Protocol (TCP = 6) and Length
	sum += uint32(6) + uint32(tcpLength)

	return sum
}

// calculatePseudoHeaderIPv6 calculates the IPv6 TCP pseudo-header checksum
func calculatePseudoHeaderIPv6(srcIP, dstIP net.IP, tcpLength uint32) uint32 {
	var sum uint32

	// Source IP (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(srcIP[i : i+2]))
	}

	// Destination IP (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(dstIP[i : i+2]))
	}

	// TCP Length (upper 16 bits then lower 16 bits)
	sum += tcpLength >> 16
	sum += tcpLength & 0xFFFF

	// Next Header (TCP = 6)
	sum += 6

	return sum
}

// calculateChecksum calculates the standard Internet checksum over data
func calculateChecksum(data []byte) uint32 {
	var sum uint32

	// Process 16-bit words
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	// Handle odd byte if data length is odd
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	return sum
}

// finalizeChecksum completes the checksum calculation with carry propagation and complement
func finalizeChecksum(sum uint32) uint16 {
	// Add carry bits until no more carries
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// Return one's complement
	return uint16(^sum)
}

// VerifyTCPChecksum verifies if the TCP checksum in a packet is correct
func VerifyTCPChecksum(packetData []byte) (bool, error) {
	if len(packetData) < 20 {
		return false, fmt.Errorf("packet too short")
	}

	// Make a copy to avoid modifying the original
	packetCopy := make([]byte, len(packetData))
	copy(packetCopy, packetData)

	// Store original checksum
	var originalChecksum uint16
	version := packetCopy[0] >> 4

	switch version {
	case 4:
		ihl := int(packetCopy[0]&0x0F) * 4
		if packetCopy[9] != 6 { // Not TCP
			return false, fmt.Errorf("not a TCP packet")
		}
		if len(packetCopy) < ihl+20 {
			return false, fmt.Errorf("packet too short for TCP header")
		}
		tcpOffset := ihl
		originalChecksum = binary.BigEndian.Uint16(packetCopy[tcpOffset+16 : tcpOffset+18])

	case 6:
		if len(packetCopy) < 60 {
			return false, fmt.Errorf("IPv6 packet too short")
		}
		if packetCopy[6] != 6 { // Not TCP
			return false, fmt.Errorf("not a TCP packet")
		}
		tcpOffset := 40
		originalChecksum = binary.BigEndian.Uint16(packetCopy[tcpOffset+16 : tcpOffset+18])

	default:
		return false, fmt.Errorf("unsupported IP version: %d", version)
	}

	// Recalculate checksum
	if err := RecalculateTCPChecksum(packetCopy); err != nil {
		return false, err
	}

	// Compare checksums
	var newChecksum uint16
	if version == 4 {
		ihl := int(packetCopy[0]&0x0F) * 4
		tcpOffset := ihl
		newChecksum = binary.BigEndian.Uint16(packetCopy[tcpOffset+16 : tcpOffset+18])
	} else {
		tcpOffset := 40
		newChecksum = binary.BigEndian.Uint16(packetCopy[tcpOffset+16 : tcpOffset+18])
	}

	return originalChecksum == newChecksum, nil
}

// GetTCPChecksum extracts the TCP checksum from a packet without modifying it
func GetTCPChecksum(packetData []byte) (uint16, error) {
	if len(packetData) < 20 {
		return 0, fmt.Errorf("packet too short")
	}

	version := packetData[0] >> 4

	switch version {
	case 4:
		ihl := int(packetData[0]&0x0F) * 4
		if packetData[9] != 6 { // Not TCP
			return 0, fmt.Errorf("not a TCP packet")
		}
		if len(packetData) < ihl+20 {
			return 0, fmt.Errorf("packet too short for TCP header")
		}
		tcpOffset := ihl
		return binary.BigEndian.Uint16(packetData[tcpOffset+16 : tcpOffset+18]), nil

	case 6:
		if len(packetData) < 60 {
			return 0, fmt.Errorf("IPv6 packet too short")
		}
		if packetData[6] != 6 { // Not TCP
			return 0, fmt.Errorf("not a TCP packet")
		}
		tcpOffset := 40
		return binary.BigEndian.Uint16(packetData[tcpOffset+16 : tcpOffset+18]), nil

	default:
		return 0, fmt.Errorf("unsupported IP version: %d", version)
	}
}
