package net

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestRecalculateTCPChecksum(t *testing.T) {
	tests := []struct {
		name        string
		packet      []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "too short packet",
			packet:      []byte{0x45, 0x00, 0x00},
			expectError: true,
			errorMsg:    "packet too short",
		},
		{
			name:        "unsupported IP version",
			packet:      createTestPacket(3, false), // IP version 3
			expectError: true,
			errorMsg:    "unsupported IP version: 3",
		},
		{
			name:        "non-TCP packet",
			packet:      createNonTCPPacket(),
			expectError: true,
			errorMsg:    "not a TCP packet, protocol: 17",
		},
		{
			name:        "valid IPv4 TCP packet",
			packet:      createValidIPv4TCPPacket(),
			expectError: false,
		},
		{
			name:        "valid IPv6 TCP packet",
			packet:      createValidIPv6TCPPacket(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RecalculateTCPChecksum(tt.packet)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), strings.Split(tt.errorMsg, ":")[0]) {
					t.Errorf("expected error message containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCalculatePseudoHeaderIPv4(t *testing.T) {
	srcIP := net.IPv4(192, 168, 1, 1)
	dstIP := net.IPv4(192, 168, 1, 2)
	tcpLength := uint16(20)

	sum := calculatePseudoHeaderIPv4(srcIP, dstIP, tcpLength)

	// Just ensure the function runs without error and produces a reasonable result
	if sum == 0 {
		t.Error("pseudo header sum should not be zero")
	}

	// Test with simple known values that we can verify manually
	testSrcIP := net.IPv4(0, 0, 0, 1).To4() // 0.0.0.1
	testDstIP := net.IPv4(0, 0, 0, 2).To4() // 0.0.0.2
	testSum := calculatePseudoHeaderIPv4(testSrcIP, testDstIP, 20)

	// Expected calculation for 0.0.0.1 and 0.0.0.2:
	// Source: 0x0000 (0) + 0x0001 (1) = 1
	// Dest: 0x0000 (0) + 0x0002 (2) = 2
	// Protocol (6) + Length (20) = 26
	// Total = 1 + 2 + 26 = 29
	expectedTest := uint32(29)
	if testSum != expectedTest {
		t.Errorf("for simple test case, expected %d, got %d", expectedTest, testSum)
	}
}

func TestCalculatePseudoHeaderIPv6(t *testing.T) {
	srcIP := net.ParseIP("2001:db8::1")
	dstIP := net.ParseIP("2001:db8::2")
	tcpLength := uint32(20)

	sum := calculatePseudoHeaderIPv6(srcIP, dstIP, tcpLength)

	// This should not be zero for valid IPv6 addresses
	if sum == 0 {
		t.Error("pseudo header sum should not be zero for valid IPv6 addresses")
	}
}

func TestCalculateChecksum(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint32
	}{
		{
			name:     "empty data",
			data:     []byte{},
			expected: 0,
		},
		{
			name:     "single byte",
			data:     []byte{0x45},
			expected: 0x4500, // 0x45 << 8
		},
		{
			name:     "two bytes",
			data:     []byte{0x45, 0x00},
			expected: 0x4500,
		},
		{
			name:     "odd number of bytes",
			data:     []byte{0x45, 0x00, 0x01},
			expected: 0x4500 + 0x0100, // 0x45, 0x00 + (0x01 << 8)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateChecksum(tt.data)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestFinalizeChecksum(t *testing.T) {
	tests := []struct {
		name     string
		sum      uint32
		expected uint16
	}{
		{
			name:     "no carry",
			sum:      0x1234,
			expected: ^uint16(0x1234),
		},
		{
			name:     "single carry",
			sum:      0x10001,
			expected: ^uint16(0x0002),
		},
		{
			name:     "multiple carries",
			sum:      0xFFFFFFFF,
			expected: 0x0000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := finalizeChecksum(tt.sum)
			if result != tt.expected {
				t.Errorf("expected 0x%04X, got 0x%04X", tt.expected, result)
			}
		})
	}
}

func TestVerifyTCPChecksum(t *testing.T) {
	// Create a valid packet
	packet := createValidIPv4TCPPacket()

	// First recalculate to ensure it has correct checksum
	err := RecalculateTCPChecksum(packet)
	if err != nil {
		t.Fatalf("failed to recalculate checksum: %v", err)
	}

	// Verify it
	valid, err := VerifyTCPChecksum(packet)
	if err != nil {
		t.Fatalf("failed to verify checksum: %v", err)
	}

	if !valid {
		t.Error("checksum should be valid after recalculation")
	}

	// Corrupt the checksum and verify it fails
	corruptedPacket := make([]byte, len(packet))
	copy(corruptedPacket, packet)

	// Corrupt TCP checksum (at offset 16 in TCP header, which starts at offset 20)
	tcpChecksumOffset := 20 + 16
	binary.BigEndian.PutUint16(corruptedPacket[tcpChecksumOffset:tcpChecksumOffset+2], 0x0000)

	valid, err = VerifyTCPChecksum(corruptedPacket)
	if err != nil {
		t.Fatalf("failed to verify corrupted checksum: %v", err)
	}

	if valid {
		t.Error("corrupted checksum should not be valid")
	}
}

func TestGetTCPChecksum(t *testing.T) {
	packet := createValidIPv4TCPPacket()

	// Set a known checksum value
	expectedChecksum := uint16(0x1234)
	tcpChecksumOffset := 20 + 16 // IP header (20) + TCP checksum offset (16)
	binary.BigEndian.PutUint16(packet[tcpChecksumOffset:tcpChecksumOffset+2], expectedChecksum)

	checksum, err := GetTCPChecksum(packet)
	if err != nil {
		t.Fatalf("failed to get TCP checksum: %v", err)
	}

	if checksum != expectedChecksum {
		t.Errorf("expected checksum 0x%04X, got 0x%04X", expectedChecksum, checksum)
	}
}

func TestIPv6TCPChecksum(t *testing.T) {
	packet := createValidIPv6TCPPacket()

	// Recalculate checksum
	err := RecalculateTCPChecksum(packet)
	if err != nil {
		t.Fatalf("failed to recalculate IPv6 TCP checksum: %v", err)
	}

	// Verify the checksum
	valid, err := VerifyTCPChecksum(packet)
	if err != nil {
		t.Fatalf("failed to verify IPv6 TCP checksum: %v", err)
	}

	if !valid {
		t.Error("IPv6 TCP checksum should be valid after recalculation")
	}
}

// Helper functions to create test packets

func createTestPacket(version byte, isTCP bool) []byte {
	packet := make([]byte, 60)
	packet[0] = (version << 4) | 0x05 // Version and IHL
	if isTCP {
		packet[9] = 6 // TCP protocol
	} else {
		packet[9] = 17 // UDP protocol
	}
	return packet
}

func createNonTCPPacket() []byte {
	// Create IPv4 UDP packet
	packet := make([]byte, 60)
	packet[0] = 0x45 // IPv4, IHL=5
	packet[9] = 17   // UDP protocol
	return packet
}

func createValidIPv4TCPPacket() []byte {
	// Create a minimal IPv4 TCP packet
	packet := make([]byte, 60) // 20 bytes IP header + 20 bytes TCP header + 20 bytes data

	// IPv4 header
	packet[0] = 0x45                                // Version 4, IHL 5 (20 bytes)
	packet[1] = 0x00                                // TOS
	binary.BigEndian.PutUint16(packet[2:4], 60)     // Total length
	binary.BigEndian.PutUint16(packet[4:6], 0x1234) // ID
	binary.BigEndian.PutUint16(packet[6:8], 0x4000) // Flags + Fragment offset
	packet[8] = 64                                  // TTL
	packet[9] = 6                                   // Protocol (TCP)
	binary.BigEndian.PutUint16(packet[10:12], 0)    // Header checksum (will be calculated)

	// Source IP: 192.168.1.1
	packet[12] = 192
	packet[13] = 168
	packet[14] = 1
	packet[15] = 1

	// Dest IP: 192.168.1.2
	packet[16] = 192
	packet[17] = 168
	packet[18] = 1
	packet[19] = 2

	// TCP header (starts at offset 20)
	binary.BigEndian.PutUint16(packet[20:22], 12345) // Source port
	binary.BigEndian.PutUint16(packet[22:24], 80)    // Dest port
	binary.BigEndian.PutUint32(packet[24:28], 1000)  // Seq number
	binary.BigEndian.PutUint32(packet[28:32], 2000)  // Ack number
	packet[32] = 0x50                                // Data offset (5 * 4 = 20 bytes)
	packet[33] = 0x18                                // Flags (PSH + ACK)
	binary.BigEndian.PutUint16(packet[34:36], 8192)  // Window size
	binary.BigEndian.PutUint16(packet[36:38], 0)     // Checksum (will be calculated)
	binary.BigEndian.PutUint16(packet[38:40], 0)     // Urgent pointer

	// Add some dummy payload
	for i := 40; i < 60; i++ {
		packet[i] = byte(i - 40)
	}

	return packet
}

func createValidIPv6TCPPacket() []byte {
	// Create a minimal IPv6 TCP packet
	packet := make([]byte, 80) // 40 bytes IPv6 header + 20 bytes TCP header + 20 bytes data

	// IPv6 header
	packet[0] = 0x60 // Version 6, Traffic class 0
	packet[1] = 0x00
	packet[2] = 0x00 // Flow label
	packet[3] = 0x00
	binary.BigEndian.PutUint16(packet[4:6], 40) // Payload length (TCP header + data)
	packet[6] = 6                               // Next header (TCP)
	packet[7] = 64                              // Hop limit

	// Source IP: 2001:db8::1
	binary.BigEndian.PutUint16(packet[8:10], 0x2001)
	binary.BigEndian.PutUint16(packet[10:12], 0x0db8)
	for i := 12; i < 22; i++ {
		packet[i] = 0
	}
	binary.BigEndian.PutUint16(packet[22:24], 0x0001)

	// Dest IP: 2001:db8::2
	binary.BigEndian.PutUint16(packet[24:26], 0x2001)
	binary.BigEndian.PutUint16(packet[26:28], 0x0db8)
	for i := 28; i < 38; i++ {
		packet[i] = 0
	}
	binary.BigEndian.PutUint16(packet[38:40], 0x0002)

	// TCP header (starts at offset 40)
	binary.BigEndian.PutUint16(packet[40:42], 12345) // Source port
	binary.BigEndian.PutUint16(packet[42:44], 80)    // Dest port
	binary.BigEndian.PutUint32(packet[44:48], 1000)  // Seq number
	binary.BigEndian.PutUint32(packet[48:52], 2000)  // Ack number
	packet[52] = 0x50                                // Data offset (5 * 4 = 20 bytes)
	packet[53] = 0x18                                // Flags (PSH + ACK)
	binary.BigEndian.PutUint16(packet[54:56], 8192)  // Window size
	binary.BigEndian.PutUint16(packet[56:58], 0)     // Checksum (will be calculated)
	binary.BigEndian.PutUint16(packet[58:60], 0)     // Urgent pointer

	// Add some dummy payload
	for i := 60; i < 80; i++ {
		packet[i] = byte(i - 60)
	}

	return packet
}

func BenchmarkRecalculateTCPChecksumIPv4(b *testing.B) {
	packet := createValidIPv4TCPPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Make a copy to avoid modifying the original
		testPacket := make([]byte, len(packet))
		copy(testPacket, packet)

		err := RecalculateTCPChecksum(testPacket)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkRecalculateTCPChecksumIPv6(b *testing.B) {
	packet := createValidIPv6TCPPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Make a copy to avoid modifying the original
		testPacket := make([]byte, len(packet))
		copy(testPacket, packet)

		err := RecalculateTCPChecksum(testPacket)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkVerifyTCPChecksum(b *testing.B) {
	packet := createValidIPv4TCPPacket()
	err := RecalculateTCPChecksum(packet)
	if err != nil {
		b.Fatalf("failed to prepare test packet: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid, err := VerifyTCPChecksum(packet)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		if !valid {
			b.Fatal("checksum should be valid")
		}
	}
}
