// SPDX-License-Identifier: AGPL-3.0-only

// Package mss lowers the TCP MSS option of SYN packets, so that TCP segments
// fit in a smaller MTU.
package mss

import "encoding/binary"

const protoTCP = 6

// Clamp lowers a larger MSS option of the TCP SYN or SYN-ACK in pkt to fit in mtu, and
// updates the TCP checksum. It reports whether it changed pkt.
func Clamp(pkt []byte, mtu int) bool {
	if len(pkt) == 0 {
		return false
	}
	var tcp []byte
	limit := mtu
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		// Only the first fragment has the TCP header.
		if ihl < 20 || len(pkt) < ihl || pkt[9] != protoTCP || binary.BigEndian.Uint16(pkt[6:])&0x1fff != 0 {
			return false
		}
		tcp, limit = pkt[ihl:], mtu-40
	case 6:
		// Packets with extension headers are not changed.
		if len(pkt) < 40 || pkt[6] != protoTCP {
			return false
		}
		tcp, limit = pkt[40:], mtu-60
	default:
		return false
	}
	if len(tcp) < 20 || tcp[13]&0x02 == 0 {
		return false
	}
	end := int(tcp[12]>>4) * 4
	if end < 20 || end > len(tcp) {
		return false
	}
	for i := 20; i < end; {
		switch tcp[i] {
		case 0:
			return false
		case 1:
			i++
			continue
		}
		if i+1 >= end || tcp[i+1] < 2 || i+int(tcp[i+1]) > end {
			return false
		}
		if tcp[i] == 2 && tcp[i+1] == 4 {
			return set(tcp, i+2, limit)
		}
		i += int(tcp[i+1])
	}
	return false
}

// set lowers the 16-bit value at tcp[off:] to limit and updates the checksum
// with RFC 1624 eqn. 3.
func set(tcp []byte, off, limit int) bool {
	old := binary.BigEndian.Uint16(tcp[off:])
	if int(old) <= limit {
		return false
	}
	m := uint16(limit)
	binary.BigEndian.PutUint16(tcp[off:], m)
	if off%2 == 1 {
		// At an odd offset, the bytes add to the sum in the other order.
		old, m = old<<8|old>>8, m<<8|m>>8
	}
	sum := uint32(^binary.BigEndian.Uint16(tcp[16:])) + uint32(^old) + uint32(m)
	sum = sum&0xffff + sum>>16
	sum = sum&0xffff + sum>>16
	binary.BigEndian.PutUint16(tcp[16:], ^uint16(sum))
	return true
}
