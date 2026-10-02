// SPDX-License-Identifier: AGPL-3.0-only

// Package flow hashes the inner packets of tunnels by flow, so that all
// packets of a flow use one lane or one connection.
package flow

import (
	"encoding/binary"
	"hash/maphash"
)

// Hash returns a keyed hash of the addresses, protocol and ports of an IPv4
// or IPv6 packet. Fragments and IPv6 packets with extension headers hash
// without ports. Other packets hash to 0.
func Hash(seed maphash.Seed, pkt []byte) uint64 {
	var k [37]byte
	n := 0
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4:
		n = copy(k[:], pkt[12:20])
		proto := pkt[9]
		k[n] = proto
		n++
		hl := int(pkt[0]&0x0f) * 4
		frag := binary.BigEndian.Uint16(pkt[6:8]) & 0x3fff // MF and the offset.
		if hasPorts(proto) && frag == 0 && len(pkt) >= hl+4 {
			n += copy(k[n:], pkt[hl:hl+4])
		}
	case len(pkt) >= 40 && pkt[0]>>4 == 6:
		n = copy(k[:], pkt[8:40])
		next := pkt[6]
		k[n] = next
		n++
		if hasPorts(next) && len(pkt) >= 44 {
			n += copy(k[n:], pkt[40:44])
		}
	default:
		return 0
	}
	return maphash.Bytes(seed, k[:n])
}

// hasPorts reports whether the protocol is TCP, UDP or SCTP.
func hasPorts(proto byte) bool { return proto == 6 || proto == 17 || proto == 132 }
