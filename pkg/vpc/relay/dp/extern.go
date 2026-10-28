// SPDX-License-Identifier: AGPL-3.0-only

package dp

import "net/netip"

// innerAddrs is the extern function inner_addrs of relay.p4. It gives the source and destination
// of the inner IPv4 or IPv6 packet as 128-bit addresses (IPv4 mapped), and its PSP Next Header:
// nextV4 or nextV6. It gives 0 for another packet.
func innerAddrs(pkt *packet, src, dst *netip.Addr) uint8 {
	b := pkt.data
	switch {
	case len(b) >= 20 && b[0]>>4 == 4:
		s, d := netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
		*src, *dst = netip.AddrFrom16(s.As16()), netip.AddrFrom16(d.As16())
		return nextV4
	case len(b) >= 40 && b[0]>>4 == 6:
		*src, *dst = netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40]))
		return nextV6
	}
	return 0
}

// flowHash is the extern function flow_hash of relay.p4. It hashes the addresses, the protocol and
// the first 4 bytes of a TCP, UDP or SCTP header (the ports) of the inner IP packet, with FNV-1a.
// It gives 0 for another packet.
func flowHash(pkt *packet) uint32 {
	b := pkt.data
	var addrs []byte
	var proto byte
	l4 := -1
	switch {
	case len(b) >= 20 && b[0]>>4 == 4:
		addrs, proto, l4 = b[12:20], b[9], int(b[0]&0x0f)*4
	case len(b) >= 40 && b[0]>>4 == 6:
		addrs, proto, l4 = b[8:40], b[6], 40
	default:
		return 0
	}
	h := uint32(2166136261)
	mix := func(b []byte) {
		for _, x := range b {
			h ^= uint32(x)
			h *= 16777619
		}
	}
	mix(addrs)
	mix([]byte{proto})
	if (proto == 6 || proto == 17 || proto == 132) && l4 >= 20 && len(b) >= l4+4 {
		mix(b[l4 : l4+4])
	}
	return h
}
