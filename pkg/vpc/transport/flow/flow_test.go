// SPDX-License-Identifier: AGPL-3.0-only

package flow

import (
	"encoding/binary"
	"hash/maphash"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func packet(src, dst netip.Addr, proto byte, sport, dport uint16, size int) []byte {
	p := make([]byte, size)
	if src.Is4() {
		p[0] = 0x45
		p[9] = proto
		copy(p[12:16], src.AsSlice())
		copy(p[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(p[20:], sport)
		binary.BigEndian.PutUint16(p[22:], dport)
		return p
	}
	p[0] = 0x60
	p[6] = proto
	copy(p[8:24], src.AsSlice())
	copy(p[24:40], dst.AsSlice())
	binary.BigEndian.PutUint16(p[40:], sport)
	binary.BigEndian.PutUint16(p[42:], dport)
	return p
}

func TestHash(t *testing.T) {
	v4a, v4b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	v6a, v6b := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	frag := func(p []byte) []byte { p[6] = 0x20; return p } // MF set.
	cases := []struct {
		name string
		x, y []byte
		same bool
	}{
		{"same flow, other size", packet(v4a, v4b, 6, 1, 2, 100), packet(v4a, v4b, 6, 1, 2, 900), true},
		{"TCP source port", packet(v4a, v4b, 6, 1, 2, 100), packet(v4a, v4b, 6, 3, 2, 100), false},
		{"UDP destination port", packet(v4a, v4b, 17, 1, 2, 100), packet(v4a, v4b, 17, 1, 4, 100), false},
		{"protocol", packet(v4a, v4b, 6, 1, 2, 100), packet(v4a, v4b, 17, 1, 2, 100), false},
		{"destination", packet(v4a, v4b, 6, 1, 2, 100), packet(v4a, v4a, 6, 1, 2, 100), false},
		{"ICMP has no ports", packet(v4a, v4b, 1, 1, 2, 100), packet(v4a, v4b, 1, 3, 4, 100), true},
		{"fragments have no ports", frag(packet(v4a, v4b, 17, 1, 2, 100)), frag(packet(v4a, v4b, 17, 3, 4, 100)), true},
		{"IPv4 too short for ports", packet(v4a, v4b, 6, 1, 2, 24)[:22], packet(v4a, v4b, 6, 3, 4, 24)[:22], true},
		{"IPv6 TCP source port", packet(v6a, v6b, 6, 1, 2, 100), packet(v6a, v6b, 6, 3, 2, 100), false},
		{"IPv6 extension header", packet(v6a, v6b, 0, 1, 2, 100), packet(v6a, v6b, 0, 3, 4, 100), true},
	}
	seed := maphash.MakeSeed()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.same, Hash(seed, tc.x) == Hash(seed, tc.y))
		})
	}
}

func TestHashNotIP(t *testing.T) {
	v4, v6 := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fd00::1")
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"empty", nil},
		{"short IPv4", packet(v4, v4, 6, 1, 2, 40)[:19]},
		{"short IPv6", packet(v6, v6, 6, 1, 2, 60)[:39]},
		{"version 5", append([]byte{0x50}, make([]byte, 40)...)},
	}
	seed := maphash.MakeSeed()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Zero(t, Hash(seed, tc.pkt))
		})
	}
}

func BenchmarkHash(b *testing.B) {
	pkt := packet(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2"), 6, 1, 2, 100)
	seed := maphash.MakeSeed()
	b.ReportAllocs()
	for b.Loop() {
		Hash(seed, pkt)
	}
}
