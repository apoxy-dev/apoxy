// SPDX-License-Identifier: AGPL-3.0-only

package mss

import (
	"encoding/binary"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	syn = 0x02
	ack = 0x10
)

func mssOpt(v uint16) []byte { return []byte{2, 4, byte(v >> 8), byte(v)} }

func opts(o ...[]byte) []byte { return slices.Concat(o...) }

// v4 returns an IPv4 TCP packet with flags, TCP options o and a valid checksum.
func v4(flags byte, o []byte) []byte {
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, protoTCP
	copy(ip[12:], []byte{10, 0, 0, 1, 10, 0, 0, 2})
	return withTCP(ip, flags, o)
}

// v6 returns an IPv6 TCP packet with flags, TCP options o and a valid checksum.
func v6(flags byte, o []byte) []byte {
	ip := make([]byte, 40)
	ip[0], ip[6], ip[7] = 0x60, protoTCP, 64
	ip[8], ip[23] = 0xfd, 1
	ip[24], ip[39] = 0xfd, 2
	return withTCP(ip, flags, o)
}

func withTCP(ip []byte, flags byte, o []byte) []byte {
	tcp := make([]byte, 20+len(o), 20+len(o)+4)
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	binary.BigEndian.PutUint32(tcp[4:], 0x01020304)
	tcp[12], tcp[13] = byte(len(tcp)/4)<<4, flags
	binary.BigEndian.PutUint16(tcp[14:], 64240)
	copy(tcp[20:], o)
	tcp = append(tcp, "data"...)
	pkt := append(ip, tcp...)
	if pkt[0]>>4 == 4 {
		binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	} else {
		binary.BigEndian.PutUint16(pkt[4:], uint16(len(tcp)))
	}
	binary.BigEndian.PutUint16(pkt[len(ip)+16:], ^tcpSum(pkt, len(ip)))
	return pkt
}

// tcpSum returns the sum of the pseudo-header and the TCP segment at pkt[hl:].
func tcpSum(pkt []byte, hl int) uint16 {
	src, dst := pkt[12:16], pkt[16:20]
	if pkt[0]>>4 == 6 {
		src, dst = pkt[8:24], pkt[24:40]
	}
	tcp := pkt[hl:]
	x := header.PseudoHeaderChecksum(header.TCPProtocolNumber, tcpip.AddrFromSlice(src), tcpip.AddrFromSlice(dst), uint16(len(tcp)))
	return checksum.Checksum(tcp, x)
}

func TestClamp(t *testing.T) {
	linux := func(m uint16) []byte {
		return opts(mssOpt(m), []byte{4, 2, 8, 10, 1, 2, 3, 4, 0, 0, 0, 0, 1, 3, 3, 7})
	}
	frag := v4(syn, mssOpt(1460))
	binary.BigEndian.PutUint16(frag[6:], 185)
	udp := v4(syn, mssOpt(1460))
	udp[9] = 17
	ext := v6(syn, mssOpt(1460))
	ext[6] = 0
	ipOpts := func(m uint16) []byte {
		p := v4(syn, mssOpt(m))
		p = slices.Insert(p, 20, 1, 1, 1, 1)
		p[0] = 0x46
		return p
	}
	cases := []struct {
		name string
		pkt  []byte
		mtu  int
		want []byte // Nil if Clamp must not change pkt.
	}{
		{"v4 syn", v4(syn, mssOpt(1460)), 1280, v4(syn, mssOpt(1240))},
		{"v4 syn-ack", v4(syn|ack, mssOpt(1460)), 1280, v4(syn|ack, mssOpt(1240))},
		{"v4 mtu 1412", v4(syn, mssOpt(1460)), 1412, v4(syn, mssOpt(1372))},
		{"v4 linux options", v4(syn, linux(65495)), 1280, v4(syn, linux(1240))},
		{"v4 odd offset", v4(syn, opts([]byte{1}, mssOpt(1460), []byte{1, 1, 1})), 1280, v4(syn, opts([]byte{1}, mssOpt(1240), []byte{1, 1, 1}))},
		{"v4 after sack", v4(syn, opts([]byte{4, 2, 1, 1}, mssOpt(9000))), 1280, v4(syn, opts([]byte{4, 2, 1, 1}, mssOpt(1240)))},
		{"v4 ip options", ipOpts(1460), 1280, ipOpts(1240)},
		{"v6 syn", v6(syn, mssOpt(1440)), 1280, v6(syn, mssOpt(1220))},
		{"v6 odd offset", v6(syn|ack, opts([]byte{1}, mssOpt(1440), []byte{1, 1, 1})), 1400, v6(syn|ack, opts([]byte{1}, mssOpt(1340), []byte{1, 1, 1}))},
		{"mss below", v4(syn, mssOpt(1200)), 1280, nil},
		{"mss equal", v4(syn, mssOpt(1240)), 1280, nil},
		{"no syn", v4(ack, mssOpt(1460)), 1280, nil},
		{"no options", v4(syn, nil), 1280, nil},
		{"fragment", frag, 1280, nil},
		{"udp", udp, 1280, nil},
		{"v6 extension header", ext, 1280, nil},
		{"end of options", v4(syn, opts([]byte{0, 0, 0, 0}, mssOpt(1460))), 1280, nil},
		{"option length 0", v4(syn, opts([]byte{3, 0, 0, 0}, mssOpt(1460))), 1280, nil},
		{"option past header", v4(syn, []byte{1, 1, 3, 4}), 1280, nil},
		{"mss length 3", v4(syn, []byte{2, 3, 5, 1}), 1280, nil},
		{"short tcp", v4(syn, mssOpt(1460))[:30], 1280, nil},
		{"data offset past end", v4(syn, mssOpt(1460))[:42], 1280, nil},
		{"empty", nil, 1280, nil},
		{"not ip", []byte{0x50, 0, 0, 0}, 1280, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := slices.Clone(tc.pkt)
			changed := Clamp(pkt, tc.mtu)
			if tc.want == nil {
				assert.False(t, changed)
				assert.Equal(t, tc.pkt, pkt)
				return
			}
			assert.True(t, changed)
			assert.Equal(t, tc.want, pkt)
		})
	}
}

// Clamp must not panic, and must keep a valid TCP checksum valid.
func FuzzClamp(f *testing.F) {
	f.Add(v4(syn, mssOpt(1460)), 1280)
	f.Add(v4(syn, opts([]byte{1}, mssOpt(1460), []byte{1, 1, 1})), 1300)
	f.Add(v6(syn|ack, mssOpt(65000)), 1412)
	f.Fuzz(func(t *testing.T, pkt []byte, mtu int) {
		if mtu < 1280 || mtu > 9000 {
			return
		}
		hl := 0
		switch {
		case len(pkt) >= 20 && pkt[0] == 0x45 && pkt[9] == protoTCP:
			hl = 20
		case len(pkt) >= 40 && pkt[0]>>4 == 6 && pkt[6] == protoTCP:
			hl = 40
		}
		valid := hl > 0 && tcpSum(pkt, hl) == 0xffff
		if Clamp(pkt, mtu) && valid {
			assert.Equal(t, uint16(0xffff), tcpSum(pkt, hl))
		}
	})
}

func BenchmarkClamp(b *testing.B) {
	for _, bc := range []struct {
		name string
		pkt  []byte
	}{
		{"syn", v4(syn, opts([]byte{1}, mssOpt(1460), []byte{1, 1, 1}))},
		{"data", v4(ack, nil)},
	} {
		b.Run(bc.name, func(b *testing.B) {
			pkt := slices.Clone(bc.pkt)
			b.ReportAllocs()
			for b.Loop() {
				copy(pkt, bc.pkt)
				Clamp(pkt, 1280)
			}
		})
	}
}
