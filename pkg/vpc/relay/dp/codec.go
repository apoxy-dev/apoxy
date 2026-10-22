// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
)

// The P4Runtime values are big-endian byte strings. The DP writes the canonical (shortest) form and
// reads a value of any length that fits its width.

// anyPrefix is an LPM field that is not in an entry: it matches all addresses.
var anyPrefix = netip.PrefixFrom(netip.IPv6Unspecified(), 0)

var errEmpty = errors.New("empty value")

// canonical removes the leading zero bytes of b and keeps at least one byte.
func canonical(b []byte) []byte {
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

func encodeUint(v uint64, bits int) []byte {
	if bits < 64 {
		v &= 1<<bits - 1
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return canonical(b[:])
}

func decodeUint(b []byte, bits int) (uint64, error) {
	if len(b) == 0 {
		return 0, errEmpty
	}
	b = canonical(b)
	if len(b) > 8 {
		return 0, fmt.Errorf("value is wider than %d bits", bits)
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	if bits < 64 && v>>bits != 0 {
		return 0, fmt.Errorf("value is wider than %d bits", bits)
	}
	return v, nil
}

func encodeBool(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}

func decodeBool(b []byte) (bool, error) {
	v, err := decodeUint(b, 1)
	return v == 1, err
}

func decodeString(b []byte) (string, error) {
	if len(b) == 0 {
		return "", errEmpty
	}
	return string(b), nil
}

// encodeAddrPort gives the 144-bit form of a: the IPv6 address (IPv4 mapped), then the port. The
// zero AddrPort is 0.
func encodeAddrPort(a netip.AddrPort) []byte {
	if !a.IsValid() {
		return []byte{0}
	}
	var b [18]byte
	ip := a.Addr().As16()
	copy(b[:16], ip[:])
	binary.BigEndian.PutUint16(b[16:], a.Port())
	return canonical(b[:])
}

func decodeAddrPort(b []byte) (netip.AddrPort, error) {
	if len(b) == 0 {
		return netip.AddrPort{}, errEmpty
	}
	b = canonical(b)
	if len(b) > 18 {
		return netip.AddrPort{}, errors.New("value is wider than 144 bits")
	}
	var w [18]byte
	copy(w[18-len(b):], b)
	if w == [18]byte{} {
		return netip.AddrPort{}, nil
	}
	return netip.AddrPortFrom(netip.AddrFrom16([16]byte(w[:16])).Unmap(), binary.BigEndian.Uint16(w[16:])), nil
}

// wide gives the 128-bit form of p: an IPv4 prefix becomes its IPv4-mapped IPv6 prefix.
func wide(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4() {
		return netip.PrefixFrom(netip.AddrFrom16(p.Addr().As16()), p.Bits()+96)
	}
	return p
}

// encodeLPM gives the LPM match of p. It is nil for a match of all addresses, which P4Runtime
// leaves out of the entry.
func encodeLPM(p netip.Prefix) *p4.FieldMatch_LPM {
	if !p.IsValid() {
		return nil
	}
	w := wide(p.Masked())
	if w.Bits() == 0 {
		return nil
	}
	a := w.Addr().As16()
	return &p4.FieldMatch_LPM{Value: canonical(a[:]), PrefixLen: int32(w.Bits())}
}

// decodeLPM returns the prefix of l. An IPv4-mapped prefix of 96 bits or more is an IPv4 prefix.
func decodeLPM(l *p4.FieldMatch_LPM) (netip.Prefix, error) {
	n := int(l.GetPrefixLen())
	if n <= 0 || n > 128 {
		return netip.Prefix{}, fmt.Errorf("prefix length %d is not valid", n)
	}
	b := canonical(l.GetValue())
	if len(b) == 0 || len(b) > 16 {
		return netip.Prefix{}, errors.New("value is not 128 bits")
	}
	var w [16]byte
	copy(w[16-len(b):], b)
	p := netip.PrefixFrom(netip.AddrFrom16(w), n)
	if p.Masked() != p {
		return netip.Prefix{}, errors.New("value has bits after the prefix length")
	}
	if p.Addr().Is4In6() && n >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), n-96), nil
	}
	return p, nil
}
