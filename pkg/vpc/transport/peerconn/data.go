// SPDX-License-Identifier: AGPL-3.0-only

package peerconn

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// DataLen is the header length of a data frame. The VNI word is the same as
// in the PSP VC: the VNI (24 bits), then 8 flag bits.
const DataLen = 1 + 4

var (
	ErrVNI    = errors.New("peerconn: frame VNI is not the VNI of the session")
	ErrSource = errors.New("peerconn: inner source is not an address of the peer")
)

// EncodeData appends a data frame for vni to b. vni must fit in 24 bits, and
// the flags are zero.
func EncodeData(b []byte, vni uint32, inner []byte) []byte {
	b = append(b, TypeData)
	b = binary.BigEndian.AppendUint32(b, vni<<8)
	return append(b, inner...)
}

// DecodeData returns the VNI and the inner packet of a data frame. inner
// shares memory with b.
func DecodeData(b []byte) (vni uint32, inner []byte, err error) {
	if err := check(b, DataLen, TypeData); err != nil {
		return 0, nil, err
	}
	return binary.BigEndian.Uint32(b[1:DataLen]) >> 8, b[DataLen:], nil
}

// OpenData returns the inner packet of a data frame if the frame VNI is vni
// and sources allows the inner source. It ignores the flags.
func OpenData(b []byte, vni uint32, sources func(netip.Addr) bool) ([]byte, error) {
	v, inner, err := DecodeData(b)
	if err != nil {
		return nil, err
	}
	if v != vni {
		return nil, ErrVNI
	}
	if src, ok := innerSource(inner); !ok || !sources(src) {
		return nil, ErrSource
	}
	return inner, nil
}

// innerSource returns the source address of an IPv4 or IPv6 packet.
func innerSource(p []byte) (netip.Addr, bool) {
	switch {
	case len(p) >= 20 && p[0]>>4 == 4:
		return netip.AddrFrom4([4]byte(p[12:16])), true
	case len(p) >= 40 && p[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(p[8:24])), true
	}
	return netip.Addr{}, false
}
