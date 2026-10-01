// SPDX-License-Identifier: AGPL-3.0-only

package peerconn

import (
	"errors"
	"net/netip"
)

// Frame types. A frame is one QUIC datagram of a relay session. The first
// byte is the type.
const (
	// TypePeer is a peer-session packet.
	TypePeer byte = 0x01
	// TypeProbe is kept for PathProbe frames: [type][dst 16 B][PathProbe].
	TypeProbe byte = 0x02
	// TypeData is kept for data frames: [type][VNI word 4 B][inner packet].
	TypeData byte = 0x03
)

// Header lengths of peer frames. Addresses are 16 B; IPv4 is 4-in-6.
const (
	// ToRelayLen is the header from the agent: [type][dst][src].
	ToRelayLen = 1 + 16 + 16
	// FromRelayLen is the header from the relay: [type][src].
	FromRelayLen = 1 + 16
)

var (
	ErrShort = errors.New("peerconn: frame is too short")
	ErrType  = errors.New("peerconn: frame is not a peer frame")
)

// EncodeToRelay appends the frame that an agent sends to b.
func EncodeToRelay(b []byte, dst, src netip.Addr, pkt []byte) []byte {
	d, s := dst.As16(), src.As16()
	b = append(b, TypePeer)
	b = append(b, d[:]...)
	b = append(b, s[:]...)
	return append(b, pkt...)
}

// DecodeToRelay returns the parts of a frame that an agent sent. pkt
// shares memory with b.
func DecodeToRelay(b []byte) (dst, src netip.Addr, pkt []byte, err error) {
	if err := check(b, ToRelayLen); err != nil {
		return dst, src, nil, err
	}
	dst = netip.AddrFrom16([16]byte(b[1:17])).Unmap()
	src = netip.AddrFrom16([16]byte(b[17:33])).Unmap()
	return dst, src, b[ToRelayLen:], nil
}

// EncodeFromRelay appends the frame that a relay delivers to b.
func EncodeFromRelay(b []byte, src netip.Addr, pkt []byte) []byte {
	s := src.As16()
	b = append(b, TypePeer)
	b = append(b, s[:]...)
	return append(b, pkt...)
}

// DecodeFromRelay returns the parts of a frame that a relay delivered. pkt
// shares memory with b.
func DecodeFromRelay(b []byte) (src netip.Addr, pkt []byte, err error) {
	if err := check(b, FromRelayLen); err != nil {
		return src, nil, err
	}
	return netip.AddrFrom16([16]byte(b[1:17])).Unmap(), b[FromRelayLen:], nil
}

// Forwarded changes a valid frame from an agent in place into the frame
// that the relay delivers, and returns it.
func Forwarded(b []byte) []byte {
	b[16] = TypePeer
	return b[16:]
}

func check(b []byte, n int) error {
	if len(b) < n {
		return ErrShort
	}
	if b[0] != TypePeer {
		return ErrType
	}
	return nil
}
