// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// tooBigRate is the most packet too big errors of a binding in one second.
const tooBigRate = 1000

// tooBig gives the sender of the inner packet virt, which is larger than mtu and which
// the binding drops, a packet too big error.
func (b *Binding) tooBig(virt []byte, mtu int) {
	if !b.ptb.admit(1) {
		return
	}
	if m := packetTooBig(virt, mtu); m != nil && b.Deliver(m) {
		b.stats.txTooBig.Add(1)
	}
}

// packetTooBig returns the ICMP error that tells the sender of pkt that the path carries
// at most mtu bytes, or nil when pkt must get no error. The error comes from the
// destination of pkt: the host has a route to it on the device, so it accepts the source.
func packetTooBig(pkt []byte, mtu int) []byte {
	switch {
	case len(pkt) >= header.IPv4MinimumSize && pkt[0]>>4 == header.IPv4Version:
		return fragNeeded4(pkt, mtu)
	case len(pkt) >= header.IPv6MinimumSize && pkt[0]>>4 == header.IPv6Version:
		return tooBig6(pkt, mtu)
	}
	return nil
}

func tooBig6(pkt []byte, mtu int) []byte {
	src, dst := netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40]))
	if !src.IsGlobalUnicast() || !dst.IsGlobalUnicast() {
		return nil
	}
	// An ICMPv6 error (type below 128) gets no error.
	if header.IPv6(pkt).TransportProtocol() == header.ICMPv6ProtocolNumber &&
		(len(pkt) == header.IPv6MinimumSize || pkt[header.IPv6MinimumSize] < 128) {
		return nil
	}
	return ICMPv6Error(pkt, dst, header.ICMPv6PacketTooBig, 0, uint32(mtu))
}

// fragNeeded4 returns the error for an IPv4 packet. RFC 1191 asks for it only with the DF
// flag, but the binding cannot fragment, so a packet without DF gets it too.
func fragNeeded4(pkt []byte, mtu int) []byte {
	ip := header.IPv4(pkt)
	n := int(ip.HeaderLength())
	src, dst := netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20]))
	if n < header.IPv4MinimumSize || len(pkt) < n || ip.FragmentOffset() != 0 ||
		!src.IsGlobalUnicast() || !dst.IsGlobalUnicast() {
		return nil
	}
	// An ICMP error gets no error.
	if ip.Protocol() == uint8(header.ICMPv4ProtocolNumber) && (len(pkt) == n || icmp4Error(header.ICMPv4Type(pkt[n]))) {
		return nil
	}
	// The next-hop MTU is the low 16 bits of the word after the checksum.
	return ICMPv4Error(pkt, header.ICMPv4DstUnreachable, header.ICMPv4FragmentationNeeded, uint32(mtu))
}

// icmp4Error reports whether an ICMPv4 message of type t is an error message.
func icmp4Error(t header.ICMPv4Type) bool {
	switch t {
	case header.ICMPv4DstUnreachable, header.ICMPv4SrcQuench, header.ICMPv4Redirect,
		header.ICMPv4TimeExceeded, header.ICMPv4ParamProblem:
		return true
	}
	return false
}
