// SPDX-License-Identifier: AGPL-3.0-only

package netstack

import (
	"encoding/binary"
	"slices"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// inFilter is the receive filter of a stack with no iptables. It keeps no
// state for each connection. It lets in TCP, UDP and ICMP errors, and ICMP
// echo requests to an address of the stack. A promiscuous NIC thus answers
// no echo request for the addresses that it forwards.
type inFilter struct {
	nested.Endpoint

	mu    sync.Mutex // Serializes add and del.
	addrs atomic.Pointer[[]tcpip.Address]
}

func newInFilter(child stack.LinkEndpoint) *inFilter {
	f := &inFilter{}
	f.Endpoint.Init(child, f)
	f.addrs.Store(&[]tcpip.Address{})
	return f
}

// DeliverNetworkPacket gives the packets that the filter lets in to the stack.
func (f *inFilter) DeliverNetworkPacket(proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if f.allow(pkt) {
		f.Endpoint.DeliverNetworkPacket(proto, pkt)
	}
}

func (f *inFilter) add(a tcpip.Address) {
	f.mu.Lock()
	defer f.mu.Unlock()
	old := *f.addrs.Load()
	if !slices.ContainsFunc(old, a.Equal) {
		addrs := append(slices.Clip(old), a)
		f.addrs.Store(&addrs)
	}
}

func (f *inFilter) del(a tcpip.Address) {
	f.mu.Lock()
	defer f.mu.Unlock()
	addrs := slices.DeleteFunc(slices.Clone(*f.addrs.Load()), a.Equal)
	f.addrs.Store(&addrs)
}

func (f *inFilter) local(a tcpip.Address) bool {
	return slices.ContainsFunc(*f.addrs.Load(), a.Equal)
}

// maxExtHeaders is the most IPv6 extension headers that the filter reads.
const maxExtHeaders = 8

func (f *inFilter) allow(pkt *stack.PacketBuffer) bool {
	b, ok := pkt.Data().PullUp(min(pkt.Data().Size(), header.IPv6MinimumSize+maxExtHeaders*8+header.ICMPv6MinimumSize))
	if !ok || len(b) == 0 {
		return false
	}
	switch b[0] >> 4 {
	case header.IPv4Version:
		if len(b) < header.IPv4MinimumSize {
			return false
		}
		ip := header.IPv4(b)
		hl := int(ip.HeaderLength())
		switch ip.TransportProtocol() {
		case header.TCPProtocolNumber, header.UDPProtocolNumber:
			return true
		case header.ICMPv4ProtocolNumber:
			if ip.FragmentOffset() != 0 || len(b) < hl+1 {
				return false
			}
			switch header.ICMPv4Type(b[hl]) {
			case header.ICMPv4DstUnreachable, header.ICMPv4TimeExceeded, header.ICMPv4ParamProblem:
				return true
			case header.ICMPv4Echo:
				return f.local(ip.DestinationAddress())
			}
		}
		return false
	case header.IPv6Version:
		if len(b) < header.IPv6MinimumSize {
			return false
		}
		ip := header.IPv6(b)
		next, off := ip.NextHeader(), header.IPv6MinimumSize
		for range maxExtHeaders {
			switch tcpip.TransportProtocolNumber(next) {
			case header.TCPProtocolNumber, header.UDPProtocolNumber:
				return true
			case header.ICMPv6ProtocolNumber:
				if len(b) < off+1 {
					return false
				}
				t := header.ICMPv6Type(b[off])
				if t == header.ICMPv6EchoRequest {
					return f.local(ip.DestinationAddress())
				}
				// Types below 128 are errors, for example Packet Too Big.
				return t < header.ICMPv6EchoRequest
			}
			switch header.IPv6ExtensionHeaderIdentifier(next) {
			case header.IPv6HopByHopOptionsExtHdrIdentifier, header.IPv6RoutingExtHdrIdentifier,
				header.IPv6DestinationOptionsExtHdrIdentifier:
				if len(b) < off+2 {
					return false
				}
				next, off = b[off], off+(int(b[off+1])+1)*8
			case header.IPv6FragmentExtHdrIdentifier:
				if len(b) < off+8 {
					return false
				}
				// Only the first fragment has the next header. Let in the others
				// of TCP and UDP.
				if binary.BigEndian.Uint16(b[off+2:])&^7 != 0 {
					p := tcpip.TransportProtocolNumber(b[off])
					return p == header.TCPProtocolNumber || p == header.UDPProtocolNumber
				}
				next, off = b[off], off+8
			default:
				return false
			}
		}
	}
	return false
}
