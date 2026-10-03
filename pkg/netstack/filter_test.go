// SPDX-License-Identifier: AGPL-3.0-only

package netstack_test

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/dpeckett/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
)

// TestFilter checks the packets that a stack takes, with the default
// iptables and with WithoutIPTables.
func TestFilter(t *testing.T) {
	const self4, peer4, self6, peer6 = "10.0.0.1", "10.0.0.2", "fd00::1", "fd00::2"
	inputDropped := func(s *stack.Stack) uint64 { return s.Stats().IP.IPTablesInputDropped.Value() }
	tooBig := func(s *stack.Stack) uint64 { return s.Stats().ICMP.V6.PacketsReceived.PacketTooBig.Value() }
	unreachable4 := func(s *stack.Stack) uint64 { return s.Stats().ICMP.V4.PacketsReceived.DstUnreachable.Value() }
	cases := []struct {
		name     string
		noTables bool
		forward  bool // ForwardTo turns on spoofing and promiscuous mode.
		pkt      []byte
		reply    bool                        // The stack answers.
		count    func(s *stack.Stack) uint64 // The packet adds 1 to this counter.
	}{
		{name: "tables drop echo", pkt: echo6(peer6, self6), count: inputDropped},
		{name: "tables drop packet too big", pkt: tooBig6(peer6, self6), count: inputDropped},
		{name: "echo", noTables: true, pkt: echo6(peer6, self6), reply: true},
		{name: "echo IPv4", noTables: true, pkt: echo4(peer4, self4), reply: true},
		{name: "echo to a forwarded address", noTables: true, forward: true, pkt: echo6(peer6, "fd00::99")},
		{name: "echo IPv4 to a forwarded address", noTables: true, forward: true, pkt: echo4(peer4, "10.9.9.9")},
		{name: "packet too big", noTables: true, pkt: tooBig6(peer6, self6), count: tooBig},
		{name: "unreachable IPv4", noTables: true, pkt: unreachable4Pkt(peer4, self4), count: unreachable4},
		// Without the filter, the stack answers with a parameter problem.
		{name: "other protocol", noTables: true, pkt: ip6(peer6, self6, 47, make([]byte, 8))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var opts []netstack.Option
			if tc.noTables {
				opts = append(opts, netstack.WithoutIPTables())
			}
			s := newStackWith(t, opts, self4+"/32", self6+"/128")
			if tc.forward {
				require.NoError(t, s.ForwardTo(t.Context(), network.Loopback()))
			}
			var before uint64
			if tc.count != nil {
				before = tc.count(s.Stack)
			}
			pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(tc.pkt)})
			proto := header.IPv6ProtocolNumber
			if tc.pkt[0]>>4 == 4 {
				proto = header.IPv4ProtocolNumber
			}
			s.Endpoint.InjectInbound(proto, pkb)
			pkb.DecRef()

			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			out := s.Endpoint.ReadContext(ctx)
			if tc.reply {
				require.NotNil(t, out, "no reply")
				assert.True(t, isEchoReply(out.ToView().AsSlice()), "the reply is not an echo reply")
			} else {
				assert.Nil(t, out, "the stack answered")
			}
			if out != nil {
				out.DecRef()
			}
			if tc.count != nil {
				assert.Equal(t, before+1, tc.count(s.Stack))
			}
		})
	}
}

// TestStackTCP checks that TCP works between two stacks, with and without
// iptables.
func TestStackTCP(t *testing.T) {
	for _, noTables := range []bool{false, true} {
		t.Run(map[bool]string{false: "tables", true: "no tables"}[noTables], func(t *testing.T) {
			var opts []netstack.Option
			if noTables {
				opts = append(opts, netstack.WithoutIPTables())
			}
			a, b := newStackWith(t, opts, "fd00::1/128"), newStackWith(t, opts, "fd00::2/128")
			spliceStacks(t, a, b)
			ln, err := gonet.ListenTCP(b.Stack, fullAddr(1, netip.MustParseAddr("fd00::2"), 80), header.IPv6ProtocolNumber)
			require.NoError(t, err)
			defer ln.Close()
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			c, err := gonet.DialContextTCP(ctx, a.Stack, fullAddr(1, netip.MustParseAddr("fd00::2"), 80), header.IPv6ProtocolNumber)
			require.NoError(t, err)
			defer c.Close()
			_, err = c.Write([]byte("ping"))
			require.NoError(t, err)
			buf := make([]byte, 4)
			_, err = io.ReadFull(c, buf)
			require.NoError(t, err)
			assert.Equal(t, "ping", string(buf))
		})
	}
}

// newStackWith makes a stack with opts and addrs, and closes it at the end
// of the test.
func newStackWith(t *testing.T, opts []netstack.Option, addrs ...string) *netstack.Stack {
	s, err := netstack.NewStack(netstack.TunnelMTU, "", opts...)
	require.NoError(t, err)
	t.Cleanup(s.Close)
	for _, a := range addrs {
		require.NoError(t, s.AddAddr(netip.MustParsePrefix(a)))
	}
	return s
}

func addr(a string) tcpip.Address { return tcpip.AddrFromSlice(netip.MustParseAddr(a).AsSlice()) }

// ip6 returns an IPv6 packet with the next header proto and payload.
func ip6(src, dst string, proto uint8, payload []byte) []byte {
	b := make([]byte, header.IPv6MinimumSize+len(payload))
	header.IPv6(b).Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(payload)),
		TransportProtocol: tcpip.TransportProtocolNumber(proto),
		HopLimit:          64,
		SrcAddr:           addr(src),
		DstAddr:           addr(dst),
	})
	copy(b[header.IPv6MinimumSize:], payload)
	return b
}

// icmp6 returns an ICMPv6 packet: the type, the 4 bytes after the checksum,
// and body.
func icmp6(src, dst string, typ header.ICMPv6Type, rest uint32, body []byte) []byte {
	msg := make([]byte, header.ICMPv6MinimumSize+len(body))
	ic := header.ICMPv6(msg)
	ic.SetType(typ)
	binary.BigEndian.PutUint32(msg[4:], rest)
	copy(msg[header.ICMPv6MinimumSize:], body)
	ic.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: ic, Src: addr(src), Dst: addr(dst)}))
	return ip6(src, dst, uint8(header.ICMPv6ProtocolNumber), msg)
}

func echo6(src, dst string) []byte {
	return icmp6(src, dst, header.ICMPv6EchoRequest, 7<<16|1, []byte("ping"))
}

// tooBig6 returns a Packet Too Big error with MTU 1280 about a UDP packet
// from dst to src.
func tooBig6(src, dst string) []byte {
	inner := ip6(dst, src, uint8(header.UDPProtocolNumber), make([]byte, header.UDPMinimumSize))
	return icmp6(src, dst, header.ICMPv6PacketTooBig, 1280, inner)
}

// ip4 returns an IPv4 packet with the protocol proto and payload.
func ip4(src, dst string, proto uint8, payload []byte) []byte {
	b := make([]byte, header.IPv4MinimumSize+len(payload))
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		TTL:         64,
		Protocol:    proto,
		SrcAddr:     addr(src),
		DstAddr:     addr(dst),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	copy(b[header.IPv4MinimumSize:], payload)
	return b
}

// icmp4 returns an ICMPv4 packet: the type, the code, the 4 bytes after the
// checksum, and body.
func icmp4(src, dst string, typ header.ICMPv4Type, code header.ICMPv4Code, rest uint32, body []byte) []byte {
	msg := make([]byte, header.ICMPv4MinimumSize+len(body))
	ic := header.ICMPv4(msg)
	ic.SetType(typ)
	ic.SetCode(code)
	binary.BigEndian.PutUint32(msg[4:], rest)
	copy(msg[header.ICMPv4MinimumSize:], body)
	ic.SetChecksum(header.ICMPv4Checksum(ic, 0))
	return ip4(src, dst, uint8(header.ICMPv4ProtocolNumber), msg)
}

func echo4(src, dst string) []byte {
	return icmp4(src, dst, header.ICMPv4Echo, 0, 7<<16|1, []byte("ping"))
}

// unreachable4Pkt returns a port unreachable error about a UDP packet from
// dst to src.
func unreachable4Pkt(src, dst string) []byte {
	inner := ip4(dst, src, uint8(header.UDPProtocolNumber), make([]byte, header.UDPMinimumSize))
	return icmp4(src, dst, header.ICMPv4DstUnreachable, header.ICMPv4PortUnreachable, 0, inner)
}

func isEchoReply(b []byte) bool {
	switch {
	case len(b) > header.IPv6MinimumSize && b[0]>>4 == 6:
		return header.ICMPv6Type(b[header.IPv6MinimumSize]) == header.ICMPv6EchoReply
	case len(b) > header.IPv4MinimumSize && b[0]>>4 == 4:
		return header.ICMPv4Type(b[header.IPv4(b).HeaderLength()]) == header.ICMPv4EchoReply
	}
	return false
}
