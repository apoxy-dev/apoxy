// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

func ipAddr(s string) tcpip.Address { return tcpip.AddrFromSlice(netip.MustParseAddr(s).AsSlice()) }

func ip6(src, dst string, proto tcpip.TransportProtocolNumber, payload []byte) []byte {
	b := make([]byte, header.IPv6MinimumSize+len(payload))
	header.IPv6(b).Encode(&header.IPv6Fields{
		PayloadLength: uint16(len(payload)), TransportProtocol: proto, HopLimit: 64, SrcAddr: ipAddr(src), DstAddr: ipAddr(dst),
	})
	copy(b[header.IPv6MinimumSize:], payload)
	return b
}

func ip4(src, dst string, proto tcpip.TransportProtocolNumber, fragOff uint16, payload []byte) []byte {
	b := make([]byte, header.IPv4MinimumSize+len(payload))
	header.IPv4(b).Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)), TTL: 64, Protocol: uint8(proto), FragmentOffset: fragOff, SrcAddr: ipAddr(src), DstAddr: ipAddr(dst),
	})
	copy(b[header.IPv4MinimumSize:], payload)
	return b
}

func TestUnreachable(t *testing.T) {
	const src6, dst6, src4, dst4 = "fd61:706f:7879:12:3400:1::1", "fd61:706f:7879:12:3400:99::1", "10.1.0.1", "10.9.0.1"
	self := netip.MustParseAddr(src6)
	udp := make([]byte, 20)
	echo6, err6 := []byte{byte(header.ICMPv6EchoRequest), 0, 0, 0}, []byte{byte(header.ICMPv6DstUnreachable), 3, 0, 0}
	echo4, err4 := []byte{byte(header.ICMPv4Echo), 0, 0, 0}, []byte{byte(header.ICMPv4DstUnreachable), 1, 0, 0}
	badIHL := ip4(src4, dst4, header.UDPProtocolNumber, 0, udp)
	badIHL[0] = 0x44
	cases := []struct {
		name string
		pkt  []byte
		from netip.Addr
		code uint8
		size int // Size of the error. Zero means no error.
	}{
		{name: "IPv6 UDP", pkt: ip6(src6, dst6, header.UDPProtocolNumber, udp), from: self, code: 3, size: 48 + 60},
		{name: "IPv6 large", pkt: ip6(src6, dst6, header.UDPProtocolNumber, make([]byte, 3000)), from: self, code: 3, size: 1280},
		{name: "IPv6 echo request", pkt: ip6(src6, dst6, header.ICMPv6ProtocolNumber, echo6), from: self, code: 3, size: 48 + 44},
		{name: "IPv6 ICMP error", pkt: ip6(src6, dst6, header.ICMPv6ProtocolNumber, err6), from: self},
		{name: "IPv6 ICMP with no header", pkt: ip6(src6, dst6, header.ICMPv6ProtocolNumber, nil), from: self},
		{name: "IPv6 multicast", pkt: ip6(src6, "ff02::1", header.UDPProtocolNumber, udp), from: self},
		{name: "IPv6 link local source", pkt: ip6("fe80::1", dst6, header.UDPProtocolNumber, udp), from: self},
		{name: "IPv6 with no IPv6 agent address", pkt: ip6(src6, dst6, header.UDPProtocolNumber, udp)},
		{name: "IPv4 UDP", pkt: ip4(src4, dst4, header.UDPProtocolNumber, 0, udp), code: 1, size: 28 + 40},
		{name: "IPv4 large", pkt: ip4(src4, dst4, header.UDPProtocolNumber, 0, make([]byte, 2000)), code: 1, size: 576},
		{name: "IPv4 echo request", pkt: ip4(src4, dst4, header.ICMPv4ProtocolNumber, 0, echo4), code: 1, size: 28 + 24},
		{name: "IPv4 ICMP error", pkt: ip4(src4, dst4, header.ICMPv4ProtocolNumber, 0, err4)},
		{name: "IPv4 fragment", pkt: ip4(src4, dst4, header.UDPProtocolNumber, 64, udp)},
		{name: "IPv4 broadcast", pkt: ip4(src4, "255.255.255.255", header.UDPProtocolNumber, 0, udp)},
		{name: "IPv4 bad header length", pkt: badIHL},
		{name: "short", pkt: []byte{0x45, 0, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := unreachable(tc.pkt, tc.from)
			if tc.size == 0 {
				assert.Nil(t, got)
				return
			}
			require.Len(t, got, tc.size)
			if got[0]>>4 == 6 {
				ip, orig := header.IPv6(got), header.IPv6(tc.pkt)
				assert.Equal(t, int(ip.PayloadLength()), len(got)-header.IPv6MinimumSize)
				assert.Equal(t, header.ICMPv6ProtocolNumber, ip.TransportProtocol())
				assert.Equal(t, ipAddr(src6), ip.SourceAddress())
				assert.Equal(t, orig.SourceAddress(), ip.DestinationAddress())
				icmp := header.ICMPv6(ip.Payload())
				assert.Equal(t, header.ICMPv6DstUnreachable, icmp.Type())
				assert.Equal(t, header.ICMPv6Code(tc.code), icmp.Code())
				sum := header.PseudoHeaderChecksum(header.ICMPv6ProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(icmp)))
				assert.Equal(t, uint16(0xffff), checksum.Checksum(icmp, sum), "checksum")
				assert.Equal(t, tc.pkt[:len(icmp.Payload())], icmp.Payload())
				return
			}
			ip, orig := header.IPv4(got), header.IPv4(tc.pkt)
			assert.True(t, ip.IsChecksumValid(), "IP checksum")
			assert.Equal(t, int(ip.TotalLength()), len(got))
			assert.Equal(t, uint8(header.ICMPv4ProtocolNumber), ip.Protocol())
			assert.Equal(t, orig.DestinationAddress(), ip.SourceAddress())
			assert.Equal(t, orig.SourceAddress(), ip.DestinationAddress())
			icmp := header.ICMPv4(ip.Payload())
			assert.Equal(t, header.ICMPv4DstUnreachable, icmp.Type())
			assert.Equal(t, header.ICMPv4Code(tc.code), icmp.Code())
			assert.Equal(t, uint16(0xffff), checksum.Checksum(icmp, 0), "checksum")
			assert.Equal(t, tc.pkt[:len(icmp.Payload())], icmp.Payload())
		})
	}
}

// TestNoRouteError checks that packets to a destination that the relay cannot
// reach get an ICMP error after the NoRoute of the relay. A destination keeps
// one error a second.
func TestNoRouteError(t *testing.T) {
	absent := func(attachEvent) netip.Addr { return netip.MustParseAddr("fd61:706f:7879:12:3400:99::1") }
	cases := []struct {
		name    string
		dst     func(eb attachEvent) netip.Addr
		dialErr string // Not empty: a TCP dial in place of a UDP packet fails with this error.
		// vpcStack uses the netstack of vpc connect, which must let the ICMPv6 error in.
		vpcStack bool
		// waits are the times before more one-packet flows; each flow gets an error.
		waits []time.Duration
	}{
		{name: "not found", dst: absent},
		{name: "TCP dial to an absent address", dst: absent, dialErr: (&tcpip.ErrHostUnreachable{}).String()},
		{name: "outside the VPC", dst: func(attachEvent) netip.Addr { return netip.MustParseAddr("fd97::1") }},
		{name: "TCP dial to an absent address, vpc connect stack", dst: absent, vpcStack: true, dialErr: (&tcpip.ErrHostUnreachable{}).String()},
		{name: "two flows 1.5 s apart", dst: absent, waits: []time.Duration{1500 * time.Millisecond}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			a, b := w.agent(t, "a", r, agentOptions{tcp: tc.dialErr != "", vpcStack: tc.vpcStack}), w.agent(t, "b", r, agentOptions{})
			ea, eb := a.attached(t), b.attached(t)
			dst := tc.dst(eb)
			if tc.dialErr != "" {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				start := time.Now()
				_, err := gonet.DialContextTCP(ctx, a.stack, *fullAddr(dst, 9000), ipv6.ProtocolNumber)
				require.ErrorContains(t, err, tc.dialErr)
				assert.Less(t, time.Since(start), time.Second, "the dial stops at the ICMP error")
				return
			}
			send(t, a.stack, ea.addr, dst, 9000, "no route")
			require.Eventually(t, func() bool { return unreachableIn(a) == 1 }, 5*time.Second, 10*time.Millisecond)
			for i, wait := range tc.waits {
				time.Sleep(wait)
				send(t, a.stack, ea.addr, dst, uint16(9001+i), "no route")
				require.Eventually(t, func() bool { return unreachableIn(a) == uint64(i+2) }, 5*time.Second, 10*time.Millisecond)
			}
		})
	}
}
