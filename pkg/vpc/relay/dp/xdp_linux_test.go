// SPDX-License-Identifier: AGPL-3.0-only

package dp_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
)

// The XDP actions of the kernel.
const (
	xdpDrop     = 1
	xdpPass     = 2
	xdpRedirect = 4
)

// testFrame is a frame from peerMAC to the relay link: the layers, serialized with their lengths.
func testFrame(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, ls...))
	return buf.Bytes()
}

var peerMAC = net.HardwareAddr{0x02, 0, 0, 0, 0x99, 0x02}

// ipFrame is a frame of the protocol proto from src to dst, with the transport layer l.
func ipFrame(t *testing.T, src, dst netip.Addr, l gopacket.SerializableLayer, proto layers.IPProtocol) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: peerMAC, DstMAC: net.HardwareAddr{0x02, 0, 0, 0, 0x99, 0x01}, EthernetType: layers.EthernetTypeIPv4}
	if dst.Is6() {
		eth.EthernetType = layers.EthernetTypeIPv6
		return testFrame(t, eth, &layers.IPv6{Version: 6, NextHeader: proto, HopLimit: 64, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}, l, gopacket.Payload("relay"))
	}
	return testFrame(t, eth, &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: proto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}, l, gopacket.Payload("relay"))
}

func udpFrame(t *testing.T, src netip.Addr, dst netip.AddrPort) []byte {
	return ipFrame(t, src, dst.Addr(), &layers.UDP{SrcPort: 7000, DstPort: layers.UDPPort(dst.Port())}, layers.IPProtocolUDP)
}

func tcpFrame(t *testing.T, src netip.Addr, dst netip.AddrPort) []byte {
	return ipFrame(t, src, dst.Addr(), &layers.TCP{SrcPort: 7000, DstPort: layers.TCPPort(dst.Port()), SYN: true, Window: 1024}, layers.IPProtocolTCP)
}

// edit sets the bytes of f at at to v.
func edit(f []byte, at int, v ...byte) []byte {
	copy(f[at:], v)
	return f
}

// TestXDPFilter runs frames through the XDP program that the device attached, with BPF test runs
// on queue 0, which has an AF_XDP socket. In Shared mode only UDP 443 and 1000 to the own addresses
// go to AF_XDP; in Dedicated mode all frames do.
func TestXDPFilter(t *testing.T) {
	const ethLen, ip4Len = 14, 20
	p, p6 := peer4.Addr(), peer6.Addr()
	r4 := func(port uint16) netip.AddrPort { return netip.AddrPortFrom(relay4.Addr(), port) }
	r6 := func(port uint16) netip.AddrPort { return netip.AddrPortFrom(relay6.Addr(), port) }
	arp := func(t *testing.T) []byte {
		return testFrame(t,
			&layers.Ethernet{SrcMAC: peerMAC, DstMAC: layers.EthernetBroadcast, EthernetType: layers.EthernetTypeARP},
			&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
				Operation: layers.ARPRequest, SourceHwAddress: peerMAC, SourceProtAddress: p.AsSlice(),
				DstHwAddress: make([]byte, 6), DstProtAddress: relay4.Addr().AsSlice()})
	}
	ndp := func(t *testing.T) []byte {
		return ipFrame(t, p6, relay6.Addr(), &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0)}, layers.IPProtocolICMPv6)
	}
	ping := func(t *testing.T) []byte {
		return ipFrame(t, p, relay4.Addr(), &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)}, layers.IPProtocolICMPv4)
	}
	type tcase struct {
		name   string
		frame  func(t *testing.T) []byte
		impair bool // An impair entry drops UDP 1000 from peer4.
		want   uint32
	}
	modes := []struct {
		mode  configv1alpha1.RelayInterfaceMode
		cases []tcase
	}{
		{mode: configv1alpha1.RelayInterfaceModeShared, cases: []tcase{
			{name: "IPv4 UDP 1000", frame: func(t *testing.T) []byte { return udpFrame(t, p, r4(1000)) }, want: xdpRedirect},
			{name: "IPv4 UDP 443", frame: func(t *testing.T) []byte { return udpFrame(t, p, r4(443)) }, want: xdpRedirect},
			{name: "IPv6 UDP 1000", frame: func(t *testing.T) []byte { return udpFrame(t, p6, r6(1000)) }, want: xdpRedirect},
			{name: "IPv6 UDP 443", frame: func(t *testing.T) []byte { return udpFrame(t, p6, r6(443)) }, want: xdpRedirect},
			{name: "IPv4 UDP to another port", frame: func(t *testing.T) []byte { return udpFrame(t, p, r4(53)) }, want: xdpPass},
			{name: "IPv6 UDP to another port", frame: func(t *testing.T) []byte { return udpFrame(t, p6, r6(5000)) }, want: xdpPass},
			{name: "IPv4 UDP 1000 to another address", frame: func(t *testing.T) []byte { return udpFrame(t, p, netip.AddrPortFrom(host4.Addr(), 1000)) }, want: xdpPass},
			{name: "IPv6 UDP 443 to another address", frame: func(t *testing.T) []byte { return udpFrame(t, p6, netip.AddrPortFrom(host6.Addr(), 443)) }, want: xdpPass},
			{name: "IPv4 TCP 443", frame: func(t *testing.T) []byte { return tcpFrame(t, p, r4(443)) }, want: xdpPass},
			{name: "IPv6 TCP 1000", frame: func(t *testing.T) []byte { return tcpFrame(t, p6, r6(1000)) }, want: xdpPass},
			{name: "ARP", frame: arp, want: xdpPass},
			{name: "NDP", frame: ndp, want: xdpPass},
			{name: "ICMP echo", frame: ping, want: xdpPass},
			// The flags and fragment offset are at byte 6 of the IPv4 header: MF is 0x20.
			{name: "IPv4 first fragment", frame: func(t *testing.T) []byte { return edit(udpFrame(t, p, r4(1000)), ethLen+6, 0x20, 0) }, want: xdpPass},
			{name: "IPv4 later fragment", frame: func(t *testing.T) []byte { return edit(udpFrame(t, p, r4(1000)), ethLen+6, 0, 185) }, want: xdpPass},
			{name: "IPv4 with options", frame: func(t *testing.T) []byte { return edit(udpFrame(t, p, r4(1000)), ethLen, 0x46) }, want: xdpPass},
			// The next header is at byte 6 of the IPv6 header.
			{name: "IPv6 hop-by-hop header", frame: func(t *testing.T) []byte { return edit(udpFrame(t, p6, r6(1000)), ethLen+6, 0) }, want: xdpPass},
			{name: "IPv6 fragment header", frame: func(t *testing.T) []byte { return edit(udpFrame(t, p6, r6(1000)), ethLen+6, 44) }, want: xdpPass},
			{name: "IPv6 destination options", frame: func(t *testing.T) []byte { return edit(udpFrame(t, p6, r6(1000)), ethLen+6, 60) }, want: xdpPass},
			{name: "short frame", frame: func(t *testing.T) []byte { return udpFrame(t, p, r4(1000))[:ethLen+ip4Len+4] }, want: xdpPass},
			// The total length is at byte 2 of the IPv4 header, and the payload length at byte 4 of IPv6.
			{name: "IPv4 length cuts the UDP header", frame: func(t *testing.T) []byte { return edit(udpFrame(t, p, r4(1000)), ethLen+2, 0, ip4Len+4) }, want: xdpPass},
			{name: "IPv6 length cuts the UDP header", frame: func(t *testing.T) []byte { return edit(udpFrame(t, p6, r6(1000)), ethLen+4, 0, 4) }, want: xdpPass},
			{name: "IPv4 EtherType, IP version 6", frame: func(t *testing.T) []byte { return edit(udpFrame(t, p, r4(1000)), ethLen, 0x65) }, want: xdpPass},
			{name: "IPv6 EtherType, IP version 4", frame: func(t *testing.T) []byte { return edit(udpFrame(t, p6, r6(1000)), ethLen, 0x40) }, want: xdpPass},
			{name: "IPv6 UDP 443 to the IPv4-mapped own address", frame: func(t *testing.T) []byte {
				return udpFrame(t, p6, netip.AddrPortFrom(netip.AddrFrom16(relay4.Addr().As16()), 443))
			}, want: xdpPass},
			{name: "impaired UDP 1000", frame: func(t *testing.T) []byte { return udpFrame(t, p, r4(1000)) }, impair: true, want: xdpDrop},
			{name: "impair entry, UDP 1000 to another address", frame: func(t *testing.T) []byte { return udpFrame(t, p, netip.AddrPortFrom(host4.Addr(), 1000)) }, impair: true, want: xdpPass},
		}},
		{mode: configv1alpha1.RelayInterfaceModeDedicated, cases: []tcase{
			{name: "IPv4 UDP 1000", frame: func(t *testing.T) []byte { return udpFrame(t, p, r4(1000)) }, want: xdpRedirect},
			{name: "IPv4 UDP to another port", frame: func(t *testing.T) []byte { return udpFrame(t, p, r4(53)) }, want: xdpRedirect},
			{name: "IPv6 UDP to another address", frame: func(t *testing.T) []byte { return udpFrame(t, p6, netip.AddrPortFrom(host6.Addr(), 443)) }, want: xdpRedirect},
			{name: "IPv4 TCP 443", frame: func(t *testing.T) []byte { return tcpFrame(t, p, r4(443)) }, want: xdpRedirect},
			{name: "ARP", frame: arp, want: xdpRedirect},
			{name: "NDP", frame: ndp, want: xdpRedirect},
			{name: "ICMP echo", frame: ping, want: xdpRedirect},
			{name: "IPv4 first fragment", frame: func(t *testing.T) []byte { return edit(udpFrame(t, p, r4(1000)), ethLen+6, 0x20, 0) }, want: xdpRedirect},
			{name: "impaired UDP 1000", frame: func(t *testing.T) []byte { return udpFrame(t, p, r4(1000)) }, impair: true, want: xdpDrop},
		}},
	}
	for _, m := range modes {
		t.Run(string(m.mode), func(t *testing.T) {
			e := newLink(t, 1, m.mode)
			e.open(t)
			l, err := netlink.LinkByName("rl0")
			require.NoError(t, err)
			require.NotNil(t, l.Attrs().Xdp)
			prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(l.Attrs().Xdp.ProgId))
			require.NoError(t, err)
			t.Cleanup(func() { prog.Close() })
			im, err := dp.OpenImpair()
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, im.Clear())
				im.Close()
			})
			for _, tc := range m.cases {
				t.Run(tc.name, func(t *testing.T) {
					require.NoError(t, im.Clear())
					if tc.impair {
						require.NoError(t, im.Set(dp.PortData, netip.PrefixFrom(p, 32), 1, 0, 0))
					}
					ret, err := prog.Run(&ebpf.RunOptions{Data: tc.frame(t)})
					require.NoError(t, err)
					require.Equal(t, tc.want, ret)
				})
			}
		})
	}
}
