// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package relay

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/filter"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
)

// udpFrame returns an Ethernet frame from src to dst with the UDP payload p and
// no link padding.
func udpFrame(t *testing.T, src, dst netip.AddrPort, p []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: xdpPeerMAC, DstMAC: xdpRelayMAC, EthernetType: layers.EthernetTypeIPv4}
	udp := &layers.UDP{SrcPort: layers.UDPPort(src.Port()), DstPort: layers.UDPPort(dst.Port())}
	var ip gopacket.NetworkLayer = &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src.Addr().AsSlice(), DstIP: dst.Addr().AsSlice()}
	n := 14 + 20 + 8 + len(p)
	if src.Addr().Is6() {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip = &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP, SrcIP: src.Addr().AsSlice(), DstIP: dst.Addr().AsSlice()}
		n += 20
	}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip.(gopacket.SerializableLayer), udp, gopacket.Payload(p)))
	// The serializer pads a short frame to 60 B.
	return buf.Bytes()[:n]
}

// geneveKeepalive returns the keepalive frame that the handler of a Geneve
// tunnel at src sends to dst.
func geneveKeepalive(t *testing.T, src, dst netip.AddrPort) []byte {
	t.Helper()
	full := func(a netip.AddrPort) *tcpip.FullAddress {
		return &tcpip.FullAddress{Addr: tcpip.AddrFromSlice(a.Addr().AsSlice()), Port: a.Port()}
	}
	h, err := icx.NewHandler(icx.WithLocalAddr(full(src)), icx.WithLayer3VirtFrames(), icx.WithKeepAliveInterval(time.Second))
	require.NoError(t, err)
	all := netip.MustParsePrefix("::/0")
	require.NoError(t, h.AddVirtualNetwork(1, full(dst), []icx.Route{{Src: all, Dst: all}}))
	require.NoError(t, h.UpdateVirtualNetworkSecret(1, [32]byte{1}, 1, 2, time.Now().Add(time.Hour)))
	phy := make([]byte, 1500)
	n := h.ToPhy(phy)
	require.NotZero(t, n)
	return phy[:n]
}

// TestGenevePassesVPCPackets checks that the Geneve program of the tunnel
// router passes the packets of VPC agents. Both use the relay port.
func TestGenevePassesVPCPackets(t *testing.T) {
	ns := newXDPNS(t)
	src := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1000"), netip.MustParseAddrPort("[2001:db8::1]:1000")}
	dst := []netip.AddrPort{netip.AddrPortFrom(xdpAddrs[0], xdpPort), netip.AddrPortFrom(xdpAddrs[1], xdpPort)}
	g, err := filter.Geneve(net.UDPAddrFromAddrPort(dst[0]), net.UDPAddrFromAddrPort(dst[1]))
	if errors.Is(err, unix.EPERM) {
		t.Skipf("cannot load BPF programs: %v", err)
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = g.Close() })

	// vpc returns a frame to each relay address for each UDP payload.
	vpc := func(payloads ...[]byte) [][]byte {
		var out [][]byte
		for _, p := range payloads {
			out = append(out, udpFrame(t, src[0], dst[0], p), udpFrame(t, src[1], dst[1], p))
		}
		return out
	}
	key := [32]byte{1}
	probe := func(reply bool, size int) []byte {
		p := p2p.Probe{Reply: reply, SID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, TxID: [12]byte{9}, Seen: src[0]}
		return p2p.AppendProbe(nil, p, size, &key)
	}
	psp := func(v pspwire.Version, inner []byte) []byte {
		aead, err := pspwire.NewAEAD(make([]byte, v.KeyLen()))
		require.NoError(t, err)
		out := make([]byte, len(inner)+pspwire.Overhead)
		_, err = pspwire.Seal(aead, pspwire.Header{Version: v, SPI: 7, VNI: testVNI}, out, inner)
		require.NoError(t, err)
		return out
	}
	inner4, inner6 := append([]byte{0x45}, make([]byte, 19)...), append([]byte{0x60}, make([]byte, 39)...)
	cases := []struct {
		name   string
		frames [][]byte
		padTo  int  // Frame length with link padding. Zero means no padding.
		taken  bool // The program takes the frame for a Geneve tunnel.
	}{
		{name: "Geneve keepalive", frames: [][]byte{geneveKeepalive(t, src[0], dst[0]), geneveKeepalive(t, src[1], dst[1])}, taken: true},
		{name: "path probe", frames: vpc(probe(false, p2p.MinProbeLen), probe(false, earlyProbeLen))},
		{name: "path probe reply", frames: vpc(probe(true, p2p.MinProbeLen), probe(true, earlyProbeLen))},
		{name: "lane keepalive", frames: vpc([]byte{p2p.TypeKeepalive})},
		// A link pads a short frame to 60 B.
		{name: "lane keepalive with link padding", frames: vpc([]byte{p2p.TypeKeepalive}), padTo: 60},
		{name: "PSP packet", frames: vpc(psp(pspwire.AESGCM128, inner4), psp(pspwire.AESGCM128, inner6), psp(pspwire.AESGCM256, inner4), psp(pspwire.AESGCM256, inner6))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range tc.frames {
				if len(f) < tc.padTo {
					f = append(f[:len(f):len(f)], make([]byte, tc.padTo-len(f))...)
				}
				ret, _ := ns.run(t, g.Program, f)
				assert.Equalf(t, tc.taken, ret != xdpPASS, "XDP action %d for a frame of %d B", ret, len(f))
			}
		})
	}
}
