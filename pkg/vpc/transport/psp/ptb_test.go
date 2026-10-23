// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/vtep/netstack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

const (
	protoUDP    = 17
	protoICMPv4 = 1
	protoICMPv6 = 58
)

// withDF sets the DF flag of the IPv4 packet p.
func withDF(p []byte) []byte {
	p[6] |= 0x40
	return p
}

// checkTooBig checks that m is the packet too big error for pkt with the MTU mtu.
func checkTooBig(t *testing.T, pkt, m []byte, mtu int) {
	t.Helper()
	if pkt[0]>>4 == 4 {
		ip := header.IPv4(m)
		require.Equal(t, min(MaxICMPv4, 28+len(pkt)), len(m))
		assert.True(t, ip.IsChecksumValid(), "IPv4 header checksum")
		assert.Equal(t, len(m), int(ip.TotalLength()))
		assert.Equal(t, uint8(protoICMPv4), ip.Protocol())
		assert.Equal(t, header.IPv4(pkt).DestinationAddress(), ip.SourceAddress(), "source")
		assert.Equal(t, header.IPv4(pkt).SourceAddress(), ip.DestinationAddress(), "destination")
		icmp := header.ICMPv4(ip.Payload())
		assert.Equal(t, header.ICMPv4DstUnreachable, icmp.Type())
		assert.Equal(t, header.ICMPv4FragmentationNeeded, icmp.Code())
		assert.Equal(t, uint16(mtu), icmp.MTU())
		assert.Equal(t, uint16(0xffff), checksum.Checksum(icmp, 0), "ICMP checksum")
		assert.Equal(t, pkt[:len(m)-28], []byte(icmp.Payload()), "quote")
		return
	}
	ip := header.IPv6(m)
	require.Equal(t, min(MaxICMPv6, 48+len(pkt)), len(m))
	assert.Equal(t, len(m)-40, int(ip.PayloadLength()))
	assert.Equal(t, tcpip.TransportProtocolNumber(protoICMPv6), ip.TransportProtocol())
	assert.Equal(t, header.IPv6(pkt).DestinationAddress(), ip.SourceAddress(), "source")
	assert.Equal(t, header.IPv6(pkt).SourceAddress(), ip.DestinationAddress(), "destination")
	icmp := header.ICMPv6(ip.Payload())
	assert.Equal(t, header.ICMPv6PacketTooBig, icmp.Type())
	assert.Equal(t, header.ICMPv6Code(0), icmp.Code())
	assert.Equal(t, uint32(mtu), icmp.MTU())
	pseudo := header.PseudoHeaderChecksum(header.ICMPv6ProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(icmp)))
	assert.Equal(t, uint16(0xffff), checksum.Checksum(icmp, pseudo), "ICMPv6 checksum")
	assert.Equal(t, pkt[:len(m)-48], []byte(icmp[8:]), "quote")
}

// TestPacketTooBig checks the error for each kind of packet, and the packets that get none.
func TestPacketTooBig(t *testing.T) {
	a4, b4 := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	a6, b6 := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	// icmp returns a packet of the ICMP protocol proto with the message type typ.
	icmp := func(src, dst netip.Addr, proto, typ byte, size int) []byte {
		p := packet(src, dst, proto, 0, 0, size)
		if src.Is4() {
			p[20] = typ
		} else {
			p[40] = typ
		}
		return p
	}
	fragment := withDF(packet(a4, b4, protoUDP, 1, 2, 1350))
	fragment[7] = 1
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"IPv6", packet(a6, b6, protoUDP, 1, 2, 1350), true},
		{"IPv6 shorter than the quote", packet(a6, b6, protoUDP, 1, 2, 200), true},
		{"IPv6 echo request", icmp(a6, b6, protoICMPv6, 128, 1350), true},
		{"IPv6 ICMP error", icmp(a6, b6, protoICMPv6, 1, 1350), false},
		{"IPv6 multicast source", packet(netip.MustParseAddr("ff02::1"), b6, protoUDP, 1, 2, 1350), false},
		{"IPv6 unspecified source", packet(netip.IPv6Unspecified(), b6, protoUDP, 1, 2, 1350), false},
		{"IPv6 multicast destination", packet(a6, netip.MustParseAddr("ff02::1"), protoUDP, 1, 2, 1350), false},
		{"IPv6 header only in part", packet(a6, b6, protoUDP, 1, 2, 1350)[:39], false},
		{"IPv4 with DF", withDF(packet(a4, b4, protoUDP, 1, 2, 1350)), true},
		{"IPv4 with DF shorter than the quote", withDF(packet(a4, b4, protoUDP, 1, 2, 200)), true},
		{"IPv4 without DF", packet(a4, b4, protoUDP, 1, 2, 1350), true},
		{"IPv4 echo request", withDF(icmp(a4, b4, protoICMPv4, 8, 1350)), true},
		{"IPv4 ICMP error", withDF(icmp(a4, b4, protoICMPv4, 3, 1350)), false},
		{"IPv4 multicast source", withDF(packet(netip.MustParseAddr("224.0.0.1"), b4, protoUDP, 1, 2, 1350)), false},
		{"IPv4 unspecified source", withDF(packet(netip.IPv4Unspecified(), b4, protoUDP, 1, 2, 1350)), false},
		{"IPv4 broadcast destination", withDF(packet(a4, netip.MustParseAddr("255.255.255.255"), protoUDP, 1, 2, 1350)), false},
		{"IPv4 later fragment", fragment, false},
		{"not IP", make([]byte, 1350), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := packetTooBig(tc.pkt, QUICMTU)
			if !tc.want {
				assert.Nil(t, m)
				return
			}
			require.NotNil(t, m)
			checkTooBig(t, tc.pkt, m, QUICMTU)
		})
	}
}

// TestTooBigRate checks the limiter of the errors at its rate: 3 errors can go at one
// time, and then one each millisecond.
func TestTooBigRate(t *testing.T) {
	var g limiter
	g.rate.Store(tooBigRate)
	steps := []struct {
		at   time.Duration
		want bool
	}{
		{0, true}, {0, true}, {0, true}, {0, false},
		{time.Millisecond, true}, {time.Millisecond, false},
		{time.Second, true}, {time.Second, true}, {time.Second, true}, {time.Second, false},
	}
	for i, s := range steps {
		assert.Equal(t, s.want, g.admitAt(1, int64(time.Hour+s.at)), "step %d", i)
	}
}

// TestTooBig sends packets of the device MTU and of the path MTU on a link in QUIC mode
// and on a link in PSP mode. A packet above the path MTU gets the error from the binding.
func TestTooBig(t *testing.T) {
	const devMTU, clamp = 1400, 1300
	udp := func(v6, df bool, size int) func(n *node) []byte {
		return func(n *node) []byte {
			if v6 {
				return packet(n.v6, n.other.v6, protoUDP, 1, 2, size)
			}
			p := packet(n.v4, n.other.v4, protoUDP, 1, 2, size)
			if df {
				withDF(p)
			}
			return p
		}
	}
	cases := []struct {
		name    string
		quic    bool
		clamp   int
		pkt     func(n *node) []byte
		wantMTU int  // MTU of the error, or 0 for no error.
		wantOut bool // The packet gets a send frame.
	}{
		{"QUIC, IPv6 above the limit", true, 0, udp(true, false, 1350), QUICMTU, false},
		{"QUIC, IPv6 at the limit", true, 0, udp(true, false, QUICMTU), 0, true},
		{"QUIC, IPv4 with DF above the limit", true, 0, udp(false, true, 1350), QUICMTU, false},
		{"QUIC, IPv4 with DF at the limit", true, 0, udp(false, true, QUICMTU), 0, true},
		{"QUIC, IPv4 without DF above the limit", true, 0, udp(false, false, 1350), QUICMTU, false},
		{"QUIC, IPv4 without DF at the limit", true, 0, udp(false, false, QUICMTU), 0, true},
		{"QUIC with a clamp, IPv6 above the QUIC limit", true, clamp, udp(true, false, 1350), QUICMTU, false},
		{"PSP with a clamp, IPv6 above the clamp", false, clamp, udp(true, false, 1350), clamp, false},
		{"PSP with a clamp, IPv6 at the clamp", false, clamp, udp(true, false, clamp), 0, true},
		{"PSP with a clamp, IPv4 with DF above the clamp", false, clamp, udp(false, true, 1350), clamp, false},
		{"PSP with a clamp, IPv4 with DF at the clamp", false, clamp, udp(false, true, clamp), 0, true},
		{"PSP with a clamp, IPv4 without DF above the clamp", false, clamp, udp(false, false, 1350), clamp, false},
		{"PSP with no clamp, IPv6 of the device MTU", false, 0, udp(true, false, devMTU), 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPairMTU(t, devMTU)
			offer(t, time.Now(), a, b)
			if tc.quic {
				require.NoError(t, a.peer.UseQUIC(&peerconn.Conn{}))
			}
			a.b.SetClampMTU(tc.clamp)
			c := &capture{}
			d := fakeDriver(a.b, c.deliver)
			a.b.drv.Store(d)
			pkt := tc.pkt(a)
			limit := a.b.pathMTU(tc.quic)

			var f netstack.TxFrame
			assert.Equal(t, len(pkt) <= limit, d.PrepareSegs(pkt, 2, len(pkt), 2*len(pkt), &f), "frames of a TCP packet")
			assert.Empty(t, c.got, "a TCP packet gets its error when the driver cuts it")

			n, _ := d.VirtToPhy(pkt, make([]byte, 2048))
			assert.Equal(t, tc.wantOut, n > 0, "send frame")
			st := a.b.Stats()
			if tc.wantMTU == 0 {
				assert.Empty(t, c.got)
				assert.Zero(t, st.TxTooBig)
				assert.Zero(t, st.TxDrops)
				return
			}
			require.Len(t, c.got, 1)
			checkTooBig(t, pkt, c.got[0], tc.wantMTU)
			assert.Equal(t, uint64(1), st.TxTooBig)
			assert.Equal(t, uint64(1), st.TxDrops)
		})
	}

	t.Run("rate limit", func(t *testing.T) {
		a, b := newPairMTU(t, devMTU)
		offer(t, time.Now(), a, b)
		a.b.SetClampMTU(clamp)
		// One error each second, so that the time of the test has no effect.
		a.b.ptb.rate.Store(1)
		c := &capture{}
		d := fakeDriver(a.b, c.deliver)
		a.b.drv.Store(d)
		for range 3 {
			n, _ := d.VirtToPhy(udp(true, false, 1350)(a), make([]byte, 2048))
			assert.Zero(t, n)
		}
		assert.Len(t, c.got, 1)
		st := a.b.Stats()
		assert.Equal(t, uint64(1), st.TxTooBig)
		assert.Equal(t, uint64(3), st.TxDrops)
	})
}

// TestTooBigNetstackTCP lowers the path MTU of an open TCP connection of the netstack.
// The binding drops the large segments, and its errors make TCP send smaller segments.
func TestTooBigNetstackTCP(t *testing.T) {
	const devMTU, clamp = 1400, 1300
	for i, name := range []string{"IPv4", "IPv6"} {
		t.Run(name, func(t *testing.T) {
			a, b := newPairMTU(t, devMTU)
			offer(t, time.Now(), a, b)
			sa, sb := startNetstack(t, a, testWindow), startNetstack(t, b, testWindow)
			dst := b.v4
			if name == "IPv6" {
				dst = b.v6
			}
			port := uint16(8000 + i)
			echo(t, sb, dst, port)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			c, err := gonet.DialContextTCP(ctx, sa, fullAddr(dst, port), protoOf(dst))
			require.NoError(t, err)
			defer c.Close()

			roundTrip(t, c)
			require.Zero(t, a.b.Stats().TxTooBig, "the path carries the device MTU")

			a.b.SetClampMTU(clamp)
			roundTrip(t, c)
			st := a.b.Stats()
			require.NotZero(t, st.TxTooBig, "TCP sent no segment above the clamp")

			// TCP has the lower MTU now, so no more segments are too large.
			roundTrip(t, c)
			assert.Equal(t, st.TxTooBig, a.b.Stats().TxTooBig)
			assert.Equal(t, st.TxDrops, a.b.Stats().TxDrops)
		})
	}
}

// roundTrip sends testData bytes on c to an echo server and reads them back.
func roundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	data := make([]byte, testData)
	_, _ = rand.Read(data)
	go func() { _, _ = c.Write(data) }()
	got := make([]byte, len(data))
	_, err := io.ReadFull(c, got)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, got))
}
