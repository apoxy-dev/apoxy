// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"runtime/debug"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TestEncodeUDP checks the frames of encodeUDP: the IP header that gVisor encodes for the datagram,
// the UDP checksum of RFC 768 on each port and family, and no heap allocation.
func TestEncodeUDP(t *testing.T) {
	const srcMAC, dstMAC = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01"), tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")
	payload := []byte("the payload of one datagram")
	v4Len := header.EthernetMinimumSize + header.IPv4MinimumSize + header.UDPMinimumSize + len(payload)
	v6Len := header.EthernetMinimumSize + header.IPv6MinimumSize + header.UDPMinimumSize + len(payload)
	v4data, v4quic, v4dst := netip.MustParseAddrPort("10.0.0.1:1000"), netip.MustParseAddrPort("10.0.0.1:443"), netip.MustParseAddrPort("10.0.0.2:1000")
	v6data, v6quic, v6dst := netip.MustParseAddrPort("[2001:db8::1]:1000"), netip.MustParseAddrPort("[2001:db8::1]:443"), netip.MustParseAddrPort("[2001:db8::2]:1000")
	cases := []struct {
		name     string
		src, dst netip.AddrPort
		ecn      uint8
		frame    int // The size of the frame buffer.
		n        int
		ffff     bool // The last 2 bytes of the payload make the sum 0xffff, so the checksum is 0xffff.
	}{
		{name: "IPv4 from PortData", src: v4data, dst: v4dst, ecn: 0b01, frame: 256, n: v4Len},
		{name: "IPv4 from PortData in a frame of its size", src: v4data, dst: v4dst, ecn: 0b10, frame: v4Len, n: v4Len},
		{name: "IPv4 from the QUIC port", src: v4quic, dst: v4dst, ecn: 0b01, frame: 256, n: v4Len},
		{name: "IPv4 from the QUIC port with a sum of 0xffff", src: v4quic, dst: v4dst, frame: 256, n: v4Len + 1, ffff: true},
		{name: "IPv4 with no room", src: v4data, dst: v4dst, frame: v4Len - 1, n: 0},
		{name: "IPv4 to IPv6", src: v4data, dst: v6dst, frame: 256, n: 0},
		{name: "IPv6 from PortData", src: v6data, dst: v6dst, ecn: 0b11, frame: 256, n: v6Len},
		{name: "IPv6 from the QUIC port", src: v6quic, dst: v6dst, ecn: 0b11, frame: 256, n: v6Len},
		{name: "IPv6 with a sum of 0xffff", src: v6data, dst: v6dst, frame: 256, n: v6Len + 1, ffff: true},
		{name: "IPv6 with no room", src: v6data, dst: v6dst, frame: v6Len - 1, n: 0},
		{name: "IPv6 to IPv4", src: v6data, dst: v4dst, frame: 256, n: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := payload
			if tc.ffff {
				// 28 bytes: the last 2 bytes are one 16-bit word of the sum.
				payload = append(bytes.Clone(payload[:26]), 0, 0)
				binary.BigEndian.PutUint16(payload[26:], ^rfc1071(udpSumInput(tc.src, tc.dst, payload)...))
			}
			// The frames of a TX queue hold old packets. 0xa5 is not neutral in a checksum sum.
			buf := bytes.Repeat([]byte{0xa5}, tc.frame)
			n := encodeUDP(buf, srcMAC, dstMAC, tc.src, tc.dst, tc.ecn, payload)
			require.Equal(t, tc.n, n)
			// The checks use the frame of the first call, on the old bytes.
			frame := bytes.Clone(buf[:n])
			// One run of 100 calls: AllocsPerRun rounds the mean of its runs down.
			allocs := testing.AllocsPerRun(1, func() {
				for range 100 {
					encodeUDP(buf, srcMAC, dstMAC, tc.src, tc.dst, tc.ecn, payload)
				}
			})
			assert.Zero(t, allocs, "heap allocations of 100 encodeUDP calls")
			if n == 0 {
				return
			}

			eth := header.Ethernet(frame)
			assert.Equal(t, srcMAC, eth.SourceAddress())
			assert.Equal(t, dstMAC, eth.DestinationAddress())
			to, d := demux(frame, func(a netip.Addr) bool { return a == tc.dst.Addr() })
			require.Equal(t, toPipeline, to)
			assert.Equal(t, tc.src, d.from)
			assert.Equal(t, tc.ecn, d.ecn)
			assert.Equal(t, payload, d.payload)

			ipb := frame[header.EthernetMinimumSize:]
			udpLen := uint16(header.UDPMinimumSize + len(payload))
			srcIP, dstIP := tcpip.AddrFromSlice(tc.src.Addr().AsSlice()), tcpip.AddrFromSlice(tc.dst.Addr().AsSlice())
			var udp header.UDP
			if tc.src.Addr().Is4() {
				want := header.IPv4(make([]byte, header.IPv4MinimumSize))
				want.Encode(&header.IPv4Fields{
					TOS: tc.ecn, TotalLength: header.IPv4MinimumSize + udpLen, Flags: header.IPv4FlagDontFragment,
					TTL: 64, Protocol: uint8(header.UDPProtocolNumber), SrcAddr: srcIP, DstAddr: dstIP,
				})
				want.SetChecksum(^want.CalculateChecksum())
				ip := header.IPv4(ipb)
				assert.Equal(t, []byte(want), ipb[:header.IPv4MinimumSize], "IPv4 header")
				assert.True(t, ip.IsChecksumValid(), "IPv4 header checksum")
				assert.Equal(t, tc.src.Addr().AsSlice(), ip.SourceAddressSlice(), "source address")
				assert.Equal(t, tc.dst.Addr().AsSlice(), ip.DestinationAddressSlice(), "destination address")
				udp = header.UDP(ip.Payload())
			} else {
				want := header.IPv6(make([]byte, header.IPv6MinimumSize))
				want.Encode(&header.IPv6Fields{
					TrafficClass: tc.ecn, PayloadLength: udpLen, TransportProtocol: header.UDPProtocolNumber,
					HopLimit: 64, SrcAddr: srcIP, DstAddr: dstIP,
				})
				ip := header.IPv6(ipb)
				assert.Equal(t, []byte(want), ipb[:header.IPv6MinimumSize], "IPv6 header")
				assert.Equal(t, tc.src.Addr().AsSlice(), ip.SourceAddressSlice(), "source address")
				assert.Equal(t, tc.dst.Addr().AsSlice(), ip.DestinationAddressSlice(), "destination address")
				udp = header.UDP(ip.Payload())
			}
			assert.Equal(t, tc.src.Port(), udp.SourcePort())
			assert.Equal(t, tc.dst.Port(), udp.DestinationPort())
			assert.Equal(t, udpLen, udp.Length())
			want := ^rfc1071(udpSumInput(tc.src, tc.dst, payload)...)
			if want == 0 {
				want = 0xffff
			}
			if tc.ffff {
				require.Equal(t, uint16(0xffff), want, "the payload of the case makes a sum of 0xffff")
			}
			assert.Equal(t, want, udp.Checksum(), "UDP checksum")
			assert.True(t, udp.IsChecksumValid(srcIP, dstIP, checksum.Checksum(udp.Payload(), 0)), "UDP checksum")
		})
	}
}

// udpSumInput returns the bytes of the UDP checksum of RFC 768 and RFC 8200: the pseudo-header, and
// the UDP header with checksum 0 and payload.
func udpSumInput(src, dst netip.AddrPort, payload []byte) [][]byte {
	n := header.UDPMinimumSize + len(payload)
	pseudo := append(src.Addr().AsSlice(), dst.Addr().AsSlice()...)
	if src.Addr().Is4() {
		pseudo = append(pseudo, 0, uint8(header.UDPProtocolNumber), byte(n>>8), byte(n))
	} else {
		pseudo = append(pseudo, 0, 0, byte(n>>8), byte(n), 0, 0, 0, uint8(header.UDPProtocolNumber))
	}
	udp := []byte{byte(src.Port() >> 8), byte(src.Port()), byte(dst.Port() >> 8), byte(dst.Port()), byte(n >> 8), byte(n), 0, 0}
	return [][]byte{pseudo, udp, payload}
}

// rfc1071 returns the 16-bit one's complement sum of the bytes of parts, as one byte string.
func rfc1071(parts ...[]byte) uint16 {
	var all []byte
	for _, p := range parts {
		all = append(all, p...)
	}
	if len(all)%2 == 1 {
		all = append(all, 0)
	}
	var sum uint32
	for i := 0; i < len(all); i += 2 {
		sum += uint32(all[i])<<8 | uint32(all[i+1])
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return uint16(sum)
}

// BenchmarkEncodeUDP encodes a frame of 1400 payload bytes, as the relay does for each packet.
func BenchmarkEncodeUDP(b *testing.B) {
	const srcMAC, dstMAC = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01"), tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")
	payload := bytes.Repeat([]byte{0xa5}, 1400)
	frame := make([]byte, 2048)
	for _, bc := range []struct {
		name     string
		src, dst netip.AddrPort
	}{
		{name: "IPv4 from PortData", src: netip.MustParseAddrPort("10.0.0.1:1000"), dst: netip.MustParseAddrPort("10.0.0.2:1000")},
		{name: "IPv4 from the QUIC port", src: netip.MustParseAddrPort("10.0.0.1:443"), dst: netip.MustParseAddrPort("10.0.0.2:1000")},
		{name: "IPv6 from PortData", src: netip.MustParseAddrPort("[2001:db8::1]:1000"), dst: netip.MustParseAddrPort("[2001:db8::2]:1000")},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.SetBytes(int64(len(payload)))
			for b.Loop() {
				encodeUDP(frame, srcMAC, dstMAC, bc.src, bc.dst, 0, payload)
			}
		})
	}
}

// TestSendAllocs checks that the device sends a full batch of the pipeline with no heap
// allocation once the next-hop MAC is known.
func TestSendAllocs(t *testing.T) {
	f := newFakeTxSize(4*rxBatch, 4*rxBatch, 256)
	d := newFakeDevice(t, f)
	b := &TxBatch{mems: [][]byte{f.mem}, txq: d.tx[0], hops: hopCache{}}
	payload := []byte("sixteen bytes...")
	send := func() {
		b.frames = b.txq.take(rxBatch, b.frames[:0])
		for range rxBatch {
			off, ok := b.room(len(payload))
			if !ok {
				panic("no room")
			}
			b.add(fakePeer, off, copy(f.mem[off:], payload))
		}
		deviceSender{d}.Send(b)
		b.reset()
	}
	send()
	require.Len(t, f.onRing(), rxBatch, "frames of one batch")
	f.completeRing()
	// The first send put the MAC from gVisor in the hop cache. It stays new for the whole test, so
	// that no batch asks gVisor again: a slow run must not pass hopTTL.
	hop, ok := b.hops[fakePeer.Addr()]
	require.True(t, ok, "the hop cache has the MAC of the peer")
	hop.at = time.Now().Add(time.Hour)
	b.hops[fakePeer.Addr()] = hop
	// The free of the device of an earlier run gives work to the background scavenger of the Go
	// runtime. It can add the first timer to the timer heap of a P in the measured run (16 bytes).
	// Return the free pages now, so that the scavenger has no work in that run.
	debug.FreeOSMemory()
	// One run of 100 batches: AllocsPerRun rounds the mean of its runs down.
	allocs := testing.AllocsPerRun(1, func() {
		for range 100 {
			send()
			f.completeRing()
		}
	})
	assert.Zero(t, allocs, "heap allocations of 100 batches of %d packets", rxBatch)
	assert.Zero(t, counted(d, ReasonTXFull)+counted(d, ReasonNoNeighbor)+counted(d, ReasonMTU), "drops")
}

// completeRing completes all frames on the TX ring of f, as a kick of the kernel that sends them,
// with no copy of the frames.
func (f *fakeTx) completeRing() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cq = append(f.cq, f.txr...)
	f.txr = f.txr[:0]
}
