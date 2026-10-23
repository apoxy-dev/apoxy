// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TestEncodeUDP checks that a frame of encodeUDP demuxes back to the datagram, with valid
// checksums and DF on IPv4, that a frame with no room is 0, and that encodeUDP makes no heap
// allocation: it runs once for each packet that the relay sends.
func TestEncodeUDP(t *testing.T) {
	const srcMAC, dstMAC = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01"), tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")
	payload := []byte("the payload of one datagram")
	v4Len := header.EthernetMinimumSize + header.IPv4MinimumSize + header.UDPMinimumSize + len(payload)
	v6Len := header.EthernetMinimumSize + header.IPv6MinimumSize + header.UDPMinimumSize + len(payload)
	v4src, v4dst := netip.MustParseAddrPort("10.0.0.1:4433"), netip.MustParseAddrPort("10.0.0.2:1000")
	v6src, v6dst := netip.MustParseAddrPort("[2001:db8::1]:4433"), netip.MustParseAddrPort("[2001:db8::2]:1000")
	cases := []struct {
		name     string
		src, dst netip.AddrPort
		ecn      uint8
		frame    int // The size of the frame buffer.
		n        int
	}{
		{name: "IPv4", src: v4src, dst: v4dst, ecn: 0b01, frame: 256, n: v4Len},
		{name: "IPv4 in a frame of its size", src: v4src, dst: v4dst, ecn: 0b10, frame: v4Len, n: v4Len},
		{name: "IPv4 with no room", src: v4src, dst: v4dst, frame: v4Len - 1, n: 0},
		{name: "IPv6", src: v6src, dst: v6dst, ecn: 0b11, frame: 256, n: v6Len},
		{name: "IPv6 with no room", src: v6src, dst: v6dst, frame: v6Len - 1, n: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame := make([]byte, tc.frame)
			n := encodeUDP(frame, srcMAC, dstMAC, tc.src, tc.dst, tc.ecn, payload)
			require.Equal(t, tc.n, n)
			// One run of 100 calls: AllocsPerRun rounds the mean of its runs down.
			allocs := testing.AllocsPerRun(1, func() {
				for range 100 {
					encodeUDP(frame, srcMAC, dstMAC, tc.src, tc.dst, tc.ecn, payload)
				}
			})
			assert.Zero(t, allocs, "heap allocations of 100 encodeUDP calls")
			if n == 0 {
				return
			}

			frame = frame[:n]
			eth := header.Ethernet(frame)
			assert.Equal(t, srcMAC, eth.SourceAddress())
			assert.Equal(t, dstMAC, eth.DestinationAddress())
			to, d := demux(frame, func(a netip.Addr) bool { return a == tc.dst.Addr() })
			require.Equal(t, toPipeline, to)
			assert.Equal(t, tc.src, d.from)
			assert.Equal(t, tc.ecn, d.ecn)
			assert.Equal(t, payload, d.payload)

			ipb := frame[header.EthernetMinimumSize:]
			var src, dst tcpip.Address
			var udp header.UDP
			if tc.src.Addr().Is4() {
				ip := header.IPv4(ipb)
				assert.True(t, ip.IsChecksumValid(), "IPv4 header checksum")
				assert.NotZero(t, ip.Flags()&header.IPv4FlagDontFragment, "DF")
				assert.Equal(t, uint8(64), ip.TTL())
				src, dst, udp = ip.SourceAddress(), ip.DestinationAddress(), header.UDP(ip.Payload())
			} else {
				ip := header.IPv6(ipb)
				assert.Equal(t, uint8(64), ip.HopLimit())
				src, dst, udp = ip.SourceAddress(), ip.DestinationAddress(), header.UDP(ip.Payload())
			}
			assert.True(t, udp.IsChecksumValid(src, dst, checksum.Checksum(udp.Payload(), 0)), "UDP checksum")
		})
	}
}

// TestSendAllocs checks that the device sends a full batch of the pipeline with no heap
// allocation once the next-hop MAC is known.
func TestSendAllocs(t *testing.T) {
	f := newFakeTx(4*rxBatch, 4*rxBatch)
	d := newFakeDevice(t, f)
	b := &TxBatch{txq: d.tx[0], hops: hopCache{}}
	payload := []byte("sixteen bytes...")
	for range rxBatch {
		copy(b.room(len(payload)), payload)
		b.add(fakePeer, len(payload))
	}
	deviceSender{d}.Send(b)
	require.Len(t, f.onRing(), rxBatch, "frames of one batch")
	f.completeRing()
	// The first send put the MAC from gVisor in the hop cache. It stays new for the whole test, so
	// that no batch asks gVisor again: a slow run must not pass hopTTL.
	hop, ok := b.hops[fakePeer.Addr()]
	require.True(t, ok, "the hop cache has the MAC of the peer")
	hop.at = time.Now().Add(time.Hour)
	b.hops[fakePeer.Addr()] = hop
	send := func() {
		deviceSender{d}.Send(b)
		f.completeRing()
	}
	// One run of 100 batches: AllocsPerRun rounds the mean of its runs down.
	allocs := testing.AllocsPerRun(1, func() {
		for range 100 {
			send()
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
