// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/apoxy-dev/softpsp/psp"
)

// The IPv6 own address of the engine devices, and a peer with a static MAC on its link.
var (
	fakeOwn6  = netip.MustParsePrefix("fd00:99::1/64")
	fakePeer6 = netip.MustParseAddrPort("[fd00:99::2]:4433")
)

// TestSendFrames checks the TX frames of a batch of a worker. Each packet that goes out is in its
// own frame, with its headers in front of it. Each other frame goes back to the pool, and each
// packet that does not go out counts in one drop reason. A batch with no worker (PacketOut) copies
// each packet into a frame.
func TestSendFrames(t *testing.T) {
	peer, peer6 := engA2, netip.AddrPortFrom(fakePeer6.Addr(), PortData)
	offLink := netip.AddrPortFrom(fakeOffLink.Addr(), PortData)
	cases := []struct {
		name       string
		frames     int  // The TX frames and the ring slots of the queue.
		busy       int  // Ring slots that look used after take, with no frame on them.
		endBefore  bool // A kick error ends the queue before take.
		endAfter   bool // A kick error ends the queue after take.
		other      bool // A batch with no worker and no TX frames.
		to         []netip.AddrPort
		sent       []int // The packets on the ring, in order.
		noRoom     int   // The packets with no TX frame.
		txFull     int
		noNeighbor int
	}{
		{name: "a frame for each packet", frames: 8, to: []netip.AddrPort{peer, peer, peer}, sent: []int{0, 1, 2}},
		{name: "IPv4 and IPv6", frames: 8, to: []netip.AddrPort{peer6, peer, peer6}, sent: []int{0, 1, 2}},
		{name: "fewer frames than packets", frames: 2, to: []netip.AddrPort{peer, peer, peer}, sent: []int{0, 1}, noRoom: 1},
		{name: "no next hop", frames: 8, to: []netip.AddrPort{offLink, peer, offLink, peer}, sent: []int{1, 3}, noNeighbor: 2},
		// The kernel can complete frames before it moves its consumer index. Then the ring can look
		// full while the pool has frames.
		{name: "a ring that looks full at the publish", frames: 8, busy: 6, to: []netip.AddrPort{peer, peer, peer}, sent: []int{0, 1}, txFull: 1},
		{name: "a queue that ended before take", frames: 8, endBefore: true, to: []netip.AddrPort{peer, peer}, noRoom: 2},
		{name: "a queue that ended after take", frames: 8, endAfter: true, to: []netip.AddrPort{peer, peer}, txFull: 2},
		{name: "a batch with no worker", frames: 8, other: true, to: []netip.AddrPort{peer6, peer, offLink}, sent: []int{0, 1}, noNeighbor: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEngine(t, 1, 1, tc.frames)
			f := e.txs[0]
			// No byte of the TX memory is zero, so a header field that Send does not write shows.
			for i := range f.mem {
				f.mem[i] = 0xa5
			}
			b := &TxBatch{mems: [][]byte{f.mem}, txq: e.tx[0], hops: hopCache{}}
			if tc.other {
				b = &TxBatch{}
			}
			if tc.endBefore {
				e.tx[0].fail(errors.New("kick"))
			}
			if !tc.other {
				b.frames = b.txq.take(len(tc.to), nil)
			}
			f.mu.Lock()
			f.busy = tc.busy
			f.mu.Unlock()
			if tc.endAfter {
				e.tx[0].fail(errors.New("kick"))
			}
			noRoom := 0
			for i, to := range tc.to {
				off, ok := b.room(16)
				if !ok {
					noRoom++
					continue
				}
				b.add(to, off, copy(b.memories()[b.txMem][off:off+16], fmt.Sprintf("packet %d", i)))
			}
			deviceSender{e.Device}.Send(b)

			var sent []string
			for j, frame := range f.onRing() {
				require.Less(t, j, len(tc.sent), "packets on the ring")
				dest := tc.to[tc.sent[j]]
				to, dg := demux(frame, func(a netip.Addr) bool { return a == dest.Addr() })
				require.Equal(t, toPipeline, to, "packet %d goes to %s", tc.sent[j], dest)
				own := fakeOwn.Addr()
				if dest.Addr().Is6() {
					own = fakeOwn6.Addr()
				}
				assert.Equal(t, netip.AddrPortFrom(own, PortData), dg.from)
				assert.Zero(t, dg.ecn, "ECN")
				eth := header.Ethernet(frame)
				assert.Equal(t, tcpip.LinkAddress(e.ifc.MAC), eth.SourceAddress(), "source MAC")
				assert.Equal(t, fakePeerMAC, eth.DestinationAddress(), "destination MAC")
				var udp header.UDP
				var src, dst tcpip.Address
				ipb := frame[header.EthernetMinimumSize:]
				if dest.Addr().Is4() {
					ip := header.IPv4(ipb)
					assert.Equal(t, header.IPv4Version, header.IPVersion(ipb), "IP version")
					assert.Equal(t, uint8(header.IPv4MinimumSize), ip.HeaderLength(), "IHL")
					tos, _ := ip.TOS()
					assert.Zero(t, tos, "TOS")
					assert.Equal(t, len(ipb), int(ip.TotalLength()), "total length")
					assert.Zero(t, ip.ID(), "ID")
					assert.Equal(t, uint8(header.IPv4FlagDontFragment), ip.Flags(), "flags: DF only")
					assert.Zero(t, ip.FragmentOffset(), "fragment offset")
					assert.Equal(t, uint8(ipv4.DefaultTTL), ip.TTL(), "TTL")
					assert.Equal(t, uint8(header.UDPProtocolNumber), ip.Protocol(), "protocol")
					assert.True(t, ip.IsChecksumValid(), "IPv4 header checksum")
					udp, src, dst = header.UDP(ip.Payload()), ip.SourceAddress(), ip.DestinationAddress()
				} else {
					ip := header.IPv6(ipb)
					assert.Equal(t, header.IPv6Version, header.IPVersion(ipb), "IP version")
					class, flow := ip.TOS()
					assert.Zero(t, class, "traffic class")
					assert.Zero(t, flow, "flow label")
					assert.Equal(t, len(ipb)-header.IPv6MinimumSize, int(ip.PayloadLength()), "payload length")
					assert.Equal(t, uint8(header.UDPProtocolNumber), ip.NextHeader(), "next header")
					assert.Equal(t, uint8(ipv6.DefaultTTL), ip.HopLimit(), "hop limit")
					udp, src, dst = header.UDP(ip.Payload()), ip.SourceAddress(), ip.DestinationAddress()
				}
				assert.Equal(t, tcpip.AddrFromSlice(own.AsSlice()), src, "IP source")
				assert.Equal(t, tcpip.AddrFromSlice(dest.Addr().AsSlice()), dst, "IP destination")
				assert.Equal(t, uint16(PortData), udp.SourcePort(), "UDP source port")
				assert.Equal(t, dest.Port(), udp.DestinationPort(), "UDP destination port")
				assert.Equal(t, len(udp), int(udp.Length()), "UDP length")
				assert.NotZero(t, udp.Checksum(), "UDP checksum")
				assert.True(t, udp.IsChecksumValid(src, dst, checksum.Checksum(udp.Payload(), 0)), "UDP checksum")
				sent = append(sent, string(dg.payload))
			}
			var want []string
			for _, i := range tc.sent {
				want = append(want, fmt.Sprintf("packet %d", i))
			}
			assert.Equal(t, want, sent, "packets on the ring")
			assert.Equal(t, tc.noRoom, noRoom, "packets with no TX frame")
			assert.Equal(t, tc.txFull, counted(e.Device, ReasonTXFull), "tx_full")
			assert.Equal(t, tc.noNeighbor, counted(e.Device, ReasonNoNeighbor), "no_neighbor")
			assert.Equal(t, tc.frames, f.frames(), "each frame is in the queue again")
			assert.Equal(t, tc.frames, f.distinct(), "no frame is in two places")
			assert.Empty(t, b.frames, "frames of the batch after Send")
		})
	}
}

// TestForwardFrames runs the pipeline of a worker on PSP packets from agent A1 to agent A2: a part,
// and then one more packet. Each packet with a TX frame goes out sealed for A2. A packet with no
// frame, or with a frame that is too small, counts tx_full and uses no sequence number, and its out
// cell counts it, as for a full TX ring. Each frame is in the queue again, and the RX packets are
// open in place.
func TestForwardFrames(t *testing.T) {
	cases := []struct {
		name      string
		frames    int    // The TX frames of the queue.
		frameSize int    // The size of a TX frame; 0 is 256.
		oneMem    bool   // The RX packets are in the memory of the TX frames, as in the UMEM of one socket.
		ended     bool   // A kick error ended the queue.
		spi       uint32 // The SPI of the packets.
		packets   int    // The packets of the part.
		sent      []int  // The packets on the ring, in order.
		ivs       []uint64
		txFull    int
		unknown   int // unknown_spi drops.
		cell      int // The packets that the out cell counts.
	}{
		{name: "a frame for each packet", frames: 8, spi: engSPIA1, packets: 3, sent: []int{0, 1, 2, 3}, ivs: []uint64{0, 1, 2, 3}, cell: 4},
		{name: "one memory for the RX packets and the TX frames", frames: 8, oneMem: true, spi: engSPIA1, packets: 3,
			sent: []int{0, 1, 2, 3}, ivs: []uint64{0, 1, 2, 3}, cell: 4},
		{name: "fewer frames than packets", frames: 2, spi: engSPIA1, packets: 3, sent: []int{0, 1, 3}, ivs: []uint64{0, 1, 2}, txFull: 1, cell: 4},
		{name: "frames that are too small", frames: 8, frameSize: 128, spi: engSPIA1, packets: 3, txFull: 4, cell: 4},
		{name: "no packet to a PSP port", frames: 8, spi: 0x999, packets: 3, unknown: 4},
		{name: "a queue that a kick error ended", frames: 8, ended: true, spi: engSPIA1, packets: 3, txFull: 4, cell: 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			size := 256
			if tc.frameSize > 0 {
				size = tc.frameSize
			}
			e := newEngineSize(t, 1, 1, tc.frames, size)
			f := e.txs[0]
			const slot = 256 // The room of each RX packet.
			var mems [][]byte
			rxMem, base := 1, 0
			if tc.oneMem {
				// The RX packets go after the TX frames, as in the UMEM of a socket.
				base = len(f.mem)
				f.mem = append(f.mem, make([]byte, (tc.packets+1)*slot)...)
				mems, rxMem = [][]byte{f.mem}, 0
			} else {
				mems = [][]byte{f.mem, make([]byte, (tc.packets+1)*slot)}
			}
			var rx []RxPacket
			var inners [][]byte
			for i := range tc.packets + 1 {
				in := inner("100.64.1.5", byte(i))
				p := sealIn(t, tc.spi, uint32(i+1), in)
				dst := mems[rxMem][base+i*slot : base+(i+1)*slot]
				rx = append(rx, RxPacket{From: engA1, Payload: dst[:copy(dst, p)], mem: rxMem})
				inners = append(inners, in)
			}
			if tc.ended {
				e.tx[0].fail(errors.New("kick"))
			}
			tx := &TxBatch{mems: mems, txq: e.tx[0], hops: hopCache{}}

			out, err := psp.NewAEAD(engKey(engSPIA2))
			require.NoError(t, err)
			var sent [][]byte
			var ivs []uint64
			for _, part := range [][]RxPacket{rx[:tc.packets], rx[tc.packets:]} {
				e.forward(part, tx)
				for _, frame := range f.onRing() {
					to, dg := demux(frame, func(a netip.Addr) bool { return a == engA2.Addr() })
					require.Equal(t, toPipeline, to)
					h, p := openToA2(t, out, dg.payload)
					sent, ivs = append(sent, p), append(ivs, h.IV)
				}
				f.completeRing()
			}
			var want [][]byte
			for _, i := range tc.sent {
				want = append(want, inners[i])
			}
			sealed := engInner + psp.Overhead
			assert.Equal(t, want, sent, "packets on the ring")
			assert.Equal(t, tc.ivs, ivs, "IVs of the packets on the ring")
			assert.Equal(t, tc.txFull, counted(e.Device, ReasonTXFull), "tx_full")
			assert.Equal(t, uint64(tc.txFull*sealed), e.p.drops[ReasonTXFull].bytes.Load(), "tx_full bytes")
			assert.Equal(t, tc.unknown, counted(e.Device, ReasonUnknownSPI), "unknown_spi")
			assert.Equal(t, uint64(tc.cell), e.p.cells[2*engOutCell+1].packets.Load(), "out cell")
			assert.Equal(t, uint64(tc.cell*engInner), e.p.cells[2*engOutCell+1].bytes.Load(), "out cell bytes")
			assert.Empty(t, portDrops(e.Device), "port_drops")
			assert.Equal(t, tc.frames, f.frames(), "each frame is in the queue again")
			assert.Equal(t, tc.frames, f.distinct(), "no frame is in two places")
			assert.Empty(t, tx.frames, "frames of the batch after forward")
			if tc.spi == engSPIA1 {
				for i, p := range rx {
					assert.Equal(t, inners[i], p.Payload[psp.PrefixLen:len(p.Payload)-psp.ICVLen], "RX packet %d is open in place", i)
				}
			}
		})
	}
}
