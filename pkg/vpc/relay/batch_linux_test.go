// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestFwdBatch checks how a batch puts packets in GSO messages, and that a
// receiver with a NonQUICPacketHandler gets each packet alone and in order.
// The receiver socket has no UDP_GRO, so the kernel splits a GSO message.
func TestFwdBatch(t *testing.T) {
	type pkt struct{ dst, size int }
	type msg struct {
		dst   int
		sizes []int
	}
	same := func(dst, n, size int) []pkt { return slices.Repeat([]pkt{{dst, size}}, n) }
	sizes := func(n, size int) []int { return slices.Repeat([]int{size}, n) }
	// Destinations 0 and 1 are receivers. The kernel refuses all packets to
	// destination 2, which has port 0.
	cases := []struct {
		name     string
		noGSO    bool // The batch does not use GSO.
		noCheck  bool // The sender has SO_NO_CHECK, so the kernel refuses GSO.
		pkts     []pkt
		msgs     []msg // The messages before the last flush.
		gsoAfter bool
	}{
		{
			name:     "same size",
			pkts:     same(0, 3, 1400),
			msgs:     []msg{{0, sizes(3, 1400)}},
			gsoAfter: true,
		},
		{
			name:     "shorter packet ends a message",
			pkts:     slices.Concat(same(0, 2, 1400), []pkt{{0, 600}, {0, 1400}}),
			msgs:     []msg{{0, []int{1400, 1400, 600}}, {0, []int{1400}}},
			gsoAfter: true,
		},
		{
			name:     "larger packet starts a message",
			pkts:     []pkt{{0, 600}, {0, 1400}},
			msgs:     []msg{{0, []int{600}}, {0, []int{1400}}},
			gsoAfter: true,
		},
		{
			name:     "two addresses",
			pkts:     []pkt{{0, 1400}, {1, 1400}, {0, 1400}, {1, 1000}},
			msgs:     []msg{{0, sizes(2, 1400)}, {1, []int{1400, 1000}}},
			gsoAfter: true,
		},
		{
			name:     "order for each address",
			pkts:     []pkt{{0, 1400}, {1, 1400}, {0, 600}, {0, 1400}},
			msgs:     []msg{{0, []int{1400, 600}}, {1, []int{1400}}, {0, []int{1400}}},
			gsoAfter: true,
		},
		{
			name:     "byte limit",
			pkts:     same(0, 50, 1400),
			msgs:     []msg{{0, sizes(46, 1400)}, {0, sizes(4, 1400)}},
			gsoAfter: true,
		},
		{
			// The first 64 packets go in one message when the batch is full.
			name:     "full batch",
			pkts:     same(0, 70, 1000),
			msgs:     []msg{{0, sizes(6, 1000)}},
			gsoAfter: true,
		},
		{
			name:  "no GSO",
			noGSO: true,
			pkts:  same(0, 3, 1400),
			msgs:  []msg{{0, []int{1400}}, {0, []int{1400}}, {0, []int{1400}}},
		},
		{
			name:    "socket refuses GSO",
			noCheck: true,
			pkts:    slices.Concat(same(0, 3, 1400), same(1, 2, 1000)),
			msgs:    []msg{{0, sizes(3, 1400)}, {1, sizes(2, 1000)}},
		},
		{
			name:     "bad address keeps GSO",
			pkts:     slices.Concat(same(2, 3, 1400), same(0, 2, 1400)),
			msgs:     []msg{{2, sizes(3, 1400)}, {0, sizes(2, 1400)}},
			gsoAfter: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var dsts []netip.AddrPort
			var rx []chan []byte
			for range 2 {
				addr, ch := nonQUICReceiver(t)
				dsts, rx = append(dsts, addr), append(rx, ch)
			}
			dsts = append(dsts, netip.MustParseAddrPort("127.0.0.1:0"))
			uc := listenLoopback(t)
			if tc.noCheck {
				rc, err := uc.SyscallConn()
				require.NoError(t, err)
				var serr error
				require.NoError(t, rc.Control(func(fd uintptr) {
					serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_NO_CHECK, 1)
				}))
				require.NoError(t, serr)
			}
			tr := &quic.Transport{Conn: uc}
			t.Cleanup(func() { _ = tr.Close() })
			f := newFwdBatch(tr)
			if !f.gso && !tc.noGSO {
				t.Skip("The kernel cannot send with UDP_SEGMENT.")
			}
			f.gso = !tc.noGSO

			want := make([][][]byte, len(rx))
			for i, p := range tc.pkts {
				b := make([]byte, p.size)
				// A first byte of 0x01 is not a QUIC packet.
				b[0], b[1] = 0x01, byte(i)
				if p.dst < len(rx) {
					want[p.dst] = append(want[p.dst], slices.Clone(b))
				}
				f.add(b, dsts[p.dst])
				// The batch must not keep b.
				clear(b)
			}
			var got []msg
			for _, m := range f.pend {
				var s []int
				for _, b := range m.bufs {
					s = append(s, len(b))
				}
				got = append(got, msg{slices.Index(dsts, m.dst), s})
			}
			assert.Equal(t, tc.msgs, got)
			f.flush()
			assert.Equal(t, tc.gsoAfter, f.gso)

			for i, ch := range rx {
				for j, w := range want[i] {
					select {
					case b := <-ch:
						require.Equal(t, w, b, "receiver %d, packet %d", i, j)
					case <-time.After(2 * time.Second):
						t.Fatalf("Receiver %d did not get packet %d.", i, j)
					}
				}
			}
			select {
			case b := <-rx[0]:
				t.Errorf("Receiver 0 got an extra packet of %d bytes.", len(b))
			case b := <-rx[1]:
				t.Errorf("Receiver 1 got an extra packet of %d bytes.", len(b))
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

func listenLoopback(t *testing.T) *net.UDPConn {
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = uc.Close() })
	return uc
}

// nonQUICReceiver starts a transport that sends a copy of each non-QUIC
// packet to the channel.
func nonQUICReceiver(t *testing.T) (netip.AddrPort, chan []byte) {
	uc := listenLoopback(t)
	ch := make(chan []byte, 256)
	tr := &quic.Transport{Conn: uc, NonQUICPacketHandler: func(b []byte, _ net.Addr) { ch <- slices.Clone(b) }}
	require.NoError(t, tr.Start())
	t.Cleanup(func() { _ = tr.Close() })
	ap := uc.LocalAddr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), ch
}
