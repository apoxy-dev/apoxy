// SPDX-License-Identifier: AGPL-3.0-only

package udpbatch

import (
	"cmp"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestBatch checks how a batch puts packets in GSO messages, and that a
// receiver with a NonQUICPacketHandler gets each packet alone and in order.
// The receiver socket has no UDP_GRO, so the kernel splits a GSO message.
func TestBatch(t *testing.T) {
	type pkt struct{ dst, size int }
	type msg struct {
		dst   int
		sizes []int
	}
	same := func(dst, n, size int) []pkt { return slices.Repeat([]pkt{{dst, size}}, n) }
	sizes := func(n, size int) []int { return slices.Repeat([]int{size}, n) }
	// Destinations 0 and 1 are receivers. The kernel refuses all packets to
	// destination 2, which has port 0, and to destination 3, which is IPv6.
	cases := []struct {
		name     string
		size     int  // The size of the batch, if not 64.
		noGSO    bool // The batch does not use GSO.
		noCheck  bool // The sender has SO_NO_CHECK, so the kernel refuses GSO.
		pkts     []pkt
		msgs     []msg // The messages before the last flush.
		gsoAfter bool
		// open returns the descriptor that sends and the function that makes its
		// batch. The test sets it.
		open func(t *testing.T) (int, func(size int) *Batch)
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
			// The caller sends the first 64 packets when the batch is full.
			name:     "full batch",
			pkts:     same(0, 70, 1000),
			msgs:     []msg{{0, sizes(6, 1000)}},
			gsoAfter: true,
		},
		{
			name:     "segment limit",
			size:     128,
			pkts:     same(0, 70, 100),
			msgs:     []msg{{0, sizes(MaxSegments, 100)}, {0, sizes(70-MaxSegments, 100)}},
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
			// The error is not a GSO error, so the batch drops the message.
			name:     "IPv6 address on an IPv4 socket",
			pkts:     slices.Concat(same(3, 3, 1400), same(0, 2, 1400)),
			msgs:     []msg{{3, sizes(3, 1400)}, {0, sizes(2, 1400)}},
			gsoAfter: true,
		},
		{
			name:     "bad address keeps GSO",
			pkts:     slices.Concat(same(2, 3, 1400), same(0, 2, 1400)),
			msgs:     []msg{{2, sizes(3, 1400)}, {0, sizes(2, 1400)}},
			gsoAfter: true,
		},
	}
	// Each case runs on a socket of the Go poller and on a send socket.
	senders := []struct {
		name string
		open func(t *testing.T) (int, func(size int) *Batch)
	}{
		{"socket of the Go poller", func(t *testing.T) (int, func(int) *Batch) {
			uc := listenLoopback(t)
			return rawFD(t, uc), func(size int) *Batch { return New(uc, size) }
		}},
		{"send socket", func(t *testing.T) (int, func(int) *Batch) {
			_, s := listen(t, "udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			return s.fd, func(size int) *Batch { return NewSend(s, size) }
		}},
	}
	all := cases[:0:0]
	for _, sd := range senders {
		for _, tc := range cases {
			tc.name, tc.open = sd.name+"/"+tc.name, sd.open
			all = append(all, tc)
		}
	}
	for _, tc := range all {
		t.Run(tc.name, func(t *testing.T) {
			var dsts []netip.AddrPort
			var rx []chan []byte
			for range 2 {
				addr, ch := nonQUICReceiver(t)
				dsts, rx = append(dsts, addr), append(rx, ch)
			}
			dsts = append(dsts, netip.MustParseAddrPort("127.0.0.1:0"), netip.MustParseAddrPort("[::1]:9"))
			fd, batch := tc.open(t)
			if tc.noCheck {
				require.NoError(t, unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_NO_CHECK, 1))
			}
			size := cmp.Or(tc.size, 64)
			bt := batch(size)
			if !bt.gso && !tc.noGSO {
				t.Skip("The kernel cannot send with UDP_SEGMENT.")
			}
			bt.gso = !tc.noGSO

			want := make([][][]byte, len(rx))
			var sent, dropped, wantSent, wantDropped int
			flush := func() {
				s, d, err := bt.Flush()
				require.NoError(t, err)
				sent, dropped = sent+s, dropped+d
			}
			for i, p := range tc.pkts {
				b := make([]byte, p.size)
				// A first byte of 0x01 is not a QUIC packet.
				b[0], b[1] = 0x01, byte(i)
				if p.dst < len(rx) {
					want[p.dst] = append(want[p.dst], b)
					wantSent++
				} else {
					wantDropped++
				}
				if bt.Len() == size {
					flush()
				}
				bt.Add(b, dsts[p.dst])
			}
			var got []msg
			for _, m := range bt.pend {
				var s []int
				for _, b := range m.bufs {
					s = append(s, len(b))
				}
				got = append(got, msg{slices.Index(dsts, m.dst), s})
			}
			assert.Equal(t, tc.msgs, got)
			flush()
			assert.Equal(t, tc.gsoAfter, bt.gso)
			assert.Equal(t, [2]int{wantSent, wantDropped}, [2]int{sent, dropped}, "sent and dropped")
			assert.Zero(t, bt.Len())

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

func listenLoopback(t testing.TB) *net.UDPConn {
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

// TestBatchClosed checks that Flush stops with net.ErrClosed when the socket
// is closed, and empties the batch.
func TestBatchClosed(t *testing.T) {
	cases := []struct {
		name string
		// open returns a batch and the function that closes its socket.
		open func(t *testing.T) (*Batch, func() error)
	}{
		{"socket of the Go poller", func(t *testing.T) (*Batch, func() error) {
			uc := listenLoopback(t)
			return New(uc, 8), uc.Close
		}},
		{"send socket", func(t *testing.T) (*Batch, func() error) {
			_, s := listen(t, "udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			return NewSend(s, 8), s.Close
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst, _ := nonQUICReceiver(t)
			bt, closeSocket := tc.open(t)
			bt.Add(make([]byte, 100), dst)
			bt.Add(make([]byte, 100), dst)
			require.NoError(t, closeSocket())
			sent, dropped, err := bt.Flush()
			assert.ErrorIs(t, err, net.ErrClosed)
			assert.Zero(t, sent)
			assert.Zero(t, dropped)
			assert.Zero(t, bt.Len())
		})
	}
}

// TestBatchShared holds the write lock of the socket, as a write that waits does.
// A batch from NewShared must send while the lock is held, and a batch from New
// must wait for the lock.
func TestBatchShared(t *testing.T) {
	cases := []struct {
		name  string
		batch func(*net.UDPConn, int) *Batch
		waits bool
	}{
		{"shared", NewShared, false},
		{"not shared", New, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst, rx := nonQUICReceiver(t)
			uc := listenLoopback(t)
			rc, err := uc.SyscallConn()
			require.NoError(t, err)
			held, release, unlocked := make(chan struct{}), make(chan struct{}), make(chan struct{})
			go func() {
				defer close(unlocked)
				_ = rc.Write(func(uintptr) bool {
					close(held)
					<-release
					return true
				})
			}()
			<-held

			bt := tc.batch(uc, 8)
			pkt := []byte{0x01, 7}
			bt.Add(pkt, dst)
			sent := make(chan int, 1)
			go func() {
				n, _, _ := bt.Flush()
				sent <- n
			}()
			if tc.waits {
				select {
				case <-sent:
					t.Fatal("The batch did not wait for the write lock.")
				case <-time.After(50 * time.Millisecond):
				}
				close(release)
			}
			select {
			case n := <-sent:
				assert.Equal(t, 1, n)
			case <-time.After(5 * time.Second):
				t.Fatal("The batch waits for the write lock.")
			}
			select {
			case b := <-rx:
				assert.Equal(t, pkt, b)
			case <-time.After(2 * time.Second):
				t.Fatal("The receiver did not get the packet.")
			}
			if !tc.waits {
				close(release)
			}
			<-unlocked
		})
	}
}

// TestBatchSharedParallel sends from 4 goroutines on one socket, each with its own
// batch. The receiver must get each packet once.
func TestBatchSharedParallel(t *testing.T) {
	const senders, flushes, perFlush = 4, 20, 8
	dst, rx := nonQUICReceiver(t)
	uc := listenLoopback(t)
	var wg sync.WaitGroup
	for s := range senders {
		bt := NewShared(uc, perFlush)
		require.NotNil(t, bt)
		wg.Go(func() {
			for f := range flushes {
				for i := range perFlush {
					// A first byte of 0x01 is not a QUIC packet.
					bt.Add([]byte{0x01, byte(s), byte(f), byte(i)}, dst)
				}
				sent, dropped, err := bt.Flush()
				assert.NoError(t, err)
				assert.Equal(t, [2]int{perFlush, 0}, [2]int{sent, dropped}, "sent and dropped")
				// The receiver keeps at most 256 packets.
				time.Sleep(time.Millisecond)
			}
		})
	}
	got := map[[3]byte]int{}
	for range senders * flushes * perFlush {
		select {
		case b := <-rx:
			require.Len(t, b, 4)
			got[[3]byte(b[1:])]++
		case <-time.After(5 * time.Second):
			t.Fatalf("The receiver got %d packets.", len(got))
		}
	}
	wg.Wait()
	assert.Len(t, got, senders*flushes*perFlush)
	for k, n := range got {
		assert.Equal(t, 1, n, "packet %v", k)
	}
}
