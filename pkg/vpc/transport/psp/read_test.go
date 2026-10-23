// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

// rxKind is a driver of the receive tests: a netstack driver with a receive pipe, a netstack
// driver with no pipe, or a TUN driver.
type rxKind string

const (
	pipeKind   rxKind = "netstack with a pipe"
	noPipeKind rxKind = "netstack with no pipe"
	tunKind    rxKind = "TUN"
)

var rxKinds = []rxKind{pipeKind, noPipeKind, tunKind}

// rxSink is the netstack or the TUN device of a driver of a receive test.
type rxSink struct {
	r   *pktRecorder
	dev *fakeTun
	got [][]byte
}

// packets returns the inner packets that the driver gave to the sink.
func (s *rxSink) packets() [][]byte {
	if s.r != nil {
		s.r.mu.Lock()
		defer s.r.mu.Unlock()
		return slices.Clone(s.r.pkts)
	}
	for {
		select {
		case p := <-s.dev.out:
			s.got = append(s.got, p)
		default:
			return s.got
		}
	}
}

// useDriver gives n a new driver of kind k, and returns it and its sink.
func useDriver(t *testing.T, n *node, k rxKind) (*driver, *rxSink) {
	t.Helper()
	if k == tunKind {
		dev := newFakeTun(256)
		_, err := n.b.Tun(dev)
		require.NoError(t, err)
		d := n.b.drv.Load()
		t.Cleanup(func() { _ = d.Close() })
		return d, &rxSink{dev: dev}
	}
	r := &pktRecorder{}
	ep := channel.New(16, MaxMTU, "")
	ep.Attach(r)
	t.Cleanup(ep.Close)
	opens := 1
	if k == noPipeKind {
		opens = noPipe
	}
	return useNetstack(t, n, ep, 2, opens), &rxSink{r: r}
}

// counted returns the receive packets of st that have a result: injected or dropped.
func counted(st Stats) uint64 { return st.RxPackets + st.RxDrops }

// waitCounted waits until the binding of n counted want packets more than before.
func waitCounted(t *testing.T, n *node, before Stats, want uint64) {
	t.Helper()
	require.Eventually(t, func() bool { return counted(n.b.Stats())-counted(before) == want }, 5*time.Second,
		time.Millisecond, "stats %+v, before %+v", n.b.Stats(), before)
}

// TestHandleData gives data frames of a relay session to a link, as the session reader does. A
// link takes only the sources that it routes, and the driver gets a copy of each after BatchEnd.
func TestHandleData(t *testing.T) {
	far := netip.MustParseAddr("10.9.9.9")
	// other is a source that only the second link of b routes.
	other := netip.MustParseAddr("10.5.0.1")
	cases := []struct {
		name   string
		frames func(a, b *node) [][]byte
		second bool // Give the frames to the second link.
		end    bool
		mutate bool // Change the frame after HandleData returns.
		want   Stats
		got    func(a, b *node) [][]byte
	}{
		{
			name:   "frame of a link with no route",
			frames: func(a, b *node) [][]byte { return [][]byte{dataFrame(packet(far, b.v4, 17, 1, 2, 100))} },
			end:    true,
			want:   Stats{RxDrops: 1},
		},
		{
			name:   "frame of a link with the route",
			frames: func(a, b *node) [][]byte { return [][]byte{dataFrame(packet(a.v4, b.v4, 17, 1, 2, 100))} },
			end:    true,
			want:   Stats{RxPackets: 1},
			got:    func(a, b *node) [][]byte { return [][]byte{packet(a.v4, b.v4, 17, 1, 2, 100)} },
		},
		{
			name:   "frame of a source that only the other link routes",
			frames: func(a, b *node) [][]byte { return [][]byte{dataFrame(packet(other, b.v4, 17, 1, 2, 100))} },
			end:    true,
			want:   Stats{RxDrops: 1},
		},
		{
			name:   "frame of the same source on the link that routes it",
			frames: func(a, b *node) [][]byte { return [][]byte{dataFrame(packet(other, b.v4, 17, 1, 2, 100))} },
			second: true,
			end:    true,
			want:   Stats{RxPackets: 1},
			got:    func(a, b *node) [][]byte { return [][]byte{packet(other, b.v4, 17, 1, 2, 100)} },
		},
		{
			name:   "frame before BatchEnd",
			frames: func(a, b *node) [][]byte { return [][]byte{dataFrame(packet(a.v4, b.v4, 17, 1, 2, 100))} },
		},
		{
			name: "BatchEnd with no frames",
			end:  true,
		},
		{
			name:   "frame changed after HandleData",
			frames: func(a, b *node) [][]byte { return [][]byte{dataFrame(packet(a.v4, b.v4, 17, 1, 2, 100))} },
			end:    true,
			mutate: true,
			want:   Stats{RxPackets: 1},
			got:    func(a, b *node) [][]byte { return [][]byte{packet(a.v4, b.v4, 17, 1, 2, 100)} },
		},
	}
	for _, k := range rxKinds {
		for _, tc := range cases {
			t.Run(string(k)+"/"+tc.name, func(t *testing.T) {
				a, b := newPair(t)
				l2, err := b.b.AddLink()
				require.NoError(t, err)
				p2, err := l2.AddRelay(netip.MustParseAddrPort("192.0.2.1:1"))
				require.NoError(t, err)
				require.NoError(t, b.b.AddRoute(netip.PrefixFrom(other, 32), p2))
				l := b.l
				if tc.second {
					l = l2
				}
				_, sink := useDriver(t, b, k)
				var frames [][]byte
				if tc.frames != nil {
					frames = tc.frames(a, b)
				}
				for _, f := range frames {
					l.HandleData(f)
					if tc.mutate {
						clear(f)
					}
				}
				if tc.end {
					l.BatchEnd()
				}
				if tc.want != (Stats{}) {
					require.Eventually(t, func() bool { return b.b.Stats() == tc.want }, 5*time.Second, time.Millisecond,
						"stats %+v", b.b.Stats())
				}
				assert.Equal(t, tc.want, b.b.Stats())
				var want [][]byte
				if tc.got != nil {
					want = tc.got(a, b)
				}
				assert.Equal(t, want, sink.packets())
			})
		}
	}
}

// dataFrame returns the data frame of an inner packet.
func dataFrame(pkt []byte) []byte { return peerconn.EncodeData(nil, testVNI, pkt) }

// TestDriverSwap changes the driver of a binding in the middle of a read of a relay session.
// Each frame counts once, in the binding, and the next read on the new driver works.
func TestDriverSwap(t *testing.T) {
	cases := []struct {
		name     string
		from, to rxKind
		opensTo  int // The open workers of a pipe of the new driver, when to is pipeKind.
	}{
		{name: "pipe to pipe", from: pipeKind, to: pipeKind},
		{name: "no pipe to no pipe", from: noPipeKind, to: noPipeKind},
		{name: "TUN to TUN", from: tunKind, to: tunKind},
		{name: "pipe to no pipe", from: pipeKind, to: noPipeKind},
		{name: "no pipe to pipe", from: noPipeKind, to: pipeKind},
		{name: "TUN to pipe", from: tunKind, to: pipeKind},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPair(t)
			pkt := packet(a.v4, b.v4, 17, 1, 2, 100)
			d1, sink1 := useDriver(t, b, tc.from)
			const frames = 3
			for range frames {
				b.l.HandleData(dataFrame(pkt))
			}
			require.NoError(t, d1.Close())
			_, sink2 := useDriver(t, b, tc.to)
			b.l.BatchEnd()
			// A set of the old pipe drops. The read batch of an old driver with no pipe goes
			// to its netstack or device at its close, or drops.
			waitCounted(t, b, Stats{}, frames)
			assert.Equal(t, uint64(len(sink1.packets())), b.b.Stats().RxPackets)

			before := b.b.Stats()
			b.l.HandleData(dataFrame(pkt))
			b.l.BatchEnd()
			waitCounted(t, b, before, 1)
			assert.Equal(t, before.RxPackets+1, b.b.Stats().RxPackets)
			assert.Equal(t, [][]byte{pkt}, sink2.packets())
		})
	}

	// A set of a pipe with no open workers must not reach a pipe that has them.
	t.Run("pipe with no open workers to pipe with open workers", func(t *testing.T) {
		a, b := newPair(t)
		pkt := packet(a.v4, b.v4, 17, 1, 2, 100)
		d1 := useNetstack(t, b, channel.New(16, MaxMTU, ""), 1, 0)
		b.l.HandleData(dataFrame(pkt))
		b.l.HandleData(dataFrame(pkt))
		require.NoError(t, d1.Close())
		r := &pktRecorder{}
		ep := channel.New(16, MaxMTU, "")
		ep.Attach(r)
		t.Cleanup(ep.Close)
		useNetstack(t, b, ep, 1, 2)
		b.l.BatchEnd()
		b.l.HandleData(dataFrame(pkt))
		b.l.BatchEnd()
		waitCounted(t, b, Stats{}, 3)
		assert.Equal(t, Stats{RxPackets: 1, RxDrops: 2}, b.b.Stats())
	})

	// The read loop waits in the read batch of the old driver while the driver closes.
	t.Run("read against close", func(t *testing.T) {
		a, b := newPair(t)
		pkt := packet(a.v4, b.v4, 17, 1, 2, 100)
		got := &capture{}
		d1 := fakeDriver(b.b, got.deliver)
		entered, hold := make(chan struct{}), make(chan struct{})
		d1.batch.(*fakeBatch).onAdd = func() {
			close(entered)
			<-hold
		}
		b.b.drv.Store(d1)
		read := make(chan struct{})
		go func() {
			defer close(read)
			b.l.HandleData(dataFrame(pkt))
		}()
		<-entered
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			_ = d1.Close()
		}()
		require.Eventually(t, d1.closed, 5*time.Second, time.Millisecond)
		close(hold)
		<-read
		b.l.BatchEnd()
		<-closed
		assert.Equal(t, Stats{RxPackets: 1}, b.b.Stats())

		got2 := &capture{}
		b.b.drv.Store(fakeDriver(b.b, got2.deliver))
		b.l.HandleData(dataFrame(pkt))
		b.l.BatchEnd()
		assert.Equal(t, Stats{RxPackets: 2}, b.b.Stats())
		assert.Equal(t, [][]byte{pkt}, got2.got)
	})

	// The read loop has the old driver and waits for rxMu while the driver closes.
	t.Run("read waits for the lock at close", func(t *testing.T) {
		a, b := newPair(t)
		pkt := packet(a.v4, b.v4, 17, 1, 2, 100)
		got := &capture{}
		d1 := fakeDriver(b.b, got.deliver)
		b.b.drv.Store(d1)
		// The test holds rxMu, so Close waits in endBatch and b.drv keeps d1.
		b.b.rxMu.Lock()
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			_ = d1.Close()
		}()
		require.Eventually(t, d1.closed, 5*time.Second, time.Millisecond)
		read := make(chan struct{})
		go func() {
			defer close(read)
			b.l.HandleData(dataFrame(pkt))
		}()
		waitLock(t, "psp.(*Binding).read(")
		b.b.rxMu.Unlock()
		<-read
		<-closed
		b.l.BatchEnd()
		assert.Equal(t, Stats{RxDrops: 1}, b.b.Stats())
		assert.Empty(t, got.got)

		got2 := &capture{}
		b.b.drv.Store(fakeDriver(b.b, got2.deliver))
		b.l.HandleData(dataFrame(pkt))
		b.l.BatchEnd()
		assert.Equal(t, Stats{RxPackets: 1, RxDrops: 1}, b.b.Stats())
		assert.Equal(t, [][]byte{pkt}, got2.got)
	})
}

// waitLock waits until a goroutine waits for a sync.Mutex in the function fn.
func waitLock(t *testing.T, fn string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	require.Eventually(t, func() bool {
		for _, g := range strings.Split(string(buf[:runtime.Stack(buf, true)]), "\n\n") {
			if strings.Contains(g, "[sync.Mutex.Lock") && strings.Contains(g, fn) {
				return true
			}
		}
		return false
	}, 5*time.Second, time.Millisecond, "no goroutine waits for a lock in %s", fn)
}

// TestPipeSetReuse gives the one set of a pipe to a relay session, then to a socket, then to
// another relay session. Each read opens its packets as its reader needs.
func TestPipeSetReuse(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	l2, err := b.b.AddLink()
	require.NoError(t, err)
	p2, err := l2.AddRelay(netip.MustParseAddrPort("192.0.2.1:1"))
	require.NoError(t, err)
	require.NoError(t, b.b.AddRoute(netip.PrefixFrom(a.v4, 32), p2))
	r := &pktRecorder{}
	ep := channel.New(16, MaxMTU, "")
	ep.Attach(r)
	t.Cleanup(ep.Close)
	d := useNetstack(t, b, ep, 1, 1)
	pkt := packet(a.v4, b.v4, 17, 1, 2, 100)
	reads := []struct {
		name string
		read func()
	}{
		{"relay session", func() { b.l.HandleData(dataFrame(pkt)); b.l.BatchEnd() }},
		{"agent socket", func() { b.b.demux.Handle(seal(a, pkt)[addrLen:], nil); b.b.demux.BatchEnd() }},
		{"other relay session", func() { l2.HandleData(dataFrame(pkt)); l2.BatchEnd() }},
		{"agent socket again", func() { b.b.demux.Handle(seal(a, pkt)[addrLen:], nil); b.b.demux.BatchEnd() }},
	}
	for i, rd := range reads {
		rd.read()
		// The set is free again before the next read, so the next read gets the same set.
		require.Eventually(t, func() bool {
			return b.b.Stats().RxPackets == uint64(i+1) && len(d.pipe.free) == int(d.pipe.made.Load())
		}, 5*time.Second, time.Millisecond, "%s: stats %+v", rd.name, b.b.Stats())
	}
	assert.Equal(t, Stats{RxPackets: uint64(len(reads))}, b.b.Stats())
	assert.Equal(t, int32(1), d.pipe.made.Load(), "sets of the pipe")
}

// TestCloseCountsReads closes the binding in the middle of a read of a socket. Each packet of
// the read counts once in the binding: as a packet when the driver still takes it, else as a drop.
func TestCloseCountsReads(t *testing.T) {
	const pkts = 3
	// read gives a read of pkts PSP packets from a to the socket of b on lane, with no end.
	read := func(t *testing.T, a, b *node, lane int) {
		for i := range pkts {
			f := seal(a, packet(a.v4, b.v4, 17, uint16(1+i), 2, 100))
			require.NotNil(t, f)
			laneRead(b.b, lane, f[addrLen:])
		}
	}
	for _, k := range rxKinds {
		t.Run(string(k), func(t *testing.T) {
			t.Run("agent socket, binding closes in a read", func(t *testing.T) {
				a, b := newPair(t)
				offer(t, time.Now(), a, b)
				useDriver(t, b, k)
				read(t, a, b, 0)
				require.NoError(t, b.b.Close())
				b.b.demux.BatchEnd()
				waitCounted(t, b, Stats{}, pkts)
			})

			t.Run("agent socket, new binding in a read", func(t *testing.T) {
				a, b := newPair(t)
				offer(t, time.Now(), a, b)
				useDriver(t, b, k)
				read(t, a, b, 0)
				require.NoError(t, b.b.Close())
				nb, err := New(Config{Transport: b.tr, Demux: b.b.demux, VNI: testVNI})
				require.NoError(t, err)
				t.Cleanup(func() { _ = nb.Close() })
				c := &node{tr: b.tr, b: nb, v4: b.v4, v6: b.v6, other: a}
				c.l, err = nb.AddLink()
				require.NoError(t, err)
				c.peer, err = c.l.AddRelay(addrOf(a.tr))
				require.NoError(t, err)
				require.NoError(t, nb.AddRoute(netip.PrefixFrom(a.v4, 32), c.peer))
				offer(t, time.Now(), c)
				_, sink := useDriver(t, c, k)
				b.b.demux.BatchEnd()
				waitCounted(t, b, Stats{}, pkts)
				assert.Equal(t, Stats{}, nb.Stats(), "the new binding counts no packet of the old read")

				pkt := packet(a.v4, b.v4, 17, 9, 2, 100)
				b.b.demux.Handle(seal(a, pkt)[addrLen:], nil)
				b.b.demux.BatchEnd()
				require.Eventually(t, func() bool { return nb.Stats() == Stats{RxPackets: 1} }, 5*time.Second,
					time.Millisecond, "stats %+v", nb.Stats())
				assert.Equal(t, [][]byte{pkt}, sink.packets())
			})

			t.Run("lane socket, binding closes in a read", func(t *testing.T) {
				a, b := newPair(t)
				offer(t, time.Now(), a, b)
				useDriver(t, b, k)
				// The test is the read loop of the lane socket. TestCloseInLaneRead has a real one.
				read(t, a, b, 1)
				require.NoError(t, b.b.Close())
				// The read loop ends its read when its transport closes.
				laneEnd(b.b, 1)
				waitCounted(t, b, Stats{}, pkts)
			})

			t.Run("two Close calls in a read", func(t *testing.T) {
				a, b := newPair(t)
				offer(t, time.Now(), a, b)
				useDriver(t, b, k)
				read(t, a, b, 1)
				var wg sync.WaitGroup
				for range 2 {
					wg.Go(func() { _ = b.b.Close() })
				}
				wg.Wait()
				laneEnd(b.b, 1)
				waitCounted(t, b, Stats{}, pkts)
				// No packet counts twice.
				time.Sleep(10 * time.Millisecond)
				assert.Equal(t, uint64(pkts), counted(b.b.Stats()))
			})

			t.Run("frame after Close", func(t *testing.T) {
				a, b := newPair(t)
				useDriver(t, b, k)
				require.NoError(t, b.b.Close())
				b.l.HandleData(dataFrame(packet(a.v4, b.v4, 17, 1, 2, 100)))
				b.l.BatchEnd()
				assert.Equal(t, Stats{RxDrops: 1}, b.b.Stats())
			})

			if k == pipeKind {
				return
			}
			t.Run("driver Close and binding Close at once", func(t *testing.T) {
				a, b := newPair(t)
				d, _ := useDriver(t, b, k)
				b.l.HandleData(dataFrame(packet(a.v4, b.v4, 17, 1, 2, 100)))
				var wg sync.WaitGroup
				wg.Go(func() { _ = d.Close() })
				wg.Go(func() { _ = b.b.Close() })
				wg.Wait()
				waitCounted(t, b, Stats{}, 1)
				time.Sleep(10 * time.Millisecond)
				assert.Equal(t, uint64(1), counted(b.b.Stats()))
			})
		})
	}
}

// TestCloseInLaneRead closes the binding while the read loop of a lane socket waits in a read.
// The packet of the read counts once, and Close returns after the read loop.
func TestCloseInLaneRead(t *testing.T) {
	for _, closes := range []int{1, 2} {
		t.Run(fmt.Sprintf("closes=%d", closes), func(t *testing.T) {
			a, b := newPair(t)
			offer(t, time.Now(), a, b)
			got := &capture{}
			d := fakeDriver(b.b, got.deliver)
			entered, hold := make(chan struct{}), make(chan struct{})
			var once sync.Once
			d.batch.(*fakeBatch).onAdd = func() { once.Do(func() { close(entered); <-hold }) }
			b.b.drv.Store(d)
			ports := b.b.OpenLanes(2)
			require.Len(t, ports, 1)
			require.NoError(t, b.b.ReadLanes())

			pkt := packet(a.v4, b.v4, 17, 1, 2, 100)
			f := seal(a, pkt)
			require.NotNil(t, f)
			dst := netip.AddrPortFrom(addrOf(b.tr).Addr(), ports[0])
			c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(dst))
			require.NoError(t, err)
			defer c.Close()
			_, err = c.Write(f[addrLen:])
			require.NoError(t, err)
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("the read loop of the lane socket did not get the packet")
			}

			var wg sync.WaitGroup
			for range closes {
				wg.Go(func() { _ = b.b.Close() })
			}
			require.Eventually(t, func() bool { return b.b.ctx.Err() != nil }, 5*time.Second, time.Millisecond)
			close(hold)
			wg.Wait()
			assert.Equal(t, Stats{RxPackets: 1}, b.b.Stats())
			assert.Equal(t, [][]byte{pkt}, got.got)
		})
	}
}
