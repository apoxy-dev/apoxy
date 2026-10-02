package connection

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// closeTestConn is a Connection for the close tests. When release is set, the
// first ReadPacket waits for it and then returns pkt, also after Close. All
// other reads wait for Close and return net.ErrClosed.
type closeTestConn struct {
	pkt     []byte
	icmp    []byte
	reading chan struct{}
	release chan struct{}
	again   chan struct{}
	closed  chan struct{}
	writes  chan struct{}

	reads     atomic.Int32
	closes    atomic.Int32
	againOnce sync.Once
	closeOnce sync.Once
}

func newCloseTestConn() *closeTestConn {
	return &closeTestConn{
		pkt:     []byte{0x60, 0, 0, 0},
		reading: make(chan struct{}),
		again:   make(chan struct{}),
		closed:  make(chan struct{}),
		writes:  make(chan struct{}, 16),
	}
}

func (c *closeTestConn) String() string { return "close-test-conn" }

func (c *closeTestConn) ReadPacket(p []byte) (int, error) {
	if c.reads.Add(1) == 1 && c.release != nil {
		close(c.reading)
		<-c.release
		return copy(p, c.pkt), nil
	}
	c.againOnce.Do(func() { close(c.again) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *closeTestConn) WritePacket([]byte) ([]byte, error) {
	select {
	case c.writes <- struct{}{}:
	default:
	}
	return c.icmp, nil
}

func (c *closeTestConn) Close() error {
	c.closes.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("no %s after 5s", what)
	}
}

// A packet, an ICMP reply or a new connection that comes after Close must not
// cause a send on a closed channel.
func TestMuxedConnClose(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8::/96")
	cases := []struct {
		name string
		run  func(t *testing.T, m *muxedConn)
	}{
		{
			name: "reader has a packet at close",
			run: func(t *testing.T, m *muxedConn) {
				c := newCloseTestConn()
				c.release = make(chan struct{})
				require.NoError(t, m.Add(prefix, c))
				waitFor(t, c.reading, "read")
				require.NoError(t, m.Close())
				close(c.release)
				// The reader drops the packet and reads again.
				waitFor(t, c.again, "second read")
				_, err := m.ReadPacket(make([]byte, 64))
				require.ErrorIs(t, err, net.ErrClosed)
			},
		},
		{
			name: "ICMP reply from a replaced connection after close",
			run: func(t *testing.T, m *muxedConn) {
				old := newCloseTestConn()
				old.icmp = []byte{0x60, 0, 0, 0}
				t.Cleanup(func() { _ = old.Close() })
				require.NoError(t, m.Add(prefix, old))
				m.mu.RLock()
				w := m.prefixes[prefix].(*asyncSendConn)
				m.mu.RUnlock()
				require.NoError(t, m.Add(prefix, newCloseTestConn()))
				// Close does not stop the sender of the replaced connection.
				require.NoError(t, m.Close())
				// The sender writes the second packet only after the ICMP reply
				// of the first packet is done.
				for i := 0; i < 2; i++ {
					_, err := w.WritePacket([]byte{0x60, 0, 0, 0})
					require.NoError(t, err)
				}
				waitFor(t, old.writes, "first write")
				waitFor(t, old.writes, "second write")
				w.shutdownSender()
			},
		},
		{
			name: "add after close",
			run: func(t *testing.T, m *muxedConn) {
				require.NoError(t, m.Close())
				c := newCloseTestConn()
				require.ErrorIs(t, m.Add(prefix, c), net.ErrClosed)
				require.Empty(t, m.Prefixes())
				require.Zero(t, c.reads.Load())
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, newMuxedConn())
		})
	}
}

// packetTo returns an IP header with dst as its destination.
func packetTo(dst netip.Addr) []byte {
	if dst.Is4() {
		p := make([]byte, 20)
		p[0] = 0x45
		copy(p[16:20], dst.AsSlice())
		return p
	}
	p := make([]byte, 40)
	p[0] = 0x60
	copy(p[24:40], dst.AsSlice())
	return p
}

// A conn added under more than one prefix has one reader and one sender, and
// its close removes all of its prefixes.
func TestMuxedConnOneWrapperForEachConn(t *testing.T) {
	v6 := netip.MustParsePrefix("2001:db8::/96")
	v4 := netip.MustParsePrefix("198.51.100.0/24")
	cases := []struct {
		name     string
		prefixes []netip.Prefix
		closeMux bool
	}{
		{name: "v6 and v4 prefix, conn closes", prefixes: []netip.Prefix{v6, v4}},
		{name: "v6 and v4 prefix, mux closes", prefixes: []netip.Prefix{v6, v4}, closeMux: true},
		{name: "same prefix two times, mux closes", prefixes: []netip.Prefix{v6, v6}, closeMux: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewDstMuxedConn()
			t.Cleanup(func() { _ = m.Close() })
			c := newCloseTestConn()
			for _, p := range tc.prefixes {
				require.NoError(t, m.Add(p, c))
			}

			waitFor(t, c.again, "read")
			require.Never(t, func() bool { return c.reads.Load() > 1 }, 100*time.Millisecond, 5*time.Millisecond,
				"more than one reader reads the conn")
			for _, p := range tc.prefixes {
				_, err := m.WritePacket(packetTo(p.Addr().Next()))
				require.NoError(t, err)
				waitFor(t, c.writes, "write to "+p.String())
			}

			if tc.closeMux {
				require.NoError(t, m.Close())
				require.EqualValues(t, 1, c.closes.Load(), "the mux closed the conn more than one time")
				return
			}
			require.NoError(t, c.Close())
			require.Eventually(t, func() bool { return len(m.Prefixes()) == 0 }, 5*time.Second, 5*time.Millisecond,
				"a prefix of the closed conn stayed in the mux")
		})
	}
}

// WritePacket can run at the same time as Close, as the splice goroutine does
// when a connection closes.
func TestAsyncSendConnWriteDuringClose(t *testing.T) {
	pkt := make([]byte, 1500)
	for i := 0; i < 100; i++ {
		c := newCloseTestConn()
		a := newAsyncSendConn(c, "write-during-close", nil)
		var stop atomic.Bool
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !stop.Load() {
					_, _ = a.WritePacket(pkt)
				}
			}()
		}
		// Close while the writers send packets.
		waitFor(t, c.writes, "write")
		require.NoError(t, a.Close())
		stop.Store(true)
		wg.Wait()
	}
}
