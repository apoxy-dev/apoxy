package conntrackpc

import (
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// listenUDP binds a loopback UDP socket that closes at the end of the test.
func listenUDP(tb testing.TB) net.PacketConn {
	tb.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = pc.Close() })
	return pc
}

// TestOldFlowKeepsNewFlow: a late Close or touch of a replaced flow does not
// change the new flow, and a closed flow in the LRU does not get packets.
func TestOldFlowKeepsNewFlow(t *testing.T) {
	closeFlow := func(t *testing.T, v *VirtualPacketConn) { require.NoError(t, v.Close()) }
	reopen := func(t *testing.T, ct *ConntrackPacketConn, old *VirtualPacketConn) *VirtualPacketConn {
		closeFlow(t, old)
		next, err := ct.Open(old.remote)
		require.NoError(t, err)
		return next
	}
	expireAndReopen := func(t *testing.T, ct *ConntrackPacketConn, old *VirtualPacketConn) *VirtualPacketConn {
		select {
		case <-old.closedCh:
		case <-time.After(5 * time.Second):
			t.Fatal("the LRU did not evict the flow after its TTL")
		}
		next, err := ct.Open(old.remote)
		require.NoError(t, err)
		return next
	}
	cases := []struct {
		name       string
		ttl        time.Duration
		autoCreate bool
		// stale makes the old flow stale and returns the new flow, or nil when
		// the next packet makes the new flow.
		stale func(t *testing.T, ct *ConntrackPacketConn, old *VirtualPacketConn) *VirtualPacketConn
		late  func(t *testing.T, v *VirtualPacketConn)
	}{
		{name: "close after close and reopen", ttl: time.Minute, stale: reopen, late: closeFlow},
		{name: "close after TTL expiry", ttl: 300 * time.Millisecond, stale: expireAndReopen, late: closeFlow},
		{
			name:  "touch after close and reopen",
			ttl:   time.Minute,
			stale: reopen,
			late:  func(_ *testing.T, v *VirtualPacketConn) { v.touch() },
		},
		{
			// A touch that races the TTL eviction can leave a closed flow in the LRU.
			name:       "packet for a closed flow in the LRU",
			ttl:        time.Minute,
			autoCreate: true,
			stale: func(_ *testing.T, _ *ConntrackPacketConn, old *VirtualPacketConn) *VirtualPacketConn {
				_ = old.closeLocked(nil)
				return nil
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct := New(listenUDP(t), Options{AutoCreate: tc.autoCreate, TTL: tc.ttl, RxBufSize: 8})
			t.Cleanup(func() { _ = ct.Close() })
			peer := listenUDP(t)

			old, err := ct.Open(peer.LocalAddr().(*net.UDPAddr))
			require.NoError(t, err)
			next := tc.stale(t, ct, old)
			if tc.late != nil {
				tc.late(t, old)
			}
			if next != nil {
				require.NotSame(t, old, next)
				cur, ok := ct.flows.Peek(next.key)
				require.True(t, ok, "the new flow left the LRU")
				require.Same(t, next, cur, "the old flow went back into the LRU")
			}

			_, err = peer.WriteTo([]byte("ping"), ct.LocalAddr())
			require.NoError(t, err)
			if next == nil {
				require.Eventually(t, func() bool {
					cur, ok := ct.flows.Peek(old.key)
					return ok && cur != old
				}, 5*time.Second, 5*time.Millisecond, "the packet did not make a new flow")
				next, _ = ct.flows.Peek(old.key)
			}
			require.NoError(t, next.SetReadDeadline(time.Now().Add(5*time.Second)))
			buf := make([]byte, 16)
			n, _, err := next.ReadFrom(buf)
			require.NoError(t, err, "the new flow did not get the packet")
			require.Equal(t, "ping", string(buf[:n]))
		})
	}
}

// BenchmarkWriteTo measures a flow write, which also refreshes the flow TTL.
func BenchmarkWriteTo(b *testing.B) {
	ct := New(listenUDP(b), Options{TTL: time.Minute})
	b.Cleanup(func() { _ = ct.Close() })
	pkt := make([]byte, 1200)
	open := func(b *testing.B) *VirtualPacketConn {
		v, err := ct.Open(listenUDP(b).LocalAddr().(*net.UDPAddr))
		require.NoError(b, err)
		return v
	}

	b.Run("serial", func(b *testing.B) {
		v := open(b)
		for b.Loop() {
			if _, err := v.WriteTo(pkt, nil); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("parallel", func(b *testing.B) {
		flows := make([]*VirtualPacketConn, runtime.GOMAXPROCS(0))
		for i := range flows {
			flows[i] = open(b)
		}
		var next atomic.Int32
		b.RunParallel(func(pb *testing.PB) {
			v := flows[int(next.Add(1)-1)%len(flows)]
			for pb.Next() {
				if _, err := v.WriteTo(pkt, nil); err != nil {
					b.Error(err)
					return
				}
			}
		})
	})
}
