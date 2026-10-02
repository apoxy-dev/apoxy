// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
)

// moveConn sends from the next socket after move, as after a NAT rebinding
// or a roam. With dataOnly, only PSP packets move, as forged packets do.
type moveConn struct {
	net.PacketConn // Socket before the move.
	next           *net.UDPConn
	dataOnly       bool
	hide           bool // LocalAddr keeps the first socket, so the agent sees no change.
	moved          atomic.Bool
}

func (c *moveConn) move() {
	c.moved.Store(true)
	if !c.dataOnly {
		// The read on the first socket stops, and ReadFrom goes to the next socket.
		_ = c.PacketConn.SetReadDeadline(time.Now())
	}
}

func (c *moveConn) reader() net.PacketConn {
	if c.moved.Load() && !c.dataOnly {
		return c.next
	}
	return c.PacketConn
}

func (c *moveConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		r := c.reader()
		n, addr, err := r.ReadFrom(p)
		if err != nil && r != c.reader() {
			continue
		}
		return n, addr, err
	}
}

func (c *moveConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.moved.Load() && (!c.dataOnly || isPSP(p)) {
		return c.next.WriteTo(p, addr)
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *moveConn) LocalAddr() net.Addr {
	if c.moved.Load() && !c.hide {
		return c.next.LocalAddr()
	}
	return c.PacketConn.LocalAddr()
}

func (c *moveConn) SetReadDeadline(t time.Time) error {
	_ = c.next.SetReadDeadline(t)
	return c.PacketConn.SetReadDeadline(t)
}

// isPSP reports whether p is a PSP packet: not QUIC and not a path probe.
func isPSP(p []byte) bool { return len(p) > 0 && p[0]&0x40 == 0 && p[0] != p2p.TypeProbe }

// tapConn keeps the times of the first QUIC packet and the first PSP packet
// that the relay sends to to.
type tapConn struct {
	net.PacketConn
	to        netip.AddrPort
	quic, psp atomic.Int64 // Unix nanoseconds.
}

func (c *tapConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if ua, ok := addr.(*net.UDPAddr); ok && unmap(ua.AddrPort()) == c.to {
		switch {
		case isPSP(p):
			c.psp.CompareAndSwap(0, time.Now().UnixNano())
		case p[0]&0x40 != 0:
			c.quic.CompareAndSwap(0, time.Now().UnixNano())
		}
	}
	return c.PacketConn.WriteTo(p, addr)
}

func unmap(a netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(a.Addr().Unmap(), a.Port()) }

// runRouter runs the sweep of r, which follows QUIC connections that moved.
func runRouter(t *testing.T, r *testRelay) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.r.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// firstEcho sends to dst:port each interval for at most d. It returns the
// time of the first echo, or the zero time if no echo came.
func firstEcho(t *testing.T, s *stack.Stack, src, dst netip.Addr, port uint16, interval, d time.Duration) time.Time {
	t.Helper()
	c, err := gonet.DialUDP(s, fullAddr(src, 0), fullAddr(dst, port), ipv6.ProtocolNumber)
	require.NoError(t, err)
	defer c.Close()
	buf := make([]byte, 64)
	for end := time.Now().Add(d); time.Now().Before(end); {
		_, err := c.Write([]byte("moved"))
		require.NoError(t, err)
		_ = c.SetReadDeadline(time.Now().Add(interval))
		if _, err := c.Read(buf); err == nil {
			return time.Now()
		}
	}
	return time.Time{}
}

// TestMove moves the socket of agent a, and checks when its data to agent b
// works again. Only the move of the QUIC connection moves the relay rows.
func TestMove(t *testing.T) {
	cases := []struct {
		name     string
		dataOnly bool
		hide     bool
		within   time.Duration // Data works again in this time. Zero means not in 3 s.
	}{
		{"only data moves", true, false, 0},
		// The next tick sends Moved.
		{"all move", false, false, 1500 * time.Millisecond},
		// The QUIC keepalive moves the connection, then the sweep moves the rows.
		{"unseen rebind", false, true, 9 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.hide && testing.Short() {
				t.Skip("waits for the QUIC keepalive")
			}
			next := loopback(t)
			t.Cleanup(func() { _ = next.Close() })
			tap := &tapConn{PacketConn: loopback(t), to: unmap(next.LocalAddr().(*net.UDPAddr).AddrPort())}
			w := newWorld(t)
			r := w.relayOn(t, "relay-1", tap)
			runRouter(t, r)
			mc := &moveConn{next: next, dataOnly: tc.dataOnly, hide: tc.hide}
			b := w.agent(t, "b", r, agentOptions{mode: TransportPSP})
			a := w.agent(t, "a", r, agentOptions{mode: TransportPSP, move: mc})
			ea, eb := a.attached(t), b.attached(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			require.NoError(t, a.a.Connect(ctx, eb.addr))
			echo(t, b.stack, eb.addr, 7)
			ping(t, a.stack, ea.addr, eb.addr, 7, "before the move")
			drops := r.r.UnknownSourceDrops()
			// With no QUIC packet in flight, quic-go does not move the connection by itself.
			time.Sleep(1500 * time.Millisecond)

			t0 := time.Now()
			mc.move()
			if tc.within == 0 {
				at := firstEcho(t, a.stack, ea.addr, eb.addr, 7, 20*time.Millisecond, 3*time.Second)
				assert.True(t, at.IsZero(), "data works with only data from the new source")
				assert.Zero(t, tap.psp.Load(), "relay sent data to the new source")
				assert.Greater(t, r.r.UnknownSourceDrops(), drops)
				return
			}
			at := firstEcho(t, a.stack, ea.addr, eb.addr, 7, 20*time.Millisecond, tc.within)
			require.False(t, at.IsZero(), "no data in %v", tc.within)
			require.NotZero(t, tap.quic.Load(), "relay sent no QUIC packet to the new source")
			require.NotZero(t, tap.psp.Load(), "relay sent no data to the new source")
			follow := time.Duration(tap.psp.Load() - tap.quic.Load())
			t.Logf("Data works again %v after the move. The rows followed the path challenge after %v.", at.Sub(t0), follow)
			if !tc.hide {
				// Moved starts a watch. The sweep alone takes up to 1 s.
				assert.Less(t, follow, 300*time.Millisecond, "rows followed the connection late")
			}
		})
	}
}
