// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// moveConn sends from the next socket after move, as after a NAT rebinding
// or a roam. With dataOnly, only PSP packets move, as forged packets do. With
// pspOnly, the PSP packets and the path probes move, as with a new NAT mapping
// for the PSP port of the relay only.
type moveConn struct {
	net.PacketConn // Socket before the move.
	next           net.PacketConn
	dataOnly       bool
	pspOnly        bool
	hide           bool // LocalAddr keeps the first socket, so the agent sees no change.
	moved          atomic.Bool
	deadline       atomic.Int64 // Read deadline of readBoth in Unix nanoseconds. Zero is none.
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
		if c.pspOnly && c.moved.Load() {
			return c.readBoth(p)
		}
		r := c.reader()
		n, addr, err := r.ReadFrom(p)
		if err != nil && (r != c.reader() || c.pspOnly && c.moved.Load()) {
			continue
		}
		return n, addr, err
	}
}

// readBoth reads the next packet of the two sockets: QUIC stays on the first one.
func (c *moveConn) readBoth(p []byte) (int, net.Addr, error) {
	for {
		if d := c.deadline.Load(); d != 0 && time.Now().UnixNano() >= d {
			return 0, nil, os.ErrDeadlineExceeded
		}
		for _, r := range []net.PacketConn{c.next, c.PacketConn} {
			_ = r.SetReadDeadline(time.Now().Add(time.Millisecond))
			n, addr, err := r.ReadFrom(p)
			if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
				return n, addr, err
			}
		}
	}
}

func (c *moveConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.moved.Load() && c.moves(p) {
		return c.next.WriteTo(p, addr)
	}
	return c.PacketConn.WriteTo(p, addr)
}

// moves reports whether the packet p goes from the next socket after the move.
func (c *moveConn) moves(p []byte) bool {
	switch {
	case c.dataOnly:
		return isPSP(p)
	case c.pspOnly:
		return len(p) > 0 && p[0]&0x40 == 0
	}
	return true
}

func (c *moveConn) LocalAddr() net.Addr {
	if c.moved.Load() && !c.hide && !c.pspOnly {
		return c.next.LocalAddr()
	}
	return c.PacketConn.LocalAddr()
}

func (c *moveConn) SetReadDeadline(t time.Time) error {
	if c.pspOnly && c.moved.Load() {
		// readBoth sets the deadlines of the two sockets.
		var d int64
		if !t.IsZero() {
			d = t.UnixNano()
		}
		c.deadline.Store(d)
		return nil
	}
	_ = c.next.SetReadDeadline(t)
	return c.PacketConn.SetReadDeadline(t)
}

// isPSP reports whether p is a PSP packet: not QUIC and not a path probe.
func isPSP(p []byte) bool { return len(p) > 0 && p[0]&0x40 == 0 && p[0] != p2p.TypeProbe }

// tapConn keeps the times of the first QUIC packet and the first PSP packet
// that a relay socket sends to to.
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

// TestMove moves the socket of agent a in an open session, and checks when its
// data works again. Only a BFD packet from the new source moves the address.
func TestMove(t *testing.T) {
	// The next BFD packet, at most checkTx later, moves the address.
	const within = checkTx + 2*time.Second
	cases := []struct {
		name                    string
		dataOnly, pspOnly, hide bool
		data                    bool // Data works again.
	}{
		{name: "only data moves", dataOnly: true},
		{name: "all move", data: true},
		{name: "unseen rebind", hide: true, data: true},
		{name: "new source port to the PSP port only", pspOnly: true, data: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := loopback(t)
			t.Cleanup(func() { _ = next.Close() })
			tap := &tapConn{PacketConn: loopback(t), to: unmap(next.LocalAddr().(*net.UDPAddr).AddrPort())}
			w := newWorld(t)
			r := w.relayOn(t, "relay-1", loopback(t), tap)
			runRouter(t, r)
			mc := &moveConn{next: next, dataOnly: tc.dataOnly, pspOnly: tc.pspOnly, hide: tc.hide}
			b := w.agent(t, "b", r, agentOptions{})
			a := w.agent(t, "a", r, agentOptions{move: mc})
			ea, eb := a.attached(t), b.attached(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			require.NoError(t, a.a.Connect(ctx, eb.addr))
			echo(t, b.stack, eb.addr, 7)
			ping(t, a.stack, ea.addr, eb.addr, 7, "before the move")
			rc, drops := a.current(), r.r.UnknownSourceDrops()

			t0 := time.Now()
			mc.move()
			// An echo is data in the two directions: the relay sends it to the address that it has.
			at := firstEcho(t, a.stack, ea.addr, eb.addr, 7, 20*time.Millisecond, within)
			if !tc.data {
				assert.True(t, at.IsZero(), "data works with only data from the new source")
				assert.Zero(t, tap.psp.Load(), "relay sent data to the new source")
				assert.Greater(t, r.r.UnknownSourceDrops(), drops)
				return
			}
			require.False(t, at.IsZero(), "no data in %v", within)
			require.NotZero(t, tap.psp.Load(), "relay sent no data to the new source")
			t.Logf("Data works again %v after the move.", at.Sub(t0))
			assert.Same(t, rc, a.current(), "the agent has the same relay session")
			assert.Empty(t, a.attach, "the agent attached again")
			assert.Equal(t, dp.Mode_MODE_PSP, a.a.Status().Mode)
		})
	}
}
