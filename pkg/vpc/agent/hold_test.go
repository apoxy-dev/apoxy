// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func TestHoldLimits(t *testing.T) {
	cases := []struct {
		name               string
		dsts, pkts, size   int // The packets go to the destinations in turn.
		opens, held, drops int
	}{
		{name: "first packet opens", dsts: 1, pkts: 3, size: 100, opens: 1, held: 3},
		{name: "packets for each destination", dsts: 1, pkts: holdPackets + 2, size: 100, opens: 1, held: holdPackets, drops: 2},
		{name: "bytes for all destinations", dsts: 2, pkts: 65, size: 64 << 10, opens: 2, held: 64, drops: 1},
		{name: "destinations", dsts: holdEntries + 1, pkts: holdEntries + 1, size: 100, opens: holdEntries, held: holdEntries, drops: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var h holds
			now := time.Unix(1000, 0)
			dsts := make([]netip.Addr, tc.dsts)
			for i := range dsts {
				dsts[i] = netip.AddrFrom16([16]byte{0xfd, 14: byte(i >> 8), 15: byte(i)})
			}
			opens := 0
			for i := range tc.pkts {
				open, icmp, _ := h.hold(dsts[i%tc.dsts], make([]byte, tc.size), now)
				assert.False(t, icmp)
				if open {
					opens++
				}
			}
			assert.Equal(t, tc.opens, opens)
			assert.Equal(t, uint64(tc.drops), h.drops.Load())
			held := 0
			for _, dst := range dsts {
				pkts, _ := h.done(dst, nil, now)
				held += len(pkts)
			}
			assert.Equal(t, tc.held, held)
			assert.Zero(t, h.bytes)
		})
	}
}

func TestHoldWait(t *testing.T) {
	other := errors.New("relay session closed")
	notFound := rpc.Errorf(rpc.NotFound, "no route")
	denied := rpc.Errorf(rpc.PermissionDenied, "permit denies")
	cases := []struct {
		name   string
		errs   []error // The results of the opens in a row. Nil is a success.
		wait   time.Duration
		denied bool
	}{
		{name: "not found", errs: []error{notFound}, wait: notFoundWait},
		{name: "no route", errs: []error{psp.ErrNoRoute}, wait: notFoundWait},
		{name: "no peer", errs: []error{errNoPeer}, wait: notFoundWait},
		{name: "denied", errs: []error{denied}, wait: deniedWait, denied: true},
		{name: "other error", errs: []error{other}, wait: minRetry},
		{name: "other errors in a row", errs: []error{other, other, other, other}, wait: 8 * time.Second},
		{name: "other errors to the limit", errs: slices.Repeat([]error{other}, 8), wait: maxRetry},
		{name: "success resets", errs: []error{other, other, nil, other}, wait: minRetry},
		{name: "denied after not found", errs: []error{notFound, denied}, wait: deniedWait, denied: true},
	}
	dst := netip.MustParseAddr("fd61:706f:7879:12:3400:2::1")
	pkt := make([]byte, 100)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var h holds
			now := time.Unix(1000, 0)
			for i, err := range tc.errs {
				open, _, _ := h.hold(dst, pkt, now)
				require.True(t, open, "open %d", i)
				pkts, d := h.done(dst, err, now)
				assert.Len(t, pkts, 1)
				assert.Equal(t, err != nil && rpc.CodeOf(err) == rpc.PermissionDenied, d)
				if err != nil {
					now = now.Add(h.failed[dst].wait)
				} else {
					assert.NotContains(t, h.failed, dst)
				}
			}
			start := now.Add(-tc.wait)
			drops := h.drops.Load()
			steps := []struct {
				at         time.Duration
				open, icmp bool
			}{
				{at: time.Millisecond},
				{at: icmpInterval, icmp: true},
				{at: icmpInterval + time.Millisecond},
				{at: tc.wait - time.Nanosecond, icmp: tc.wait > 2*icmpInterval},
				{at: tc.wait, open: true},
			}
			for _, s := range steps {
				// The steps after the end of a short wait do not apply.
				if s.at >= tc.wait && !s.open {
					continue
				}
				open, icmp, d := h.hold(dst, pkt, start.Add(s.at))
				assert.Equal(t, s.open, open, "open at %v", s.at)
				assert.Equal(t, s.icmp, icmp, "ICMP at %v", s.at)
				assert.Equal(t, s.icmp && tc.denied, d, "denied at %v", s.at)
				if !s.open {
					drops++
				}
			}
			assert.Equal(t, drops, h.drops.Load())

			h.sweep(start.Add(2 * tc.wait))
			assert.Contains(t, h.failed, dst)
			h.sweep(start.Add(2*tc.wait + time.Nanosecond))
			assert.NotContains(t, h.failed, dst)
		})
	}
}

// TestOnce checks that the opens for one key run once, and that other keys
// do not wait.
func TestOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var h holds
		k1, k2 := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
		release, want := make(chan struct{}), errors.New("dial failed")
		var runs atomic.Int32
		open := func() error {
			runs.Add(1)
			<-release
			return want
		}
		var wg sync.WaitGroup
		errs := make([]error, 4)
		for i := range errs {
			wg.Go(func() { errs[i] = h.once(k1, open) })
		}
		synctest.Wait()
		assert.Equal(t, int32(1), runs.Load())
		assert.NoError(t, h.once(k2, func() error { return nil }))
		close(release)
		wg.Wait()
		assert.Equal(t, int32(1), runs.Load())
		for _, err := range errs {
			assert.Equal(t, want, err)
		}
		assert.Empty(t, h.opening)
	})
}

// sendOnce sends msg once from src to dst:port and waits for the echo.
func sendOnce(s *stack.Stack, src, dst netip.Addr, port uint16, msg string) error {
	c, err := gonet.DialUDP(s, fullAddr(src, 0), fullAddr(dst, port), ipv6.ProtocolNumber)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != msg {
		return errors.New("wrong echo")
	}
	return nil
}

// send sends msg once from src to dst:port.
func send(t *testing.T, s *stack.Stack, src, dst netip.Addr, port uint16, msg string) {
	t.Helper()
	c, err := gonet.DialUDP(s, fullAddr(src, 0), fullAddr(dst, port), ipv6.ProtocolNumber)
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Write([]byte(msg))
	require.NoError(t, err)
}

// unreachableIn returns the ICMPv6 destination unreachable errors that the
// netstack of ta got.
func unreachableIn(ta *testAgent) uint64 {
	return ta.stack.Stats().ICMP.V6.PacketsReceived.DstUnreachable.Value()
}

// TestFirstPacket checks that the first packets to an address of a peer and
// to a route of the peer open one peer session, and that they arrive.
func TestFirstPacket(t *testing.T) {
	cases := []struct {
		name string
		mode TransportMode
	}{{"PSP", TransportPSP}, {"QUIC", TransportQUIC}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			route, far := netip.MustParsePrefix("fd99::/64"), netip.MustParseAddr("fd99::5")
			a := w.agent(t, "a", r, agentOptions{mode: tc.mode})
			b := w.agent(t, "b", r, agentOptions{mode: tc.mode, routes: []netip.Prefix{route}})
			ea, eb := a.attached(t), b.attached(t)
			b.netstack(t, b.binding(), far, false)
			echo(t, b.stack, eb.addr, 9000)
			echo(t, b.stack, far, 9001)
			require.Eventually(t, func() bool { return slices.Contains(a.routeSet(), route) },
				5*time.Second, 10*time.Millisecond)

			var wg sync.WaitGroup
			var errB, errFar error
			wg.Go(func() { errB = sendOnce(a.stack, ea.addr, eb.addr, 9000, "to b") })
			wg.Go(func() { errFar = sendOnce(a.stack, ea.addr, far, 9001, "to a route of b") })
			wg.Wait()
			require.NoError(t, errB)
			require.NoError(t, errFar)
			assert.Equal(t, 1, peerCount(a.a))
			assert.Zero(t, a.a.Stats().HoldDrops)
			assert.Zero(t, b.a.Stats().HoldDrops)
		})
	}
}

// TestNoPeer checks that packets to a destination that no peer session can
// get drop, and that the sender gets an ICMP error. gVisor does not give
// ICMPv6 codes 3 and 1 to sockets, so the test counts the ICMP errors.
func TestNoPeer(t *testing.T) {
	cases := []struct {
		name   string
		dst    func(eb attachEvent) netip.Addr
		permit relay.Permit
	}{
		{name: "not found", dst: func(attachEvent) netip.Addr { return netip.MustParseAddr("fd61:706f:7879:12:3400:99::1") }},
		{name: "outside the VPC", dst: func(attachEvent) netip.Addr { return netip.MustParseAddr("fd97::1") }},
		{
			name:   "denied",
			dst:    func(eb attachEvent) netip.Addr { return eb.addr },
			permit: func(relay.VPCKey, string, relay.VPCKey, netip.Addr) bool { return false },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			a, b := w.agent(t, "a", r, agentOptions{}), w.agent(t, "b", r, agentOptions{})
			ea, eb := a.attached(t), b.attached(t)
			if tc.permit != nil {
				r.r.SetPermit(tc.permit)
			}
			send(t, a.stack, ea.addr, tc.dst(eb), 9000, "no peer")
			require.Eventually(t, func() bool { return unreachableIn(a) == 1 }, 5*time.Second, 10*time.Millisecond)
			assert.Equal(t, uint64(1), a.a.Stats().HoldDrops)
			assert.Zero(t, peerCount(a.a))
		})
	}
}

// TestLateRoutes checks that a route that comes after the peer session opens
// gets packets, and that its remove stops them.
func TestLateRoutes(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	a, b := w.agent(t, "a", r, agentOptions{}), w.agent(t, "b", r, agentOptions{})
	ea, eb := a.attached(t), b.attached(t)
	late := netip.MustParseAddr("fd98::5")
	b.netstack(t, b.binding(), late, false)
	echo(t, b.stack, late, 9000)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, a.a.Connect(ctx, eb.addr))

	a.a.mu.Lock()
	rc := a.a.rc
	a.a.mu.Unlock()
	a.a.routeMu.Lock()
	id := rc.routes.origins[eb.prefixes[0]]
	a.a.routeMu.Unlock()
	require.NotEmpty(t, id)
	routes := []*dp.Route{
		{Prefix: "fd98::/64", Origin: id},
		{Prefix: "::/0", Origin: id},
		{Prefix: "fd61:706f:7879:12:3400:99::/96", Origin: id},
	}
	a.a.applyRoutes(rc, &dp.RouteDelta{Add: routes})
	ping(t, a.stack, ea.addr, late, 9000, "late route")
	a.a.mu.Lock()
	for _, p := range a.a.peers {
		assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("fd98::/64")}, p.advertised)
	}
	a.a.mu.Unlock()

	a.a.applyRoutes(rc, &dp.RouteDelta{Remove: routes[:1]})
	send(t, a.stack, ea.addr, late, 9000, "removed route")
	require.Eventually(t, func() bool { return unreachableIn(a) == 1 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, uint64(1), a.a.Stats().HoldDrops)
	assert.Equal(t, 1, peerCount(a.a))
}
