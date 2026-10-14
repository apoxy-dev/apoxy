// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// agentOn starts agent name with one session on each of the first sessions
// relays, and returns it with its attached sessions in rank order.
func (w *world) agentOn(t *testing.T, name string, opts agentOptions, sessions int, relays ...*testRelay) (*testAgent, []*relayConn) {
	t.Helper()
	for _, r := range relays {
		opts.relays = append(opts.relays, r.ref())
	}
	opts.sessions = sessions
	a := w.agent(t, name, relays[0], opts)
	for range min(sessions, len(relays)) {
		a.attached(t)
	}
	return a, a.a.sessions(connAttached)
}

// ranks returns the ranks of the attached and the draining sessions of a.
func ranks(a *testAgent) (attached, draining []uint32) {
	for _, c := range a.a.Status().Connections {
		if c.Draining {
			draining = append(draining, c.Rank)
		} else {
			attached = append(attached, c.Rank)
		}
	}
	return attached, draining
}

// peersOn returns the number of open peer sessions of a on rc, from Status.
func peersOn(a *testAgent, rc *relayConn) int {
	for _, c := range a.a.Status().Connections {
		if c.Address == rc.self {
			return c.Peers
		}
	}
	return 0
}

// serveTCP answers the bytes of each TCP connection to addr:port.
func serveTCP(t *testing.T, s *stack.Stack, addr netip.Addr, port uint16) {
	t.Helper()
	ln, err := gonet.ListenTCP(s, *fullAddr(addr, port), ipv6.ProtocolNumber)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
}

// roundTrip writes msg on c and reads the answer of serveTCP.
func roundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	roundTripIn(t, c, msg, 5*time.Second)
}

// roundTripIn is roundTrip with the wait for the answer.
func roundTripIn(t *testing.T, c net.Conn, msg string, wait time.Duration) {
	t.Helper()
	require.NoError(t, c.SetDeadline(time.Now().Add(wait)))
	_, err := c.Write([]byte(msg))
	require.NoError(t, err, msg)
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(c, buf)
	require.NoError(t, err, msg)
	assert.Equal(t, msg, string(buf))
}

// localOf returns the local address of the TCP connection c.
func localOf(c net.Conn) netip.Addr {
	return c.LocalAddr().(*net.TCPAddr).AddrPort().Addr()
}

// TestRoutesAfterAttach checks that routes from the relay before the end of the
// Attach call reach OnRoutes only after OnAttach of the session.
func TestRoutesAfterAttach(t *testing.T) {
	cases := []struct {
		name     string
		sessions int
	}{
		{name: "one session", sessions: 1},
		{name: "two sessions", sessions: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, r1, r2 := meshRelays(t)
			var want []netip.Prefix
			for i, r := range []*testRelay{r1, r2, r1, r2} {
				o := w.agent(t, fmt.Sprintf("other-%d", i), r, agentOptions{})
				want = append(want, o.attached(t).prefixes...)
			}
			a, _ := w.agentOn(t, "a", agentOptions{}, tc.sessions, r1, r2)
			a.hasRoutes(t, want...)
		})
	}
}

// TestSessions checks that the agent attaches on Config.Sessions relays, with
// an address, a rank and each extra attachment on each session.
func TestSessions(t *testing.T) {
	cases := []struct {
		name             string
		sessions, relays int
		want             int
	}{
		{name: "one session of two relays", sessions: 1, relays: 2, want: 1},
		{name: "two sessions", sessions: 2, relays: 2, want: 2},
		{name: "more sessions than relays", sessions: 3, relays: 2, want: 2},
		{name: "three sessions", sessions: 3, relays: 3, want: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			var relays []*testRelay
			for _, id := range []string{"relay-1", "relay-2", "relay-3"}[:tc.relays] {
				relays = append(relays, w.relay(t, id))
			}
			a, rcs := w.agentOn(t, "a", agentOptions{}, tc.sessions, relays...)
			require.Len(t, rcs, tc.want)
			require.Never(t, func() bool { return len(a.attach) > 0 }, 300*time.Millisecond, 20*time.Millisecond, "one session for each relay")

			conns := a.a.Status().Connections
			require.Len(t, conns, tc.want)
			var addrs []netip.Addr
			for i, c := range conns {
				assert.Equal(t, relays[i].addr, c.Relay, "the relays have the order of the list")
				assert.Equal(t, uint32(i), c.Rank)
				assert.Equal(t, rcs[i].self, c.Address)
				assert.False(t, slices.Contains(addrs, c.Address), "each session has its own address")
				addrs = append(addrs, c.Address)
			}
			assert.Same(t, rcs[0], a.current(), "the session with rank 0 has the default address")
			for i, c := range conns {
				deprecated := func() bool { return slices.Contains(a.events("a"), "deprecate a "+c.Address.String()) }
				if i == 0 {
					assert.False(t, deprecated(), "address of rank 0 is deprecated")
				} else {
					require.Eventually(t, deprecated, 5*time.Second, 10*time.Millisecond, "address of rank %d is deprecated", i)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			x, err := a.a.Attach(ctx, AttachmentSpec{Name: "x-1"})
			require.NoError(t, err)
			assert.Equal(t, relays[0].addr, x.Relay, "Attach returns the attachment on the session with the lowest rank")
			lives := func() []string {
				return slices.DeleteFunc(a.events("x-1"), func(e string) bool { return !strings.HasPrefix(e, "attach ") && !strings.HasPrefix(e, "detach ") })
			}
			require.Eventually(t, func() bool { return len(lives()) == tc.want }, 5*time.Second, 10*time.Millisecond)
			var base, extra []string
			for _, at := range a.a.Attachments() {
				if at.Base {
					base = append(base, at.Relay)
				} else {
					extra = append(extra, at.Relay)
				}
				assert.True(t, at.Address.IsValid())
			}
			var want []string
			for _, c := range conns {
				want = append(want, c.Relay)
			}
			assert.Equal(t, want, base, "the attachment of Config is on each session")
			assert.Equal(t, want, extra, "the extra attachment is on each session")
			require.NoError(t, a.a.Detach(ctx, "x-1"))
			assert.Len(t, lives(), 2*tc.want, "OnDetach runs for each session")
		})
	}
}

// TestSendRule checks which relay session carries a packet: the session that has
// the source address, or else the session with the lowest rank that does not drain.
func TestSendRule(t *testing.T) {
	w, r1, r2 := meshRelays(t)
	route, far := netip.MustParsePrefix("fd99::/64"), netip.MustParseAddr("fd99::5")
	a, rcs := w.agentOn(t, "a", agentOptions{routes: []netip.Prefix{route}}, 2, r1, r2)
	b := w.agent(t, "b", r1, agentOptions{})
	eb := b.attached(t)
	echo(t, b.stack, eb.addr, 9000)
	a.netstack(t, a.binding(), far, false)
	a.hasRoutes(t, eb.prefixes[0])
	b.hasRoutes(t, route)
	// Each relay session of a has the route to b.
	for _, rc := range rcs {
		require.Eventually(t, func() bool { _, ok := a.a.peerAddr(rc, eb.addr); return ok }, 10*time.Second, 10*time.Millisecond)
	}

	cases := []struct {
		name string
		src  netip.Addr
		want []int // Peer sessions of a on each relay session after the packet.
	}{
		{name: "source that no session has", src: far, want: []int{1, 0}},
		{name: "source of the second session", src: rcs[1].self, want: []int{1, 1}},
		{name: "source of the first session", src: rcs[0].self, want: []int{1, 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ping(t, a.stack, tc.src, eb.addr, 9000, tc.name)
			// The packet starts the peer session after it went on the default route.
			require.Eventually(t, func() bool { return slices.Equal(tc.want, []int{peersOn(a, rcs[0]), peersOn(a, rcs[1])}) },
				5*time.Second, 10*time.Millisecond, "peer sessions of a on each relay session")
		})
	}

	// When the relay of the first session drains, the second session carries
	// the packets with a source that no session has.
	drain(t, r1, nil)
	require.Eventually(t, func() bool { return a.current() == rcs[1] }, 5*time.Second, 10*time.Millisecond)
	a.a.mu.Lock()
	var second *peer
	for _, p := range a.a.peers {
		if p.rc == rcs[1] {
			second = p
		}
	}
	a.a.mu.Unlock()
	require.NotNil(t, second)
	require.Eventually(t, func() bool { return routeTo(b.a, rcs[1].self).State == "up" }, 10*time.Second, 10*time.Millisecond,
		"route of b to the second session after BFD Up")
	before := rxCountOf(second.bp).packets
	ping(t, a.stack, far, eb.addr, 9000, "after the drain")
	assert.Greater(t, rxCountOf(second.bp).packets, before, "the answer comes on the second session")
}

// TestPeersOfEachSession checks that two agents with two relay sessions each
// keep one peer session for each pair of their addresses.
func TestPeersOfEachSession(t *testing.T) {
	w, r1, r2 := meshRelays(t)
	a, ra := w.agentOn(t, "a", agentOptions{}, 2, r1, r2)
	b, rb := w.agentOn(t, "b", agentOptions{}, 2, r1, r2)
	for i, rc := range rb {
		echo(t, b.stack, rc.self, uint16(9000+i))
	}
	for _, rc := range ra {
		for _, peer := range rb {
			require.Eventually(t, func() bool { _, ok := a.a.peerAddr(rc, peer.self); return ok }, 10*time.Second, 10*time.Millisecond)
		}
	}
	for _, from := range ra {
		for i, to := range rb {
			ping(t, a.stack, from.self, to.self, uint16(9000+i), from.self.String()+" to "+to.self.String())
		}
	}
	open := func() bool {
		return peersOn(a, ra[0]) == 2 && peersOn(a, ra[1]) == 2 && peersOn(b, rb[0]) == 2 && peersOn(b, rb[1]) == 2
	}
	// The packets start the peer sessions after they went on the default route.
	require.Eventually(t, open, 5*time.Second, 10*time.Millisecond, "each relay session has a peer session to each address of the peer")
	require.Never(t, func() bool { return !open() }, 500*time.Millisecond, 20*time.Millisecond, "the peer sessions of one agent stay open together")
	for _, from := range ra {
		for i, to := range rb {
			ping(t, a.stack, from.self, to.self, uint16(9000+i), "again")
		}
	}
}

// TestDrainKeepsStream checks that a TCP stream carries data until its draining
// relay closes the session, and a new one uses the new address.
func TestDrainKeepsStream(t *testing.T) {
	w, r1, r2 := meshRelays(t)
	a := w.agent(t, "a", r1, agentOptions{tcp: true, relays: []identity.Relay{r1.ref(), r2.ref()}})
	b := w.agent(t, "b", r2, agentOptions{tcp: true})
	ea, eb := a.attached(t), b.attached(t)
	serveTCP(t, b.stack, eb.addr, 9000)
	a.hasRoutes(t, eb.prefixes[0])
	require.Equal(t, dp.Reach_REACH_TRUNK, a.resolved(t, eb.addr).GetReach())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dial := func() net.Conn {
		c, err := gonet.DialContextTCP(ctx, a.stack, *fullAddr(eb.addr, 9000), ipv6.ProtocolNumber)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	old := dial()
	require.Equal(t, ea.addr, localOf(old))
	roundTrip(t, old, "before the drain")

	prev := a.current()
	end := drain(t, r1, nil)
	moved := a.attached(t)
	require.Equal(t, r2.addr, a.current().addr)
	roundTrip(t, old, "on the address of the draining relay")
	next := dial()
	assert.Equal(t, moved.addr, localOf(next), "a new connection uses the address of the relay that does not drain")
	roundTrip(t, next, "on the address of the new session")
	roundTrip(t, old, "on the address of the draining relay again")
	require.Never(t, func() bool { return len(a.attach) > 0 }, 500*time.Millisecond, 20*time.Millisecond,
		"the agent opens one session after the Drain")
	assert.Equal(t, 2, len(a.a.Status().Connections))
	roundTrip(t, old, "until the relay closes the session")

	end()
	closedByDrain(t, prev)
	roundTrip(t, next, "after the drain")
}

// TestNextRank checks that the session that the agent opens after a drain or
// a lost session gets the next rank, and that the other sessions stay.
func TestNextRank(t *testing.T) {
	cases := []struct {
		name  string
		drain bool
		// Ranks of the sessions after the new session attaches.
		attached, draining []uint32
	}{
		{name: "relay drains", drain: true, attached: []uint32{1, 2}, draining: []uint32{0}},
		{name: "session lost", attached: []uint32{1, 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r1, r2, r3 := w.relay(t, "relay-1"), w.relay(t, "relay-2"), w.relay(t, "relay-3")
			a, rcs := w.agentOn(t, "a", agentOptions{}, 2, r1, r2, r3)
			// Agent b stays on relay-1, which gives it no alternate.
			b := w.agent(t, "b", r1, agentOptions{})
			eb := b.attached(t)
			echo(t, b.stack, eb.addr, 9000)
			ping(t, a.stack, rcs[0].self, eb.addr, 9000, "before")
			require.Eventually(t, func() bool { return peersOn(a, rcs[0]) == 1 }, 5*time.Second, 10*time.Millisecond, "peer session before")

			if tc.drain {
				drain(t, r1, nil)
			} else {
				// The relay of the lost session takes no new session.
				r1.stopAccept()
				_ = rcs[0].qc.CloseWithError(0, "lost")
			}
			a.attached(t)
			attached, draining := ranks(a)
			assert.Equal(t, tc.attached, attached)
			assert.Equal(t, tc.draining, draining)
			assert.Same(t, rcs[1], a.current(), "the session with the lowest rank that does not drain has the default address")
			assert.NoError(t, rcs[1].qc.Context().Err(), "the other session stays")
			require.Never(t, func() bool { return len(a.attach) > 0 }, 300*time.Millisecond, 20*time.Millisecond, "the agent opens one session")
			if tc.drain {
				assert.Equal(t, 1, peersOn(a, rcs[0]), "the peer session of the draining session stays")
				ping(t, a.stack, rcs[0].self, eb.addr, 9000, "on the draining session")
			}
		})
	}
}

// TestAttachFails checks that a relay with no answer to Attach closes only its
// own session, and that the agent attaches again with backoff.
func TestAttachFails(t *testing.T) {
	w := newWorld(t)
	r1, r2 := w.relay(t, "relay-1"), w.relay(t, "relay-2")
	a := w.agent(t, "a", r1, agentOptions{})
	a.attached(t)
	prev := a.current()
	// The Attach calls of the agent get no address, so they end at their time limit.
	release := w.addrs.hold("a")
	drain(t, r1, []*dp.RelayRef{{Id: r2.id, Addresses: []string{r2.addr}}})
	require.Eventually(t, func() bool { now, _ := w.addrs.held(); return now == 1 }, 5*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { now, _ := w.addrs.held(); return now == 0 }, openTimeout+5*time.Second, 50*time.Millisecond,
		"the Attach call ends at its time limit")
	assert.NoError(t, prev.qc.Context().Err(), "the other session stays open")
	assert.Same(t, prev, a.current())
	release()
	a.attached(t)
	assert.Equal(t, r2.addr, a.current().addr)
	assert.NoError(t, prev.qc.Context().Err(), "the other session stays open")
}

// TestAddressAgain checks that the OnDetach of an address comes before the
// next OnAttach of it, when the relay gives the next session the same address.
func TestAddressAgain(t *testing.T) {
	w := newWorld(t)
	w.addrs.sameAgain()
	r := w.relay(t, "relay-1")
	a := w.agent(t, "a", r, agentOptions{})
	first := a.attached(t)
	_ = a.current().qc.CloseWithError(0, "test ends the session")
	second := a.attached(t)
	require.Equal(t, first.addr, second.addr, "the relay gave the same address")
	addr := first.addr.String()
	require.Equal(t, []string{"attach a " + addr, "detach a " + addr, "attach a " + addr}, a.events("a"))
}
