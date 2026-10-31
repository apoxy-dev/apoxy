// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// meshWait is the longest wait for a change of the mesh: an idle timeout of 5 s,
// and a dial of a lost member after up to 15 s.
const meshWait = 30 * time.Second

// relayCut drops the packets that a relay sends to the sockets of another relay
// while it is on.
type relayCut struct {
	on atomic.Bool
	to []netip.AddrPort
}

// cutConn is a relay socket with a relayCut.
type cutConn struct {
	net.PacketConn
	c *relayCut
}

func (c cutConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if ua, ok := addr.(*net.UDPAddr); ok && c.c.on.Load() && slices.Contains(c.c.to, unmap(ua.AddrPort())) {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

// cutRelays returns relay-1 and relay-2 of one mesh, in slot 1 and slot 2 of testNetwork, relay-1 with
// its own pool in w.pools, and the function that cuts (true) or heals (false) their path.
func cutRelays(t *testing.T) (w *world, r1, r2 *testRelay, setCut func(bool)) {
	t.Helper()
	w = newWorld(t)
	w.mesh = true
	w.slots = map[string]int{"relay-1": 1, "relay-2": 2}
	w.pools = map[string]*fakeAddresses{"relay-1": {Addresses: &vpctest.Addresses{}}}
	q1, p1, q2, p2 := loopback(t), loopback(t), loopback(t), loopback(t)
	addrOf := func(c *net.UDPConn) netip.AddrPort { return unmap(c.LocalAddr().(*net.UDPAddr).AddrPort()) }
	c1 := &relayCut{to: []netip.AddrPort{addrOf(q2), addrOf(p2)}}
	c2 := &relayCut{to: []netip.AddrPort{addrOf(q1), addrOf(p1)}}
	r1 = w.relayOn(t, "relay-1", cutConn{q1, c1}, cutConn{p1, c1})
	r2 = w.relayOn(t, "relay-2", cutConn{q2, c2}, cutConn{p2, c2})
	joinMesh(t, r1, r2)
	return w, r1, r2, func(on bool) {
		t.Helper()
		c1.on.Store(on)
		c2.on.Store(on)
		require.Eventually(t, func() bool { return r1.r.Up("relay-2") != on && r2.r.Up("relay-1") != on }, meshWait, 10*time.Millisecond,
			"mesh up %v", !on)
	}
}

// twoSessions gives opts a session on relay-2, with rank 0 as relay-1 answers late, and one on
// relay-1. first waits for the attach on relay-2 and returns its address.
func twoSessions(t *testing.T, r1, r2 *testRelay, opts agentOptions) (agentOptions, func(ta *testAgent) netip.Addr) {
	slow := &slowConn{}
	slow.set(r1, 150*time.Millisecond)
	// Both relays answer in the wait of the choice, so the agent dials each one time.
	opts.slow, opts.rttChoice, opts.rttWait = slow, true, 5*time.Second
	opts.sessions, opts.relays = 2, []identity.Relay{r2.ref(), r1.ref()}
	return opts, func(ta *testAgent) netip.Addr {
		t.Helper()
		addr := ta.attached(t).addr
		_, slot2 := slotAddr(2)
		require.Equal(t, slot2, slotOf(addr), "the first attach is on relay-2")
		require.True(t, slices.ContainsFunc(ta.a.Status().Connections, func(c ConnStatus) bool {
			return c.Relay == r2.addr && c.Rank == 0
		}), "the session on relay-2 has rank 0")
		slow.set(r1, 0)
		return addr
	}
}

// slotOf returns the VPC slot of addr.
func slotOf(addr netip.Addr) netip.Prefix { return netip.PrefixFrom(addr, 88).Masked() }

// noEcho checks that no echo comes for packets from src to dst:port in 1 s.
func noEcho(t *testing.T, ta *testAgent, src, dst netip.Addr, port uint16, msg string) {
	t.Helper()
	assert.True(t, firstEcho(t, ta.stack, src, dst, port, 200*time.Millisecond, time.Second).IsZero(), "echo from %s to %s: %s", src, dst, msg)
}

// revOf returns the revision of the RouteDelta of tap that adds p.
func revOf(tap *sessionTap, p netip.Prefix) (uint64, bool) {
	for _, m := range tap.responses() {
		d := m.GetRouteDelta()
		if slices.ContainsFunc(d.GetAdd(), func(r *dp.Route) bool { return r.GetPrefix() == p.String() }) {
			return d.GetRev(), true
		}
	}
	return 0, false
}

// acked reports whether the agent sent the Ack of the RouteDelta of tap that adds p.
func acked(tap *sessionTap, p netip.Prefix) bool {
	rev, ok := revOf(tap, p)
	return ok && slices.Contains(tap.acked(), rev)
}

// TestMeshCut checks that in a mesh cut agent a keeps its two sessions and dials no relay, and that the
// traffic between relay-1 and relay-2 stops until the heal while the traffic on one relay goes on.
func TestMeshCut(t *testing.T) {
	t.Parallel()
	w, r1, r2, setCut := cutRelays(t)
	// far is in the network that a advertises.
	route, far := netip.MustParsePrefix("fd99::/64"), netip.MustParseAddr("fd99::5")
	c := w.agent(t, "c", r1, agentOptions{})
	c1 := c.attached(t).addr
	echo(t, c.stack, c1, 9000)
	d := w.agent(t, "d", r2, agentOptions{})
	d2 := d.attached(t).addr
	echo(t, d.stack, d2, 9000)
	opts, first := twoSessions(t, r1, r2, agentOptions{routes: []netip.Prefix{route}})
	a := w.agent(t, "a", r2, opts)
	a2 := first(a)
	a1 := a.attached(t).addr
	a.netstack(t, a.binding(), far, false)
	echo(t, a.stack, a2, 9000)
	slot1 := slotOf(c1)
	a.hasRoutes(t, slot1)
	c.hasRoutes(t, route)
	ping(t, a.stack, a2, c1, 9000, "a2 to c1 with the mesh up")
	ping(t, a.stack, far, c1, 9000, "the network of a to c1 with the mesh up")
	conns := connsOf(a)
	require.Equal(t, []string{
		fmt.Sprintf("%s %s rank 0", r2.addr, a2), fmt.Sprintf("%s %s rank 1", r1.addr, a1),
	}, conns, "the sessions of a")
	dials1, dials2 := a.dials(r1), a.dials(r2)
	same := func() bool {
		return a.dials(r1) == dials1 && a.dials(r2) == dials2 && slices.Equal(connsOf(a), conns)
	}

	setCut(true)
	require.Eventually(t, func() bool { return !slices.Contains(a.routeSet(), slot1) }, meshWait, 10*time.Millisecond,
		"the primary of a loses the slot of relay-1")
	noEcho(t, a, a2, c1, 9000, "a2 to c1 in the cut")
	// The binding sends a packet from a source that no session has on the primary.
	noEcho(t, a, far, c1, 9000, "the network of a to c1 in the cut")
	// A packet from a session address goes on that session.
	ping(t, a.stack, a1, c1, 9000, "a1 to c1 on relay-1 in the cut")
	ping(t, a.stack, a2, d2, 9000, "a2 to d2 on relay-2 in the cut")
	ping(t, d.stack, d2, a2, 9000, "d2 to a2 on relay-2 in the cut")
	require.Never(t, func() bool { return !same() }, quietWait, 20*time.Millisecond,
		"a dialed a relay or changed a session in the cut: %v", connsOf(a))

	setCut(false)
	require.Eventually(t, func() bool { return slices.Contains(a.routeSet(), slot1) }, meshWait, 10*time.Millisecond,
		"the primary of a has the slot of relay-1 after the heal")
	ping(t, a.stack, a2, c1, 9000, "a2 to c1 after the heal")
	ping(t, a.stack, far, c1, 9000, "the network of a to c1 after the heal")
	assert.True(t, same(), "a dialed a relay or changed a session: %v", connsOf(a))
}

// connsOf returns the relay, the address and the rank of each connection of ta.
func connsOf(ta *testAgent) []string {
	var out []string
	for _, c := range ta.a.Status().Connections {
		out = append(out, fmt.Sprintf("%s %s rank %d", c.Relay, c.Address, c.Rank))
	}
	return out
}
