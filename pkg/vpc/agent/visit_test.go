// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// cutRelays returns relay-1 and relay-2 of one mesh, in slot 1 and slot 2 of
// testNetwork, and the function that cuts (true) or heals (false) their path.
func cutRelays(t *testing.T) (w *world, r1, r2 *testRelay, setCut func(bool)) {
	t.Helper()
	w = newWorld(t)
	w.mesh = true
	w.slots = map[string]int{"relay-1": 1, "relay-2": 2}
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

// attach makes ta attach the extra attachment name with the route p.
func attach(t *testing.T, ta *testAgent, name string, p netip.Prefix) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := ta.a.Attach(ctx, AttachmentSpec{Name: name, Routes: []netip.Prefix{p}})
	require.NoError(t, err)
}

// slotOf returns the VPC slot of addr.
func slotOf(addr netip.Addr) netip.Prefix { return netip.PrefixFrom(addr, 88).Masked() }

// waitVisits waits until the last OnVisits of ta gives want.
func (ta *testAgent) waitVisits(t *testing.T, want map[netip.Prefix]netip.Addr, msg string) {
	t.Helper()
	require.Eventually(t, func() bool { return maps.Equal(ta.visitSet(), want) }, meshWait, 10*time.Millisecond,
		"%s: visits %v, want %v", msg, ta.visitSet(), want)
}

// noEcho checks that no echo comes for packets from src to dst:port in 1 s.
func noEcho(t *testing.T, ta *testAgent, src, dst netip.Addr, port uint16, msg string) {
	t.Helper()
	assert.True(t, firstEcho(t, ta.stack, src, dst, port, 200*time.Millisecond, time.Second).IsZero(), "echo from %s to %s: %s", src, dst, msg)
}

// before reports whether the log entry first comes before the entry second in
// history, and both are there.
func before(history []string, first, second func(string) bool) bool {
	i, j := slices.IndexFunc(history, first), slices.IndexFunc(history, second)
	return i >= 0 && j >= 0 && i < j
}

// TestVisitCut checks that in a mesh cut, agents on relay-2 reach relay-1 from
// their visit address, also with a reply from an advertised network.
func TestVisitCut(t *testing.T) {
	t.Parallel()
	w, r1, r2, setCut := cutRelays(t)
	route, far := netip.MustParsePrefix("fd99::/64"), netip.MustParseAddr("fd99::5")
	c := w.agent(t, "c", r1, agentOptions{})
	c1 := c.attached(t).addr
	echo(t, c.stack, c1, 9000)
	b := w.agent(t, "b", r2, agentOptions{routes: []netip.Prefix{route}})
	b.attached(t)
	b1 := b.attached(t).addr
	b.netstack(t, b.binding(), far, false)
	echo(t, b.stack, far, 9000)
	a := w.agent(t, "a", r2, agentOptions{})
	a2 := a.attached(t).addr
	a1 := a.attached(t).addr
	c.attached(t)
	slot1 := slotOf(c1)
	a.hasRoutes(t, slot1, route)
	ping(t, a.stack, a2, c1, 9000, "a2 to c1 with the mesh up")
	assert.Empty(t, a.visitSet(), "visits with the mesh up")

	setCut(true)
	a.waitVisits(t, map[netip.Prefix]netip.Addr{slot1: a1}, "a in the cut")
	b.waitVisits(t, map[netip.Prefix]netip.Addr{slot1: b1}, "b in the cut")
	ping(t, a.stack, a1, c1, 9000, "a1 to c1 in the cut")
	noEcho(t, a, a2, c1, 9000, "a2 to c1 in the cut")
	ping(t, a.stack, a1, far, 9000, "a1 to the advertised network of b in the cut")

	setCut(false)
	a.waitVisits(t, map[netip.Prefix]netip.Addr{}, "a after the heal")
	b.waitVisits(t, map[netip.Prefix]netip.Addr{}, "b after the heal")
	ping(t, a.stack, a1, c1, 9000, "a1 to c1 after the heal")
	ping(t, a.stack, a2, c1, 9000, "a2 to c1 after the heal")
}

// visitBlock makes the next OnVisits with a set of a given size wait.
type visitBlock struct {
	size    atomic.Int32 // It is the size of the set that waits, or -1.
	entered chan chan struct{}
	done    chan struct{} // It closes before the agent stops.
}

// newVisitBlock returns a visitBlock for the agent that start returns.
func newVisitBlock(t *testing.T, start func(onVisits func(map[netip.Prefix]netip.Addr)) *testAgent) (*visitBlock, *testAgent) {
	b := &visitBlock{entered: make(chan chan struct{}, 1), done: make(chan struct{})}
	b.size.Store(-1)
	ta := start(func(v map[netip.Prefix]netip.Addr) {
		if b.size.CompareAndSwap(int32(len(v)), -1) {
			ch := make(chan struct{})
			b.entered <- ch
			select {
			case <-ch:
			case <-b.done:
			}
		}
	})
	t.Cleanup(func() { close(b.done) })
	return b, ta
}

// arm makes the next OnVisits with n entries wait.
func (b *visitBlock) arm(n int) { b.size.Store(int32(n)) }

// wait waits until OnVisits waits, and returns the function that ends the wait.
func (b *visitBlock) wait(t *testing.T, msg string) func() {
	t.Helper()
	var ch chan struct{}
	select {
	case ch = <-b.entered:
	case <-time.After(meshWait):
		t.Fatal(msg)
	}
	var once sync.Once
	release := func() { once.Do(func() { close(ch) }) }
	t.Cleanup(release)
	return release
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

// TestVisitLifecycle follows the visit set of agent a in a mesh cut: the attach,
// the end of each session with its new dial, and the end of Run.
func TestVisitLifecycle(t *testing.T) {
	t.Parallel()
	w, r1, r2, setCut := cutRelays(t)
	// Agent a advertises the network of far, and b on relay-2 answers.
	route, far := netip.MustParsePrefix("fd95::/64"), netip.MustParseAddr("fd95::5")
	blk, a := newVisitBlock(t, func(f func(map[netip.Prefix]netip.Addr)) *testAgent {
		return w.agent(t, "a", r2, agentOptions{routes: []netip.Prefix{route}, onVisits: f})
	})
	a2 := a.attached(t).addr
	a.netstack(t, a.binding(), far, false)
	from := a.tr.Conn.LocalAddr()
	b := w.agent(t, "b", r2, agentOptions{})
	b2 := b.attached(t).addr
	echo(t, b.stack, b2, 9000)
	// The relay-1 sessions of a do not attach until the release.
	var once sync.Once
	hold := w.addrs.hold("a")
	release := func() { once.Do(hold) }
	defer release()
	c := w.agent(t, "c", r1, agentOptions{})
	c1 := c.attached(t).addr
	slot1, slot2 := slotOf(c1), slotOf(a2)
	a.hasRoutes(t, slot1)
	require.Eventually(t, func() bool { return len(r1.sessionConns(from)) == 1 }, 5*time.Second, 10*time.Millisecond, "dial of relay-1")
	first := r1.sessionConns(from)[0]

	setCut(true)
	require.Eventually(t, func() bool { return !slices.Contains(a.routeSet(), slot1) }, 5*time.Second, 10*time.Millisecond,
		"the primary loses the slot of relay-1")
	// The first session does not attach before the cut, and ends at the open timeout.
	require.Eventually(t, func() bool { return first.Context().Err() != nil }, 2*openTimeout, 10*time.Millisecond,
		"end of the first session on relay-1")
	require.Eventually(t, func() bool { return len(r1.sessionConns(from)) == 2 }, 5*time.Second, 10*time.Millisecond,
		"dial of relay-1 in the cut")
	tap := r1.tapOf(r1.sessionConns(from)[1])
	// The reader reads the delta that ends the first table only after the root
	// took the slot, so its Ack shows that the root has the slot before the attach.
	require.Eventually(t, func() bool {
		rev, ok := revOf(tap, slot1)
		return ok && slices.ContainsFunc(tap.acked(), func(r uint64) bool { return r > rev })
	}, 5*time.Second, 10*time.Millisecond, "Ack of the end of the first table before the attach")
	assert.Empty(t, a.visitSet(), "visits before the attach")
	release()
	a1 := a.attached(t).addr
	a.waitVisits(t, map[netip.Prefix]netip.Addr{slot1: a1}, "after the attach")

	// isVisits returns a match for the OnVisits entry of a with the set s.
	isVisits := func(s string) func(string) bool { return func(e string) bool { return e == "visits a "+s } }
	isDetach := func(addr netip.Addr) func(string) bool {
		return func(e string) bool { return e == "detach a "+addr.String() }
	}
	// closeOn makes r close the connections of a.
	closeOn := func(r *testRelay) {
		for _, qc := range r.agentConns(from, true) {
			require.NoError(t, qc.CloseWithError(0, "relay closed the session"))
		}
	}
	steps := []struct {
		name  string
		relay *testRelay   // This relay closes the session of a.
		gone  netip.Addr   // The session of this address ends.
		slot  netip.Prefix // The next visit set has this slot.
		// block makes the first OnVisits wait until the next session attached.
		block bool
	}{
		{name: "visit session ends", relay: r1, gone: a1, slot: slot1},
		// The session on relay-1 becomes the primary, and the new session on
		// relay-2 has the slot of relay-2.
		{name: "primary ends", relay: r2, gone: a2, slot: slot2, block: true},
	}
	var last netip.Addr // It is the address in the last visit set.
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			n := len(a.history())
			if st.block {
				blk.arm(0)
			}
			closeOn(st.relay)
			if st.block {
				done := blk.wait(t, "no OnVisits at the end of the primary")
				require.Eventually(t, func() bool {
					return slices.ContainsFunc(a.a.Status().Connections, func(c ConnStatus) bool {
						return c.Relay == st.relay.addr && c.Address != st.gone
					})
				}, 2*openTimeout, 10*time.Millisecond, "attach on %s while OnVisits waits", st.relay.id)
				done()
			}
			last = a.attached(t).addr
			want := map[netip.Prefix]netip.Addr{st.slot: last}
			a.waitVisits(t, want, "after the next attach")
			h := a.history()[n:]
			assert.True(t, before(h, isVisits("-"), isDetach(st.gone)), "the entry goes before the detach: %v", h)
			assert.True(t, before(h, isDetach(st.gone), isVisits(st.slot.String()+"="+last.String())),
				"the next set comes after the detach: %v", h)
			if st.block {
				// The binding has the last set: the packet from far goes to relay-2.
				ping(t, a.stack, far, b2, 9000, "far to b after the queued changes")
			}
		})
	}

	n := len(a.history())
	a.stop()
	history := a.history()[n:]
	i := slices.IndexFunc(history, func(e string) bool { return strings.HasPrefix(e, "visits a ") })
	require.GreaterOrEqual(t, i, 0, "OnVisits at the end of Run: %v", history)
	assert.Equal(t, "visits a -", history[i], "the set is empty at the end of Run")
	assert.True(t, before(history, isVisits("-"), isDetach(last)), "the set is empty before the detach of %s: %v", last, history)
	assert.Equal(t, 1, len(slices.DeleteFunc(slices.Clone(history), func(e string) bool { return !strings.HasPrefix(e, "visits a ") })),
		"one OnVisits at the end of Run: %v", history)
}

// TestVisitAcks checks that a session reads its next route change only after
// the callbacks of its last change, and that each session waits only for its own.
func TestVisitAcks(t *testing.T) {
	t.Parallel()
	w, r1, r2, setCut := cutRelays(t)
	blk, a := newVisitBlock(t, func(f func(map[netip.Prefix]netip.Addr)) *testAgent {
		return w.agent(t, "a", r2, agentOptions{onVisits: f})
	})
	a.attached(t)
	c := w.agent(t, "c", r1, agentOptions{})
	c1 := c.attached(t).addr
	a1 := a.attached(t).addr
	c.attached(t)
	from := a.tr.Conn.LocalAddr()
	tap1, tap2 := r1.tapOf(r1.agentConns(from, true)[0]), r2.tapOf(r2.agentConns(from, true)[0])

	setCut(true)
	a.waitVisits(t, map[netip.Prefix]netip.Addr{slotOf(c1): a1}, "in the cut")

	// Agent d in slot 3 gives the session of a on relay-1 a change of only the visit set.
	addr3, slot3 := slotAddr(3)
	w.addrs.fix("d", addr3)
	blk.arm(2)
	w.agent(t, "d", r1, agentOptions{}).attached(t)
	release := blk.wait(t, "no OnVisits for slot 3")
	require.Eventually(t, func() bool { return acked(tap1, slot3) }, 5*time.Second, 10*time.Millisecond,
		"Ack of slot 3 while OnVisits waits")
	next := netip.MustParsePrefix("fd97::/64")
	attach(t, c, "y", next)
	require.Eventually(t, func() bool { _, ok := revOf(tap1, next); return ok }, 5*time.Second, 10*time.Millisecond, "next route change on relay-1")
	require.Never(t, func() bool { return acked(tap1, next) }, time.Second, 10*time.Millisecond, "Ack of the next change while OnVisits waits")
	release()
	require.Eventually(t, func() bool { return acked(tap1, next) }, 5*time.Second, 10*time.Millisecond, "Ack of the next change after OnVisits")
	a.waitVisits(t, map[netip.Prefix]netip.Addr{slotOf(c1): a1, slot3: a1}, "with slot 3")

	// At the heal, the primary waits for its OnVisits, and the session on relay-1 does not.
	blk.arm(0)
	setCut(false)
	release = blk.wait(t, "no OnVisits after the heal")
	route := netip.MustParsePrefix("fd98::/64")
	attach(t, c, "x", route)
	require.Eventually(t, func() bool { return acked(tap1, route) }, 5*time.Second, 10*time.Millisecond,
		"Ack on relay-1 while the OnVisits of the primary waits")
	// The Ack of a second change shows that the reader on relay-1 read on.
	second := netip.MustParsePrefix("fd94::/64")
	attach(t, c, "w", second)
	require.Eventually(t, func() bool { return acked(tap1, second) }, 5*time.Second, 10*time.Millisecond,
		"Ack of a second change on relay-1 while the OnVisits of the primary waits")
	require.Eventually(t, func() bool { _, ok := revOf(tap2, route); return ok }, 5*time.Second, 10*time.Millisecond, "route change on relay-2")
	require.Never(t, func() bool { return acked(tap2, route) }, time.Second, 10*time.Millisecond, "Ack on relay-2 while its OnVisits waits")
	release()
	require.Eventually(t, func() bool { return acked(tap2, route) }, 5*time.Second, 10*time.Millisecond, "Ack on relay-2 after OnVisits")
	a.hasRoutes(t, route)
	a.waitVisits(t, map[netip.Prefix]netip.Addr{}, "after the heal")
}
