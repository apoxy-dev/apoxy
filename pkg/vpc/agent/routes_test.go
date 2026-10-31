// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func pfx(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestRouteTable(t *testing.T) {
	rt := func(prefix, origin string) *dp.Route { return &dp.Route{Prefix: prefix, Origin: origin} }
	add := func(prefix, origin string) routeChange {
		return routeChange{netip.MustParsePrefix(prefix), routeInfo{origin: origin}, true}
	}
	rm := func(prefix, origin string) routeChange {
		return routeChange{netip.MustParsePrefix(prefix), routeInfo{origin: origin}, false}
	}
	type step struct {
		delta  *dp.RouteDelta
		want   []routeChange
		synced bool // The table is synced after the step.
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{name: "add and remove", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "b"), rt("fd00:2::/96", "b")}}, []routeChange{add("10.0.0.0/8", "b"), add("fd00:2::/96", "b")}, false},
			{&dp.RouteDelta{Remove: []*dp.Route{rt("10.0.0.0/8", "b")}}, []routeChange{rm("10.0.0.0/8", "b")}, false},
		}},
		{name: "routes of self", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{rt("fd00:1::/96", "self"), rt("10.1.0.0/16", "self")}}, nil, false},
			{&dp.RouteDelta{Remove: []*dp.Route{rt("fd00:1::/96", "self")}}, nil, false},
		}},
		{name: "routes of another attachment of self", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{rt("fd00:3::/96", "self-2"), rt("10.2.0.0/16", "self-2"), rt("fd00:2::/96", "b")}}, []routeChange{add("fd00:2::/96", "b")}, false},
			{&dp.RouteDelta{Remove: []*dp.Route{rt("fd00:3::/96", "self-2"), rt("fd00:2::/96", "b")}}, []routeChange{rm("fd00:2::/96", "b")}, false},
		}},
		{name: "new origin", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "b")}}, []routeChange{add("10.0.0.0/8", "b")}, false},
			{&dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "c")}}, []routeChange{rm("10.0.0.0/8", "b"), add("10.0.0.0/8", "c")}, false},
			{&dp.RouteDelta{Remove: []*dp.Route{rt("10.0.0.0/8", "b")}}, nil, false},
			{&dp.RouteDelta{Remove: []*dp.Route{rt("10.0.0.0/8", "c")}}, []routeChange{rm("10.0.0.0/8", "c")}, false},
		}},
		{name: "new origin in one delta", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "b")}}, []routeChange{add("10.0.0.0/8", "b")}, false},
			{&dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "c")}, Remove: []*dp.Route{rt("10.0.0.0/8", "b")}},
				[]routeChange{rm("10.0.0.0/8", "b"), add("10.0.0.0/8", "c")}, false},
		}},
		{name: "repeated and unknown routes", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.1/8", "b"), rt("10.0.0.0/8", "b"), rt("bad", "b")}}, []routeChange{add("10.0.0.0/8", "b")}, false},
			{&dp.RouteDelta{Remove: []*dp.Route{rt("10.0.0.0/8", "c"), rt("192.0.2.0/24", "b")}}, nil, false},
		}},
		{name: "first table in parts", steps: []step{
			{&dp.RouteDelta{Rev: 1, Add: []*dp.Route{rt("2001:db8:1::/64", "b")}}, []routeChange{add("2001:db8:1::/64", "b")}, false},
			{&dp.RouteDelta{Rev: 2, Add: []*dp.Route{rt("2001:db8:2::/64", "c")}}, []routeChange{add("2001:db8:2::/64", "c")}, false},
			{&dp.RouteDelta{Rev: 3}, nil, true},
			{&dp.RouteDelta{Rev: 4, Remove: []*dp.Route{rt("2001:db8:1::/64", "b")}}, []routeChange{rm("2001:db8:1::/64", "b")}, true},
		}},
		{name: "empty first table", steps: []step{
			{&dp.RouteDelta{Rev: 1}, nil, true},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tbl routeTable
			for i, s := range tc.steps {
				own := func(origin string) bool { return origin == "self" || origin == "self-2" }
				assert.Equal(t, s.want, tbl.apply(s.delta, own), "step %d", i)
				assert.Equal(t, s.synced, tbl.synced, "step %d: synced", i)
			}
		})
	}
}

func TestPrefixChanges(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.0/8")
	cases := []struct {
		name        string
		changes     []routeChange
		add, remove []netip.Prefix
	}{
		{"add", []routeChange{{p, routeInfo{origin: "b"}, true}}, pfx("10.0.0.0/8"), nil},
		{"remove", []routeChange{{p, routeInfo{origin: "b"}, false}}, nil, pfx("10.0.0.0/8")},
		{"new origin", []routeChange{{p, routeInfo{origin: "b"}, false}, {p, routeInfo{origin: "c"}, true}}, nil, nil},
		{"none", nil, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			add, remove := prefixChanges(tc.changes)
			assert.Equal(t, tc.add, add)
			assert.Equal(t, tc.remove, remove)
		})
	}
}

func TestRoutable(t *testing.T) {
	vpc := netip.MustParsePrefix("fd61:706f:7879:12:3400::/72")
	cases := []struct {
		prefix string
		vpc    netip.Prefix
		want   bool
	}{
		{"10.9.0.0/16", vpc, true},
		{"fd99::/64", vpc, true},
		{"0.0.0.0/0", vpc, false},
		{"::/0", vpc, false},
		{"fd61:706f:7879:12:3456:7800::/96", vpc, false},
		{"fd61:706f:7879::/48", vpc, false},
		{"fd61:706f:7879:12:3500::/72", vpc, true},
		{"10.9.0.0/16", netip.Prefix{}, true},
		{"::/0", netip.Prefix{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.prefix, func(t *testing.T) {
			assert.Equal(t, tc.want, Routable(netip.MustParsePrefix(tc.prefix), tc.vpc))
		})
	}
}

// TestOnRoutes checks that OnRoutes has the prefixes of the other attachments
// and follows the new session after a reconnect.
func TestOnRoutes(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	routeB, routeC := netip.MustParsePrefix("fd98::/64"), netip.MustParsePrefix("fd99::/64")
	a := w.agent(t, "a", r, agentOptions{routes: []netip.Prefix{netip.MustParsePrefix("fd97::/64")}})
	a.attached(t)
	b := w.agent(t, "b", r, agentOptions{routes: []netip.Prefix{routeB}})
	eb := b.attached(t)
	c := w.agent(t, "c", r, agentOptions{routes: []netip.Prefix{routeC}})
	ec := c.attached(t)

	wait := func(want ...netip.Prefix) {
		t.Helper()
		require.Eventually(t, func() bool {
			got := a.routeSet()
			return len(got) == len(want) && !slices.ContainsFunc(want, func(p netip.Prefix) bool { return !slices.Contains(got, p) })
		}, 5*time.Second, 10*time.Millisecond, "routes of a: %v, want %v", a.routeSet(), want)
	}
	wait(eb.prefixes[0], routeB, ec.prefixes[0], routeC)

	a.reconnect()
	a.attached(t)
	b.stop()
	// Only the new session of a sees b leave.
	wait(ec.prefixes[0], routeC)
	c.stop()
	wait()
}

// TestDNS checks that the agent has the DNS config of the VPC.
func TestDNS(t *testing.T) {
	w := newWorld(t)
	w.dns, w.search = []string{"fd00::53", "10.0.0.53"}, []string{"vpc.internal"}
	r := w.relay(t, "relay-1")
	a := w.agent(t, "a", r, agentOptions{})
	a.attached(t)
	servers, search := a.a.DNS()
	assert.Equal(t, w.dns, servers)
	assert.Equal(t, w.search, search)
}

// routesWait makes the first OnRoutes after arm wait until release.
type routesWait struct {
	armed   atomic.Bool
	entered chan struct{}
	done    chan struct{}
	once    sync.Once
}

func newRoutesWait() *routesWait {
	return &routesWait{entered: make(chan struct{}, 1), done: make(chan struct{})}
}

// onRoutes is the agentOptions.onRoutes of the agent that waits.
func (w *routesWait) onRoutes(_, _ []netip.Prefix) {
	if w.armed.CompareAndSwap(true, false) {
		w.entered <- struct{}{}
		<-w.done
	}
}

func (w *routesWait) arm() { w.armed.Store(true) }

// wait waits until OnRoutes waits.
func (w *routesWait) wait(t *testing.T, msg string) {
	t.Helper()
	select {
	case <-w.entered:
	case <-time.After(10 * time.Second):
		t.Fatal(msg)
	}
}

func (w *routesWait) release() { w.once.Do(func() { close(w.done) }) }

// attach makes ta attach the extra attachment name with the route p.
func attach(t *testing.T, ta *testAgent, name string, p netip.Prefix) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := ta.a.Attach(ctx, AttachmentSpec{Name: name, Routes: []netip.Prefix{p}})
	require.NoError(t, err)
}

// TestRouteAcks checks that a session sends the Ack of a route change at once, and reads its next change only after
// the OnRoutes of the last one returned. A session that is not the primary has no OnRoutes, so it reads on.
func TestRouteAcks(t *testing.T) {
	cases := []struct {
		name string
		// twoSessions gives a a second session, on a relay with a mesh to the relay of the primary.
		twoSessions bool
	}{
		{name: "one session"},
		{name: "two sessions", twoSessions: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hold := newRoutesWait()
			defer hold.release()
			// tapP is the session of the primary of a, tapO its other session. b attaches on peerRelay.
			var (
				w          *world
				a          *testAgent
				peerRelay  *testRelay
				tapP, tapO *sessionTap
			)
			if tc.twoSessions {
				var r1, r2 *testRelay
				w, r1, r2 = meshRelays(t)
				a = w.agent(t, "a", r1, agentOptions{sessions: 2, relays: []identity.Relay{r1.ref(), r2.ref()}, onRoutes: hold.onRoutes})
				a.attached(t)
				a.attached(t)
				// The agent shuffles its relays, so the primary can be on either.
				primary, other := r1, r2
				if a.current().addr == r2.addr {
					primary, other = r2, r1
				}
				from := a.tr.Conn.LocalAddr()
				tapP, tapO = primary.tapOf(primary.agentConns(from, true)[0]), other.tapOf(other.agentConns(from, true)[0])
				peerRelay = other
			} else {
				w = newWorld(t)
				peerRelay = w.relay(t, "relay-1")
				a = w.agent(t, "a", peerRelay, agentOptions{onRoutes: hold.onRoutes})
				a.attached(t)
				tapP = peerRelay.tapOf(peerRelay.agentConns(a.tr.Conn.LocalAddr(), true)[0])
			}
			b := w.agent(t, "b", peerRelay, agentOptions{})
			a.hasRoutes(t, b.attached(t).prefixes[0])
			q1, q2 := netip.MustParsePrefix("fd91::/64"), netip.MustParsePrefix("fd92::/64")
			eventually := func(cond func() bool, msg string) {
				t.Helper()
				require.Eventually(t, cond, 5*time.Second, 10*time.Millisecond, msg)
			}

			hold.arm()
			attach(t, b, "q1", q1)
			hold.wait(t, "no OnRoutes for q1")
			eventually(func() bool { return acked(tapP, q1) }, "Ack of q1 on the primary while its OnRoutes waits")
			if tapO != nil {
				eventually(func() bool { return acked(tapO, q1) }, "Ack of q1 on the other session")
			}
			attach(t, b, "q2", q2)
			eventually(func() bool { _, ok := revOf(tapP, q2); return ok }, "the relay of the primary sends q2")
			if tapO != nil {
				// q2 comes after the Ack of q1, in a new delta, so its Ack shows that the other session read on.
				eventually(func() bool { return acked(tapO, q2) }, "Ack of q2 on the other session while the OnRoutes of the primary waits")
				rev1, _ := revOf(tapO, q1)
				rev2, _ := revOf(tapO, q2)
				require.NotEqual(t, rev1, rev2, "q1 and q2 in one delta on the other session")
			}
			require.Never(t, func() bool { return acked(tapP, q2) }, time.Second, 10*time.Millisecond,
				"Ack of q2 on the primary while the OnRoutes of q1 waits")
			hold.release()
			eventually(func() bool { return acked(tapP, q2) }, "Ack of q2 on the primary after the OnRoutes of q1")
			a.hasRoutes(t, q1, q2)
		})
	}
}
