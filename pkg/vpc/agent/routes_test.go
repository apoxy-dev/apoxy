// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func TestRouteTable(t *testing.T) {
	rt := func(prefix, origin string) *dp.Route { return &dp.Route{Prefix: prefix, Origin: origin} }
	pfx := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	type step struct {
		delta       *dp.RouteDelta
		add, remove []netip.Prefix
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{name: "add and remove", steps: []step{
			{delta: &dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "b"), rt("fd00:2::/96", "b")}}, add: pfx("10.0.0.0/8", "fd00:2::/96")},
			{delta: &dp.RouteDelta{Remove: []*dp.Route{rt("10.0.0.0/8", "b")}}, remove: pfx("10.0.0.0/8")},
		}},
		{name: "routes of self", steps: []step{
			{delta: &dp.RouteDelta{Add: []*dp.Route{rt("fd00:1::/96", "self"), rt("10.1.0.0/16", "self")}}},
			{delta: &dp.RouteDelta{Remove: []*dp.Route{rt("fd00:1::/96", "self")}}},
		}},
		{name: "new origin", steps: []step{
			{delta: &dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "b")}}, add: pfx("10.0.0.0/8")},
			{delta: &dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "c")}}},
			{delta: &dp.RouteDelta{Remove: []*dp.Route{rt("10.0.0.0/8", "b")}}},
			{delta: &dp.RouteDelta{Remove: []*dp.Route{rt("10.0.0.0/8", "c")}}, remove: pfx("10.0.0.0/8")},
		}},
		{name: "new origin in one delta", steps: []step{
			{delta: &dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "b")}}, add: pfx("10.0.0.0/8")},
			{delta: &dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "c")}, Remove: []*dp.Route{rt("10.0.0.0/8", "b")}}},
		}},
		{name: "repeated and unknown routes", steps: []step{
			{delta: &dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.1/8", "b"), rt("10.0.0.0/8", "b"), rt("bad", "b")}}, add: pfx("10.0.0.0/8")},
			{delta: &dp.RouteDelta{Remove: []*dp.Route{rt("10.0.0.0/8", "c"), rt("192.0.2.0/24", "b")}}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tbl routeTable
			for i, s := range tc.steps {
				add, remove := tbl.apply(s.delta, "self")
				assert.ElementsMatch(t, s.add, add, "step %d add", i)
				assert.ElementsMatch(t, s.remove, remove, "step %d remove", i)
			}
		})
	}
}

// TestOnRoutes checks that OnRoutes has the prefixes of the other attachments
// and follows the new session after a reconnect.
func TestOnRoutes(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	routeB, routeC := netip.MustParsePrefix("10.9.0.0/16"), netip.MustParsePrefix("fd99::/64")
	a := w.agent(t, "a", r, agentOptions{routes: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}})
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
