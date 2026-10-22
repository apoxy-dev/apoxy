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

func pfx(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestRouteTable(t *testing.T) {
	rt := func(prefix, origin string) *dp.Route { return &dp.Route{Prefix: prefix, Origin: origin} }
	// via is a route whose relay is id at addrs.
	via := func(prefix, origin, id string, addrs ...string) *dp.Route {
		return &dp.Route{Prefix: prefix, Origin: origin, Relay: &dp.RelayRef{Id: id, Addresses: addrs}}
	}
	add := func(prefix, origin string) routeChange {
		return routeChange{netip.MustParsePrefix(prefix), routeInfo{origin: origin}, true}
	}
	rm := func(prefix, origin string) routeChange {
		return routeChange{netip.MustParsePrefix(prefix), routeInfo{origin: origin}, false}
	}
	// on is c with the relay id at addrs.
	on := func(c routeChange, id string, addrs ...string) routeChange {
		c.relay, c.addrs = id, addrs
		return c
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
		{name: "slot route and its relay", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{via("fd61:706f:7879:1:200::/88", "rb", "rb", "192.0.2.2:443")}},
				[]routeChange{on(add("fd61:706f:7879:1:200::/88", "rb"), "rb", "192.0.2.2:443")}, false},
			{&dp.RouteDelta{Add: []*dp.Route{via("fd61:706f:7879:1:200::/88", "rb", "rb", "192.0.2.2:443")}}, nil, false},
		}},
		{name: "same origin and another relay", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{via("2001:db8:1::/64", "b", "rb", "192.0.2.2:443")}},
				[]routeChange{on(add("2001:db8:1::/64", "b"), "rb", "192.0.2.2:443")}, false},
			{&dp.RouteDelta{Add: []*dp.Route{via("2001:db8:1::/64", "b", "rc", "192.0.2.3:443")}},
				[]routeChange{on(rm("2001:db8:1::/64", "b"), "rb", "192.0.2.2:443"), on(add("2001:db8:1::/64", "b"), "rc", "192.0.2.3:443")}, false},
		}},
		{name: "same relay at other addresses", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{via("2001:db8:1::/64", "b", "rb", "192.0.2.2:443")}},
				[]routeChange{on(add("2001:db8:1::/64", "b"), "rb", "192.0.2.2:443")}, false},
			{&dp.RouteDelta{Add: []*dp.Route{via("2001:db8:1::/64", "b", "rb", "192.0.2.9:443")}},
				[]routeChange{on(rm("2001:db8:1::/64", "b"), "rb", "192.0.2.2:443"), on(add("2001:db8:1::/64", "b"), "rb", "192.0.2.9:443")}, false},
		}},
		{name: "remove with no relay", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{via("2001:db8:1::/64", "b", "rb")}}, []routeChange{on(add("2001:db8:1::/64", "b"), "rb")}, false},
			{&dp.RouteDelta{Remove: []*dp.Route{rt("2001:db8:1::/64", "b")}}, []routeChange{on(rm("2001:db8:1::/64", "b"), "rb")}, false},
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
		{"new relay", []routeChange{{p, routeInfo{origin: "b", relay: "rb"}, false}, {p, routeInfo{origin: "b", relay: "rc"}, true}}, nil, nil},
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
