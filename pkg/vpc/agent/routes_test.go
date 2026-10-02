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
	add := func(prefix, origin string) routeChange {
		return routeChange{netip.MustParsePrefix(prefix), origin, true}
	}
	rm := func(prefix, origin string) routeChange {
		return routeChange{netip.MustParsePrefix(prefix), origin, false}
	}
	type step struct {
		delta *dp.RouteDelta
		want  []routeChange
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{name: "add and remove", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "b"), rt("fd00:2::/96", "b")}}, []routeChange{add("10.0.0.0/8", "b"), add("fd00:2::/96", "b")}},
			{&dp.RouteDelta{Remove: []*dp.Route{rt("10.0.0.0/8", "b")}}, []routeChange{rm("10.0.0.0/8", "b")}},
		}},
		{name: "routes of self", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{rt("fd00:1::/96", "self"), rt("10.1.0.0/16", "self")}}, nil},
			{&dp.RouteDelta{Remove: []*dp.Route{rt("fd00:1::/96", "self")}}, nil},
		}},
		{name: "routes of another attachment of self", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{rt("fd00:3::/96", "self-2"), rt("10.2.0.0/16", "self-2"), rt("fd00:2::/96", "b")}}, []routeChange{add("fd00:2::/96", "b")}},
			{&dp.RouteDelta{Remove: []*dp.Route{rt("fd00:3::/96", "self-2"), rt("fd00:2::/96", "b")}}, []routeChange{rm("fd00:2::/96", "b")}},
		}},
		{name: "new origin", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "b")}}, []routeChange{add("10.0.0.0/8", "b")}},
			{&dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "c")}}, []routeChange{rm("10.0.0.0/8", "b"), add("10.0.0.0/8", "c")}},
			{&dp.RouteDelta{Remove: []*dp.Route{rt("10.0.0.0/8", "b")}}, nil},
			{&dp.RouteDelta{Remove: []*dp.Route{rt("10.0.0.0/8", "c")}}, []routeChange{rm("10.0.0.0/8", "c")}},
		}},
		{name: "new origin in one delta", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "b")}}, []routeChange{add("10.0.0.0/8", "b")}},
			{&dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.0/8", "c")}, Remove: []*dp.Route{rt("10.0.0.0/8", "b")}},
				[]routeChange{rm("10.0.0.0/8", "b"), add("10.0.0.0/8", "c")}},
		}},
		{name: "repeated and unknown routes", steps: []step{
			{&dp.RouteDelta{Add: []*dp.Route{rt("10.0.0.1/8", "b"), rt("10.0.0.0/8", "b"), rt("bad", "b")}}, []routeChange{add("10.0.0.0/8", "b")}},
			{&dp.RouteDelta{Remove: []*dp.Route{rt("10.0.0.0/8", "c"), rt("192.0.2.0/24", "b")}}, nil},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tbl routeTable
			for i, s := range tc.steps {
				own := func(origin string) bool { return origin == "self" || origin == "self-2" }
				assert.Equal(t, s.want, tbl.apply(s.delta, own), "step %d", i)
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
		{"add", []routeChange{{p, "b", true}}, pfx("10.0.0.0/8"), nil},
		{"remove", []routeChange{{p, "b", false}}, nil, pfx("10.0.0.0/8")},
		{"new origin", []routeChange{{p, "b", false}, {p, "c", true}}, nil, nil},
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

func TestPeerAddr(t *testing.T) {
	rc := &relayConn{self: netip.MustParseAddr("fd61:706f:7879:12:3400:1::1"), routes: routeTable{origins: map[netip.Prefix]string{
		netip.MustParsePrefix("fd61:706f:7879:12:3400:2::/96"): "b",
		netip.MustParsePrefix("10.9.0.0/16"):                   "b",
		netip.MustParsePrefix("10.9.9.0/24"):                   "c",
		netip.MustParsePrefix("fd61:706f:7879:12:3400:3::/96"): "c",
		netip.MustParsePrefix("0.0.0.0/0"):                     "c",
		netip.MustParsePrefix("10.7.0.0/16"):                   "d",
	}}}
	b, c := netip.MustParseAddr("fd61:706f:7879:12:3400:2::1"), netip.MustParseAddr("fd61:706f:7879:12:3400:3::1")
	cases := []struct {
		name string
		dst  string
		want netip.Addr
		ok   bool
	}{
		{"peer address", "fd61:706f:7879:12:3400:2::1", b, true},
		{"other address in the peer /96", "fd61:706f:7879:12:3400:2::5", b, true},
		{"route of a peer", "10.9.0.5", b, true},
		{"longest route", "10.9.9.5", c, true},
		{"unknown address in the VPC", "fd61:706f:7879:12:3400:9::1", netip.MustParseAddr("fd61:706f:7879:12:3400:9::1"), true},
		{"only a default route", "192.0.2.1", netip.MustParseAddr("192.0.2.1"), false},
		{"origin with no address", "10.7.0.1", netip.MustParseAddr("10.7.0.1"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := (&Agent{}).peerAddr(rc, netip.MustParseAddr(tc.dst))
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.ok, ok)
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
