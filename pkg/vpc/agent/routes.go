// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"net/netip"
	"slices"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// Routable reports whether a prefix that another attachment advertises can get a
// route: it is not a default route and does not overlap the VPC network vpc.
func Routable(p, vpc netip.Prefix) bool {
	return p.Bits() > 0 && !p.Overlaps(vpc)
}

// routeTable is the prefixes of the other attachments on one relay session,
// to their origin and the relay of the origin. A prefix has one origin in a VPC.
type routeTable struct {
	routes map[netip.Prefix]routeInfo
	// synced is set at the empty RouteDelta that ends the first table.
	synced bool
}

// routeInfo is the origin of a route and the relay that has the origin.
type routeInfo struct {
	origin string
	relay  string   // Relay ID from Route.relay. Empty when the Route names none.
	addrs  []string // Addresses of the relay. Empty when the Route gives none.
}

// same reports whether i and o have the same origin and relay.
func (i routeInfo) same(o routeInfo) bool {
	return i.origin == o.origin && i.relay == o.relay && slices.Equal(i.addrs, o.addrs)
}

// routeChange is a prefix that an origin gets or loses.
type routeChange struct {
	prefix netip.Prefix
	routeInfo
	add bool
}

// apply applies d, skips the routes of the attachments of this agent, and
// returns the changes. A prefix that moves to a new origin or relay is a
// remove and an add. An empty delta ends the first table.
func (t *routeTable) apply(d *dp.RouteDelta, own func(origin string) bool) []routeChange {
	if t.routes == nil {
		t.routes = map[netip.Prefix]routeInfo{}
	}
	if len(d.GetAdd())+len(d.GetRemove()) == 0 {
		t.synced = true
	}
	var out []routeChange
	for _, r := range d.GetRemove() {
		if p, ok := parseRoute(r, own); ok {
			if old, had := t.routes[p]; had && old.origin == r.GetOrigin() {
				delete(t.routes, p)
				out = append(out, routeChange{p, old, false})
			}
		}
	}
	for _, r := range d.GetAdd() {
		p, ok := parseRoute(r, own)
		if !ok {
			continue
		}
		info := routeInfo{origin: r.GetOrigin(), relay: r.GetRelay().GetId()}
		if info.relay != "" {
			info.addrs = slices.Clone(r.GetRelay().GetAddresses())
		}
		old, had := t.routes[p]
		if had && old.same(info) {
			continue
		}
		if had {
			out = append(out, routeChange{p, old, false})
		}
		t.routes[p] = info
		out = append(out, routeChange{p, info, true})
	}
	return out
}

// drop removes the routes of origin and returns the changes.
func (t *routeTable) drop(origin string) []routeChange {
	var out []routeChange
	for p, info := range t.routes {
		if info.origin == origin {
			delete(t.routes, p)
			out = append(out, routeChange{p, info, false})
		}
	}
	return out
}

func parseRoute(r *dp.Route, own func(string) bool) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(r.GetPrefix())
	if err != nil || r.GetOrigin() == "" || own(r.GetOrigin()) {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// prefixChanges returns the prefixes that changes add to the table and the
// prefixes that they remove from it.
func prefixChanges(changes []routeChange) (add, remove []netip.Prefix) {
	n := map[netip.Prefix]int{}
	for _, c := range changes {
		if c.add {
			n[c.prefix]++
		} else {
			n[c.prefix]--
		}
	}
	for p, v := range n {
		switch {
		case v > 0:
			add = append(add, p)
		case v < 0:
			remove = append(remove, p)
		}
	}
	return add, remove
}
