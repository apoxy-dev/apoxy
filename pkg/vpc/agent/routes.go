// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"net/netip"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// Routable reports whether a prefix that another attachment advertises can get a
// route: it is not a default route and does not overlap the VPC network vpc.
func Routable(p, vpc netip.Prefix) bool {
	return p.Bits() > 0 && !p.Overlaps(vpc)
}

// routeTable is the prefixes of the other attachments on one relay session,
// to their origin. A prefix has one origin in a VPC.
type routeTable struct {
	origins map[netip.Prefix]string
	synced  bool // A RouteDelta came.
}

// routeChange is a prefix that an origin gets or loses.
type routeChange struct {
	prefix netip.Prefix
	origin string
	add    bool
}

// apply applies d, skips the routes of the attachments of this agent, and
// returns the changes. A prefix that moves to a new origin is a remove and an add.
func (t *routeTable) apply(d *dp.RouteDelta, own func(origin string) bool) []routeChange {
	if t.origins == nil {
		t.origins = map[netip.Prefix]string{}
	}
	t.synced = true
	var out []routeChange
	for _, r := range d.GetRemove() {
		if p, ok := parseRoute(r, own); ok && t.origins[p] == r.GetOrigin() {
			delete(t.origins, p)
			out = append(out, routeChange{p, r.GetOrigin(), false})
		}
	}
	for _, r := range d.GetAdd() {
		p, ok := parseRoute(r, own)
		if !ok {
			continue
		}
		old, had := t.origins[p]
		if had && old == r.GetOrigin() {
			continue
		}
		if had {
			out = append(out, routeChange{p, old, false})
		}
		t.origins[p] = r.GetOrigin()
		out = append(out, routeChange{p, r.GetOrigin(), true})
	}
	return out
}

// drop removes the routes of origin and returns their prefixes.
func (t *routeTable) drop(origin string) []netip.Prefix {
	var out []netip.Prefix
	for p, o := range t.origins {
		if o == origin {
			delete(t.origins, p)
			out = append(out, p)
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

// peerAddr returns the overlay address that gets the packets to dst: the
// origin of the longest route, or dst itself in the VPC network of self.
func (t *routeTable) peerAddr(dst, self netip.Addr) (netip.Addr, bool) {
	vpc := tunnet.NetworkPrefixOf(self)
	if best := t.bestRoute(dst, vpc); best.IsValid() {
		// The lowest prefix of the origin in the VPC network gives its address.
		origin, own := t.origins[best], netip.Prefix{}
		for p, o := range t.origins {
			if o == origin && inNetwork(p, vpc) && (!own.IsValid() || p.Addr().Less(own.Addr())) {
				own = p
			}
		}
		if own.IsValid() {
			return overlayAddr([]netip.Prefix{own}), true
		}
	}
	return dst, vpc.Contains(dst)
}

// bestRoute returns the longest prefix of the table that covers dst, or none.
func (t *routeTable) bestRoute(dst netip.Addr, vpc netip.Prefix) netip.Prefix {
	best := netip.Prefix{}
	for p := range t.origins {
		if p.Contains(dst) && p.Bits() > best.Bits() && (Routable(p, vpc) || inNetwork(p, vpc)) {
			best = p
		}
	}
	return best
}

// routeOf returns the prefix of the route that covers dst, or else the prefix
// of dst alone.
func (t *routeTable) routeOf(dst, self netip.Addr) netip.Prefix {
	if best := t.bestRoute(dst, tunnet.NetworkPrefixOf(self)); best.IsValid() {
		return best
	}
	return netip.PrefixFrom(dst, dst.BitLen())
}

// inNetwork reports whether p is a part of the VPC network vpc, such as the
// addresses of an attachment.
func inNetwork(p, vpc netip.Prefix) bool {
	return p.Bits() > vpc.Bits() && vpc.Contains(p.Addr())
}
