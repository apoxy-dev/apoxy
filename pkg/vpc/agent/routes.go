// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"log/slog"
	"maps"
	"net/netip"
	"slices"

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

// apply applies d, skips the routes of the attachment self, and returns the
// changes. A prefix that moves to a new origin is a remove and an add.
func (t *routeTable) apply(d *dp.RouteDelta, self string) []routeChange {
	if t.origins == nil {
		t.origins = map[netip.Prefix]string{}
	}
	t.synced = true
	var out []routeChange
	for _, r := range d.GetRemove() {
		if p, ok := parseRoute(r, self); ok && t.origins[p] == r.GetOrigin() {
			delete(t.origins, p)
			out = append(out, routeChange{p, r.GetOrigin(), false})
		}
	}
	for _, r := range d.GetAdd() {
		p, ok := parseRoute(r, self)
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

// drop removes the routes of origin.
func (t *routeTable) drop(origin string) {
	maps.DeleteFunc(t.origins, func(_ netip.Prefix, o string) bool { return o == origin })
}

func parseRoute(r *dp.Route, self string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(r.GetPrefix())
	if err != nil || r.GetOrigin() == "" || r.GetOrigin() == self {
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

// applyRoutes applies a route change of rc to the binding, and gives OnRoutes
// the change if OnRoutes has the routes of rc.
func (a *Agent) applyRoutes(rc *relayConn, d *dp.RouteDelta) {
	a.routeMu.Lock()
	defer a.routeMu.Unlock()
	first := !rc.routes.synced
	changes := rc.routes.apply(d, rc.attachmentID)
	a.bindRoutes(rc, changes)
	switch {
	case a.routesOf != rc:
	case first:
		a.syncRoutes()
	default:
		a.report(prefixChanges(changes))
	}
}

// setAttachment sets the attachment and the addresses of rc. The routes that
// came for it before the attach leave the route table of rc.
func (a *Agent) setAttachment(rc *relayConn, id string, prefixes []netip.Prefix) {
	a.routeMu.Lock()
	defer a.routeMu.Unlock()
	rc.attachmentID, rc.prefixes, rc.self = id, prefixes, overlayAddr(prefixes)
	rc.routes.drop(id)
}

// useRoutes makes OnRoutes follow the routes of rc. Until the first RouteDelta
// of rc, OnRoutes keeps the routes of the session before.
func (a *Agent) useRoutes(rc *relayConn) {
	a.routeMu.Lock()
	defer a.routeMu.Unlock()
	a.routesOf = rc
	if rc.routes.synced {
		a.syncRoutes()
	}
}

// syncRoutes gives OnRoutes the change from the prefixes that it has to the
// routes of a.routesOf. a.routeMu must be held.
func (a *Agent) syncRoutes() {
	want := a.routesOf.routes.origins
	var add, remove []netip.Prefix
	for p := range want {
		if !a.reported[p] {
			add = append(add, p)
		}
	}
	for p := range a.reported {
		if _, ok := want[p]; !ok {
			remove = append(remove, p)
		}
	}
	a.report(add, remove)
}

// report gives a change to OnRoutes. a.routeMu must be held.
func (a *Agent) report(add, remove []netip.Prefix) {
	if len(add)+len(remove) == 0 {
		return
	}
	if a.reported == nil {
		a.reported = map[netip.Prefix]bool{}
	}
	for _, p := range remove {
		delete(a.reported, p)
	}
	for _, p := range add {
		a.reported[p] = true
	}
	if a.cfg.OnRoutes != nil {
		a.cfg.OnRoutes(add, remove)
	}
}

// routeAdvertised routes the prefixes that the attachment of p advertises to p
// in the binding. Call it after p opens.
func (a *Agent) routeAdvertised(p *peer) {
	a.routeMu.Lock()
	defer a.routeMu.Unlock()
	vpc := tunnet.NetworkPrefixOf(p.rc.self)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.peers[p.conn] != p || p.bp == nil {
		return
	}
	for pfx, origin := range p.rc.routes.origins {
		if origin == p.attachmentID() {
			a.addAdvertised(p, pfx, vpc)
		}
	}
}

// bindRoutes gives route changes of rc to the binding, for the open peers of
// their origins. a.routeMu must be held.
func (a *Agent) bindRoutes(rc *relayConn, changes []routeChange) {
	vpc := tunnet.NetworkPrefixOf(rc.self)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range changes {
		for _, p := range a.peers {
			if p.rc != rc || p.bp == nil || p.attachmentID() != c.origin {
				continue
			}
			if c.add {
				a.addAdvertised(p, c.prefix, vpc)
			} else {
				a.removeAdvertised(p, c.prefix)
			}
		}
	}
}

// addAdvertised routes pfx to p if pfx is routable. a.mu must be held.
func (a *Agent) addAdvertised(p *peer, pfx, vpc netip.Prefix) {
	if !Routable(pfx, vpc) || slices.Contains(p.advertised, pfx) || slices.Contains(p.prefixes, pfx) {
		return
	}
	if err := a.bind.AddRoute(pfx, p.bp); err != nil {
		slog.Warn("Failed to route an advertised prefix to a peer", "peer", p.subject, "prefix", pfx, "error", err)
		return
	}
	p.advertised = append(p.advertised, pfx)
}

// removeAdvertised removes the route of pfx to p. a.mu must be held.
func (a *Agent) removeAdvertised(p *peer, pfx netip.Prefix) {
	i := slices.Index(p.advertised, pfx)
	if i < 0 {
		return
	}
	p.advertised = slices.Delete(p.advertised, i, i+1)
	if p.quic {
		a.unrouteQUIC(p, []netip.Prefix{pfx})
	} else {
		a.bind.RemoveRoute(pfx, p.bp)
	}
}

// peerAddr returns the overlay address of the attachment that packets to dst
// go to on rc: the origin of the longest route with dst, or dst in the VPC
// network. It reports false when no attachment can get packets to dst.
func (a *Agent) peerAddr(rc *relayConn, dst netip.Addr) (netip.Addr, bool) {
	a.routeMu.Lock()
	defer a.routeMu.Unlock()
	vpc := tunnet.NetworkPrefixOf(rc.self)
	best := netip.Prefix{}
	for p := range rc.routes.origins {
		if p.Contains(dst) && p.Bits() > best.Bits() && (Routable(p, vpc) || inNetwork(p, vpc)) {
			best = p
		}
	}
	if best.IsValid() {
		// The lowest prefix of the origin in the VPC network gives its address.
		origin, own := rc.routes.origins[best], netip.Prefix{}
		for p, o := range rc.routes.origins {
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

// inNetwork reports whether p is a part of the VPC network vpc, such as the
// addresses of an attachment.
func inNetwork(p, vpc netip.Prefix) bool {
	return p.Bits() > vpc.Bits() && vpc.Contains(p.Addr())
}
