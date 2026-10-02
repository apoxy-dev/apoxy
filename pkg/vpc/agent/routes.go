// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"net/netip"
	"slices"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// routeTable is the prefixes of the other attachments on one relay session,
// to their origin. A prefix has one origin in a VPC.
type routeTable struct {
	origins map[netip.Prefix]string
	synced  bool // A RouteDelta came.
}

// apply applies d and skips the routes of the attachment self. It returns the
// prefixes that the table gets and the prefixes that it loses.
func (t *routeTable) apply(d *dp.RouteDelta, self string) (add, remove []netip.Prefix) {
	if t.origins == nil {
		t.origins = map[netip.Prefix]string{}
	}
	t.synced = true
	for _, r := range d.GetRemove() {
		if p, ok := parseRoute(r, self); ok && t.origins[p] == r.GetOrigin() {
			delete(t.origins, p)
			remove = append(remove, p)
		}
	}
	for _, r := range d.GetAdd() {
		p, ok := parseRoute(r, self)
		if !ok {
			continue
		}
		if _, ok := t.origins[p]; !ok {
			// A prefix that moves to a new origin in one delta does not change.
			if i := slices.Index(remove, p); i >= 0 {
				remove = slices.Delete(remove, i, i+1)
			} else {
				add = append(add, p)
			}
		}
		t.origins[p] = r.GetOrigin()
	}
	return add, remove
}

func parseRoute(r *dp.Route, self string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(r.GetPrefix())
	if err != nil || r.GetOrigin() == "" || r.GetOrigin() == self {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// applyRoutes applies a route change of rc, and gives OnRoutes the change if
// OnRoutes has the routes of rc.
func (a *Agent) applyRoutes(rc *relayConn, d *dp.RouteDelta) {
	a.routeMu.Lock()
	defer a.routeMu.Unlock()
	first := !rc.routes.synced
	add, remove := rc.routes.apply(d, rc.claims.GetAttachmentId())
	switch {
	case a.routesOf != rc:
	case first:
		a.syncRoutes()
	default:
		a.report(add, remove)
	}
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
