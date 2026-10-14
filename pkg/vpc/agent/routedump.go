// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Route is one route of the agent, as GET /debug/routes shows it: the route to
// a peer, the route of a visit, or the default route of a relay session.
type Route struct {
	Dst   string `json:"dst"`             // A prefix, an address, or "default".
	Via   string `json:"via"`             // The peer or the relay.
	Dev   string `json:"dev"`             // "psp" for a peer, else the relay.
	Proto string `json:"proto,omitempty"` // "bfd" for the route to a peer.
	// State is "up" for the route to a peer after BFD Up, else "down". A down
	// route sends nothing: its packets use the default route.
	State  string  `json:"state,omitempty"`
	Src    string  `json:"src,omitempty"`    // The source address of a relay session.
	Metric *uint32 `json:"metric,omitempty"` // The rank of the relay session.
}

// String returns r in the form of ip route.
func (r Route) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s via %s dev %s", r.Dst, r.Via, r.Dev)
	if r.Proto != "" {
		fmt.Fprintf(&b, " proto %s", r.Proto)
	}
	if r.State != "" {
		fmt.Fprintf(&b, " state %s", r.State)
	}
	if r.Src != "" {
		fmt.Fprintf(&b, " src %s", r.Src)
	}
	if r.Metric != nil {
		fmt.Fprintf(&b, " metric %d", *r.Metric)
	}
	return b.String()
}

// routeDst returns pfx as ip route shows it: an address for a host prefix.
func routeDst(pfx netip.Prefix) string {
	if pfx.IsSingleIP() {
		return pfx.Addr().String()
	}
	return pfx.String()
}

// Routes returns the routes of the agent: the routes to the peers, the routes
// of the visits, then the default route of each relay session in rank order.
func (a *Agent) Routes() []Route {
	a.mu.Lock()
	defer a.mu.Unlock()
	conns := a.sessionsLocked(connAttached, connDraining)
	var peers, visits, defaults []Route
	for _, p := range a.peers {
		if p.bp == nil || a.gone(p) {
			continue
		}
		state := "down"
		if p.up {
			state = "up"
		}
		for _, pfx := range p.allPrefixes() {
			peers = append(peers, Route{Dst: routeDst(pfx), Via: p.subject, Dev: "psp", Proto: "bfd", State: state})
		}
	}
	for _, v := range a.visits {
		if rc := v.session(); rc != nil {
			for _, pfx := range v.routes {
				visits = append(visits, Route{Dst: routeDst(pfx), Via: rc.name, Dev: rc.name, Src: rc.self.String()})
			}
		}
	}
	for _, rc := range conns {
		rank := rc.rank
		defaults = append(defaults, Route{Dst: "default", Via: rc.name, Dev: rc.name, Src: rc.self.String(), Metric: &rank})
	}
	byDst := func(x, y Route) int { return cmp.Or(cmp.Compare(x.Dst, y.Dst), cmp.Compare(x.Via, y.Via)) }
	slices.SortFunc(peers, byDst)
	slices.SortFunc(visits, byDst)
	return slices.Concat(peers, visits, defaults)
}

// allPrefixes returns the prefixes of the grants of p and the prefixes that p
// advertises. Agent.mu must be held.
func (p *peer) allPrefixes() []netip.Prefix {
	out := slices.Concat(p.prefixes, p.advertised)
	for _, ps := range p.extra {
		out = append(out, ps...)
	}
	return out
}
