// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Route is one route of the agent, as GET /debug/routes shows it: the route of
// a visit, or the default route of a relay session.
type Route struct {
	Dst    string  `json:"dst"`              // A prefix, an address, or "default".
	Via    string  `json:"via"`              // The relay.
	Dev    string  `json:"dev"`              // The relay.
	Src    string  `json:"src,omitempty"`    // The source address of a relay session.
	Metric *uint32 `json:"metric,omitempty"` // The rank of the relay session.
}

// String returns r in the form of ip route.
func (r Route) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s via %s dev %s", r.Dst, r.Via, r.Dev)
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

// Routes returns the routes of the agent: the routes of the visits, then the
// default route of each relay session in rank order.
func (a *Agent) Routes() []Route {
	s := a.snap.Load()
	visits := slices.Clone(s.visits)
	slices.SortFunc(visits, func(x, y Route) int { return cmp.Or(cmp.Compare(x.Dst, y.Dst), cmp.Compare(x.Via, y.Via)) })
	out := visits
	for _, c := range s.conns {
		rank := c.rank
		out = append(out, Route{Dst: "default", Via: c.name, Dev: c.name, Src: c.base.Address.String(), Metric: &rank})
	}
	return out
}
