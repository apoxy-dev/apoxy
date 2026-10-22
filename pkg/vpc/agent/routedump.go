// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"fmt"
	"strings"
)

// Route is one route of the agent, as GET /debug/routes shows it: the default
// route of a relay session.
type Route struct {
	Dst    string  `json:"dst"`              // "default".
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

// Routes returns the default route of each relay session in rank order.
func (a *Agent) Routes() []Route {
	var out []Route
	for _, c := range a.snap.Load().conns {
		rank := c.rank
		out = append(out, Route{Dst: "default", Via: c.name, Dev: c.name, Src: c.base.Address.String(), Metric: &rank})
	}
	return out
}
