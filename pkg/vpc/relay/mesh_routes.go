// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
)

// meshRoutesRevision is the first revision of an agent that gets the routes of
// the attachments of other relays.
const meshRoutesRevision = 6

// remoteKey names one agent session of another relay.
type remoteKey struct {
	home  string
	id    Identity
	agent string
	tag   uint32
}

// session returns the key of the session that has the attachment e.
func (e *presenceEntry) session() remoteKey {
	return remoteKey{home: e.sess.name, id: Identity{VPC: e.vpc, ID: e.subject}, agent: e.agent, tag: e.tag}
}

// before reports whether e gets a prefix that o also lists: the higher
// generation, then the lower relay name, then the lower attachment ID.
func (e *presenceEntry) before(o *presenceEntry) bool {
	return cmp.Or(cmp.Compare(o.gen, e.gen), cmp.Compare(e.sess.name, o.sess.name), cmp.Compare(e.id, o.id)) < 0
}

// record returns the record of the session that has the attachment e, and
// makes it if needed. Router.mu must be held.
func (r *Router) record(e *presenceEntry) *Session {
	k := e.session()
	s := r.remotes[k]
	if s == nil {
		s = newSession(k.id, func() netip.AddrPort { return netip.AddrPort{} })
		s.home, s.name, s.tag = k.home, k.agent, k.tag
		r.remotes[k] = s
	}
	return s
}

// release forgets the record s of a session of another relay when it has no
// route. Router.mu must be held.
func (r *Router) release(s *Session) {
	if s.home != "" && len(s.routes) == 0 {
		delete(r.remotes, remoteKey{home: s.home, id: s.id, agent: s.name, tag: s.tag})
	}
}

// claim adds the attachment e of another relay to the domain of its VPC, with
// its routes. A wrong network ID gives an error. Router.mu must be held.
func (r *Router) claim(e *presenceEntry) error {
	d := r.domain(e.vpc)
	for _, p := range e.prefixes {
		d.claims[p] = append(d.claims[p], e)
		r.elect(d, p)
	}
	r.dropDomain(e.vpc, d)
	if d.known && e.networkID != d.networkID {
		return fmt.Errorf("network ID %d is not the ID %d of the VPC on this relay", e.networkID, d.networkID)
	}
	return nil
}

// unclaim removes the attachment e of another relay from the domain of its
// VPC, and the routes that it has. Router.mu must be held.
func (r *Router) unclaim(e *presenceEntry) {
	d := r.domains[e.vpc]
	if d == nil {
		return
	}
	for _, p := range e.prefixes {
		left := slices.DeleteFunc(d.claims[p], func(o *presenceEntry) bool { return o == e })
		if len(left) == 0 {
			delete(d.claims, p)
		} else {
			d.claims[p] = left
		}
		r.elect(d, p)
	}
	r.dropDomain(e.vpc, d)
}

// elect gives the prefix p of d to the best attachment of another relay that
// lists it. An attachment of this relay keeps p. Router.mu must be held.
func (r *Router) elect(d *domain, p netip.Prefix) {
	cur, had := d.routes[p]
	if had && cur.s.home == "" {
		return
	}
	var best *presenceEntry
	for _, e := range d.claims[p] {
		// An attachment gets routes only in a VPC that this relay knows.
		if d.known && e.networkID == d.networkID && (best == nil || e.before(best)) {
			best = e
		}
	}
	switch {
	case best == nil && had:
		r.dropRoute(cur.s, p)
		// The rows to the addresses of p have no receiver now.
		r.dropInbound(cur.s)
		r.release(cur.s)
	case best == nil:
	case had && cur.origin == best.id && cur.s == r.remotes[best.session()]:
	default:
		r.setOwner(d, p, owner{s: r.record(best), origin: best.id})
	}
}

// know sets the network ID of d from a Session call, and routes the entries
// with that ID. It returns the number of the others. Router.mu must be held.
func (r *Router) know(d *domain, id uint32) int {
	if d.known && d.networkID == id {
		return 0
	}
	d.networkID, d.known = id, true
	refused := map[*presenceEntry]struct{}{}
	for p, entries := range d.claims {
		for _, e := range entries {
			if e.networkID != id {
				refused[e] = struct{}{}
			}
		}
		r.elect(d, p)
	}
	return len(refused)
}
