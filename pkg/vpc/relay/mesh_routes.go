// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// meshRoutesRevision is the first revision of an agent that gets the routes of
// the attachments of other relays.
const meshRoutesRevision = 6

// remoteKey names one agent session of another relay.
type remoteKey struct {
	home     string
	id       Identity
	agent    string
	instance uint64
	tag      uint32
}

// session returns the key of the session that has the attachment e.
func (e *presenceEntry) session() remoteKey {
	return remoteKey{home: e.sess.name, id: Identity{VPC: e.vpc, ID: e.subject}, agent: e.agent, instance: e.instance, tag: e.tag}
}

// record returns the record of the session that has the attachment e, and
// makes it if needed. Router.mu must be held.
func (r *Router) record(e *presenceEntry) *Session {
	k := e.session()
	s := r.remotes[k]
	if s == nil {
		s = newSession(k.id, func() netip.AddrPort { return netip.AddrPort{} })
		s.home, s.name, s.instance, s.tag = k.home, k.agent, k.instance, k.tag
		r.remotes[k] = s
	}
	return s
}

// remoteKey returns the key of the record s. Router.mu must be held.
func (s *Session) remoteKey() remoteKey {
	return remoteKey{home: s.home, id: s.id, agent: s.name, instance: s.instance, tag: s.tag}
}

// release forgets the record s of a session of another relay when it has no
// entry in the route table. Router.mu must be held.
func (r *Router) release(s *Session) {
	if s.home != "" && len(s.routes) == 0 {
		delete(r.remotes, s.remoteKey())
	}
}

// attachedAt returns the generation of e at the attach. A member from before
// the field sends one entry for an attachment, so its generation is that one.
func (e *presenceEntry) attachedAt() uint64 {
	return cmp.Or(e.attached, e.gen)
}

// routeState returns the state of the route entries of e on this relay: the
// state that its relay sent, and at least suspect while its member is lost.
func (e *presenceEntry) routeState() dp.AnnouncerState {
	if e.lost {
		return max(e.state, dp.AnnouncerState_ANNOUNCER_STATE_SUSPECT)
	}
	return e.state
}

// restateClaim gives the record of e, an attachment of another relay, its new
// state and hold time, and selects again. Router.mu must be held.
func (r *Router) restateClaim(e *presenceEntry) {
	state, from := e.routeState(), e.activeFrom
	if e.cand.state == state && e.cand.activeFrom.Equal(from) {
		return
	}
	e.cand.state, e.cand.activeFrom = state, from
	d, s := r.domains[e.vpc], r.remotes[e.session()]
	if d == nil || s == nil {
		return
	}
	for _, p := range e.prefixes {
		if set := d.routes[p]; set != nil && set.find(s, e.id) != nil {
			r.restated(d, p, set)
		}
	}
}

// claim adds e, an attachment of another relay, to the domain of its VPC. A
// wrong network ID gives an error. Router.mu must be held.
func (r *Router) claim(e *presenceEntry) error {
	e.cand = candidate{
		agent: agentKey{id: e.subject, name: e.agent, instance: e.instance},
		relay: e.sess.name, attached: e.attachedAt(), rank: e.rank,
		state: e.routeState(), activeFrom: e.activeFrom,
	}
	d := r.domain(e.vpc)
	for _, p := range e.prefixes {
		d.claims[p] = append(d.claims[p], e)
		r.routeClaim(d, p, e)
	}
	r.dropDomain(e.vpc, d)
	if d.known && e.networkID != d.networkID {
		return fmt.Errorf("network ID %d is not the ID %d of the VPC on this relay", e.networkID, d.networkID)
	}
	return nil
}

// unclaim removes the attachment e of another relay from the domain of its
// VPC, with its entries in the route table. Router.mu must be held.
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
		if s := r.remotes[e.session()]; s != nil {
			r.removeAnnouncer(d, p, s, e.id)
		}
	}
	r.dropDomain(e.vpc, d)
}

// routeClaim makes e an announcer of p in d only if this relay knows the VPC
// with the network ID of e, else removes it. Router.mu must be held.
func (r *Router) routeClaim(d *domain, p netip.Prefix, e *presenceEntry) {
	if d.known && e.networkID == d.networkID {
		r.addAnnouncer(d, p, target{s: r.record(e), origin: e.id}, &e.cand)
	} else if s := r.remotes[e.session()]; s != nil {
		r.removeAnnouncer(d, p, s, e.id)
	}
}

// know sets the network ID of d and makes the entries with that ID announcers.
// It returns the count of the others. Router.mu must be held.
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
			r.routeClaim(d, p, e)
		}
	}
	return len(refused)
}
