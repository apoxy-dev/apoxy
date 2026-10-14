// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// announcerRevision is the first revision with a set of announcers for each
// prefix: Hello.instance, and the standby list in RouteDelta.
const announcerRevision = 16

// agentKey names one agent process: the SPIFFE ID, the name from Hello, and the
// instance from Hello. An agent from before Hello.instance has the instance 0.
// One agent process can have attachments on more than one relay.
type agentKey struct {
	id, name string
	instance uint64
}

// agent returns the key of the agent of s. Router.mu must be held.
func (s *Session) agent() agentKey {
	return agentKey{id: s.id.ID, name: s.name, instance: s.instance}
}

// target is where the packets for an address go: a session, and the attachment
// that has the address. The zero target is no route.
type target struct {
	s      *Session
	origin string // ID of the attachment.
	// att is the attachment. It is nil for an attachment of another relay.
	att *Attachment
}

// candidate is what the selection reads of one attachment. One place has it:
// the Attachment on its relay, and the presenceEntry on each other relay.
type candidate struct {
	agent agentKey
	// relay is the name of the relay with the attachment. Each relay must sort
	// by the same name, so an attachment of this relay has the name of this relay.
	relay string
	// attached is the generation at the attach. A later state of the attachment
	// does not change it, so it tells which attachment of a connection is newer.
	attached uint64
	// rank is the order that the agent gives to its own connections. The lower
	// one is selected first.
	rank  uint32
	state dp.AnnouncerState // The lower state is selected first.
	// activeFrom is the end of the hold time, from the relay with the
	// attachment. The zero time is no hold time.
	activeFrom time.Time
}

// restate gives c the state. A return to the normal state starts a new hold
// time at now.
func (c *candidate) restate(state dp.AnnouncerState, now time.Time) {
	c.state = state
	if state == stateNormal {
		c.activeFrom = now.Add(holdTime)
	}
}

// announcer is one entry of the route table, with the key prefix and attachment
// ID. Each connection of an agent to a relay is its own announcer.
type announcer struct {
	target
	// candidate is the record of the attachment, which each entry of the
	// attachment reads. Only the state and the hold time in it change.
	*candidate
	// hash is a hash of the agent and the prefix. The lower one is selected
	// first, so each prefix has its own order of the agents.
	hash [sha256.Size]byte
}

// newAnnouncer returns the entry for p of the attachment of t, which has the
// record c. The hash is made here, one time, and not at a lookup.
func newAnnouncer(t target, c *candidate, p netip.Prefix) *announcer {
	// A SPIFFE ID and an agent name have no zero byte, so the parts stay apart.
	// The buffer is on the stack, and append makes a larger one for a long text.
	var buf [256]byte
	b := append(buf[:0], c.agent.id...)
	b = append(b, 0)
	b = append(b, c.agent.name...)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint64(b, c.agent.instance)
	return &announcer{target: t, candidate: c, hash: sha256.Sum256(p.AppendTo(b))}
}

// relayOf returns the name of the relay that has s. It is empty for a session
// of this relay with no mesh. Router.mu must be held.
func (r *Router) relayOf(s *Session) string {
	return cmp.Or(s.home, r.name)
}

// sameConn reports whether e and o are entries of one agent process on one
// relay: a reconnect to that relay, or two attachments of one session.
func (e *announcer) sameConn(o *announcer) bool {
	return e.agent == o.agent && e.relay == o.relay
}

// newer reports whether e comes in the place of o in the selection, when
// sameConn is true: the later attach, then the lower attachment ID.
func (e *announcer) newer(o *announcer) bool {
	return cmp.Or(cmp.Compare(o.attached, e.attached), cmp.Compare(e.origin, o.origin)) < 0
}

// held returns 1 if e is in its hold time at now, and 0 if not. Only a normal
// entry has a hold time.
func (e *announcer) held(now time.Time) int {
	if e.state == dp.AnnouncerState_ANNOUNCER_STATE_NORMAL && now.Before(e.activeFrom) {
		return 1
	}
	return 0
}

// selectOrder returns the active announcer, then the standby ones: by state,
// hold time and agent hash, then rank. Only the set and now decide.
func selectOrder(entries []*announcer, now time.Time) []*announcer {
	order := make([]*announcer, 0, len(entries))
	for _, e := range entries {
		i := slices.IndexFunc(order, e.sameConn)
		switch {
		case i < 0:
			order = append(order, e)
		case e.newer(order[i]):
			order[i] = e
		}
	}
	// When each normal entry is in its hold time, the one whose hold time ends
	// first is active, and it stays active at that end.
	allHeld := !slices.ContainsFunc(order, func(e *announcer) bool {
		return e.state == dp.AnnouncerState_ANNOUNCER_STATE_NORMAL && e.held(now) == 0
	})
	slices.SortFunc(order, func(a, b *announcer) int {
		byEnd := 0
		if allHeld && a.held(now)+b.held(now) == 2 {
			byEnd = a.activeFrom.Compare(b.activeFrom)
		}
		return cmp.Or(
			cmp.Compare(a.state, b.state),
			// Each relay reads its own clock, so two relays can have different
			// orders only for the time by which their clocks differ.
			cmp.Compare(a.held(now), b.held(now)),
			byEnd,
			bytes.Compare(a.hash[:], b.hash[:]),
			cmp.Compare(a.rank, b.rank),
			cmp.Compare(a.relay, b.relay),
			cmp.Compare(a.origin, b.origin),
		)
	})
	return order
}

// routeSet has the announcers of one prefix and the result of the selection.
// The route table has no empty set. Router.mu guards all but senders.
type routeSet struct {
	entries []*announcer // Each entry of the prefix, in no order.
	order   []*announcer // Result of selectOrder for entries.
	// local is the first entry of order with a session of this relay, or nil.
	local *announcer
	// wake is the time at which the selection runs again because a hold time
	// ends then. The zero time is no such time.
	wake time.Time
	// senders has the sessions of entries, for the source checks with no lock.
	senders atomic.Pointer[[]*Session]
}

// active returns the announcer that gets the packets for the prefix, or nil
// for a set with no entry. Router.mu must be held.
func (set *routeSet) active() *announcer {
	if len(set.order) == 0 {
		return nil
	}
	return set.order[0]
}

// find returns the entry of the attachment origin on s, or nil. Router.mu must
// be held.
func (set *routeSet) find(s *Session, origin string) *announcer {
	for _, e := range set.entries {
		if e.s == s && e.origin == origin {
			return e
		}
	}
	return nil
}

// sends reports whether s can send from the prefix. A standby announcer can
// too: traffic from its network can leave through it. It takes no lock.
func (set *routeSet) sends(s *Session) bool {
	senders := set.senders.Load()
	return senders != nil && slices.Contains(*senders, s)
}

// selectAgain runs the selection at the time now, after a change of entries or
// at the end of a hold time. Router.mu must be held for writing.
func (set *routeSet) selectAgain(now time.Time) {
	set.order = selectOrder(set.entries, now)
	set.local = nil
	if i := slices.IndexFunc(set.order, func(e *announcer) bool { return e.s.home == "" }); i >= 0 {
		set.local = set.order[i]
	}
	senders := make([]*Session, len(set.entries))
	for i, e := range set.entries {
		senders[i] = e.s
	}
	set.senders.Store(&senders)
}

// nextHold returns the first end of a hold time in set after now, or the zero
// time, also for a set with one announcer. Router.mu must be held.
func (set *routeSet) nextHold(now time.Time) time.Time {
	var next time.Time
	if len(set.order) < 2 {
		return next
	}
	for _, e := range set.entries {
		if e.held(now) == 1 && (next.IsZero() || e.activeFrom.Before(next)) {
			next = e.activeFrom
		}
	}
	return next
}

// setOf returns the announcers of the longest route to a, or nil.
func (d *domain) setOf(a netip.Addr) *routeSet {
	for _, n := range d.lens {
		if p, err := a.Prefix(n); err == nil {
			if set := d.routes[p]; set != nil {
				return set
			}
		}
	}
	return nil
}

// orderOf returns the selection for the exact prefix p, or nil. A nil d has no
// routes.
func (d *domain) orderOf(p netip.Prefix) []*announcer {
	if d == nil || d.routes[p] == nil {
		return nil
	}
	return d.routes[p].order
}

// activeOf returns the active announcer of the longest route to a as a target,
// or the zero target.
func (d *domain) activeOf(a netip.Addr) target {
	if set := d.setOf(a); set != nil {
		return set.active().target
	}
	return target{}
}

// addAnnouncer adds an entry for p to d for the attachment of t with the record
// c, and selects again. Router.mu must be held for writing.
func (r *Router) addAnnouncer(d *domain, p netip.Prefix, t target, c *candidate) {
	set := d.routes[p]
	if set == nil {
		set = &routeSet{}
		d.routes[p] = set
		_ = d.fast.Add(p, set) // p is valid and has no route.
		if !slices.Contains(d.lens, p.Bits()) {
			d.lens = append(d.lens, p.Bits())
			slices.SortFunc(d.lens, func(a, b int) int { return cmp.Compare(b, a) })
		}
	} else if set.find(t.s, t.origin) != nil {
		return
	}
	e := newAnnouncer(t, c, p)
	was := set.order
	set.entries = append(set.entries, e)
	e.s.routes = append(e.s.routes, p)
	r.selected(d, p, set, was)
	r.displace(d, p, e)
}

// AddRoute makes s an announcer of p with the attachment ID origin and no
// attachment, for a host that has no Attach call. The entry has its own record.
func (r *Router) AddRoute(s *Session, p netip.Prefix, origin string) error {
	p = p.Masked()
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed {
		return rpc.Errorf(rpc.FailedPrecondition, "session closed")
	}
	now := time.Now()
	c := &candidate{agent: s.agent(), relay: r.relayOf(s), attached: r.nextGen(now), state: s.state, activeFrom: now.Add(holdTime)}
	r.addAnnouncer(r.domain(s.id.VPC), p, target{s: s, origin: origin}, c)
	return nil
}

// removeAnnouncer removes the entry of the attachment origin on s for p from d,
// and selects again. Router.mu must be held for writing.
func (r *Router) removeAnnouncer(d *domain, p netip.Prefix, s *Session, origin string) {
	set := d.routes[p]
	if set == nil || set.find(s, origin) == nil {
		return
	}
	was := set.order
	set.entries = slices.DeleteFunc(set.entries, func(e *announcer) bool { return e.s == s && e.origin == origin })
	if i := slices.Index(s.routes, p); i >= 0 {
		s.routes = slices.Delete(s.routes, i, i+1)
	}
	if len(set.entries) == 0 {
		delete(d.routes, p)
		d.fast.Remove(p, set)
		if !d.usesLen(p.Bits()) {
			d.lens = slices.DeleteFunc(d.lens, func(n int) bool { return n == p.Bits() })
		}
	}
	r.selected(d, p, set, was)
	r.release(s)
	r.dropDomain(s.id.VPC, d)
}

// removeAnnouncers removes each entry of s from the domain of its VPC.
// Router.mu must be held for writing.
func (r *Router) removeAnnouncers(s *Session) {
	d := r.domains[s.id.VPC]
	if d == nil {
		return
	}
	for _, p := range slices.Clone(s.routes) {
		set := d.routes[p]
		if set == nil {
			continue
		}
		for _, e := range slices.Clone(set.entries) {
			if e.s == s {
				r.removeAnnouncer(d, p, s, e.origin)
			}
		}
	}
}

// restated selects for p after an entry got a new state. Sessions and rows
// change only with a new order. Router.mu must be held for writing.
func (r *Router) restated(d *domain, p netip.Prefix, set *routeSet) {
	was := set.order
	r.reselect(d, p, set)
	if !slices.Equal(was, set.order) {
		r.reroute(d, p, set, was)
	}
}

// selected runs the selection for p after a change of set, whose result was
// was before. Router.mu must be held for writing.
func (r *Router) selected(d *domain, p netip.Prefix, set *routeSet, was []*announcer) {
	r.reselect(d, p, set)
	r.reroute(d, p, set, was)
}

// reselect runs the selection for p now, and makes it run again at the next
// end of a hold time. Router.mu must be held for writing.
func (r *Router) reselect(d *domain, p netip.Prefix, set *routeSet) {
	now := time.Now()
	set.selectAgain(now)
	r.holdUntil(d, p, set, set.nextHold(now), now)
}

// reroute gives the sessions of d the change of the selection for p from was,
// and moves the rows. Router.mu must be held for writing.
func (r *Router) reroute(d *domain, p netip.Prefix, set *routeSet, was []*announcer) {
	d.queueRoute(p, was, set.order)
	r.newEpoch()
	if len(was) > 0 && was[0] != set.active() {
		r.moveRows(p, was[0], set.active())
	}
}

// holdEnd is a pending end of a hold time: the selection for the prefix p of
// d runs again at the time at.
type holdEnd struct {
	at time.Time
	d  *domain
	p  netip.Prefix
}

// holdUntil makes the selection for p run again at the time at, if at is not
// zero and set has no earlier such time. Router.mu must be held for writing.
func (r *Router) holdUntil(d *domain, p netip.Prefix, set *routeSet, at, now time.Time) {
	if at.IsZero() || !set.wake.IsZero() && !at.Before(set.wake) {
		return
	}
	set.wake = at
	i, _ := slices.BinarySearchFunc(r.holds, at, func(h holdEnd, at time.Time) int { return h.at.Compare(at) })
	r.holds = slices.Insert(r.holds, i, holdEnd{at: at, d: d, p: p})
	if i == 0 {
		r.armHolds(now)
	}
}

// armHolds sets the hold timer, the one such timer of the router, to the first
// pending end. Router.mu must be held for writing.
func (r *Router) armHolds(now time.Time) {
	switch {
	case len(r.holds) == 0:
	case r.holdTimer == nil:
		r.holdTimer = time.AfterFunc(r.holds[0].at.Sub(now), r.endHolds)
	default:
		r.holdTimer.Reset(r.holds[0].at.Sub(now))
	}
}

// endHolds selects again for each prefix with a hold time that ended. The hold
// timer calls it. An end whose set is gone or changed does nothing.
func (r *Router) endHolds() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	n := 0
	for n < len(r.holds) && !r.holds[n].at.After(now) {
		n++
	}
	ended := slices.Clone(r.holds[:n])
	r.holds = slices.Delete(r.holds, 0, n)
	for _, h := range ended {
		if set := h.d.routes[h.p]; set != nil && set.wake.Equal(h.at) {
			set.wake = time.Time{}
			r.selected(h.d, h.p, set, set.order)
		}
	}
	r.armHolds(now)
}

// moveRows gives the rows to p on from to the new target. With to nil they go
// nowhere, not to a shorter prefix. Router.mu must be held for writing.
func (r *Router) moveRows(p netip.Prefix, from, to *announcer) {
	for w := range from.s.inbound {
		if !p.Contains(w.dst) {
			continue
		}
		now := r.reach(w.sender, w.dst)
		switch {
		case now.s == w.receiver && now.att == w.att:
			// A longer prefix of the same attachment has the address.
		case now.s == nil, to == nil && now.s != w.receiver, now.s.home != "" && !r.trunked(w.sender):
			r.removeRow(w)
		default:
			r.move(w, now)
		}
	}
}

// sees returns the announcer of order for s, or nil: never its own agent,
// another relay only with meshRoutes. Router.mu must be held.
func (s *Session) sees(order []*announcer) *announcer {
	if len(order) == 0 {
		return nil
	}
	own := s.agent()
	if slices.ContainsFunc(order, func(e *announcer) bool { return e.agent == own }) {
		return nil
	}
	if active := order[0]; active.s.home == "" || s.sync.meshRoutes {
		return active
	}
	return nil
}

// standby returns the IDs of the standby announcers of order that s can
// reach, in the order of selection. Router.mu must be held.
func (s *Session) standby(order []*announcer) []string {
	var ids []string
	for i, e := range order {
		if i == 0 {
			continue
		}
		if e.s.home == "" || s.sync.meshRoutes {
			ids = append(ids, e.origin)
		}
	}
	return ids
}

// queueRoute gives the sessions of d the change of the selection for p from
// was to now. A session at announcerRevision or later also gets a change of
// only the standby list. Router.mu must be held.
func (d *domain) queueRoute(p netip.Prefix, was, now []*announcer) {
	for m := range d.members {
		old, cur := m.sees(was), m.sees(now)
		switch {
		case old != cur:
			if old != nil {
				m.queueRoute(route{p, old.origin}, false)
			}
			if cur != nil {
				m.queueRoute(route{p, cur.origin}, true)
			}
		case cur != nil && m.version.GetRevision() >= announcerRevision && !slices.Equal(m.standby(was), m.standby(now)):
			// The route stays, and its standby list is new.
			m.sync.standby[p] = struct{}{}
			m.notify()
		}
	}
}

// queueRoutes puts each route of d that s gets in the sync queue of s. Call it
// only before the first RouteDelta of s. Router.mu must be held.
func (d *domain) queueRoutes(s *Session) {
	clear(s.sync.routes)
	clear(s.sync.standby)
	for p, set := range d.routes {
		if e := s.sees(set.order); e != nil {
			s.sync.routes[route{p, e.origin}] = true
		}
	}
	s.notify()
}

// announces reports whether the attachment origin on the member home is an
// announcer of the longest route to a in vpc. Router.mu must be held.
func (r *Router) announces(vpc VPCKey, a netip.Addr, home, origin string) bool {
	d := r.domains[vpc]
	if d == nil {
		return false
	}
	set := d.setOf(a)
	return set != nil && slices.ContainsFunc(set.entries, func(e *announcer) bool { return e.s.home == home && e.origin == origin })
}
