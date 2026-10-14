// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// maxVisits is the most visitor sessions of one agent on a relay.
	maxVisits = 2
	// maxVisitPrefixes is the most visits of one visitor session: the most
	// prefixes of an entry of a mesh member.
	maxVisitPrefixes = maxEntryPrefixes
)

// visit is the use of an address of another relay by a session here, with no
// route or attachment. The grant check is at the call: no time limit.
type visit struct {
	prefix netip.Prefix // Prefix of the grant that has the address.
	id     string       // Attachment of the grant, on the home relay.
	relay  string       // Relay ID of the grant.
}

// visitor has the visits of a visitor session, each with its own prefix. A
// change makes a new list, so a reader needs no lock.
type visitor []*visit

// of returns the visit of vs that has a in its prefix, or nil.
func (vs *visitor) of(a netip.Addr) *visit {
	if vs == nil {
		return nil
	}
	for _, v := range *vs {
		if v.prefix.Contains(a) {
			return v
		}
	}
	return nil
}

// without returns vs with no visit for which drop is true.
func (vs *visitor) without(drop func(*visit) bool) visitor {
	var out visitor
	if vs != nil {
		for _, v := range *vs {
			if !drop(v) {
				out = append(out, v)
			}
		}
	}
	return out
}

// visits has the visitor sessions of a domain by the prefix of their visit.
type visits struct {
	by   map[netip.Prefix][]*Session // The newest session of a prefix is last.
	lens []int                       // Prefix lengths in use, longest first.
}

// of returns the newest visitor session with a in its prefix, and the length
// of that prefix. The longest prefix wins.
func (v *visits) of(a netip.Addr) (*Session, int) {
	for _, n := range v.lens {
		if p, err := a.Prefix(n); err == nil {
			if ss := v.by[p]; len(ss) > 0 {
				return ss[len(ss)-1], n
			}
		}
	}
	return nil, 0
}

func (v *visits) add(p netip.Prefix, s *Session) {
	if v.by == nil {
		v.by = map[netip.Prefix][]*Session{}
	}
	v.by[p] = append(v.by[p], s)
	if !slices.Contains(v.lens, p.Bits()) {
		v.lens = append(v.lens, p.Bits())
		slices.SortFunc(v.lens, func(a, b int) int { return cmp.Compare(b, a) })
	}
}

func (v *visits) remove(p netip.Prefix, s *Session) {
	if left := slices.DeleteFunc(v.by[p], func(o *Session) bool { return o == s }); len(left) > 0 {
		v.by[p] = left
		return
	}
	delete(v.by, p)
	for q := range v.by {
		if q.Bits() == p.Bits() {
			return
		}
	}
	v.lens = slices.DeleteFunc(v.lens, func(n int) bool { return n == p.Bits() })
}

// reach returns the visitor of a as its target, or the active announcer of the
// longest route to a if that route is longer than the prefix of the visit.
func (d *domain) reach(a netip.Addr) target {
	v, bits := d.visits.of(a)
	if v == nil {
		return d.activeOf(a)
	}
	// A route with the prefix of the visit is of the same agent on another relay.
	for _, n := range d.lens {
		if n <= bits {
			break
		}
		if p, err := a.Prefix(n); err == nil {
			if set := d.routes[p]; set != nil {
				return set.active().target
			}
		}
	}
	return target{s: v, origin: v.visit.Load().of(a).id}
}

// reach is activeOf for src, a session of this relay: a visitor has its address,
// and a visitor src reaches only this relay. Router.mu must be held.
func (r *Router) reach(src *Session, dst netip.Addr) target {
	d := r.domains[src.id.VPC]
	switch {
	case d == nil:
		return target{}
	case len(d.visits.lens) == 0:
		return d.activeOf(dst)
	case src.visit.Load() == nil:
		return d.reach(dst)
	}
	// Nothing of a visitor goes to another relay, or to another visitor.
	if o := d.activeOf(dst); o.s != nil && o.s.home == "" {
		return o
	}
	return target{}
}

// has reports whether s sends from a: s visits with a, or is an announcer of
// the route of a. Router.mu must be held.
func (r *Router) has(s *Session, a netip.Addr) bool {
	if vs := s.visit.Load(); vs != nil {
		return vs.of(a) != nil
	}
	d := r.domains[s.id.VPC]
	if d == nil {
		return false
	}
	set := d.setOf(a)
	return set != nil && set.sends(s)
}

// Visit makes the caller a visitor: this relay reaches its address of another
// relay on this session. One more call adds another attachment.
func (srv *Server) Visit(ctx context.Context, in *dp.VisitRequest) (*emptypb.Empty, error) {
	s, err := srv.R.caller(ctx)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, srv.R.startVisit(s, in, time.Now())
}

func (r *Router) startVisit(s *Session, in *dp.VisitRequest, now time.Time) error {
	t := r.trunk.Load()
	if t == nil {
		return rpc.Errorf(rpc.Unimplemented, "relay has no mesh")
	}
	_, addr, err := s.target(in.GetVpc(), in.GetAddress())
	if err != nil {
		return err
	}
	v, err := r.checkVisit(s, t.m, addr, in.GetGrant(), now)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := s.visit.Load()
	same := func(o *visit) bool { return o.prefix == v.prefix }
	switch {
	case s.closed:
		return rpc.Errorf(rpc.Unauthenticated, "relay session closed")
	case !s.sync.open || s.sync.meshRoutes:
		// A visitor reaches no other relay, so it must not have their routes.
		return rpc.Errorf(rpc.FailedPrecondition, "a visit needs a Session call with local_routes_only")
	case s.tag != 0 || len(s.routes) > 0:
		// A session with a trunk tag can have rows to another relay.
		return rpc.Errorf(rpc.FailedPrecondition, "session has or had an attachment")
	case cur != nil && (*cur)[0].relay != v.relay:
		return rpc.Errorf(rpc.FailedPrecondition, "session is a visitor with a grant of relay %q", (*cur)[0].relay)
	case cur != nil && len(cur.without(same)) >= maxVisitPrefixes:
		return rpc.Errorf(rpc.ResourceExhausted, "session has %d visits, which is the limit", len(*cur))
	case !r.permit(s.id.VPC, s.id.ID, s.id.VPC, addr):
		return rpc.Errorf(rpc.PermissionDenied, "permit denies %s", addr)
	}
	d := r.domain(s.id.VPC)
	// The grant can be older than the attachment that the address has now.
	if set := d.routes[v.prefix]; set != nil && slices.ContainsFunc(set.entries, s.visitEndedBy) {
		return rpc.Errorf(rpc.AlreadyExists, "address %s has another owner", addr)
	}
	// The limit counts sessions: a session with many visits is one of them.
	others := map[*Session]bool{}
	for p, ss := range d.visits.by {
		for _, o := range ss {
			if o.agent() == s.agent() {
				others[o] = true
			} else if p == v.prefix {
				return rpc.Errorf(rpc.AlreadyExists, "address %s has another visitor", addr)
			}
		}
	}
	if cur == nil && len(others) >= maxVisits {
		return rpc.Errorf(rpc.ResourceExhausted, "agent has %d visitor sessions on this relay, which is the limit", len(others))
	}
	// A new grant for a prefix of the session replaces the old one.
	next := append(cur.without(same), v)
	if cur == nil || len(next) > len(*cur) {
		d.visits.add(v.prefix, s)
	}
	s.visit.Store(&next)
	// The rows to the prefix go to the visitor, as for a new owner of a route.
	r.rehome(d, v.prefix)
	slog.Info("Started a visit", "agent", s.id.ID, "prefix", v.prefix, "home", v.relay)
	return nil
}

// checkVisit checks the grant g of s for a visit with addr, and returns the
// visit. It does the checks that need no state of the router.
func (r *Router) checkVisit(s *Session, m *Mesh, addr netip.Addr, g *dp.AttachmentGrant, now time.Time) (*visit, error) {
	if r.trust == nil {
		return nil, rpc.Errorf(rpc.Unavailable, "relay has no trust data")
	}
	roots, err := r.trust.RelayRoots(s.id.VPC.Project)
	if err != nil {
		return nil, rpc.Errorf(rpc.Unavailable, "relay roots: %v", err)
	}
	c, err := VerifyGrant(g, roots, now)
	if err != nil {
		return nil, rpc.Errorf(rpc.PermissionDenied, "grant: %v", err)
	}
	if vpc, err := KeyOf(c.GetVpc()); err != nil || vpc != s.id.VPC || c.GetSubject() != s.id.ID {
		return nil, rpc.Errorf(rpc.PermissionDenied, "grant is not of the caller")
	}
	// The grant names its relay itself, and with the system roots each public
	// certificate verifies. So only the ID of a member is a home relay.
	if !m.hasRelay(c.GetRelayId()) {
		return nil, rpc.Errorf(rpc.PermissionDenied, "relay %q of the grant is not a member of the mesh", c.GetRelayId())
	}
	for _, text := range c.GetAddresses() {
		if p, err := netip.ParsePrefix(text); err == nil && p.Masked().Contains(addr) {
			return &visit{prefix: p.Masked(), id: c.GetAttachmentId(), relay: c.GetRelayId()}, nil
		}
	}
	return nil, rpc.Errorf(rpc.PermissionDenied, "address %s is not in the grant", addr)
}

// endVisit ends the visits of s that end selects, and reports whether one
// ended. Their rows go to the owner. Router.mu must be held for writing.
func (r *Router) endVisit(s *Session, reason string, end func(*visit) bool) bool {
	cur := s.visit.Load()
	if cur == nil {
		return false
	}
	left := cur.without(end)
	if len(left) == len(*cur) {
		return false
	}
	if len(left) == 0 {
		s.visit.Store(nil)
	} else {
		s.visit.Store(&left)
	}
	for _, v := range *cur {
		if !end(v) {
			continue
		}
		if d := r.domains[s.id.VPC]; d != nil {
			d.visits.remove(v.prefix, s)
			r.rehome(d, v.prefix)
		}
		slog.Info("Ended a visit", "agent", s.id.ID, "prefix", v.prefix, "home", v.relay, "reason", reason)
	}
	return true
}

// each is the endVisit choice of all visits of a session.
func each(*visit) bool { return true }

// leave ends the visit of s with the grant of the attachment id, for a Detach
// call of a visitor. It reports whether s had that visit.
func (r *Router) leave(s *Session, id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.endVisit(s, "agent detached", func(v *visit) bool { return v.id == id })
}

// visitEndedBy reports whether the entry e for a prefix ends a visit of s to
// that prefix: e is an attachment of this relay, or of another agent. The
// instance is not a part of the check, because an older relay does not send it.
func (s *Session) visitEndedBy(e *announcer) bool {
	return e.s.home == "" || e.agent.id != s.id.ID || e.agent.name != s.name
}

// displace ends each visit with the prefix p that the new entry e for p ends.
// Router.mu must be held for writing.
func (r *Router) displace(d *domain, p netip.Prefix, e *announcer) {
	for _, s := range slices.Clone(d.visits.by[p]) {
		if s.visitEndedBy(e) {
			r.endVisit(s, "address has another owner", func(v *visit) bool { return v.prefix == p })
		}
	}
}

// rehome gives each row of d to an address of p the target that its sender
// reaches now. A row with no target ends. Router.mu must be held for writing.
func (r *Router) rehome(d *domain, p netip.Prefix) {
	for m := range d.members {
		for _, w := range m.rows {
			if !p.Contains(w.dst) {
				continue
			}
			to := r.reach(m, w.dst)
			switch {
			case to.s == w.receiver && to.att == w.att:
			case to.s == nil || to.s.home != "" && !r.trunked(m):
				r.removeRow(w)
			default:
				r.move(w, to)
			}
		}
	}
}
