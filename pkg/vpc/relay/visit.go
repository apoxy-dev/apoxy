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

// maxVisits is the most visitor sessions of one agent on a relay.
const maxVisits = 2

// visit is the use of an address of another relay by a session of this relay.
// The session gets no route and no attachment, so no other relay learns of it.
type visit struct {
	prefix   netip.Prefix // Prefix of the grant that has the address.
	id       string       // Attachment of the grant, on the home relay.
	relay    string       // Relay ID of the grant.
	notAfter time.Time    // End time of the grant.
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

// reach returns the visitor of a as its owner, or the owner of the longest
// route to a if that route is longer than the prefix of the visit.
func (d *domain) reach(a netip.Addr) owner {
	v, bits := d.visits.of(a)
	if v == nil {
		return d.ownerOf(a)
	}
	// A route with the prefix of the visit is of the same agent on another relay.
	for _, n := range d.lens {
		if n <= bits {
			break
		}
		if p, err := a.Prefix(n); err == nil {
			if o, ok := d.routes[p]; ok {
				return o
			}
		}
	}
	return owner{s: v, origin: v.visit.Load().id}
}

// reach is ownerOf for src, a session of this relay: a visitor has its address,
// and a visitor src reaches only this relay. Router.mu must be held.
func (r *Router) reach(src *Session, dst netip.Addr) owner {
	d := r.domains[src.id.VPC]
	switch {
	case d == nil:
		return owner{}
	case len(d.visits.lens) == 0:
		return d.ownerOf(dst)
	case src.visit.Load() == nil:
		return d.reach(dst)
	}
	// Nothing of a visitor goes to another relay, or to another visitor.
	if o := d.ownerOf(dst); o.s != nil && o.s.home == "" {
		return o
	}
	return owner{}
}

// has reports whether s sends from a: s visits with a, or has the route of a.
// Router.mu must be held.
func (r *Router) has(s *Session, a netip.Addr) bool {
	if v := s.visit.Load(); v != nil {
		return v.prefix.Contains(a)
	}
	return r.lookup(s.id.VPC, a) == s
}

// Visit makes the session of the caller a visitor: the sessions of this relay
// reach its address of another relay of the mesh on this session.
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
	switch {
	case s.closed:
		return rpc.Errorf(rpc.Unauthenticated, "relay session closed")
	case !s.sync.open || s.sync.meshRoutes:
		// A visitor reaches no other relay, so it must not have their routes.
		return rpc.Errorf(rpc.FailedPrecondition, "a visit needs a Session call with local_routes_only")
	case s.tag != 0 || len(s.routes) > 0:
		// A session with a trunk tag can have rows to another relay.
		return rpc.Errorf(rpc.FailedPrecondition, "session has or had an attachment")
	case s.visit.Load() != nil:
		return rpc.Errorf(rpc.FailedPrecondition, "session is a visitor already")
	case !r.permit(s.id.VPC, s.id.ID, s.id.VPC, addr):
		return rpc.Errorf(rpc.PermissionDenied, "permit denies %s", addr)
	}
	d := r.domain(s.id.VPC)
	// The grant can be older than the owner that the address has now.
	if o, ok := d.routes[v.prefix]; ok && (o.s.home == "" || !o.s.sameAgent(s)) {
		return rpc.Errorf(rpc.AlreadyExists, "address %s has another owner", addr)
	}
	n := 0
	for p, ss := range d.visits.by {
		for _, o := range ss {
			if o.sameAgent(s) {
				n++
			} else if p == v.prefix {
				return rpc.Errorf(rpc.AlreadyExists, "address %s has another visitor", addr)
			}
		}
	}
	if n >= maxVisits {
		return rpc.Errorf(rpc.ResourceExhausted, "agent has %d visitor sessions on this relay, which is the limit", n)
	}
	s.visit.Store(v)
	d.visits.add(v.prefix, s)
	// The rows to the prefix go to the visitor, as for a new owner of a route.
	r.rehome(d, v.prefix)
	slog.Info("Started a visit", "agent", s.id.ID, "prefix", v.prefix, "home", v.relay, "until", v.notAfter)
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
			return &visit{prefix: p.Masked(), id: c.GetAttachmentId(), relay: c.GetRelayId(), notAfter: c.GetNotAfter().AsTime()}, nil
		}
	}
	return nil, rpc.Errorf(rpc.PermissionDenied, "address %s is not in the grant", addr)
}

// endVisit ends the visit of s, if it has one. The rows to its prefix go to
// the owner that their senders reach then. Router.mu must be held for writing.
func (r *Router) endVisit(s *Session, reason string) {
	v := s.visit.Swap(nil)
	if v == nil {
		return
	}
	if d := r.domains[s.id.VPC]; d != nil {
		d.visits.remove(v.prefix, s)
		r.rehome(d, v.prefix)
	}
	slog.Info("Ended a visit", "agent", s.id.ID, "prefix", v.prefix, "home", v.relay, "reason", reason)
}

// displace ends each visit with the prefix p that its new route owner o ends:
// an attachment of this relay, or another agent. Router.mu must be held for writing.
func (r *Router) displace(d *domain, p netip.Prefix, o *Session) {
	for _, s := range slices.Clone(d.visits.by[p]) {
		if o.home == "" || !o.sameAgent(s) {
			r.endVisit(s, "address has another owner")
		}
	}
}

// rehome gives each row of d to an address of p the owner that its sender
// reaches now. A row with no owner ends. Router.mu must be held for writing.
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
