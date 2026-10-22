// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// visitExtras is the first revision of a relay that takes a Visit call for
	// each extra attachment on one visitor session.
	visitExtras = 15
	// visitCalls is the most Visit calls for extra attachments that run at once
	// on a new visitor session.
	visitCalls = 16
	// visitCheck is the interval at which the agent asks its relay for the
	// addresses of a visit, to move them back when the relay reaches them again.
	visitCheck = 10 * time.Second
)

// visitParams is what a visitor session takes from its home session.
type visitParams struct {
	b        *psp.Binding
	link     *psp.Link
	self     netip.Addr
	prefixes []netip.Prefix
	grant    ownGrant
	// home gets new grants from the relay of the home session at homeAddr.
	home      dp.RelayClient
	homeAddr  string
	homeRoots *x509.CertPool
	roots     *x509.CertPool // Check the cert of the visited relay.
	extras    []extra
}

// visit is the process of one visit: a visitor session on the relay of an
// address that the home relay does not reach. It is a child of the home session.
type visit struct {
	a      *Agent
	mb, up *mailbox
	key    string
	ref    *dp.RelayRef
	vp     *visitParams
	ctx    context.Context
	cancel context.CancelFunc
	h      *session // The visitor session.
	tasks  int
	ending bool
	err    error
	peer   *psp.Peer
	queue  []any // Messages for the visitor session before it exists.
}

// visitRec is the record of a visit in its home session.
type visitRec struct {
	v        *visit
	key      string
	name     string
	peer     *psp.Peer
	up       bool
	extras   bool // The visited relay takes the extra attachments.
	routes   map[netip.Prefix]netip.Addr
	joined   map[string]bool
	checking int
	ending   bool
}

// Messages of the visits.
type (
	joinMsg  struct{ x extra }
	leaveMsg struct{ id string }
	// joinedMsg and leftMsg answer joinMsg and leaveMsg.
	joinedMsg struct {
		v   *visit
		id  string
		err error
	}
	leftMsg struct {
		v  *visit
		id string
	}
	// visitUp tells that the visitor session started.
	visitUp struct {
		v      *visit
		peer   *psp.Peer
		name   string
		extras bool
		joined []string
	}
	visitNoRoute struct{ dst netip.Addr }
	// vEnded is the last message of a visit.
	vEnded struct {
		v    *visit
		err  error
		peer *psp.Peer
	}
	visitDialed struct {
		d   *dialed
		err error
	}
	visitSet struct {
		extras bool
		joined []string
		err    error
	}
	vjoinDone struct {
		id  string
		err error
	}
	vleaveDone struct{ id string }
	resolved   struct {
		dst, addr netip.Addr
		res       *dp.ResolvePeerResponse
		err       error
	}
	visitChecked struct {
		rec *visitRec
		pfx netip.Prefix
		ok  bool
	}
	icmpReady struct {
		head   []byte
		denied bool
	}
)

// resolve asks the relay of c how it reaches dst.
func resolve(ctx context.Context, c dp.RelayClient, vpc *dp.VPCRef, dst netip.Addr) (*dp.ResolvePeerResponse, error) {
	res, err := c.ResolvePeer(ctx, &dp.ResolvePeerRequest{Vpc: vpc, Address: dst.String()})
	if err != nil {
		return nil, fmt.Errorf("resolve peer %s: %w", dst, err)
	}
	return res, nil
}

// reachable reports whether the relay that gave res reaches the address, so
// that no visit is necessary.
func reachable(res *dp.ResolvePeerResponse) bool {
	return res.GetReach() == dp.Reach_REACH_LOCAL || res.GetReach() == dp.Reach_REACH_TRUNK
}

// handleVisits takes the messages of the visits, of the visitor session and
// the messages of a visitor session that go up to the root.
func (s *session) handleVisits(m any) {
	switch m := m.(type) {
	case offerMsg:
		m.s = s
		s.up.send(m)
	case refusedMsg:
		m.s = s
		s.up.send(m)
	case applyMsg:
		m.s = s
		s.up.send(m)
	case reportMsg:
		m.s = s
		s.up.send(m)
	case clampMsg:
		m.s = s
		s.up.send(m)
	case peerMode:
		m.s = s
		s.up.send(m)
	case visitNoRoute:
		s.icmp(m.dst)
	case visitUp:
		s.visitUp(m)
	case joinedMsg:
		s.joined(m)
	case leftMsg:
		for _, dj := range s.detaching {
			if dj.id == m.id {
				delete(dj.leaves, m.v)
			}
		}
		s.detachProgress()
	case resolved:
		s.resolved(m)
	case visitChecked:
		s.visitChecked(m)
	case icmpReady:
		if pkt := unreachable(m.head, s.self, m.denied); pkt != nil {
			b := s.b
			s.write(func() { b.Deliver(pkt) })
		}
	case endVisit:
		if rec := s.visits[m.key]; rec != nil && !rec.ending {
			s.endVisitRec(rec, "agent attaches to the relay")
		}
	case visitSet:
		s.visitSet(m)
	case joinMsg:
		s.vjoin(m)
	case leaveMsg:
		s.vleave(m)
	case vjoinDone:
		if m.err == nil {
			s.vjoined[m.id] = true
		}
		s.up.send(joinedMsg{id: m.id, err: m.err})
	case vleaveDone:
		s.up.send(leftMsg{id: m.id})
	}
}

// noRoute takes a NoRoute of the relay. With a home relay, the address goes
// through a visit of that relay. With none, the sender of a packet to the
// address gets an ICMP error.
func (s *session) noRoute(m *dp.NoRoute) {
	dst, err := netip.ParseAddr(m.GetAddress())
	if err != nil {
		return
	}
	dst = dst.Unmap()
	switch {
	case m.GetHomeRelay() == nil && s.visitor():
		s.up.send(visitNoRoute{dst})
		return
	case m.GetHomeRelay() == nil:
		s.icmp(dst)
		return
	case s.visitor() || !s.attached:
		return
	}
	addr, ok := s.routes.peerAddr(dst, s.self)
	if !ok || s.resolving[addr] {
		return
	}
	s.resolving[addr] = true
	c, vpc, ctx := s.d.client, s.d.config.GetVpc(), s.ctx
	s.task(func() any {
		ctx, cancel := context.WithTimeout(ctx, keysTimeout)
		defer cancel()
		res, err := resolve(ctx, c, vpc, addr)
		return resolved{dst, addr, res, err}
	})
}

// resolved starts a visit, or routes an address through the visit that runs,
// when the home relay answers that the address is on another relay.
func (s *session) resolved(m resolved) {
	delete(s.resolving, m.addr)
	if m.err != nil {
		slog.Warn("Failed to visit the relay of a peer", "peer", m.addr, "error", m.err)
		return
	}
	if m.res.GetReach() != dp.Reach_REACH_VISIT {
		return
	}
	ref := m.res.GetHomeRelay()
	if len(ref.GetAddresses()) == 0 {
		slog.Warn("Failed to visit the relay of a peer", "peer", m.addr, "error", "relay has no address")
		return
	}
	key := endpoint{id: ref.GetId(), addr: ref.GetAddresses()[0]}.key()
	if s.homes[key] {
		// The address of the agent on that relay reaches the peer.
		return
	}
	rec := s.visits[key]
	if rec == nil {
		rec = s.startVisitTo(key, ref)
	}
	pfx := s.routes.routeOf(m.dst, s.self)
	if _, ok := rec.routes[pfx]; ok || rec.ending {
		return
	}
	rec.routes[pfx] = m.addr
	if rec.up {
		s.routeVisit(rec, pfx)
		s.sendLinkRoutes()
	}
}

// startVisitTo starts the visit of the relay ref.
func (s *session) startVisitTo(key string, ref *dp.RelayRef) *visitRec {
	v := &visit{
		a: s.a, mb: newMailbox(), up: s.mb, key: key, ref: ref,
		vp: &visitParams{
			b: s.b, link: s.link, self: s.self, prefixes: s.prefixes, grant: s.grant,
			home: s.d.client, homeAddr: s.addr(), homeRoots: s.d.roots, roots: s.a.rootsOf(), extras: s.extrasCopy(),
		},
	}
	v.ctx, v.cancel = context.WithCancel(s.ctx)
	rec := &visitRec{v: v, key: key, routes: map[netip.Prefix]netip.Addr{}, joined: map[string]bool{}}
	s.visits[key] = rec
	go v.run()
	if s.visitTk == nil {
		s.visitTk = time.NewTicker(s.a.visitCheck)
	}
	return rec
}

// recOf returns the record of v, or nil.
func (s *session) recOf(v *visit) *visitRec {
	if rec := s.visits[v.key]; rec != nil && rec.v == v {
		return rec
	}
	return nil
}

// toVisit gives m to the visit whose visitor peer is p.
func (s *session) toVisit(p *psp.Peer, m any) {
	for _, rec := range s.visits {
		if rec.peer == p {
			rec.v.mb.send(m)
			return
		}
	}
}

func (s *session) visitUp(m visitUp) {
	rec := s.recOf(m.v)
	if rec == nil || rec.ending {
		return
	}
	rec.up, rec.peer, rec.name, rec.extras = true, m.peer, m.name, m.extras
	for _, id := range m.joined {
		if s.byID[id] != nil {
			rec.joined[id] = true
		} else {
			// The attachment left during the setup of the visit.
			m.v.mb.send(leaveMsg{id})
		}
	}
	// An attachment that came during the setup joins now.
	if rec.extras {
		for _, x := range s.extras {
			if !rec.joined[x.id] {
				m.v.mb.send(joinMsg{x: *x})
			}
		}
	}
	s.up.send(visitorPeer{s: s, peer: m.peer})
	for pfx := range rec.routes {
		s.routeVisit(rec, pfx)
	}
	slog.Info("Started a visit", "relay", rec.name, "address", s.self)
	s.sendLinkRoutes()
}

// joined takes the answer of a visit to a joinMsg.
func (s *session) joined(m joinedMsg) {
	rec := s.recOf(m.v)
	switch {
	case m.err != nil:
		slog.Warn("Failed to put an attachment in a visit; the visited relay does not route it", "attachment", m.id, "error", m.err)
	case s.byID[m.id] == nil:
		// The attachment left during the join.
		m.v.mb.send(leaveMsg{m.id})
	case rec != nil:
		rec.joined[m.id] = true
	}
	for j := range s.joining {
		if j.x.id == m.id {
			delete(j.joins, m.v)
		}
	}
	s.joinProgress()
}

// routeVisit routes pfx to the visitor peer of rec, so that the packets to
// it go through the visit.
func (s *session) routeVisit(rec *visitRec, pfx netip.Prefix) {
	if err := s.b.AddRoute(pfx, rec.peer); err != nil {
		slog.Warn("Failed to route an address through a visit", "relay", rec.name, "prefix", pfx, "error", err)
		delete(rec.routes, pfx)
	}
}

// checkVisits asks the home relay for the addresses of each visit.
func (s *session) checkVisits() {
	c, vpc, ctx := s.d.client, s.d.config.GetVpc(), s.ctx
	for _, rec := range s.visits {
		if !rec.up || rec.ending || rec.checking > 0 {
			continue
		}
		for pfx, addr := range rec.routes {
			rec.checking++
			s.task(func() any {
				ctx, cancel := context.WithTimeout(ctx, keysTimeout)
				defer cancel()
				// The visit route ends when the home relay reaches the address again.
				res, err := resolve(ctx, c, vpc, addr)
				return visitChecked{rec, pfx, err == nil && reachable(res)}
			})
		}
	}
}

// visitChecked moves an address back from a visit when the home relay reaches
// it. A visit with no address left ends.
func (s *session) visitChecked(m visitChecked) {
	rec := m.rec
	if s.visits[rec.key] != rec || rec.ending {
		return
	}
	rec.checking--
	if _, ok := rec.routes[m.pfx]; ok && m.ok {
		delete(rec.routes, m.pfx)
		s.b.RemoveRoute(m.pfx, rec.peer)
		slog.Info("Moved an address back from a visit", "prefix", m.pfx, "relay", rec.name)
		s.sendLinkRoutes()
	}
	if rec.checking == 0 && len(rec.routes) == 0 {
		s.endVisitRec(rec, "home relay reaches the peers again")
	}
}

// endVisitRec removes the routes of a visit, then ends it.
func (s *session) endVisitRec(rec *visitRec, reason string) {
	rec.ending = true
	for pfx := range rec.routes {
		if rec.up {
			s.b.RemoveRoute(pfx, rec.peer)
		}
	}
	clear(rec.routes)
	rec.v.mb.send(endMsg{})
	slog.Info("Ended a visit", "relay", cmp.Or(rec.name, rec.key), "reason", reason)
	s.sendLinkRoutes()
}

// visitEnded forgets an ended visit.
func (s *session) visitEnded(m vEnded) {
	rec := s.recOf(m.v)
	if rec == nil {
		return
	}
	delete(s.visits, rec.key)
	if len(s.visits) == 0 && s.visitTk != nil {
		s.visitTk.Stop()
		s.visitTk = nil
	}
	if s.ending {
		return
	}
	if rec.up {
		for pfx := range rec.routes {
			s.b.RemoveRoute(pfx, rec.peer)
		}
	}
	if p := cmp.Or(rec.peer, m.peer); p != nil {
		s.up.send(visitorGone{s: s, peer: p})
	}
	switch {
	case rec.ending:
	case rec.up:
		slog.Info("Ended a visit", "relay", rec.name, "reason", "relay session ended", "error", m.err)
	default:
		slog.Warn("Failed to visit the relay of a peer", "relay", rec.key, "error", m.err)
	}
	for j := range s.joining {
		delete(j.joins, m.v)
	}
	for _, dj := range s.detaching {
		delete(dj.leaves, m.v)
	}
	s.joinProgress()
	s.detachProgress()
	s.sendLinkRoutes()
}

// sendLinkRoutes gives the root the routes of the visits.
func (s *session) sendLinkRoutes() {
	if s.visitor() {
		return
	}
	var out []Route
	for _, rec := range s.visits {
		if !rec.up {
			continue
		}
		for pfx := range rec.routes {
			out = append(out, Route{Dst: routeDst(pfx), Via: rec.name, Dev: rec.name, Src: s.self.String()})
		}
	}
	s.up.send(linkRoutes{s, out})
}

// icmp sends an ICMP error to the sender of a packet to dst after a NoRoute
// with no home relay. The code shows whether a Permit denies dst.
func (s *session) icmp(dst netip.Addr) {
	if s.b == nil || s.link == nil {
		return
	}
	head := s.b.TakeHead(s.link, dst, time.Now())
	if head == nil {
		return
	}
	c, vpc, ctx := s.d.client, s.d.config.GetVpc(), s.ctx
	s.task(func() any {
		ctx, cancel := context.WithTimeout(ctx, keysTimeout)
		defer cancel()
		_, err := resolve(ctx, c, vpc, dst)
		return icmpReady{head, rpc.CodeOf(err) == rpc.PermissionDenied}
	})
}

func (v *visit) run() {
	v.dial()
	for !v.ending || v.tasks > 0 || v.h != nil {
		<-v.mb.wake
		for _, m := range v.mb.take() {
			v.handle(m)
		}
	}
	v.up.send(vEnded{v, v.err, v.peer})
}

func (v *visit) task(f func() any) {
	v.tasks++
	mb := v.mb
	go func() { mb.send(taskDone{f()}) }()
}

// dial dials the relay of the visit: its addresses in order.
func (v *visit) dial() {
	a, ctx, ref, roots := v.a, v.ctx, v.ref, v.vp.roots
	v.task(func() any {
		ctx, cancel := context.WithTimeout(ctx, openTimeout)
		defer cancel()
		errs := []error{errors.New("relay has no address")}
		for i, e := range refEndpoints([]*dp.RelayRef{ref}) {
			if i == 0 {
				errs = nil
			}
			d, err := a.dial(ctx, e, roots, true)
			if err == nil {
				return visitDialed{d: d}
			}
			errs = append(errs, fmt.Errorf("relay %s: %w", e.addr, err))
		}
		return visitDialed{err: errors.Join(errs...)}
	})
}

func (v *visit) end(err error) {
	if v.ending {
		return
	}
	v.ending, v.err = true, err
	v.cancel()
	if v.h != nil {
		v.h.mb.send(endMsg{})
	}
}

func (v *visit) handle(m any) {
	switch m := m.(type) {
	case taskDone:
		v.tasks--
		v.handle(m.m)
	case visitDialed:
		switch {
		case m.err != nil:
			v.end(m.err)
		case v.ending:
			m.d.close("visit ended")
		default:
			v.h = newSession(v.a, v.ctx, v.mb, m.d, 0, v.vp)
			go v.h.run()
			for _, q := range v.queue {
				v.h.mb.send(q)
			}
			v.queue = nil
		}
	case endMsg:
		v.end(nil)
	case sessEnded:
		if m.s != v.h {
			return
		}
		v.h = nil
		v.peer = cmp.Or(v.peer, m.peer)
		v.end(cmp.Or(m.err, errSessionClosed))
	case visitUp:
		v.peer, m.v = m.peer, v
		v.up.send(m)
	case joinedMsg:
		m.v = v
		v.up.send(m)
	case leftMsg:
		m.v = v
		v.up.send(m)
	case joinMsg, leaveMsg, rekeyMsg, appliedMsg, clampedMsg:
		switch {
		case v.h != nil:
			v.h.mb.send(m)
		case !v.ending:
			v.queue = append(v.queue, m)
		}
	default:
		v.up.send(m)
	}
}

// startVisit starts the Visit call of a visitor session with the grant and the
// address of its home, and joins the extra attachments.
func (s *session) startVisit() {
	vp, c, qc, vpc, ctx := s.vp, s.d.client, s.d.qc, s.d.config.GetVpc(), s.ctx
	extras := s.d.relayAtLeast(visitExtras)
	addr := s.addr()
	s.task(func() any {
		ctx, cancel := context.WithTimeout(ctx, openTimeout)
		defer cancel()
		// A relay that does not answer in time ends the visit.
		stop := context.AfterFunc(ctx, func() { _ = qc.CloseWithError(0, "visit did not start in time") })
		defer stop()
		grant, err := vp.grant.get(ctx, vp.home, vp.homeAddr, vp.homeRoots)
		if err != nil {
			return visitSet{err: fmt.Errorf("visit: %w", err)}
		}
		if _, err := c.Visit(ctx, &dp.VisitRequest{Vpc: vpc, Address: vp.self.String(), Grant: grant}); err != nil {
			return visitSet{err: attachError(qc, fmt.Errorf("visit: %w", err))}
		}
		if !extras {
			return visitSet{}
		}
		return visitSet{extras: true, joined: joinAll(ctx, c, vpc, vp, addr)}
	})
}

// joinAll puts the extra attachments of vp in the visit on c, at most
// visitCalls at once. It returns the IDs that joined.
func joinAll(ctx context.Context, c dp.RelayClient, vpc *dp.VPCRef, vp *visitParams, addr string) []string {
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		joined []string
		failed int
		first  error
	)
	calls := make(chan struct{}, visitCalls)
	for _, x := range vp.extras {
		calls <- struct{}{}
		wg.Go(func() {
			defer func() { <-calls }()
			err := joinVisit(ctx, c, vpc, vp, x)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				first = cmp.Or(first, err)
				return
			}
			joined = append(joined, x.id)
		})
	}
	wg.Wait()
	if failed > 0 {
		slog.Warn("Failed to put extra attachments in a visit; the visited relay does not route them",
			"relay", addr, "failed", failed, "attachments", len(vp.extras), "error", first)
	}
	return joined
}

// joinVisit runs Visit on c for each prefix of x. After an error, the relay
// can have a part of the prefixes, so the attachment leaves the visit.
func joinVisit(ctx context.Context, c dp.RelayClient, vpc *dp.VPCRef, vp *visitParams, x extra) error {
	grant, err := x.grant.get(ctx, vp.home, vp.homeAddr, vp.homeRoots)
	for _, p := range x.prefixes {
		if err != nil {
			break
		}
		_, err = c.Visit(ctx, &dp.VisitRequest{Vpc: vpc, Address: relay.OverlayAddr(p).String(), Grant: grant})
	}
	if err != nil {
		_ = detach(ctx, c, x.id)
		return fmt.Errorf("visit with attachment %s: %w", x.spec.Name, err)
	}
	return nil
}

// visitSet makes the relay peer of a visitor session on the link of its home
// after the Visit call.
func (s *session) visitSet(m visitSet) {
	if m.err != nil {
		s.end(m.err)
		return
	}
	vp := s.vp
	p, err := vp.link.AddRelay(s.d.relayAddr)
	if err != nil {
		s.end(err)
		return
	}
	s.b, s.link, s.self, s.prefixes, s.peer = vp.b, vp.link, vp.self, vp.prefixes, p
	// The packets for the addresses of the visit go as data frames on s.
	if err := s.useConn(); err != nil {
		s.end(err)
		return
	}
	s.attached = true
	for _, id := range m.joined {
		s.vjoined[id] = true
	}
	s.up.send(visitUp{peer: p, name: s.d.name, extras: m.extras, joined: m.joined})
	for _, q := range s.vqueue {
		s.handle(q)
	}
	s.vqueue = nil
	s.takePending()
}

// vjoin puts an extra attachment in the visit of a visitor session.
func (s *session) vjoin(m joinMsg) {
	if !s.attached {
		s.vqueue = append(s.vqueue, m)
		return
	}
	c, vpc, vp, ctx := s.d.client, s.d.config.GetVpc(), s.vp, s.ctx
	s.task(func() any {
		ctx, cancel := context.WithTimeout(ctx, openTimeout)
		defer cancel()
		return vjoinDone{m.x.id, joinVisit(ctx, c, vpc, vp, m.x)}
	})
}

// vleave removes an extra attachment from the visit of a visitor session.
func (s *session) vleave(m leaveMsg) {
	if !s.attached {
		s.vqueue = append(s.vqueue, m)
		return
	}
	if !s.vjoined[m.id] {
		s.up.send(leftMsg{id: m.id})
		return
	}
	delete(s.vjoined, m.id)
	c, ctx := s.d.client, s.ctx
	s.task(func() any {
		ctx, cancel := context.WithTimeout(ctx, openTimeout)
		defer cancel()
		_ = detach(ctx, c, m.id)
		return vleaveDone{m.id}
	})
}
