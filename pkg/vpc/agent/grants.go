// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// grantRefreshAge is the age of a stored grant from which the agent gets a
// new one before it sends a grant. See relay.GrantLife for the clock difference.
const grantRefreshAge = relay.GrantLife / 3

// ownGrant is the grant of one attachment of this agent. The agent sends it
// to visited relays, which check it one time.
type ownGrant struct {
	id  string
	cur *dp.AttachmentGrant
	got time.Time // When the agent got cur.
}

func newOwnGrant(g *dp.AttachmentGrant, id string) ownGrant {
	return ownGrant{id: id, cur: g, got: time.Now()}
}

// get returns the stored grant while its age is below grantRefreshAge, else a
// new one from the relay of c at addr. The age is elapsed time of this host,
// so no clock matters.
func (g ownGrant) get(ctx context.Context, c dp.RelayClient, addr string, roots *x509.CertPool) (*dp.AttachmentGrant, error) {
	if time.Since(g.got) < grantRefreshAge {
		return g.cur, nil
	}
	res, err := c.Grant(ctx, &dp.GrantRequest{AttachmentId: g.id})
	if err != nil {
		return nil, fmt.Errorf("new grant of attachment %s: %w", g.id, err)
	}
	if _, err := verifyOwn(addr, roots, res.GetGrant()); err != nil {
		return nil, fmt.Errorf("new grant of attachment %s: %w", g.id, err)
	}
	return res.GetGrant(), nil
}

// verifyOwn checks a grant that the relay at addr signed for this agent now.
// It has ended only if the clock of this host or of the relay is wrong.
func verifyOwn(addr string, roots *x509.CertPool, g *dp.AttachmentGrant) (*dp.GrantClaims, error) {
	now := time.Now()
	claims, err := relay.VerifyGrant(g, roots, now)
	if errors.Is(err, relay.ErrGrantEnded) {
		slog.Error("A grant that the relay signed in this moment has ended; the clock of this host or of the relay is wrong",
			"relay", addr, "host_time", now.UTC().Format(time.RFC3339), "error", err)
	}
	return claims, err
}

// extra is an attachment of this agent on a relay session, other than the
// attachment of Config.
type extra struct {
	spec     *AttachmentSpec
	id       string
	grant    ownGrant
	prefixes []netip.Prefix
}

// xjob is an attachX in a home session: queued, in its Attach call, or
// waiting for the joins of the visits.
type xjob struct {
	spec     *AttachmentSpec
	ctx      context.Context
	x        *extra
	detached bool // A detachX came during the Attach call.
	joins    map[*visit]bool
}

// djob is a detachX in a home session after its Detach call started.
type djob struct {
	spec    *AttachmentSpec
	id      string
	running bool
	leaves  map[*visit]bool
}

// xattached is the result of the Attach call of an xjob.
type xattached struct {
	j   *xjob
	x   *extra
	err error
}

// xdetached is the result of a Detach call: of a djob, or of the xjob of a
// spec that Detach forgot during its Attach call.
type xdetached struct {
	j   *xjob
	dj  *djob
	err error
}

// handleExtras takes the messages of the extra attachments and the visits.
func (s *session) handleExtras(m any) {
	switch m := m.(type) {
	case attachX:
		s.queue = append(s.queue, &xjob{spec: m.spec, ctx: m.ctx})
		s.admit()
	case cancelX:
		s.queue = slices.DeleteFunc(s.queue, func(j *xjob) bool {
			if j.spec != m.spec {
				return false
			}
			err := context.Canceled
			if j.ctx != nil && j.ctx.Err() != nil {
				err = j.ctx.Err()
			}
			s.up.send(attachedX{s: s, spec: j.spec, err: err})
			return true
		})
	case detachX:
		s.detachExtra(m)
	case xattached:
		s.xattached(m)
	case xdetached:
		s.xdetached(m)
	default:
		s.handleVisits(m)
	}
}

// admit starts the Attach calls of queued specs, at most maxInFlight at once.
// A spec whose caller stopped to wait gets the error of its context.
func (s *session) admit() {
	for len(s.running) < maxInFlight && len(s.queue) > 0 {
		j := s.queue[0]
		s.queue = s.queue[1:]
		if j.ctx != nil && j.ctx.Err() != nil {
			s.up.send(attachedX{s: s, spec: j.spec, err: j.ctx.Err()})
			continue
		}
		s.running[j] = true
		s.attachCall(j)
	}
}

// attachCall starts the Attach call of j. It runs under the session with
// openTimeout, not under the context of the caller.
func (s *session) attachCall(j *xjob) {
	sp := j.spec
	c, qc, addr, roots, ctx := s.d.client, s.d.qc, s.addr(), s.d.roots, s.ctx
	req := &dp.AttachRequest{Vpc: s.d.config.GetVpc(), Name: sp.Name, Labels: sp.Labels, Routes: prefixStrings(sp.Routes), Rank: s.rank}
	s.task(func() any {
		ctx, cancel := context.WithTimeout(ctx, openTimeout)
		defer cancel()
		res, err := c.Attach(ctx, req)
		if err != nil {
			return xattached{j: j, err: attachError(qc, fmt.Errorf("attach: %w", err))}
		}
		logRefused(addr, sp.Name, res.GetRoutes())
		claims, err := verifyOwn(addr, roots, res.GetGrant())
		if err != nil {
			return xattached{j: j, err: err}
		}
		prefixes, err := parsePrefixes(claims.GetAddresses())
		if err != nil {
			return xattached{j: j, err: err}
		}
		id := claims.GetAttachmentId()
		return xattached{j: j, x: &extra{spec: sp, id: id, grant: newOwnGrant(res.GetGrant(), id), prefixes: prefixes}}
	})
}

func (s *session) xattached(m xattached) {
	j := m.j
	delete(s.running, j)
	defer s.admit()
	switch {
	case m.err != nil:
		s.up.send(attachedX{s: s, spec: j.spec, err: m.err})
		return
	case j.detached:
		// Detach forgot the spec during the call, so the attachment goes again.
		s.detachCall(m.x.id, nil, xdetached{j: j})
		return
	}
	x := m.x
	j.x = x
	// Routes of the attachment that came before leave the route table.
	if removed := s.routes.drop(x.id); len(removed) > 0 {
		s.up.send(routesMsg{s: s, remove: removed})
	}
	for _, pfx := range x.prefixes {
		if err := s.link.AddSource(pfx); err != nil {
			slog.Warn("Failed to send from the address of an attachment", "name", x.spec.Name, "prefix", pfx, "error", err)
		}
	}
	s.extras[x.spec.Name], s.byID[x.id] = x, x
	// The visits take the new attachment too.
	j.joins = map[*visit]bool{}
	for _, rec := range s.visits {
		if rec.up && rec.extras {
			rec.v.mb.send(joinMsg{x: *x})
			j.joins[rec.v] = true
		}
	}
	if len(j.joins) > 0 {
		s.joining[j] = true
		return
	}
	s.attachedOK(j)
}

// attachedOK gives the root the attachment of j.
func (s *session) attachedOK(j *xjob) {
	s.up.send(attachedX{s: s, spec: j.spec, at: s.attachmentOf(j.x)})
}

// attachmentOf returns the extra attachment x of s.
func (s *session) attachmentOf(x *extra) Attachment {
	at := x.spec.attachment()
	at.ID, at.Address, at.Prefixes, at.Relay = x.id, overlayAddr(x.prefixes), slices.Clone(x.prefixes), s.addr()
	return at
}

// detachExtra takes a detachX. A spec that waits or that is in its Attach call
// has nothing at the relay yet, so the answer goes at once.
func (s *session) detachExtra(m detachX) {
	name := m.spec.Name
	if i := slices.IndexFunc(s.queue, func(j *xjob) bool { return j.spec == m.spec }); i >= 0 {
		s.queue = slices.Delete(s.queue, i, i+1)
		s.up.send(attachedX{s: s, spec: m.spec, err: fmt.Errorf("%w: %s", ErrNoAttachment, name)})
		s.up.send(detachedX{s, m.spec})
		return
	}
	for j := range s.running {
		if j.spec == m.spec {
			j.detached = true
			s.up.send(detachedX{s, m.spec})
			return
		}
	}
	for j := range s.joining {
		if j.spec == m.spec {
			delete(s.joining, j)
			s.attachedOK(j)
		}
	}
	x := s.extras[name]
	if x == nil || x.spec != m.spec {
		s.up.send(detachedX{s, m.spec})
		return
	}
	delete(s.extras, name)
	delete(s.byID, x.id)
	for _, pfx := range x.prefixes {
		s.link.RemoveSource(pfx)
	}
	dj := &djob{spec: m.spec, id: x.id, running: true, leaves: map[*visit]bool{}}
	for _, rec := range s.visits {
		if rec.joined[x.id] {
			delete(rec.joined, x.id)
			rec.v.mb.send(leaveMsg{x.id})
			dj.leaves[rec.v] = true
		}
	}
	s.detaching = append(s.detaching, dj)
	s.detachCall(x.id, m.ctx, xdetached{dj: dj})
}

// detachCall starts the Detach call of the attachment id under ctx, or under
// the session when ctx is nil, with openTimeout. res is its result.
func (s *session) detachCall(id string, ctx context.Context, res xdetached) {
	c, sctx := s.d.client, s.ctx
	if ctx == nil {
		ctx = sctx
	}
	s.task(func() any {
		ctx, cancel := context.WithTimeout(ctx, openTimeout)
		defer cancel()
		stop := context.AfterFunc(sctx, cancel)
		defer stop()
		res.err = detach(ctx, c, id)
		return res
	})
}

// detach runs Detach for the attachment id. An attachment that the relay
// does not have is not an error.
func detach(ctx context.Context, c dp.RelayClient, id string) error {
	if _, err := c.Detach(ctx, &dp.DetachRequest{AttachmentId: id}); err != nil && rpc.CodeOf(err) != rpc.NotFound {
		return fmt.Errorf("detach: %w", err)
	}
	return nil
}

func (s *session) xdetached(m xdetached) {
	if m.err != nil {
		slog.Warn("Failed to detach an attachment at the relay; the relay keeps it until the session ends", "relay", s.addr(), "error", m.err)
	}
	if j := m.j; j != nil {
		s.up.send(attachedX{s: s, spec: j.spec, err: fmt.Errorf("%w: %s", ErrNoAttachment, j.spec.Name)})
		return
	}
	m.dj.running = false
	s.detachProgress()
}

// detachProgress answers each djob whose call and leaves ended.
func (s *session) detachProgress() {
	s.detaching = slices.DeleteFunc(s.detaching, func(dj *djob) bool {
		if dj.running || len(dj.leaves) > 0 {
			return false
		}
		s.up.send(detachedX{s, dj.spec})
		return true
	})
}

// joinProgress answers each xjob whose joins ended.
func (s *session) joinProgress() {
	for j := range s.joining {
		if len(j.joins) == 0 {
			delete(s.joining, j)
			s.attachedOK(j)
		}
	}
}

// extrasCopy returns copies of the extra attachments of s.
func (s *session) extrasCopy() []extra {
	var out []extra
	for _, x := range slices.Collect(maps.Values(s.extras)) {
		out = append(out, *x)
	}
	return out
}
