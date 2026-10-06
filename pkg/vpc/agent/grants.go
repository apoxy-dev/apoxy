// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// maxGrants is the most grants in one Open or Grants call. A grant with its
// relay chain is about 1.5 KB.
const maxGrants = 256

// extra is an attachment of this agent on a relay session, other than the
// attachment of Config.
type extra struct {
	spec     *AttachmentSpec
	id       string
	grant    *dp.AttachmentGrant
	prefixes []netip.Prefix
}

// attachExtra runs Attach on rc for s and checks the grant.
func (rc *relayConn) attachExtra(ctx context.Context, s *AttachmentSpec) (*extra, error) {
	res, err := rc.c.Attach(ctx, &dp.AttachRequest{Vpc: rc.ref, Name: s.Name, Labels: s.Labels, Routes: prefixStrings(s.Routes)})
	if err != nil {
		return nil, attachError(rc, fmt.Errorf("attach: %w", err))
	}
	claims, err := relay.VerifyGrant(res.GetGrant(), rc.roots, time.Now())
	if err != nil {
		return nil, err
	}
	prefixes, err := parsePrefixes(claims.GetAddresses())
	if err != nil {
		return nil, err
	}
	return &extra{spec: s, id: claims.GetAttachmentId(), grant: res.GetGrant(), prefixes: prefixes}, nil
}

// addExtra adds x to rc and queues its grant for the peers on rc. Routes of x
// that came before leave the route table of rc. a.attMu must be held.
func (a *Agent) addExtra(rc *relayConn, x *extra) {
	a.routeMu.Lock()
	defer a.routeMu.Unlock()
	removed := rc.routes.drop(x.id)
	a.mu.Lock()
	if rc.extras == nil {
		rc.extras = map[string]*extra{}
	}
	rc.extras[x.id] = x
	for _, p := range a.peers {
		if p.rc == rc {
			p.queueGrants(x, "")
		}
	}
	a.mu.Unlock()
	if a.routesOf == rc {
		a.report(nil, slices.DeleteFunc(removed, func(p netip.Prefix) bool { return !a.reported[p] }))
	}
}

// detachExtra runs Detach on rc for the attachment id. An attachment that the
// relay does not have is not an error.
func (rc *relayConn) detachExtra(ctx context.Context, id string) error {
	if _, err := rc.c.Detach(ctx, &dp.DetachRequest{AttachmentId: id}); err != nil && rpc.CodeOf(err) != rpc.NotFound {
		return fmt.Errorf("detach: %w", err)
	}
	return nil
}

// removeExtra removes the attachment id from rc and queues the remove for the
// peers on rc. It returns nil if rc has no such attachment. a.attMu must be held.
func (a *Agent) removeExtra(rc *relayConn, id string) *extra {
	a.routeMu.Lock()
	defer a.routeMu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	x := rc.extras[id]
	if x == nil {
		return nil
	}
	delete(rc.extras, id)
	for _, p := range a.peers {
		if p.rc == rc {
			p.queueGrants(nil, id)
		}
	}
	return x
}

// ownOrigin reports whether origin is an attachment of this agent on rc. The
// caller holds a.routeMu or a.mu.
func (rc *relayConn) ownOrigin(origin string) bool {
	return origin == rc.attachmentID || rc.extras[origin] != nil
}

// ownAddr reports whether an attachment of this agent on rc has addr. The
// caller holds a.mu.
func (rc *relayConn) ownAddr(addr netip.Addr) bool {
	has := func(p netip.Prefix) bool { return p.Contains(addr) }
	if slices.ContainsFunc(rc.prefixes, has) {
		return true
	}
	for _, x := range rc.extras {
		if slices.ContainsFunc(x.prefixes, has) {
			return true
		}
	}
	return false
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

// openGrants returns the grants for the Open call of p, at most maxGrants.
// The others go to p after Open. a.mu must be held.
func (a *Agent) openGrants(p *peer) []*dp.AttachmentGrant {
	var out []*dp.AttachmentGrant
	for _, x := range p.rc.extras {
		if len(out) < maxGrants {
			out = append(out, x.grant)
		} else {
			p.queueGrants(x, "")
		}
	}
	return out
}

// queueGrants queues an added grant or a removed attachment ID for the peer,
// and starts the sender if it does not run. a.mu must be held.
func (p *peer) queueGrants(add *extra, remove string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.noGrants {
		return
	}
	if p.sendAdd == nil {
		p.sendAdd, p.sendRemove = map[string]*dp.AttachmentGrant{}, map[string]bool{}
	}
	if add != nil {
		delete(p.sendRemove, add.id)
		p.sendAdd[add.id] = add.grant
	} else {
		// The peer can have the grant from Open, so the remove always goes.
		delete(p.sendAdd, remove)
		p.sendRemove[remove] = true
	}
	if !p.sending {
		p.sending = true
		go p.sendGrants()
	}
}

// sendGrants sends the queued grant changes to the peer, one call at a time,
// until the queue is empty. On an error it closes the peer session. A peer
// that does not serve Grants keeps its session and gets no more changes.
func (p *peer) sendGrants() {
	select {
	case <-p.ready:
	case <-p.qc.Context().Done():
		return
	}
	for {
		p.mu.Lock()
		req := &dp.GrantsRequest{}
		for id, g := range p.sendAdd {
			if len(req.Add) == maxGrants {
				break
			}
			req.Add = append(req.Add, g)
			delete(p.sendAdd, id)
		}
		for id := range p.sendRemove {
			req.Remove = append(req.Remove, id)
			delete(p.sendRemove, id)
		}
		if len(req.Add)+len(req.Remove) == 0 {
			p.sending = false
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()
		ctx, cancel := context.WithTimeout(p.rc.ctx, keysTimeout)
		_, err := p.client.Grants(ctx, req)
		cancel()
		if rpc.CodeOf(err) == rpc.Unimplemented {
			p.mu.Lock()
			p.noGrants, p.sending, p.sendAdd, p.sendRemove = true, false, nil, nil
			p.mu.Unlock()
			slog.Info("Peer does not serve grant changes; it gets only the grants of Open", "peer", p.subject)
			return
		}
		if err != nil {
			if p.qc.Context().Err() == nil {
				slog.Warn("Failed to send grants to a peer; closing the peer session", "peer", p.subject, "error", err)
				_ = p.qc.CloseWithError(0, "grant change failed")
			}
			return
		}
	}
}

// addGrants checks the grants of the other attachments of the peer, and routes
// their prefixes to it. It skips the grants that fail and returns their errors.
func (a *Agent) addGrants(p *peer, gs []*dp.AttachmentGrant) error {
	if len(gs) == 0 {
		return nil
	}
	type grant struct {
		id       string
		prefixes []netip.Prefix
	}
	var errs []error
	var ok []grant
	for _, g := range gs {
		claims, prefixes, err := a.checkGrant(p, g)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ok = append(ok, grant{claims.GetAttachmentId(), prefixes})
	}
	a.routeMu.Lock()
	defer a.routeMu.Unlock()
	vpc := tunnet.NetworkPrefixOf(p.rc.self)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.peers[p.conn] != p || p.bp == nil {
		return errors.Join(append(errs, errors.New("peer session is closed"))...)
	}
	for _, g := range ok {
		if g.id == p.attachmentID() || p.extra[g.id] != nil {
			continue
		}
		if err := a.routeGrant(p, g.prefixes); err != nil {
			errs = append(errs, fmt.Errorf("attachment %s: %w", g.id, err))
			continue
		}
		if p.extra == nil {
			p.extra = map[string][]netip.Prefix{}
		}
		p.extra[g.id] = g.prefixes
		for pfx, origin := range p.rc.routes.origins {
			if origin == g.id {
				a.addAdvertised(p, pfx, vpc)
			}
		}
		close(a.admitted)
		a.admitted = make(chan struct{})
	}
	return errors.Join(errs...)
}

// waitGrant returns the peer session on rc that covers dst. When dst is another
// attachment of an open peer with subject, its grant can come after its route,
// so waitGrant waits for it up to duplicateWait. Else it returns nil.
func (a *Agent) waitGrant(ctx context.Context, rc *relayConn, dst netip.Addr, subject string) *peer {
	if subject == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, duplicateWait)
	defer cancel()
	for {
		a.mu.Lock()
		p, admitted := a.peerTo(rc, dst), a.admitted
		open := false
		for _, q := range a.peers {
			if q.rc == rc && q.subject == subject && q.bp != nil && q.qc.Context().Err() == nil {
				open = true
				break
			}
		}
		a.mu.Unlock()
		if p != nil || !open {
			return p
		}
		select {
		case <-admitted:
		case <-rc.ctx.Done():
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// routeGrant routes prefixes to p. It routes all of them or none. a.mu must
// be held.
func (a *Agent) routeGrant(p *peer, prefixes []netip.Prefix) error {
	for i, pfx := range prefixes {
		if err := a.bind.AddRoute(pfx, p.bp); err != nil {
			if p.quic {
				a.unrouteQUIC(p, prefixes[:i])
			} else {
				for _, q := range prefixes[:i] {
					a.bind.RemoveRoute(q, p.bp)
				}
			}
			return fmt.Errorf("route %s: %w", pfx, err)
		}
	}
	return nil
}

// removeGrants removes the routes of the attachments ids of the peer.
func (a *Agent) removeGrants(p *peer, ids []string) {
	a.routeMu.Lock()
	defer a.routeMu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, id := range ids {
		a.dropGrant(p, id)
	}
}

// dropGrant removes the routes of the attachment id of the peer. a.routeMu
// and a.mu must be held.
func (a *Agent) dropGrant(p *peer, id string) {
	prefixes, ok := p.extra[id]
	if !ok {
		return
	}
	delete(p.extra, id)
	if a.peers[p.conn] != p || p.bp == nil {
		return
	}
	if len(p.advertised) > 0 {
		for pfx, origin := range p.rc.routes.origins {
			if origin == id {
				a.removeAdvertised(p, pfx)
			}
		}
	}
	if p.quic {
		a.unrouteQUIC(p, prefixes)
	} else {
		for _, pfx := range prefixes {
			a.bind.RemoveRoute(pfx, p.bp)
		}
	}
}

// Grants applies a grant change from the peer, after the grants of Open.
func (s *peerService) Grants(ctx context.Context, in *dp.GrantsRequest) (*emptypb.Empty, error) {
	p := s.a.peerOf(ctx)
	if p == nil {
		return nil, rpc.Errorf(rpc.Unauthenticated, "no peer session")
	}
	select {
	case <-p.granted:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	s.a.removeGrants(p, in.GetRemove())
	if err := s.a.addGrants(p, in.GetAdd()); err != nil {
		slog.Warn("Refused grants of a peer", "peer", p.subject, "error", err)
	}
	return &emptypb.Empty{}, nil
}

// grantsOfOpen applies the grants that came in Open, after admit, and lets
// Grants calls of the peer run.
func (a *Agent) grantsOfOpen(p *peer, gs []*dp.AttachmentGrant) {
	if err := a.addGrants(p, gs); err != nil {
		slog.Warn("Refused grants of a peer", "peer", p.subject, "error", err)
	}
	close(p.granted)
}
