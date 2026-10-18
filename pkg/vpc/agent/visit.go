// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// maxVisits is the most visitor sessions of one agent.
	maxVisits = 2
	// visitExtras is the first revision of a relay that takes a Visit call for
	// each extra attachment on one visitor session.
	visitExtras = 15
	// visitCalls is the most Visit calls for extra attachments that run at once
	// on a new visitor session.
	visitCalls = 16
	// visitCheck is the interval at which the agent asks its relay for the
	// peers of a visit, to move them back when the relay reaches them again.
	visitCheck = 10 * time.Second
	// visitAsk is the interval at which an agent that waits for the visit of a
	// peer asks its relay again.
	visitAsk = time.Second
	// visitWait is the time that the agent with the higher address waits for the
	// peer session of the visit of its peer, before it visits too.
	visitWait = 2 * time.Second
)

var (
	errVisitLimit = errors.New("agent has the most visitor sessions")
	errPeerVisits = errors.New("peer has the lower address and did not visit this relay yet")
)

// visit is one visitor session: a session on the relay of peers that the relay
// of this agent cannot reach. The agent keeps its address on that session.
type visit struct {
	key  string        // Relay of the visit.
	home *relayConn    // Attached session whose grant the visit uses.
	done chan struct{} // Closed when the setup ends.
	// rc and err are set before done closes. rc is nil after a failed setup.
	rc  *relayConn
	err error
	// users counts the callers that open a peer session on the visit now.
	// Guarded by Agent.mu.
	users int
	// routes are the prefixes that route to the relay of the visit, on the
	// link of home. Guarded by Agent.mu.
	routes []netip.Prefix
}

// session returns the visitor session after its setup, or nil.
func (v *visit) session() *relayConn {
	select {
	case <-v.done:
		return v.rc
	default:
		return nil
	}
}

// visits reports whether the agent with the address self visits first to reach
// peer. The agent with the higher address visits only after visitWait.
func visits(self, peer netip.Addr) bool {
	return self.Compare(peer) < 0
}

// keeps reports whether a peer session on rc with the agent at peer stays when
// the two agents visit: the one on the relay of the agent with the higher address.
func keeps(rc *relayConn, peer netip.Addr) bool {
	return rc.visitor() == visits(rc.self, peer)
}

// reachable reports whether the relay that gave res reaches the peer, so that
// no visit is necessary.
func reachable(res *dp.ResolvePeerResponse) bool {
	return res.GetReach() == dp.Reach_REACH_LOCAL || res.GetReach() == dp.Reach_REACH_TRUNK
}

// noRoute applies a NoRoute of rc. With a home relay, the peer sessions stay
// with the path down, and a visit starts. With none, the sessions close, and
// the sender of a packet to the address gets an ICMP error.
func (a *Agent) noRoute(rc *relayConn, m *dp.NoRoute) {
	dst, err := netip.ParseAddr(m.GetAddress())
	if err != nil {
		return
	}
	if m.GetHomeRelay() == nil {
		a.closePeers(func(p *peer) bool { return p.rc == rc && p.routes(dst) }, "relay has no route to the peer")
		go a.unreachable(rc, dst.Unmap())
		return
	}
	a.setDown(rc, dst.Unmap(), true)
	// The Sync reader must not wait for the visit.
	go a.visitAfterNoRoute(rc, dst.Unmap())
}

// setDown sets the path of the peer sessions on rc that route dst to down or up.
func (a *Agent) setDown(rc *relayConn, dst netip.Addr, down bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.peers {
		if p.rc == rc && p.routes(dst) {
			p.down = down
		}
	}
}

// cutFrom asks the relay of p how it reaches the open sessions of the subject of
// p. It sets the path to down on the answer REACH_VISIT, and reports that.
func (a *Agent) cutFrom(ctx context.Context, p *peer) bool {
	if p.rc.visitor() {
		return false
	}
	a.mu.Lock()
	var old []*peer
	for _, q := range a.peers {
		if q != p && q.rc == p.rc && q.bp != nil && !q.down && q.subject == p.subject {
			old = append(old, q)
		}
	}
	a.mu.Unlock()
	found := false
	for _, q := range old {
		if res, err := p.rc.resolve(ctx, q.addr); err == nil && res.GetReach() == dp.Reach_REACH_VISIT {
			a.setDown(p.rc, q.addr, true)
			found = true
		}
	}
	return found
}

// visitAfterNoRoute ends the starts to the peer of dst on rc, and visits it if
// rc still answers REACH_VISIT. If rc reaches it, its path is up again.
func (a *Agent) visitAfterNoRoute(rc *relayConn, dst netip.Addr) {
	if rc.visitor() {
		return
	}
	addr, ok := a.peerAddr(rc, dst)
	if !ok {
		return
	}
	key := startKey{rc.link, addr}
	at, ok := a.starts.renew(rc.ctx, key, dst, time.Now())
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(at.ctx, keysTimeout)
	defer cancel()
	err := a.starts.once(ctx, key, at, func() error {
		res, err := rc.resolve(ctx, addr)
		if err != nil {
			return err
		}
		if res.GetReach() != dp.Reach_REACH_VISIT {
			if reachable(res) {
				a.setDown(rc, addr, false)
			}
			return nil
		}
		return a.connectVisit(ctx, rc, addr, res.GetHomeRelay())
	})
	a.starts.end(key, at, err, time.Now(), a.retryMin, a.retryMax)
	if err != nil {
		slog.Warn("Failed to visit the relay of a peer", "peer", addr, "error", err)
	}
}

// connectVisit opens a visitor session to the relay of ref and a peer session
// on it. The agent with the higher address first waits for its peer.
func (a *Agent) connectVisit(ctx context.Context, home *relayConn, dst netip.Addr, ref *dp.RelayRef) error {
	if home.visitor() || len(ref.GetAddresses()) == 0 {
		return fmt.Errorf("relay has no path to peer %s (%v)", dst, dp.Reach_REACH_VISIT)
	}
	// The agent with the lower address visits first, so the other agent waits.
	// It does not wait again for a peer that it reaches on its own visit.
	use := a.usePeer
	if !visits(home.self, dst) && !a.visiting(home, dst) {
		use = a.awaitVisit
	}
	if ok, err := use(ctx, home, dst); ok {
		return err
	}
	v, err := a.visit(ctx, home, ref)
	if err != nil {
		return fmt.Errorf("visit relay %s for peer %s: %w", ref.GetId(), dst, err)
	}
	defer a.release(v)
	a.routeVisit(v, dst)
	// The peer opened a session as a visitor while this visit started. It stays.
	if ok, err := a.usePeer(ctx, home, dst); ok {
		return err
	}
	// A session on another relay session of the link has the routes of the peer, and
	// its path is down. The close code moves an agent that waits for it to the new session.
	a.closePeersWith(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE,
		func(q *peer) bool { return q.rc != v.rc && q.rc.link == v.rc.link && q.routes(dst) }, "peer is on a visited relay")
	return a.connect(ctx, v.rc, dst, nil)
}

// visiting reports whether a peer session that routes dst is on a visitor
// session of home.
func (a *Agent) visiting(home *relayConn, dst netip.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.peers {
		if p.rc.home == home && p.bp != nil && p.qc.Context().Err() == nil && p.routes(dst) {
			return true
		}
	}
	return false
}

// usePeer waits for the data path of the peer session on rc to dst whose path
// is not down. It reports false when the caller must visit: no such session.
func (a *Agent) usePeer(ctx context.Context, rc *relayConn, dst netip.Addr) (bool, error) {
	a.mu.Lock()
	p := a.livePeerTo(rc, dst)
	a.mu.Unlock()
	if p == nil {
		return false, nil
	}
	return true, a.waitPath(ctx, p, dst)
}

// awaitVisit is usePeer with a wait of visitWait for the session that the agent
// at dst opens as a visitor. It dials when the relay reaches dst again.
func (a *Agent) awaitVisit(ctx context.Context, rc *relayConn, dst netip.Addr) (bool, error) {
	t := time.NewTicker(a.visitAsk)
	defer t.Stop()
	wait := time.NewTimer(a.visitWait)
	defer wait.Stop()
	for {
		a.mu.Lock()
		p, admitted := a.livePeerTo(rc, dst), a.admitted
		a.mu.Unlock()
		if p != nil {
			return true, a.waitPath(ctx, p, dst)
		}
		select {
		case <-admitted:
			continue
		case <-rc.ctx.Done():
			return true, errors.New("relay session closed")
		case <-ctx.Done():
			return true, fmt.Errorf("peer %s: %w: %w", dst, errPeerVisits, ctx.Err())
		case <-wait.C:
			return false, nil
		case <-t.C:
		}
		res, err := rc.resolve(ctx, dst)
		if err != nil {
			return true, err
		}
		if reachable(res) {
			return true, a.connect(ctx, rc, dst, res)
		}
	}
}

// visit returns the visit of the relay ref with its setup done, and counts the
// caller as a user. It opens the visitor session if the agent has none there.
func (a *Agent) visit(ctx context.Context, home *relayConn, ref *dp.RelayRef) (*visit, error) {
	key := endpoint{id: ref.GetId(), addr: ref.GetAddresses()[0]}.key()
	a.mu.Lock()
	v := a.visits[key]
	if v != nil {
		v.users++
		a.mu.Unlock()
		select {
		case <-v.done:
		case <-ctx.Done():
			a.release(v)
			return nil, ctx.Err()
		}
		if v.err != nil {
			a.release(v)
			return nil, v.err
		}
		return v, nil
	}
	switch {
	case !home.live() || a.stopped:
		a.mu.Unlock()
		return nil, errNoRelay
	case slices.ContainsFunc(a.conns, func(rc *relayConn) bool { return !rc.visitor() && rc.ep.key() == key }):
		// The address of the agent on that relay reaches the peer.
		a.mu.Unlock()
		return nil, errors.New("agent has a session on the relay to visit")
	case len(a.visits) >= maxVisits:
		a.mu.Unlock()
		return nil, fmt.Errorf("%w (%d)", errVisitLimit, maxVisits)
	}
	v = &visit{key: key, home: home, done: make(chan struct{}), users: 1}
	a.visits[key] = v
	a.mu.Unlock()

	rc, err := a.openVisit(ctx, home, ref)
	a.mu.Lock()
	if err == nil && a.visits[key] != v {
		// The visit ended while its session opened.
		err = errNoRelay
	}
	if err != nil {
		if a.visits[key] == v {
			delete(a.visits, key)
		}
	} else {
		v.rc, rc.state = rc, connAttached
	}
	v.err = err
	a.mu.Unlock()
	close(v.done)
	if err != nil {
		if rc != nil {
			a.end(rc)
		}
		return nil, err
	}
	slog.Info("Started a visit", "relay", rc.addr, "address", rc.self, "transport", transportName(rc.dataMode()))
	go a.keepVisit(v, newPSPRetry(rc))
	return v, nil
}

// release ends the use of v by one caller of visit.
func (a *Agent) release(v *visit) {
	a.mu.Lock()
	v.users--
	a.mu.Unlock()
}

// openVisit opens a session to the relay ref with local routes only, and makes
// it a visitor with the grant of home.
func (a *Agent) openVisit(ctx context.Context, home *relayConn, ref *dp.RelayRef) (*relayConn, error) {
	ctx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	var errs []error
	for _, e := range refEndpoints([]*dp.RelayRef{ref}) {
		rc, err := a.dialRelay(ctx, e, home)
		if err != nil {
			errs = append(errs, fmt.Errorf("relay %s: %w", e.addr, err))
			continue
		}
		if err := rc.startVisit(ctx); err != nil {
			return rc, fmt.Errorf("relay %s: %w", e.addr, err)
		}
		return rc, nil
	}
	return nil, errors.Join(errs...)
}

// startVisit runs Visit on rc with a grant and the address of its home, then
// makes the relay peer and the peer listener on the link of home.
func (rc *relayConn) startVisit(ctx context.Context) error {
	a, home := rc.a, rc.home
	// A relay that does not answer in time ends the visit.
	stop := context.AfterFunc(ctx, func() { _ = rc.qc.CloseWithError(0, "visit did not start in time") })
	defer stop()
	a.routeMu.Lock()
	rc.grant, rc.claims, rc.prefixes, rc.self = home.grant, home.claims, home.prefixes, home.self
	a.routeMu.Unlock()
	a.mu.Lock()
	l := home.link
	rc.link = l
	a.mu.Unlock()
	grant, err := home.grant.get(ctx)
	if err != nil {
		return fmt.Errorf("visit: %w", err)
	}
	if _, err := rc.c.Visit(ctx, &dp.VisitRequest{Vpc: rc.ref, Address: rc.self.String(), Grant: grant}); err != nil {
		return attachError(rc, fmt.Errorf("visit: %w", err))
	}
	if rc.relayAtLeast(visitExtras) {
		// The peer sessions open after this, so each Open has the grants.
		a.joinExtras(ctx, home, rc)
	}
	p, err := l.AddRelay(rc.relayAddr)
	if err != nil {
		return err
	}
	rc.setRelayPeer(p)
	rc.pc = peerconn.New(rc.qc, rc.self)
	rc.pc.HandleData(l.HandleData)
	// The packets for the peers of the visit go as data frames on rc, and the
	// packets for the other peers stay on the attached session.
	if err := p.UseQUIC(rc.pc); err != nil {
		return err
	}
	rc.peerTr = &quic.Transport{Conn: rc.pc}
	ln, err := rc.peerTr.Listen(a.peerTLS(), peerQUIC)
	if err != nil {
		return err
	}
	go rc.accept(ln)
	return nil
}

// joinExtras puts the extra attachments of home in the visit of rc. After it, an
// attachment that home gets goes in the visit too. An older relay takes neither.
func (a *Agent) joinExtras(ctx context.Context, home, rc *relayConn) {
	a.attMu.Lock()
	rc.extrasOf = home
	a.mu.Lock()
	xs := slices.Collect(maps.Values(home.extras))
	a.mu.Unlock()
	a.attMu.Unlock()
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		failed int
		first  error
	)
	calls := make(chan struct{}, visitCalls)
	for _, x := range xs {
		calls <- struct{}{}
		wg.Go(func() {
			defer func() { <-calls }()
			if err := a.joinVisit(ctx, rc, x); err != nil {
				mu.Lock()
				defer mu.Unlock()
				failed++
				first = cmp.Or(first, err)
			}
		})
	}
	wg.Wait()
	if failed > 0 {
		slog.Warn("Failed to put extra attachments in a visit; the peers of the visit do not reach them",
			"relay", rc.addr, "failed", failed, "attachments", len(xs), "error", first)
	}
}

// joinVisit runs Visit on the visitor session rc for each prefix of x, then adds
// x to rc for the peers of the visit. An attachment that left meanwhile leaves rc.
func (a *Agent) joinVisit(ctx context.Context, rc *relayConn, x *extra) error {
	grant, err := x.grant.get(ctx)
	for _, p := range x.prefixes {
		if err != nil {
			break
		}
		req := &dp.VisitRequest{Vpc: rc.ref, Address: relay.OverlayAddr(p).String(), Grant: grant}
		_, err = rc.c.Visit(ctx, req)
	}
	if err != nil {
		err = fmt.Errorf("visit with attachment %s: %w", x.spec.Name, err)
	}
	a.attMu.Lock()
	a.mu.Lock()
	kept := err == nil && rc.extrasOf.extras[x.id] == x
	a.mu.Unlock()
	if kept {
		a.addExtra(rc, x)
	}
	a.attMu.Unlock()
	if !kept {
		// The relay can have a part of the prefixes.
		_ = rc.detachExtra(ctx, x.id)
	}
	return err
}

// visitorsOf returns the open visitor sessions that take the extra attachments
// of home. a.attMu must be held.
func (a *Agent) visitorsOf(home *relayConn) []*relayConn {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []*relayConn
	for _, rc := range a.conns {
		if rc.extrasOf == home && !rc.ended() {
			out = append(out, rc)
		}
	}
	return out
}

// keepVisit ends v when its session ends, and moves its peers back when the
// relay of the agent reaches them. It changes the mode of v as watch does.
func (a *Agent) keepVisit(v *visit, retry *pspRetry) {
	t := time.NewTicker(a.visitCheck)
	defer t.Stop()
	defer retry.timer.Stop()
	for {
		select {
		case <-v.rc.ctx.Done():
			return
		case <-v.rc.qc.Context().Done():
			a.endVisit(v, "relay session ended")
			return
		case <-v.rc.pspLost():
			a.useQUIC(v.rc)
			retry.restart()
		case <-retry.timer.C:
			retry.probe()
		case ok := <-retry.probed:
			retry.result(ok)
		case <-t.C:
			if a.checkVisit(v) {
				return
			}
		}
	}
}

// checkVisit moves the peers of v that the home relay reaches back to the
// attached session. It reports whether the visit ended with no peer.
func (a *Agent) checkVisit(v *visit) bool {
	a.mu.Lock()
	attached, busy := v.home.live(), v.users > 0
	var peers []*peer
	for _, p := range a.peers {
		if p.rc == v.rc && p.bp != nil && !a.gone(p) {
			peers = append(peers, p)
		}
	}
	a.mu.Unlock()
	if !attached {
		a.endVisit(v, "attached session ended")
		return true
	}
	// The dials below run after the visitor session closes.
	ctx, cancel := context.WithTimeout(v.home.ctx, keysTimeout)
	defer cancel()
	back := map[*peer]*dp.ResolvePeerResponse{}
	for _, p := range peers {
		if res, err := v.home.resolve(ctx, p.addr); err == nil && reachable(res) {
			back[p] = res
		}
	}
	// The visit ends before the dials, so that the visited relay sends the peer
	// frames of the peers to the home relay and not to the visitor session.
	ended := len(back) == len(peers) && !busy
	if ended {
		reason := "no peer uses the visit"
		if len(back) > 0 {
			reason = "home relay reaches the peers again"
		}
		a.endVisit(v, reason)
	} else {
		a.unrouteVisit(v, func(pfx netip.Prefix) bool {
			return slices.ContainsFunc(peers, func(p *peer) bool { return back[p] != nil && p.routes(pfx.Addr()) })
		})
		a.closePeers(func(p *peer) bool { return back[p] != nil }, "home relay reaches the peer again")
	}
	for p, res := range back {
		key := startKey{v.home.link, p.addr}
		err := a.starts.once(ctx, key, attempt{}, func() error {
			return a.connect(ctx, v.home, p.addr, res)
		})
		if err != nil {
			slog.Warn("Failed to move a peer session back from a visit", "peer", p.addr, "error", err)
			continue
		}
		slog.Info("Moved a peer session back from a visit", "peer", p.addr, "relay", v.rc.addr)
	}
	return ended
}

// endVisit closes the visitor session of v and its peer sessions.
func (a *Agent) endVisit(v *visit, reason string) {
	a.mu.Lock()
	if a.visits[v.key] != v {
		a.mu.Unlock()
		return
	}
	delete(a.visits, v.key)
	a.mu.Unlock()
	// A setup that still runs ends its session itself.
	if rc := v.session(); rc != nil {
		a.end(rc)
		slog.Info("Ended a visit", "relay", rc.addr, "reason", reason)
	}
}

// endVisitTo ends the visit of the relay with key, if the agent has one.
func (a *Agent) endVisitTo(key, reason string) {
	a.mu.Lock()
	v := a.visits[key]
	a.mu.Unlock()
	if v != nil {
		a.endVisit(v, reason)
	}
}

// endVisits ends each visit of home: a visit uses the grant of its home session.
func (a *Agent) endVisits(home *relayConn, reason string) {
	a.mu.Lock()
	var vs []*visit
	for _, v := range a.visits {
		if v.home == home {
			vs = append(vs, v)
		}
	}
	a.mu.Unlock()
	for _, v := range vs {
		a.endVisit(v, reason)
	}
}

// routeVisit routes the prefix of dst to the relay of the visit v, so that the
// packets to dst go through the visit until the route of a peer is up.
func (a *Agent) routeVisit(v *visit, dst netip.Addr) {
	pfx := a.routeOf(v.home, dst)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.visits[v.key] != v || slices.Contains(v.routes, pfx) {
		return
	}
	if err := a.bind.AddRoute(pfx, v.rc.relay); err != nil {
		slog.Warn("Failed to route an address through a visit", "relay", v.rc.addr, "prefix", pfx, "error", err)
		return
	}
	v.routes = append(v.routes, pfx)
}

// unrouteVisit removes the routes of the visit v whose prefix match reports.
func (a *Agent) unrouteVisit(v *visit, match func(netip.Prefix) bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v.routes = slices.DeleteFunc(v.routes, func(pfx netip.Prefix) bool {
		if !match(pfx) {
			return false
		}
		a.bind.RemoveRoute(pfx, v.rc.relay)
		return true
	})
}
