// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// maxVisits is the most visitor sessions of one agent.
	maxVisits = 2
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
	errVisitLimit  = errors.New("agent has the most visitor sessions")
	errVisitNoData = errors.New("path to the visited relay carries no data")
	errPeerVisits  = errors.New("peer has the lower address and did not visit this relay yet")
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
	return rc.visitor == visits(rc.self, peer)
}

// reachable reports whether the relay that gave res reaches the peer, so that
// no visit is necessary.
func reachable(res *dp.ResolvePeerResponse) bool {
	return res.GetReach() == dp.Reach_REACH_LOCAL || res.GetReach() == dp.Reach_REACH_TRUNK
}

// noRoute applies a NoRoute of rc. With a home relay, the peer sessions stay
// with the path down, and a visit starts. With none, the sessions close.
func (a *Agent) noRoute(rc *relayConn, m *dp.NoRoute) {
	dst, err := netip.ParseAddr(m.GetAddress())
	if err != nil {
		return
	}
	if m.GetHomeRelay() == nil {
		a.closePeers(func(p *peer) bool { return p.rc == rc && p.routes(dst) }, "relay has no route to the peer")
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

// noDataPath sets the path of p to down: the peer has no data path to this agent.
func (a *Agent) noDataPath(p *peer) {
	a.mu.Lock()
	p.down = true
	a.mu.Unlock()
	close(p.noData)
}

// cutFrom asks the relay of p how it reaches the open sessions of the subject of
// p. It sets the path to down on the answer REACH_VISIT, and reports that.
func (a *Agent) cutFrom(ctx context.Context, p *peer) bool {
	if p.rc.visitor {
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

// visitAfterNoRoute asks rc again how it reaches dst, and starts the visit if
// the answer is still a visit. Another answer sets the path of dst to up again.
func (a *Agent) visitAfterNoRoute(rc *relayConn, dst netip.Addr) {
	a.mu.Lock()
	current := a.rc == rc
	a.mu.Unlock()
	if !current {
		return
	}
	addr, ok := a.peerAddr(rc, dst)
	if !ok || a.holds.failing(addr, time.Now()) {
		return
	}
	ctx, cancel := context.WithTimeout(rc.ctx, holdTime)
	defer cancel()
	err := a.holds.once(addr, func() error {
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
	if err != nil {
		a.holds.mu.Lock()
		a.holds.fail(addr, err, time.Now())
		a.holds.mu.Unlock()
		slog.Warn("Failed to visit the relay of a peer", "peer", addr, "error", err)
	}
}

// connectVisit reaches dst after the answer REACH_VISIT of home with the relay
// ref. The agent opens a visitor session to that relay and a peer session on
// it. The agent with the higher address first waits for the visit of its peer.
func (a *Agent) connectVisit(ctx context.Context, home *relayConn, dst netip.Addr, ref *dp.RelayRef) error {
	if home.visitor || len(ref.GetAddresses()) == 0 {
		return fmt.Errorf("relay has no path to peer %s (%v)", dst, dp.Reach_REACH_VISIT)
	}
	// The agent with the lower address visits first, so the other agent waits.
	// It does not wait again for a peer that it reaches on its own visit.
	use := a.usePeer
	if !visits(home.self, dst) && !a.visiting(dst) {
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
	a.mu.Lock()
	p := a.peerTo(v.rc, dst)
	a.mu.Unlock()
	if p != nil && p.idle && a.probeVisit(ctx, v.home, v.rc) {
		// The sessions with no data path close, and the dial below makes a new one.
		a.closePeers(func(q *peer) bool { return q.rc == v.rc && q.idle }, "path to the visited relay carries data now")
	}
	// The peer opened a session as a visitor while this visit started. It stays.
	if ok, err := a.usePeer(ctx, home, dst); ok {
		return err
	}
	// A session on another relay session has the routes of the peer, and its path
	// is down. The close code moves an agent that waits for it to the new session.
	a.closePeersWith(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE,
		func(q *peer) bool { return q.rc != v.rc && q.routes(dst) }, "peer is on a visited relay")
	return a.connect(ctx, v.rc, dst, nil)
}

// visiting reports whether a peer session that routes dst is on a visitor
// session of this agent.
func (a *Agent) visiting(dst netip.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.peers {
		if p.rc.visitor && p.bp != nil && p.qc.Context().Err() == nil && p.routes(dst) {
			return true
		}
	}
	return false
}

// usePeer waits for the SAs of the peer session on rc to dst whose path is not
// down. It reports false when the caller must visit: no session, or no data path.
func (a *Agent) usePeer(ctx context.Context, rc *relayConn, dst netip.Addr) (bool, error) {
	a.mu.Lock()
	p := a.livePeerTo(rc, dst)
	a.mu.Unlock()
	if p == nil {
		return false, nil
	}
	err := a.waitKeys(ctx, p, dst)
	return !errors.Is(err, errVisitNoData), err
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
			err := a.waitKeys(ctx, p, dst)
			return !errors.Is(err, errVisitNoData), err
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
	case a.rc != home || a.stopped:
		a.mu.Unlock()
		return nil, errNoRelay
	case key == home.ep.key():
		a.mu.Unlock()
		return nil, errors.New("relay names itself as the relay to visit")
	case len(a.visits) >= maxVisits:
		a.mu.Unlock()
		return nil, fmt.Errorf("%w (%d)", errVisitLimit, maxVisits)
	}
	v = &visit{key: key, home: home, done: make(chan struct{}), users: 1}
	a.visits[key] = v
	a.mu.Unlock()

	rc, err := a.openVisit(ctx, home, ref, key)
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
		v.rc = rc
	}
	v.err = err
	a.mu.Unlock()
	close(v.done)
	if err != nil {
		if rc != nil {
			rc.close()
		}
		return nil, err
	}
	slog.Info("Started a visit", "relay", rc.addr, "address", rc.self, "transport", transportName(rc.mode), "data", rc.data.Load())
	go a.keepVisit(v)
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
func (a *Agent) openVisit(ctx context.Context, home *relayConn, ref *dp.RelayRef, key string) (*relayConn, error) {
	// A spare has the routes of other relays, so the relay takes no Visit call on
	// it. The agent keeps one session for each relay, so the spare closes.
	if spare := a.takeSpareOn(key); spare != nil {
		slog.Info("Closed a spare relay session for a visit", "relay", spare.addr)
		spare.close()
	}
	ctx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	var errs []error
	for _, addr := range ref.GetAddresses() {
		rc, err := a.dialRelay(ctx, endpoint{id: ref.GetId(), addr: addr}, spareHello, true)
		if err != nil {
			errs = append(errs, fmt.Errorf("relay %s: %w", addr, err))
			continue
		}
		if err := rc.startVisit(ctx, home); err != nil {
			return rc, fmt.Errorf("relay %s: %w", addr, err)
		}
		return rc, nil
	}
	return nil, errors.Join(errs...)
}

// startVisit runs Visit on rc after hello with the grant and the address of
// home, then makes the relay peer and the peer listener, as attach does.
func (rc *relayConn) startVisit(ctx context.Context, home *relayConn) error {
	a := rc.a
	// A relay that does not answer in time ends the visit.
	stop := context.AfterFunc(ctx, func() { _ = rc.qc.CloseWithError(0, "visit did not start in time") })
	defer stop()
	a.routeMu.Lock()
	rc.grant, rc.claims, rc.prefixes, rc.self = home.grant, home.claims, home.prefixes, home.self
	a.routeMu.Unlock()
	a.mu.Lock()
	b := a.bind
	a.mu.Unlock()
	// The path probe runs while the relay checks the grant.
	probed := a.startProbe(ctx, home, rc)
	if _, err := rc.c.Visit(ctx, &dp.VisitRequest{Vpc: rc.ref, Address: rc.self.String(), Grant: rc.grant}); err != nil {
		return attachError(rc, fmt.Errorf("visit: %w", err))
	}
	p, err := b.AddPeer(rc.relayAddr)
	if err != nil {
		return err
	}
	rc.setRelayPeer(p)
	rc.pc = peerconn.New(rc.qc, rc.self)
	rc.pc.HandleData(b.HandleData)
	rc.peerTr = &quic.Transport{Conn: rc.pc}
	ln, err := rc.peerTr.Listen(a.peerTLS(), peerQUIC)
	if err != nil {
		return err
	}
	// The peer sessions open only after the probe, so that each one knows the result.
	rc.data.Store(probed != nil && <-probed)
	go rc.accept(ln)
	if rc.mode == dp.Mode_MODE_QUIC {
		close(rc.bridgeTx)
		close(rc.bridgeRx)
	} else {
		go rc.giveRelayKeys()
	}
	return nil
}

// startProbe starts the path probe of the visitor session rc at the device
// MTU, or returns nil when data cannot go on rc. The binding sends data frames
// only on the attached session, so the two sessions must be in PSP mode.
func (a *Agent) startProbe(ctx context.Context, home, rc *relayConn) <-chan bool {
	if home.mode != dp.Mode_MODE_PSP || rc.mode != dp.Mode_MODE_PSP {
		return nil
	}
	a.mu.Lock()
	mtu := a.bind.DeviceMTU()
	a.mu.Unlock()
	return rc.probe(ctx, mtu)
}

// probeVisit runs the path probe of the visitor session rc again after a probe
// that failed, and keeps the result. It reports whether data can go on rc now.
func (a *Agent) probeVisit(ctx context.Context, home, rc *relayConn) bool {
	probed := a.startProbe(ctx, home, rc)
	ok := probed != nil && <-probed
	rc.data.Store(ok)
	return ok
}

// keepVisit ends v when its session ends, and moves its peers back when the
// relay of the agent reaches them again.
func (a *Agent) keepVisit(v *visit) {
	t := time.NewTicker(a.visitCheck)
	defer t.Stop()
	for {
		select {
		case <-v.rc.ctx.Done():
			return
		case <-v.rc.qc.Context().Done():
			a.endVisit(v, "relay session ended")
			return
		case <-t.C:
			if a.checkVisit(v) {
				return
			}
		}
	}
}

// checkVisit asks the home relay how it reaches each peer of v. The peers
// that it reaches move back to the attached session. The visit ends when no
// peer uses it, and checkVisit reports that.
func (a *Agent) checkVisit(v *visit) bool {
	a.mu.Lock()
	attached, busy := a.rc == v.home, v.users > 0
	var peers []*peer
	for _, p := range a.peers {
		if p.rc == v.rc && p.bp != nil && !a.gone(p) {
			peers = append(peers, p)
		}
	}
	a.mu.Unlock()
	if !attached {
		a.endVisit(v, "attachment moved")
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
		a.closePeers(func(p *peer) bool { return back[p] != nil }, "home relay reaches the peer again")
	}
	for p, res := range back {
		err := a.holds.once(p.addr, func() error { return a.connect(ctx, v.home, p.addr, res) })
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
	// A setup that still runs closes its session itself.
	if rc := v.session(); rc != nil {
		rc.close()
		slog.Info("Ended a visit", "relay", rc.addr, "reason", reason)
	}
	// A spare can use the relay again.
	a.wakeSpares()
}

// endVisits ends each visit that does not use the grant of the session keep.
func (a *Agent) endVisits(keep *relayConn, reason string) {
	a.mu.Lock()
	var vs []*visit
	for _, v := range a.visits {
		if v.home != keep {
			vs = append(vs, v)
		}
	}
	a.mu.Unlock()
	for _, v := range vs {
		a.endVisit(v, reason)
	}
}

// admitIdle adds a peer session on a visitor session whose path carries no
// data. The peer gets no route and no SAs, so only the peer frames go there.
func (a *Agent) admitIdle(p *peer, v *dp.Version, g *dp.AttachmentGrant, instance uint64) error {
	claims, prefixes, err := a.checkGrant(p, g)
	if err != nil {
		return err
	}
	bp, err := a.bind.AddPeer(p.rc.relayAddr)
	if err != nil {
		return err
	}
	a.mu.Lock()
	if a.gone(p) {
		a.bind.RemovePeer(bp)
		a.mu.Unlock()
		return p.closedError()
	}
	p.instance, p.version, p.claims, p.prefixes, p.addr, p.bp, p.idle = instance, v, claims, prefixes, overlayAddr(prefixes), bp, true
	close(a.admitted)
	a.admitted = make(chan struct{})
	a.mu.Unlock()
	close(p.ready)
	slog.Info("Opened peer session with no data path", "peer", p.subject, "address", p.addr, "dialer", p.dialer)
	return nil
}
