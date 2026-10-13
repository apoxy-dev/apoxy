// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// connState is the state of a relay session. A session only moves forward:
// dialing, attached, draining, ended.
type connState int

const (
	// connDialing is the state from the dial until the Attach call ends. Only
	// the goroutine that dials the session uses it.
	connDialing connState = iota
	// connAttached is the state of the session that has the attachment of the
	// agent. A visitor session is attached after its Visit call.
	connAttached
	// connDraining is the state of an attached session whose relay drains. It
	// keeps its traffic until the relay closes it, and its addresses are not
	// preferred.
	connDraining
	// connEnded is the state of a closed session. The agent forgets it.
	connEnded
)

func (s connState) String() string {
	return [...]string{"dialing", "attached", "draining", "ended"}[s]
}

// relayConn is one relay session with its attachments. Each attached session
// has its own addresses.
type relayConn struct {
	a      *Agent
	ctx    context.Context // Ends when the session ends.
	cancel context.CancelFunc
	// state is guarded by Agent.mu.
	state connState
	// rank orders the attached sessions: the relays and the agent prefer the
	// lowest rank. The attach sets it.
	rank uint32
	// link has the routes of the session in the binding. A visitor session uses
	// the link of its home. Set under Agent.mu.
	link *psp.Link
	// alternates are the relays that the Drain of the relay names. Guarded by
	// Agent.mu.
	alternates []endpoint
	// qc is set under Agent.mu after the handshake. After the dial, it does not change.
	qc     quic.Connection
	c      dp.RelayClient
	st     rpc.BidiStreamClient[dp.SessionRequest, dp.SessionResponse]
	sendMu sync.Mutex     // Guards sends on st after start.
	local  netip.AddrPort // Local address at the last check. Only tick changes it after the dial.
	ep     endpoint
	addr   string         // Relay address as dialed.
	name   string         // TLS name of the relay.
	roots  *x509.CertPool // Check relay certs and grants. Nil means the system roots.
	// home is the attached session of a visitor session, and nil for the other
	// sessions. A visitor session has no attachment: its grant, prefixes and
	// address are those of home.
	home *relayConn
	// data is true when the path of a visitor session carries data: the result
	// of its path probe.
	data atomic.Bool
	// extrasOf is home after the relay took the extra attachments of home in the
	// visit. An older relay takes none. Guarded by Agent.attMu.
	extrasOf *relayConn

	relayAddr netip.AddrPort    // Where PSP packets to peers go.
	version   *dp.Version       // Version of the relay, from Welcome. Nil is revision 0.
	reflexive netip.AddrPort    // Address of the agent socket as the relay sees it.
	maxLanes  uint32            // Most lane ports that the relay takes.
	lanes     atomic.Int32      // Send lanes: the lane ports that the relay took, plus 1.
	mode      dp.Mode           // Data mode of the Session call.
	reason    dp.FallbackReason // Why mode is QUIC.
	connect   time.Duration     // Time to connect: from the start of the dial to the first Config.
	rtt       *atomic.Int64     // Smoothed RTT of qc in nanoseconds.
	probeRTT  atomic.Int64      // Round-trip time of the last path probe with a reply. Zero is none.
	setup     time.Duration     // See Status.Setup.
	vpcConfig *dp.Config        // The first Config.
	ref       *dp.VPCRef
	mtu       uint32
	grant     *ownGrant
	claims    *dp.GrantClaims
	prefixes  []netip.Prefix
	self      netip.Addr // Overlay address of this agent.
	// routes and attachmentID are guarded by Agent.routeMu. The attach also
	// sets prefixes and self under it, because the sync reads self.
	routes       routeTable
	attachmentID string
	// extras are the other attachments of this agent on rc, by attachment ID.
	// Writers hold Agent.attMu, Agent.routeMu and Agent.mu, so readers hold one
	// of them.
	extras map[string]*extra
	// sem limits the Attach calls of extras that run at once. attaching is the
	// specs that they run for, guarded by Agent.mu.
	sem       chan struct{}
	attaching map[*AttachmentSpec]bool

	dnsServers, dnsSearch []string

	// relay is the relay as a peer of the binding. Packets for QUIC-mode peers
	// go to it, sealed with the SAs that the relay gives in PSP mode. The
	// attach sets it. Relay SAs that come before it wait in pendingKeys.
	keyMu       sync.Mutex
	relay       *psp.Peer
	pendingKeys []*dp.KeysRequest
	// bridgeTx closes when the relay SAs first apply. bridgeRx closes when the
	// relay first takes the SAs of this agent. QUIC pairs wait for both.
	bridgeTx, bridgeRx chan struct{}

	pc     *peerconn.Conn
	peerTr *quic.Transport
	// drained gets the alternates of the Drain of the relay. The watcher of the
	// session reads it.
	drained chan []*dp.RelayRef
}

// visitor reports whether rc is a visitor session.
func (rc *relayConn) visitor() bool { return rc.home != nil }

// dialRelay adds a session to the relay at e in the state dialing, and runs it up to
// the first Config. The caller attaches on the session or ends it. home is the
// attached session of a visitor session, or nil.
func (a *Agent) dialRelay(ctx context.Context, e endpoint, home *relayConn) (*relayConn, error) {
	host, _, err := net.SplitHostPort(e.addr)
	if err != nil {
		return nil, err
	}
	rc := &relayConn{
		a:        a,
		rtt:      new(atomic.Int64),
		ep:       e,
		addr:     e.addr,
		name:     cmp.Or(e.id, host),
		roots:    a.relayRoots(a.cfg.Identity.Current()),
		home:     home,
		sem:      make(chan struct{}, maxInFlight),
		drained:  make(chan []*dp.RelayRef, 1),
		bridgeTx: make(chan struct{}),
		bridgeRx: make(chan struct{}),
	}
	rc.ctx, rc.cancel = context.WithCancel(context.Background())
	a.mu.Lock()
	stopped := a.stopped
	if !stopped {
		a.conns = append(a.conns, rc)
	}
	a.mu.Unlock()
	if stopped {
		return nil, errNoRelay
	}
	if err := rc.open(ctx); err != nil {
		a.end(rc)
		return nil, err
	}
	return rc, nil
}

// attach runs the Attach call on rc after dialRelay, and makes rc an attached
// session with rank. old is the session on the same relay that rc replaces, or
// nil: it ends when rc is attached.
func (a *Agent) attach(ctx context.Context, rc, old *relayConn, rank uint32, begin time.Time) error {
	rc.rank = rank
	if err := rc.attach(ctx, begin); err != nil {
		a.end(rc)
		return fmt.Errorf("relay %s: %w", rc.addr, err)
	}
	if !a.setAttached(rc) {
		a.end(rc)
		return errNoRelay
	}
	slog.Info("Attached to the VPC", "relay", rc.addr, "address", rc.self, "prefixes", rc.prefixes, "rank", rank,
		"transport", transportName(rc.mode), "fallback", rc.reason, "connect", rc.connect, "setup", rc.setup)
	if old != nil {
		a.end(old)
	}
	// OnRoutes follows the new session only after its OnAttach.
	a.deliver()
	a.usePrimary()
	a.wakeAttach()
	a.watchers.Go(func() { a.watch(rc) })
	return nil
}

// setAttached moves rc to attached and queues OnAttach for its address. It
// reports false when the agent stopped.
func (a *Agent) setAttached(rc *relayConn) bool {
	a.attMu.Lock()
	defer a.attMu.Unlock()
	a.mu.Lock()
	ok := !a.stopped && rc.ctx.Err() == nil
	if ok {
		rc.state = connAttached
	}
	b := a.bind
	a.mu.Unlock()
	if !ok {
		return false
	}
	if f := a.cfg.OnAttach; f != nil {
		addr, prefixes := rc.self, rc.prefixes
		a.events = append(a.events, func() { f(b, addr, prefixes) })
	}
	return true
}

// drain moves rc to draining when its relay starts to drain, and queues
// OnDeprecated for its addresses. Then Run opens a session on another relay.
func (a *Agent) drain(rc *relayConn, alts []*dp.RelayRef) {
	a.attMu.Lock()
	a.mu.Lock()
	ok := rc.state == connAttached
	if ok {
		rc.state, rc.alternates = connDraining, refEndpoints(alts)
	}
	a.mu.Unlock()
	if f := a.cfg.OnDeprecated; ok && f != nil {
		for _, at := range rc.attachments() {
			a.events = append(a.events, func() { f(at) })
		}
	}
	a.attMu.Unlock()
	if !ok {
		return
	}
	slog.Info("Relay drains; its session stays until the relay closes it", "relay", rc.addr, "address", rc.self, "alternates", len(alts))
	a.deliver()
	a.usePrimary()
	a.wakeRun()
}

// end closes rc with its peer sessions and its visits, and queues OnDetach for
// its addresses. It runs when the session is lost, when its replacement in PSP
// mode is attached, when a dial fails, and when the agent stops.
func (a *Agent) end(rc *relayConn) {
	a.attMu.Lock()
	a.mu.Lock()
	was := rc.state
	rc.state = connEnded
	a.conns = slices.DeleteFunc(a.conns, func(o *relayConn) bool { return o == rc })
	a.mu.Unlock()
	shown := !rc.visitor() && (was == connAttached || was == connDraining)
	if f := a.cfg.OnDetach; shown && f != nil {
		for _, at := range slices.Backward(rc.attachments()) {
			a.events = append(a.events, func() { f(at) })
		}
	}
	a.attMu.Unlock()
	if was == connEnded {
		return
	}
	a.endVisits(rc, "attached session ended")
	rc.close()
	if shown {
		a.deliver()
		a.usePrimary()
	}
	a.wakeRun()
}

// wakeRun makes Run count the sessions again.
func (a *Agent) wakeRun() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

// primary returns the session with the default address of the agent: the
// attached session with the lowest rank, or else the draining one with the
// lowest rank. It returns nil when the agent has none.
func (a *Agent) primary() *relayConn {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.primaryLocked()
}

// primaryLocked is primary for a caller that holds a.mu.
func (a *Agent) primaryLocked() *relayConn {
	if rcs := a.sessionsLocked(connAttached); len(rcs) > 0 {
		return rcs[0]
	}
	if rcs := a.sessionsLocked(connDraining); len(rcs) > 0 {
		return rcs[0]
	}
	return nil
}

// sessions returns the sessions of the agent in one of states that are not
// visitor sessions, in rank order.
func (a *Agent) sessions(states ...connState) []*relayConn {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessionsLocked(states...)
}

// sessionsLocked is sessions for a caller that holds a.mu.
func (a *Agent) sessionsLocked(states ...connState) []*relayConn {
	var out []*relayConn
	for _, rc := range a.conns {
		if !rc.visitor() && slices.Contains(states, rc.state) {
			out = append(out, rc)
		}
	}
	slices.SortStableFunc(out, func(x, y *relayConn) int { return cmp.Compare(x.rank, y.rank) })
	return out
}

// live reports whether rc is attached or draining. Agent.mu must be held.
func (rc *relayConn) live() bool {
	return rc.state == connAttached || rc.state == connDraining
}

// usePrimary gives the primary session the packets with a source that no
// session has, and makes OnRoutes follow its routes. It runs after each change
// of the attached sessions, after the callbacks of the change: OnAttach of a
// session comes before OnRoutes gives its routes. Until the first RouteDelta of the new primary
// session, OnRoutes keeps the routes of the session before.
func (a *Agent) usePrimary() {
	a.routeMu.Lock()
	defer a.routeMu.Unlock()
	a.mu.Lock()
	rc, b := a.primaryLocked(), a.bind
	a.mu.Unlock()
	if rc == nil || a.routesOf == rc {
		return
	}
	b.SetDefault(rc.link)
	a.routesOf = rc
	if rc.routes.synced {
		a.syncRoutes()
	}
}

// watch follows the attached session rc until it ends. It replaces rc when
// PSP passes again. A new agent cert does not change rc.
func (a *Agent) watch(rc *relayConn) {
	retry := newPSPRetry(rc)
	defer retry.timer.Stop()
	var probed <-chan bool
	for {
		select {
		case <-rc.ctx.Done():
			return
		case <-rc.qc.Context().Done():
			err := context.Cause(rc.qc.Context())
			slog.Info("Relay session ended", "relay", rc.addr, "error", err)
			if certRefused(err) {
				a.renew(rc.ctx)
			}
			a.end(rc)
			return
		case alts := <-rc.drained:
			a.drain(rc, alts)
		case <-retry.timer.C:
			probed = rc.probe(rc.ctx, psp.DefaultMTU)
		case ok := <-probed:
			probed = nil
			// The new session probes again before it picks its mode.
			if retry.passed(ok) && a.replace(rc) != nil {
				retry.backoff()
			}
		}
	}
}

// replace opens a session in PSP mode on the relay of rc that takes the rank
// of rc. rc ends when the new session is attached, so its addresses change.
// The open stops when rc ends: then Run opens a session. A relay that drains
// takes no new session.
func (a *Agent) replace(rc *relayConn) error {
	a.mu.Lock()
	draining := rc.state == connDraining
	a.mu.Unlock()
	if draining {
		return nil
	}
	ctx, cancel := context.WithCancel(rc.ctx)
	defer cancel()
	defer context.AfterFunc(rc.qc.Context(), cancel)()
	slog.Info("Replacing the relay session because PSP passes again", "relay", rc.addr)
	begin := time.Now()
	next, err := a.dialRelay(ctx, rc.ep, nil)
	if err == nil && next.mode != dp.Mode_MODE_PSP {
		a.end(next)
		err = errors.New("the PSP probe of the new session failed")
	}
	if err == nil {
		err = a.attach(ctx, next, rc, rc.rank, begin)
	}
	if err != nil && ctx.Err() == nil {
		slog.Warn("Failed to replace the relay session", "relay", rc.addr, "error", err)
	}
	return err
}

// refEndpoints returns the addresses of the relays in refs.
func refEndpoints(refs []*dp.RelayRef) []endpoint {
	var eps []endpoint
	for _, r := range refs {
		for _, addr := range r.GetAddresses() {
			eps = append(eps, endpoint{id: r.GetId(), addr: addr})
		}
	}
	return eps
}

// pspRetry probes PSP again, with backoff, for a session that is in QUIC mode
// because its first probe failed.
type pspRetry struct {
	timer  *time.Timer // Starts the next probe.
	wait   time.Duration
	passes int // Probes in a row that passed.
}

func newPSPRetry(rc *relayConn) *pspRetry {
	r := &pspRetry{timer: time.NewTimer(pspRetryMin), wait: pspRetryMin}
	if rc.reason != dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT {
		r.timer.Stop()
	}
	return r
}

// passed takes the result of one probe. It reports true after pspPasses
// probes in a row passed: then the agent opens a session for PSP.
func (r *pspRetry) passed(ok bool) bool {
	if !ok {
		r.backoff()
		return false
	}
	if r.passes++; r.passes < pspPasses {
		r.timer.Reset(pspRetryNext)
		return false
	}
	return true
}

// backoff starts again after a probe or a new session that failed.
func (r *pspRetry) backoff() {
	r.passes, r.wait = 0, min(2*r.wait, pspRetryMax)
	r.timer.Reset(r.wait)
}
