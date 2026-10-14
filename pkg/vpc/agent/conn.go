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
	sendMu sync.Mutex // Guards sends on st after start.
	ep     endpoint
	addr   string         // Relay address as dialed.
	name   string         // TLS name of the relay.
	roots  *x509.CertPool // Check relay certs and grants. Nil means the system roots.
	// home is the attached session of a visitor session, and nil for the other
	// sessions. A visitor session has no attachment: its grant, prefixes and
	// address are those of home.
	home *relayConn
	// extrasOf is home after the relay took the extra attachments of home in the
	// visit. An older relay takes none. Guarded by Agent.attMu.
	extrasOf *relayConn

	relayAddr netip.AddrPort // Where PSP packets, path probes and lane keep-alives go. See pspAddr.
	version   *dp.Version    // Version of the relay, from Welcome. Nil is revision 0.
	// seen is the address of the agent socket as the PSP socket of the relay saw it, from
	// the last probe reply. The relay sends the PSP packets of the session there.
	seen     atomic.Pointer[netip.AddrPort]
	maxLanes uint32       // Most lane ports that the relay takes.
	lanes    atomic.Int32 // Send lanes: the lane ports that the relay took, plus 1.
	mode     atomic.Int32 // Data mode, a dp.Mode. See dataMode.
	// check is the BFD session of the PSP path. It is nil in QUIC mode.
	// The goroutine that follows the session writes it.
	check     atomic.Pointer[pathCheck]
	reason    atomic.Int32  // Why the session is in QUIC mode, a dp.FallbackReason. See fallback.
	first     <-chan bool   // Result of the probe that starts after Welcome. Nil for no probe.
	probeSeq  atomic.Uint64 // Counter of the last path probe packet of the connection.
	connect   time.Duration // Time to connect: from the start of the dial to the first Config.
	rtt       *atomic.Int64 // Smoothed RTT of qc in nanoseconds.
	lowRTT    atomic.Int64  // Lowest RTT of qc in nanoseconds, for the relay choice. Zero is not known.
	helloRTT  atomic.Int64  // Time from the send of Hello to Welcome in nanoseconds, for the relay choice.
	setup     time.Duration // See Status.Setup.
	vpcConfig *dp.Config    // The first Config.
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
	// attach sets it.
	keyMu sync.Mutex
	relay *psp.Peer
	// bridgeTx closes when the relay SAs first apply, bridgeRx when the
	// relay takes the SAs of this agent. keyMu: useQUIC replaces the two.
	bridgeTx, bridgeRx chan struct{}

	pc     *peerconn.Conn
	peerTr *quic.Transport
	// stopShards stops the QUIC shards of the session. A visitor session has none.
	stopShards context.CancelFunc
	// drained gets the alternates of the Drain of the relay. The watcher of the
	// session reads it.
	drained chan []*dp.RelayRef
}

// visitor reports whether rc is a visitor session.
func (rc *relayConn) visitor() bool { return rc.home != nil }

// dataMode returns the form of the data that rc sends. Each session starts in
// QUIC mode. After that, only usePSP and useQUIC write it.
func (rc *relayConn) dataMode() dp.Mode { return dp.Mode(rc.mode.Load()) }

// wantsPSP reports whether rc changes to PSP mode when its PSP path passes.
func (rc *relayConn) wantsPSP() bool { return rc.a.cfg.TransportMode != TransportQUIC }

// wantedMode returns the mode that Hello tells the relay. The relay only counts it.
func (rc *relayConn) wantedMode() dp.Mode {
	if rc.wantsPSP() {
		return dp.Mode_MODE_PSP
	}
	return dp.Mode_MODE_QUIC
}

// fallback returns why rc is in QUIC mode: its config or a probe that failed. It
// returns no reason before the first probe result and for a session in PSP mode.
func (rc *relayConn) fallback() dp.FallbackReason {
	if rc.dataMode() != dp.Mode_MODE_QUIC {
		return dp.FallbackReason_FALLBACK_REASON_UNSPECIFIED
	}
	return dp.FallbackReason(rc.reason.Load())
}

// pspAddr returns where the PSP packets, the path probes and the lane
// keep-alives of a session go: the PSP host of the relay, or dialed, the IP
// address of the QUIC connection, when the relay gives no host, at its PSP port.
func pspAddr(w *dp.Welcome, dialed netip.Addr) (netip.AddrPort, error) {
	port := w.GetPspPort()
	if port == 0 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("relay PSP port %d is not a port", port)
	}
	host := dialed
	if h := w.GetPspHost(); h != "" {
		var err error
		if host, err = netip.ParseAddr(h); err != nil {
			return netip.AddrPort{}, fmt.Errorf("relay PSP host %q is not an IP address", h)
		}
	}
	return netip.AddrPortFrom(host.Unmap(), uint16(port)), nil
}

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
// session with rank.
func (a *Agent) attach(ctx context.Context, rc *relayConn, rank uint32, begin time.Time) error {
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
		"transport", transportName(rc.dataMode()), "fallback", rc.fallback(), "connect", rc.connect, "setup", rc.setup)
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
// its addresses. It runs when the session is lost, when a dial fails, and when
// the agent stops.
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

// watch follows the attached session rc until it ends, and changes its mode
// with the state of the PSP path. A new agent cert does not change rc.
func (a *Agent) watch(rc *relayConn) {
	retry := newPSPRetry(rc)
	defer retry.timer.Stop()
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
		case <-rc.pspLost():
			a.useQUIC(rc)
			retry.restart()
		case <-retry.timer.C:
			retry.probe()
		case ok := <-retry.probed:
			retry.result(ok)
		}
	}
}

// usePSP changes rc from QUIC mode to PSP mode on its open connection. The session and
// its addresses stay. After an error, or on a relay that drains, data goes as before.
func (a *Agent) usePSP(rc *relayConn) error {
	a.mu.Lock()
	draining, b := rc.state == connDraining, a.bind
	a.mu.Unlock()
	if draining {
		return nil
	}
	ctx, cancel := context.WithTimeout(rc.ctx, keysTimeout)
	defer cancel()
	defer context.AfterFunc(rc.qc.Context(), cancel)()
	// A path that does not carry the device MTU gets the MSS clamp.
	mtu := a.probeMTU()
	if mtu != 0 && !<-rc.probe(ctx, mtu) {
		mtu = a.changeMTU(rc)
	}
	if err := rc.tradeRelayKeys(ctx); err != nil {
		if !rc.ended() {
			slog.Warn("Failed to change the relay session to PSP mode; data stays on QUIC", "relay", rc.addr, "error", err)
		}
		return err
	}
	if mtu != 0 {
		a.mu.Lock()
		a.setClamp(mtu)
		a.mu.Unlock()
	}
	if !rc.visitor() {
		rc.registerLanes(ctx, b)
	}
	if err := rc.startCheck(); err != nil {
		return err
	}
	// The relay has the SAs of this agent and sends PSP. Now this agent sends PSP too.
	if err := rc.relay.UseQUIC(nil); err != nil {
		return err
	}
	rc.mode.Store(int32(dp.Mode_MODE_PSP))
	if !rc.visitor() {
		rc.stopShards()
	}
	// The peer sessions of QUIC mode send through the relay. The next packet to
	// a peer opens a session of PSP mode.
	a.closePeers(func(p *peer) bool { return p.rc == rc }, "relay session changed to PSP mode")
	slog.Info("Changed the relay session from QUIC mode to PSP mode", "relay", rc.addr, "address", rc.self)
	return nil
}

// changeMTU returns the inner packet size of the probes before the change to PSP
// mode: the largest packet of QUIC mode, so that each open connection still fits.
func (a *Agent) changeMTU(rc *relayConn) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return min(a.deviceMTU(int(rc.mtu)), psp.QUICMTU)
}

// tradeRelayKeys gives the relay the receive SAs of this agent with Rekey, which changes
// the session to PSP mode at the relay. Then it waits for the relay SAs.
func (rc *relayConn) tradeRelayKeys(ctx context.Context) error {
	if !rc.giveRelayKeys() {
		return errors.New("relay did not take the receive SAs")
	}
	select {
	case <-rc.bridgeTx:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for the relay SAs: %w", context.Cause(ctx))
	}
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

// pspRetry runs the PSP probes of a session in QUIC mode: the probe that starts
// after Welcome, then probes with backoff. It changes the session to PSP mode.
type pspRetry struct {
	rc     *relayConn
	timer  *time.Timer // Starts the next probe.
	probed <-chan bool // Result of the probe that runs. Nil for none.
	wait   time.Duration
	passes int // Probes in a row that passed.
}

// newPSPRetry returns the probes of rc. One pass of the first probe is enough. A
// session with QUIC mode in its config has no probe, so its timer never starts.
func newPSPRetry(rc *relayConn) *pspRetry {
	r := &pspRetry{rc: rc, timer: time.NewTimer(rc.a.retryMin), probed: rc.first, wait: rc.a.retryMin, passes: pspPasses - 1}
	r.timer.Stop()
	return r
}

// probe starts the next probe.
func (r *pspRetry) probe() {
	r.probed = r.rc.probe(r.rc.ctx, r.rc.a.changeMTU(r.rc))
}

// result takes the result of the probe that ran. After pspPasses probes in a
// row passed, it changes the session to PSP mode.
func (r *pspRetry) result(ok bool) {
	r.probed = nil
	switch {
	case !ok:
		r.rc.reason.Store(int32(dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT))
		r.backoff()
	case r.passes+1 < pspPasses:
		r.passes++
		r.timer.Reset(r.rc.a.retryNext)
	case r.rc.a.usePSP(r.rc) != nil:
		r.backoff()
	}
}

// restart starts the probes with backoff again, after PSP mode ends.
func (r *pspRetry) restart() {
	r.wait = r.rc.a.retryMin
	r.backoff()
}

// backoff starts again after a probe or a mode change that failed.
func (r *pspRetry) backoff() {
	r.passes = 0
	r.timer.Reset(r.wait)
	r.wait = min(2*r.wait, r.rc.a.retryMax)
}
