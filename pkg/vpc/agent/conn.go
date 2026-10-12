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

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
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
	// connDraining is the state of an attached session whose relay drains, or
	// whose replacement is attached. It keeps its traffic until it ends.
	connDraining
	// connEnded is the state of a closed session. The agent forgets it.
	connEnded
)

func (s connState) String() string {
	return [...]string{"dialing", "attached", "draining", "ended"}[s]
}

// cause is why the agent replaces an attached session.
type cause int

const (
	causeDrain cause = iota // The relay of the session drains.
	causeRenew              // The agent has a new cert.
	causePSP                // PSP passes again for a session in QUIC mode.
)

func (c cause) String() string {
	return [...]string{"relay drains", "new cert", "PSP passes again"}[c]
}

// relayConn is one relay session with its attachment.
type relayConn struct {
	a      *Agent
	ctx    context.Context // Ends when the session ends.
	cancel context.CancelFunc
	// state is guarded by Agent.mu.
	state connState
	// qc is set under Agent.mu after the handshake. After the dial, it does not change.
	qc     quic.Connection
	c      dp.RelayClient
	st     rpc.BidiStreamClient[dp.SessionRequest, dp.SessionResponse]
	sendMu sync.Mutex     // Guards sends on st after start.
	local  netip.AddrPort // Local address at the last check. Only tick changes it after the dial.
	cred   *identity.Credential
	ep     endpoint
	addr   string         // Relay address as dialed.
	name   string         // TLS name of the relay.
	roots  *x509.CertPool // Check relay certs and grants. Nil means the system roots.
	// visitor is true for a visitor session. It has no attachment: its grant,
	// prefixes and address are those of the attached session.
	visitor bool
	// data is true when the path of a visitor session carries data: the result
	// of its path probe.
	data atomic.Bool
	// extrasOf is the attached session whose extra attachments a visitor
	// session has in its visit. Guarded by Agent.attMu.
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
	grant     *dp.AttachmentGrant
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
	// drained gets the alternates of the Drain of the relay. renewed gets a
	// value when the agent has a new cert. The watcher of the session reads them.
	drained chan []*dp.RelayRef
	renewed chan struct{}
}

// dialRelay adds a session to the relay at e in the state dialing, and runs it up to
// the first Config. The caller attaches on the session or ends it.
func (a *Agent) dialRelay(ctx context.Context, e endpoint, visitor bool) (*relayConn, error) {
	host, _, err := net.SplitHostPort(e.addr)
	if err != nil {
		return nil, err
	}
	cred := a.cfg.Identity.Current()
	rc := &relayConn{
		a:        a,
		rtt:      new(atomic.Int64),
		cred:     cred,
		ep:       e,
		addr:     e.addr,
		name:     cmp.Or(e.id, host),
		roots:    a.relayRoots(cred),
		visitor:  visitor,
		sem:      make(chan struct{}, maxInFlight),
		drained:  make(chan []*dp.RelayRef, 1),
		renewed:  make(chan struct{}, 1),
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

// attach runs the Attach call on rc after dialRelay, and gives rc the attachment of
// the agent. The agent keeps one attached session, so old ends. old can be nil.
func (a *Agent) attach(ctx context.Context, rc, old *relayConn, begin time.Time) error {
	if err := rc.attach(ctx, begin); err != nil {
		a.end(rc)
		return fmt.Errorf("relay %s: %w", rc.addr, err)
	}
	if old != nil {
		a.moveExtras(ctx, old, rc)
	}
	if !a.setAttached(rc, old) {
		a.end(rc)
		return errNoRelay
	}
	if old != nil {
		a.end(old)
	}
	slog.Info("Attached to the VPC", "relay", rc.addr, "address", rc.self, "prefixes", rc.prefixes,
		"transport", transportName(rc.mode), "fallback", rc.reason, "connect", rc.connect, "setup", rc.setup)
	a.deliver()
	a.useRoutes(rc)
	a.wakeAttach()
	go a.watch(rc)
	return nil
}

// setAttached moves rc to attached and old to draining, and queues the
// callbacks of the new address. It reports false when the agent stopped.
func (a *Agent) setAttached(rc, old *relayConn) bool {
	a.attMu.Lock()
	defer a.attMu.Unlock()
	a.mu.Lock()
	ok := !a.stopped && rc.ctx.Err() == nil
	if ok {
		rc.state = connAttached
		if old != nil && old.state == connAttached {
			old.state = connDraining
		}
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
	// The callbacks of the extras compare with the session before, which can be ended.
	a.queueMove(a.shown, rc)
	a.shown = rc
	return true
}

// drain moves rc to draining when its relay starts to drain. The session
// keeps the traffic until its replacement is attached or the relay closes it.
func (a *Agent) drain(rc *relayConn) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if rc.state == connAttached {
		rc.state = connDraining
	}
}

// end closes rc with its peer sessions and its visits. It runs when the
// session is lost, when its replacement is attached, when a dial fails, and
// when the agent stops. Then Run opens a session if the agent has none.
func (a *Agent) end(rc *relayConn) {
	a.mu.Lock()
	ended := rc.state == connEnded
	rc.state = connEnded
	a.conns = slices.DeleteFunc(a.conns, func(o *relayConn) bool { return o == rc })
	a.mu.Unlock()
	if ended {
		return
	}
	rc.close()
	a.endVisits(rc, "attached session ended")
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

// primary returns the session that has the address of the agent: the attached
// session, or else the draining one. It returns nil when the agent has none.
func (a *Agent) primary() *relayConn {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.primaryLocked()
}

// primaryLocked is primary for a caller that holds a.mu.
func (a *Agent) primaryLocked() *relayConn {
	var draining *relayConn
	for _, rc := range a.conns {
		switch {
		case rc.visitor:
		case rc.state == connAttached:
			return rc
		case rc.state == connDraining:
			draining = rc
		}
	}
	return draining
}

// watch follows the attached session rc until it ends. It replaces rc when its
// relay drains, when the agent has a new cert, and when PSP passes again.
func (a *Agent) watch(rc *relayConn) {
	renew := time.NewTimer(0)
	defer renew.Stop()
	if a.cfg.Identity.Current() == rc.cred {
		renew.Stop()
	}
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
			a.drain(rc)
			_ = a.replace(rc, causeDrain, alts)
		case <-rc.renewed:
			renew.Reset(0)
		case <-renew.C:
			// A value can be for the cert that rc already uses.
			if a.cfg.Identity.Current() != rc.cred && a.replace(rc, causeRenew, nil) != nil {
				renew.Reset(renewRetry)
			}
		case <-retry.timer.C:
			probed = rc.probe(rc.ctx, psp.DefaultMTU)
		case ok := <-probed:
			probed = nil
			// The new session probes again before it picks its mode.
			if retry.passed(ok) && a.replace(rc, causePSP, nil) != nil {
				retry.backoff()
			}
		}
	}
}

// replace opens the session that takes over from rc, for each cause. rc ends
// when the new session is attached. The open stops when rc ends: then Run
// opens a session.
func (a *Agent) replace(rc *relayConn, why cause, alts []*dp.RelayRef) error {
	eps := []endpoint{rc.ep}
	if why == causeDrain {
		// A relay that drains takes no new session.
		eps = refEndpoints(alts)
	}
	if len(eps) == 0 {
		slog.Info("Relay drains and names no other relay; the agent stays until the relay closes the session", "relay", rc.addr)
		return nil
	}
	ctx, cancel := context.WithCancel(rc.ctx)
	defer cancel()
	defer context.AfterFunc(rc.qc.Context(), cancel)()
	slog.Info("Replacing the relay session", "relay", rc.addr, "cause", why, "relays", len(eps))
	var errs []error
	for _, e := range eps {
		if ctx.Err() != nil {
			break
		}
		err := a.takeOver(ctx, e, rc, why)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}
	if len(errs) > 0 && ctx.Err() == nil {
		slog.Warn("Failed to replace the relay session", "relay", rc.addr, "cause", why, "error", errors.Join(errs...))
	}
	return errors.Join(errs...)
}

// takeOver dials the relay at e and attaches on the new session in place of old.
func (a *Agent) takeOver(ctx context.Context, e endpoint, old *relayConn, why cause) error {
	begin := time.Now()
	rc, err := a.dialRelay(ctx, e, false)
	if err != nil {
		return fmt.Errorf("relay %s: %w", e.addr, err)
	}
	if why == causePSP && rc.mode != dp.Mode_MODE_PSP {
		a.end(rc)
		return fmt.Errorf("relay %s: the PSP probe of the new session failed", e.addr)
	}
	return a.attach(ctx, rc, old, begin)
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
