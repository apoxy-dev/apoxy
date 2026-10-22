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
	"strings"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

var (
	errSessionClosed = errors.New("relay session closed")
	errAgentStopped  = errors.New("agent stopped")
)

// home is the record of a relay session in the root.
type home struct {
	s  *session
	ep endpoint
	// id is the relay ID from the Welcome. The session holds it from the dial
	// result until it ends, so no other connection to that relay attaches.
	id         string
	wanted     bool // Dialed for the wanted set, not for Config.Sessions.
	rank       uint32
	st         sessState
	since      time.Time // The attach.
	draining   bool
	alternates []endpoint
	// routes is the copy of the route table of the session.
	routes map[netip.Prefix]routeInfo
	synced bool // The first table ended.
	// held are the extra attachments of the session, by name. pending are the
	// specs of an attachX with no attachedX yet.
	held       map[string]heldX
	pending    map[string]*AttachmentSpec
	deprecated bool
	// remotes is the last remote set sent for each attachment ID of the session.
	remotes map[string]string
}

// heldX is an extra attachment on a home session.
type heldX struct {
	spec *AttachmentSpec
	at   Attachment
}

// routeWait is a routes event whose callback a home session waits for.
type routeWait struct {
	s   *session
	rev uint64
	seq uint64
}

// root is the process of Run. It owns the binding, the dial plan, the
// records of the home sessions and the public requests.
type root struct {
	a      *Agent
	mb     *mailbox
	ctx    context.Context
	cancel context.CancelFunc
	tasks  int
	ending bool
	err    error

	idRunning  bool
	homes      []*home
	keep       keeper
	expired    *identity.ExpiredError
	renewing   bool
	renewAgain bool

	b        *psp.Binding
	binding  bool
	bindWait []*session

	specs       map[string]*AttachmentSpec
	attaches    map[*AttachmentSpec]*attachReq
	detaches    []*detachReq
	attachRetry *time.Timer
	retryWait   time.Duration

	// reported are the routes of the primary that OnRoutes has. They stay
	// while no session is live, and the wanted set comes from them.
	routesOf   *home
	reported   map[netip.Prefix]routeInfo
	relayRefs  map[string]int // Count of the reported routes of each relay ID.
	routeWaits []routeWait
	// primaryID is the relay of the last primary, and primaryAddr the address
	// that the agent dialed for it. They stay while no session is live.
	primaryID, primaryAddr string
	// relayAddrs are the newest addresses that a route gave for each relay ID
	// that is wanted or that a session holds.
	relayAddrs map[string][]string
	// welcome is the relay ID of the newest Welcome at each dialed address.
	welcome map[string]string
	wanted  map[string]bool // The last wanted set.
	// remoteDirty tells that the attachments of a session changed, so the
	// remote sets go again.
	remoteDirty bool

	clamps   map[*psp.Peer]int
	pspPeers map[*psp.Peer]bool

	cb        *mailbox
	cbRunning bool
	cbEnding  bool
	seq, done uint64
	events    []eventMsg
}

// Run keeps Config.Sessions relay sessions, each on its own relay, until ctx
// ends. It returns ErrUpgrade or identity.ExpiredError with no session.
func (a *Agent) Run(ctx context.Context) error {
	if m := a.cfg.MTU; m != 0 && (m < psp.DefaultMTU || m > psp.MaxMTU) {
		return fmt.Errorf("MTU must be %d to %d, got %d", psp.DefaultMTU, psp.MaxMTU, m)
	}
	if n := a.cfg.Sessions; n < 0 || n > maxSessions {
		return fmt.Errorf("sessions must be 1 to %d, got %d", maxSessions, n)
	}
	if err := a.cfg.Identity.Start(ctx); err != nil {
		return fmt.Errorf("agent cert: %w", err)
	}
	r := &root{
		a: a, mb: newMailbox(), retryWait: minBackoff,
		attaches: map[*AttachmentSpec]*attachReq{}, reported: map[netip.Prefix]routeInfo{}, relayRefs: map[string]int{},
		relayAddrs: map[string][]string{}, welcome: map[string]string{}, wanted: map[string]bool{},
		clamps: map[*psp.Peer]int{}, pspPeers: map[*psp.Peer]bool{},
	}
	r.ctx, r.cancel = context.WithCancel(ctx)
	defer r.cancel()
	ref := &runRef{mb: r.mb, stopped: make(chan struct{})}
	if !a.run.CompareAndSwap(nil, ref) {
		return errors.New("agent runs already")
	}
	defer func() {
		a.run.Store(nil)
		close(ref.stopped)
	}()
	// The end of the last Run set a write deadline on the socket.
	if t := a.cfg.Transport; t != nil && t.Conn != nil {
		_ = t.Conn.SetWriteDeadline(time.Time{})
	}
	r.specs = a.setRunning()
	return r.run()
}

// setRunning publishes a snapshot with running set and returns the wanted
// extra attachments.
func (a *Agent) setRunning() map[string]*AttachmentSpec {
	for {
		old := a.snap.Load()
		n := *old
		n.running = true
		if a.snap.CompareAndSwap(old, &n) {
			specs := maps.Clone(old.specs)
			if specs == nil {
				specs = map[string]*AttachmentSpec{}
			}
			return specs
		}
	}
}

func (r *root) run() error {
	r.startIdentity()
	r.cb, r.cbRunning = newMailbox(), true
	go runCallbacks(r.cb, r.mb)
	r.keep.backoff = minBackoff
	r.plan()
	tick := time.NewTicker(tickInterval)
	defer tick.Stop()
	report := time.NewTicker(reportInterval)
	defer report.Stop()
	for {
		r.sendRemotes()
		r.flush()
		if r.ending && r.idle() {
			if !r.cbRunning {
				break
			}
			if !r.cbEnding {
				// The callbacks run each event that the root queued before.
				r.cbEnding = true
				r.cb.send(endMsg{})
			}
		}
		var stop <-chan struct{}
		if !r.ending {
			stop = r.ctx.Done()
		}
		select {
		case <-stop:
			r.shutdown()
		case <-r.mb.wake:
			for _, m := range r.mb.take() {
				r.handle(m)
			}
		case now := <-tick.C:
			r.tick(now)
		case now := <-report.C:
			if r.b != nil {
				r.b.ReportQUIC(now, r.a.quicLost.Load())
			}
		case <-r.a.cfg.Identity.Changed():
			r.plan()
		case <-r.keep.choiceTimer():
			r.closeRound()
		case <-r.keep.waitTimer():
			r.keep.wait = nil
			r.plan()
		case <-timerC(r.keep.wake):
			r.keep.wake = nil
			r.plan()
		case <-timerC(r.attachRetry):
			r.attachRetry = nil
			r.attachMissing()
		}
	}
	if b := r.b; b != nil {
		// The close waits for the lane read loops, which a blocked device write
		// holds. The API user stops the driver after Run returns.
		go func() { _ = b.Close() }()
	}
	r.publish(false)
	return r.err
}

// timerC returns the channel of t, or nil.
func timerC(t *time.Timer) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}

// task runs f in a goroutine and gives its result to the root.
func (r *root) task(f func() any) {
	r.tasks++
	mb := r.mb
	go func() { mb.send(taskDone{f()}) }()
}

// idle reports whether the root has no child and no task.
func (r *root) idle() bool {
	return len(r.homes) == 0 && r.tasks == 0 && !r.idRunning
}

// stop ends Run with err.
func (r *root) stop(err error) {
	if r.err == nil {
		r.err = err
	}
	r.cancel()
}

// shutdown starts the end of Run: the writes on the socket get a deadline, so
// that a blocked write or close ends, and each session ends.
func (r *root) shutdown() {
	r.ending = true
	if t := r.a.cfg.Transport; t != nil && t.Conn != nil {
		_ = t.Conn.SetWriteDeadline(time.Now().Add(closeWrites))
	}
	r.cancel()
	k := &r.keep
	if rd := k.round; rd != nil {
		rd.cancel()
		if rd.choice != nil {
			rd.choice.Stop()
		}
		k.round = nil
	}
	if k.wait != nil {
		k.wait.Stop()
		k.wait = nil
	}
	if k.wake != nil {
		k.wake.Stop()
		k.wake = nil
	}
	if r.attachRetry != nil {
		r.attachRetry.Stop()
		r.attachRetry = nil
	}
	for _, h := range r.homes {
		h.s.mb.send(endMsg{})
	}
	for spec, q := range r.attaches {
		q.reply <- attachReply{err: errNoRelay}
		delete(r.attaches, spec)
	}
	for _, q := range r.detaches {
		q.reply <- nil
	}
	r.detaches = nil
}

// startIdentity starts the identity process: it renews the cert, so that the
// next handshake has a valid one.
func (r *root) startIdentity() {
	r.idRunning = true
	id, ctx, mb := r.a.cfg.Identity, r.ctx, r.mb
	go func() { mb.send(identityEnded{id.Run(ctx)}) }()
}

func (r *root) handle(m any) {
	switch m := m.(type) {
	case taskDone:
		r.tasks--
		r.handle(m.m)
	case dialResult:
		if r.ending {
			if m.d != nil {
				m.d.close("agent stopped")
			}
			return
		}
		r.dialDone(m)
	case wantDialed:
		r.wantDone(m)
	case relisted:
		r.relistDone(m)
		r.plan()
	case renewed:
		r.renewDone(m)
		r.plan()
	case bound:
		r.bound(m)
	case identityEnded:
		r.idRunning = false
		// After the cert of an identity file expires, the sessions stay, and Run opens none.
		if e := (*identity.ExpiredError)(nil); errors.As(m.err, &e) {
			r.expired = e
			r.plan()
		}
	case sessEnded:
		r.sessEnded(m)
	case doneMsg:
		r.done = m.seq
		r.callbackDone()
	case cbEnded:
		r.cbRunning = false
	case attachReqMsg:
		r.attachRequest(m)
	case cancelReqMsg:
		r.cancelRequest(m)
	case detachReqMsg:
		r.detachRequest(m)
	case attachedX:
		r.attached(m)
	case detachedX:
		r.detached(m)
	case bindMsg:
		r.bind(m)
	default:
		if !r.ending {
			r.handleLive(m)
		}
	}
}

// handleLive takes the messages that the root drops after the end started.
func (r *root) handleLive(m any) {
	now := time.Now()
	switch m := m.(type) {
	case statusMsg:
		r.status(m)
	case clampMsg:
		if r.homeOf(m.s) == nil {
			return
		}
		r.clamps[m.peer] = m.mtu
		r.setClamp()
		m.s.mb.send(clampedMsg{m.peer, m.attempt})
	case peerMode:
		r.peerMode(m.peer, m.mode)
	case routesMsg:
		r.routes(m)
	case reportMsg:
		m.peer.Report(now, m.sas)
	case offerMsg:
		req, err := m.peer.Offer(now)
		m.s.mb.send(rekeyMsg{peer: m.peer, attempt: m.attempt, req: req, err: err})
	case refusedMsg:
		req, err := m.peer.Refused(m.spis, now)
		m.s.mb.send(rekeyMsg{peer: m.peer, attempt: m.attempt, req: req, err: err})
	case applyMsg:
		refused, err := m.peer.Apply(m.req, now)
		m.s.mb.send(appliedMsg{peer: m.peer, attempt: m.attempt, refused: refused, err: err})
	case drainedMsg:
		r.drained(m)
	}
}

// homeOf returns the record of the home session s, or nil.
func (r *root) homeOf(s *session) *home {
	for _, h := range r.homes {
		if h.s == s {
			return h
		}
	}
	return nil
}

// take starts a session on the connection d, which holds the relay ID of its
// Welcome from now on. When another session holds that ID, d ends before its
// Attach, and take returns false.
func (r *root) take(d *dialed, wanted bool) bool {
	if o := r.holder(d.relayID); o != nil {
		slog.Warn("Closed a second connection to a relay before its attach", "relay", d.relayID, "address", d.ep.addr, "other_address", o.ep.addr)
		d.close("agent has a connection to this relay")
		r.failRelay(d.relayID)
		return false
	}
	k := &r.keep
	s := newSession(r.a, r.ctx, r.mb, d, k.rank)
	r.homes = append(r.homes, &home{
		s: s, ep: d.ep, id: d.relayID, wanted: wanted, rank: k.rank,
		routes: map[netip.Prefix]routeInfo{}, held: map[string]heldX{}, pending: map[string]*AttachmentSpec{}, remotes: map[string]string{},
	})
	k.rank++
	go s.run()
	return true
}

// holder returns the session that holds the relay ID id, or nil.
func (r *root) holder(id string) *home {
	for _, h := range r.homes {
		if h.id == id {
			return h
		}
	}
	return nil
}

// live returns the attached and the draining home sessions in rank order.
func (r *root) live() []*home {
	var out []*home
	for _, h := range r.homes {
		if h.st.attached {
			out = append(out, h)
		}
	}
	slices.SortStableFunc(out, func(x, y *home) int { return cmp.Compare(x.rank, y.rank) })
	return out
}

// attachedHomes returns the attached home sessions that do not drain, in rank order.
func (r *root) attachedHomes() []*home {
	return slices.DeleteFunc(r.live(), func(h *home) bool { return h.draining })
}

// primary returns the session with the default address: the attached one with
// the lowest rank, else the draining one with the lowest rank, or nil.
func (r *root) primary() *home {
	live := r.live()
	if len(live) == 0 {
		return nil
	}
	if i := slices.IndexFunc(live, func(h *home) bool { return !h.draining }); i >= 0 {
		return live[i]
	}
	return live[0]
}

// status takes the state of a home session. The first attached state makes
// the session one of the agent.
func (r *root) status(m statusMsg) {
	h := r.homeOf(m.s)
	if h == nil {
		return
	}
	first := m.st.attached && !h.st.attached
	h.st = m.st
	if !first {
		return
	}
	k := &r.keep
	k.failed, k.refused = 0, nil
	h.since = time.Now()
	r.remoteDirty = true
	st := &h.st
	slog.Info("Attached to the VPC", "relay", h.ep.addr, "relay_id", h.id, "address", st.base.Address, "prefixes", st.base.Prefixes, "rank", h.rank,
		"transport", transportName(st.mode), "fallback", st.reason, "connect", st.connect, "setup", st.setup)
	if f := r.a.cfg.OnAttach; f != nil {
		b, addr, prefixes := r.b, st.base.Address, slices.Clone(st.base.Prefixes)
		r.queue(func() { f(b, addr, prefixes) })
	}
	r.prefer()
	// OnRoutes follows the new session only after its OnAttach.
	r.usePrimary()
	r.attachMissing()
}

// drained marks a home session draining: its relay drains. The dial plan
// opens a session on another relay.
func (r *root) drained(m drainedMsg) {
	h := r.homeOf(m.s)
	if h == nil || !h.st.attached || h.draining {
		return
	}
	h.draining, h.alternates = true, m.alts
	slog.Info("Relay drains; its session stays until the relay closes it", "relay", h.ep.addr, "address", h.st.base.Address, "alternates", len(m.alts))
	r.prefer()
	r.usePrimary()
	r.plan()
}

// sessEnded forgets a home session, queues OnDetach for its attachments and
// counts the sessions again.
func (r *root) sessEnded(m sessEnded) {
	h := r.homeOf(m.s)
	if h == nil {
		return
	}
	r.homes = slices.DeleteFunc(r.homes, func(o *home) bool { return o == h })
	if !r.ending {
		slog.Info("Relay session ended", "relay", h.ep.addr, "error", m.err)
	}
	if f := r.a.cfg.OnDetach; f != nil && h.st.attached {
		for _, at := range slices.Backward(r.attachmentsOf(h)) {
			r.queue(func() { f(at) })
		}
	}
	if r.b != nil && m.link != nil {
		r.b.RemoveLink(m.link)
	}
	if m.peer != nil {
		r.removePeer(m.peer)
	}
	if r.routesOf == h {
		r.routesOf = nil
	}
	r.routeWaits = slices.DeleteFunc(r.routeWaits, func(w routeWait) bool { return w.s == h.s })
	for _, q := range r.attaches {
		q.sessEnded(h.s)
	}
	for _, q := range r.detaches {
		delete(q.wait, h.s)
	}
	r.callbackDone()
	if r.ending {
		return
	}
	if certRefused(m.err) {
		r.renew()
	}
	if h.st.attached {
		r.remoteDirty = true
		// After a session of this age, the next failed dial of its relay waits minBackoff.
		if time.Since(h.since) > stableSession {
			delete(r.keep.waits, h.id)
		}
		r.prefer()
		r.usePrimary()
	} else {
		r.retry([]string{h.id}, fmt.Errorf("relay %s: %w", h.ep.addr, m.err))
	}
	r.plan()
}

// removePeer removes a relay peer from the binding with its SAs and routes.
func (r *root) removePeer(p *psp.Peer) {
	delete(r.pspPeers, p)
	if _, ok := r.clamps[p]; ok {
		delete(r.clamps, p)
		r.setClamp()
	}
	if r.b != nil {
		r.b.RemovePeer(p)
	}
}

// peerMode takes the mode of a relay peer. A peer in QUIC mode has no path MTU
// for the clamp, and the rekeys of its receive SAs stop after PSP mode.
func (r *root) peerMode(p *psp.Peer, mode dp.Mode) {
	if mode == dp.Mode_MODE_PSP {
		r.pspPeers[p] = true
		return
	}
	if _, ok := r.clamps[p]; ok {
		delete(r.clamps, p)
		r.setClamp()
	}
	if r.pspPeers[p] {
		delete(r.pspPeers, p)
		p.StopRekeys()
	}
}

// setClamp sets the MSS clamp of the binding: the smallest path MTU of the
// sessions below the device MTU, else none.
func (r *root) setClamp() {
	if r.b == nil {
		return
	}
	dev, clamp := r.b.DeviceMTU(), 0
	for _, mtu := range r.clamps {
		if mtu < dev && (clamp == 0 || mtu < clamp) {
			clamp = mtu
		}
	}
	if r.b.SetClampMTU(clamp) == clamp {
		return
	}
	if clamp == 0 {
		slog.Info("Path to the relay carries the device MTU; removed the TCP MSS clamp", "device_mtu", dev)
	} else {
		slog.Info("Path to the relay does not carry the device MTU; clamped the TCP MSS", "mtu", clamp, "device_mtu", dev)
	}
}

// bound is the result of the bind task.
type bound struct {
	b   *psp.Binding
	err error
}

// bind gives a session the binding. The first one starts the bind task.
func (r *root) bind(m bindMsg) {
	switch {
	case r.ending:
		m.s.mb.send(bindingMsg{err: errAgentStopped})
		return
	case r.b != nil:
		m.s.mb.send(bindingMsg{b: r.b})
		return
	}
	r.bindWait = append(r.bindWait, m.s)
	if r.binding {
		return
	}
	r.binding = true
	a, cfg := r.a, m.cfg
	r.task(func() any {
		b, err := a.newBinding(cfg)
		return bound{b, err}
	})
}

func (r *root) bound(m bound) {
	r.binding = false
	if m.err == nil {
		r.b = m.b
	}
	for _, s := range r.bindWait {
		s.mb.send(bindingMsg{m.b, m.err})
	}
	r.bindWait = nil
}

// newBinding makes the PSP binding of the VPC of cfg.
func (a *Agent) newBinding(cfg *dp.Config) (*psp.Binding, error) {
	mtu := int(cfg.GetMtu())
	if mtu == 0 {
		mtu = psp.DefaultMTU
	}
	dev := a.deviceMTU(mtu)
	b, err := psp.New(psp.Config{
		Transport: a.cfg.Transport, Demux: &a.demux, VNI: cfg.GetVpc().GetNetworkId(), MTU: mtu, DeviceMTU: dev,
		OnTrip: onTrip,
	})
	if err != nil {
		return nil, err
	}
	if dev < mtu {
		slog.Info("Using a device MTU below the VPC MTU", "mtu", mtu, "device_mtu", dev)
	}
	return b, nil
}

// tick runs the timers of the binding and gives each receive SA renewal to
// the session of its relay peer.
func (r *root) tick(now time.Time) {
	if r.b == nil || r.ending {
		return
	}
	ups, err := r.b.Tick(now)
	if err != nil {
		slog.Warn("Failed to rekey receive SAs", "error", err)
	}
	for _, u := range ups {
		if h := r.peerHome(u.Peer); h != nil {
			h.s.mb.send(rekeyMsg{peer: u.Peer, req: u.Request})
		}
	}
}

// peerHome returns the home session whose relay peer is p, or nil.
func (r *root) peerHome(p *psp.Peer) *home {
	for _, h := range r.homes {
		if h.st.peer == p {
			return h
		}
	}
	return nil
}

// prefer queues OnDeprecated for the addresses of each session that is not the
// attached session with the lowest rank, and OnPreferred for that session when
// its addresses were deprecated. A new connection then takes its source address
// from the relay with the lowest rank that is up.
func (r *root) prefer() {
	live := r.live()
	var best *home
	if i := slices.IndexFunc(live, func(h *home) bool { return !h.draining }); i >= 0 {
		best = live[i]
	}
	for _, h := range live {
		if h.deprecated == (h != best) {
			continue
		}
		h.deprecated = h != best
		f := r.a.cfg.OnPreferred
		if h.deprecated {
			f = r.a.cfg.OnDeprecated
		}
		if f == nil {
			continue
		}
		for _, at := range r.attachmentsOf(h) {
			r.queue(func() { f(at) })
		}
	}
}

// attachmentsOf returns the attachment of Config on h, then its extra
// attachments by name.
func (r *root) attachmentsOf(h *home) []Attachment {
	out := []Attachment{h.st.base}
	for _, x := range h.held {
		out = append(out, x.at)
	}
	slices.SortFunc(out[1:], func(x, y Attachment) int { return cmp.Compare(x.Name, y.Name) })
	return out
}

// usePrimary gives the primary session the packets with no session source, and
// OnRoutes its routes. The relay of the primary replaces the kept one. Run it
// after the callbacks of the change.
func (r *root) usePrimary() {
	p := r.primary()
	if p == nil || r.routesOf == p {
		return
	}
	r.b.SetDefault(p.st.link)
	r.routesOf = p
	r.primaryID, r.primaryAddr = p.id, p.ep.addr
	if p.synced {
		r.syncRoutes()
	}
}

// routes takes a change of the route table of a session. The routes of the
// primary go to OnRoutes; the end of the first table of a session is a sync.
// The wanted set follows the reported routes.
func (r *root) routes(m routesMsg) {
	h := r.homeOf(m.s)
	if h == nil {
		return
	}
	for _, c := range m.changes {
		if c.add {
			h.routes[c.prefix] = c.routeInfo
		} else {
			delete(h.routes, c.prefix)
		}
	}
	if m.first {
		h.synced = true
	}
	queued := false
	switch {
	case r.routesOf != h:
	case m.first:
		queued = r.syncRoutes()
	default:
		queued = r.report(m.changes)
	}
	if r.routesOf == h {
		r.plan()
	}
	if !m.delta {
		return
	}
	if queued {
		r.routeWaits = append(r.routeWaits, routeWait{m.s, m.rev, r.seq})
		return
	}
	m.s.mb.send(routesDone{m.rev})
}

// syncRoutes makes the reported routes the routes of the primary and queues
// the change of their prefixes. It reports whether it queued an event.
func (r *root) syncRoutes() bool {
	want := r.routesOf.routes
	var add, remove []netip.Prefix
	for p, info := range want {
		if _, ok := r.reported[p]; !ok {
			add = append(add, p)
		}
		r.setReported(p, info)
	}
	for p := range r.reported {
		if _, ok := want[p]; !ok {
			remove = append(remove, p)
			r.unsetReported(p)
		}
	}
	return r.onRoutes(add, remove)
}

// report applies changes of the routes of the primary to the reported routes
// and queues the change of their prefixes. It reports whether it queued an event.
func (r *root) report(changes []routeChange) bool {
	had := map[netip.Prefix]bool{}
	for _, c := range changes {
		if _, seen := had[c.prefix]; !seen {
			_, had[c.prefix] = r.reported[c.prefix]
		}
		if c.add {
			r.setReported(c.prefix, c.routeInfo)
		} else {
			r.unsetReported(c.prefix)
		}
	}
	var add, remove []netip.Prefix
	for p, was := range had {
		switch _, is := r.reported[p]; {
		case is && !was:
			add = append(add, p)
		case was && !is:
			remove = append(remove, p)
		}
	}
	return r.onRoutes(add, remove)
}

// setReported sets the reported route of p. A route with the addresses of its
// relay gives the newest addresses of that relay.
func (r *root) setReported(p netip.Prefix, info routeInfo) {
	r.unsetReported(p)
	r.reported[p] = info
	if info.relay != "" {
		r.relayRefs[info.relay]++
		if len(info.addrs) > 0 {
			r.relayAddrs[info.relay] = info.addrs
		}
	}
}

// unsetReported removes the reported route of p.
func (r *root) unsetReported(p netip.Prefix) {
	old, ok := r.reported[p]
	if !ok {
		return
	}
	delete(r.reported, p)
	if old.relay == "" {
		return
	}
	if r.relayRefs[old.relay]--; r.relayRefs[old.relay] <= 0 {
		delete(r.relayRefs, old.relay)
	}
}

// onRoutes queues OnRoutes for a change of the reported prefixes. It reports
// whether it queued an event.
func (r *root) onRoutes(add, remove []netip.Prefix) bool {
	if len(add)+len(remove) == 0 {
		return false
	}
	f := r.a.cfg.OnRoutes
	if f == nil {
		return false
	}
	r.queue(func() { f(add, remove) })
	return true
}

// queue queues a callback for the callbacks process. The root sends it after
// it published the snapshot of the step.
func (r *root) queue(fn func()) {
	r.seq++
	r.events = append(r.events, eventMsg{r.seq, fn})
}

// flush publishes the snapshot, then gives the queued callbacks to the
// callbacks process, so that a callback reads the state of its event.
func (r *root) flush() {
	r.publish(true)
	for _, e := range r.events {
		r.cb.send(e)
	}
	r.events = nil
}

// callbackDone answers the waits for callbacks that returned.
func (r *root) callbackDone() {
	r.routeWaits = slices.DeleteFunc(r.routeWaits, func(w routeWait) bool {
		if w.seq > r.done {
			return false
		}
		w.s.mb.send(routesDone{w.rev})
		return true
	})
	for _, q := range r.attaches {
		r.attachProgress(q)
	}
	r.detaches = slices.DeleteFunc(r.detaches, r.detachProgress)
}

// publish stores the snapshot of the root state for the public reads.
func (r *root) publish(running bool) {
	s := &snapshot{running: running, specs: maps.Clone(r.specs)}
	for _, h := range r.live() {
		c := &connSnap{
			relay: h.ep.addr, name: h.s.d.name, rank: h.rank, draining: h.draining,
			mode: h.st.mode, reason: h.st.reason, connect: h.st.connect, setup: h.st.setup, rtt: h.st.rtt,
			base: h.st.base, dnsServers: h.st.dnsServers, dnsSearch: h.st.dnsSearch,
		}
		for _, x := range h.held {
			c.extras = append(c.extras, x.at)
		}
		slices.SortFunc(c.extras, func(x, y Attachment) int { return cmp.Compare(x.Name, y.Name) })
		s.conns = append(s.conns, c)
	}
	r.a.snap.Store(s)
}

// runCallbacks runs the user callbacks in order, one at a time, until end.
// It runs each event that came before end.
func runCallbacks(mb, up *mailbox) {
	for range mb.wake {
		for _, m := range mb.take() {
			switch m := m.(type) {
			case eventMsg:
				m.fn()
				up.send(doneMsg{m.seq})
			case endMsg:
				up.send(cbEnded{})
				return
			}
		}
	}
}

// sendRemotes gives each live session, for each of its attachments, the
// attachments of the same name on the other live sessions when that set
// changed. The relay keeps the last set of each attachment.
func (r *root) sendRemotes() {
	if !r.remoteDirty || r.ending {
		return
	}
	r.remoteDirty = false
	live := r.live()
	for _, h := range live {
		ids := map[string]bool{}
		for _, at := range r.attachmentsOf(h) {
			ids[at.ID] = true
			var others []*dp.RemoteAttachment
			for _, o := range live {
				if o == h {
					continue
				}
				for _, oat := range r.attachmentsOf(o) {
					if oat.Name == at.Name {
						others = append(others, &dp.RemoteAttachment{RelayId: o.id, AttachmentId: oat.ID, Addresses: prefixStrings(oat.Prefixes)})
					}
				}
			}
			slices.SortFunc(others, func(x, y *dp.RemoteAttachment) int { return cmp.Compare(x.RelayId, y.RelayId) })
			var key strings.Builder
			for _, o := range others {
				fmt.Fprintf(&key, "%s %s %v;", o.RelayId, o.AttachmentId, o.Addresses)
			}
			if h.remotes[at.ID] == key.String() {
				continue
			}
			h.remotes[at.ID] = key.String()
			h.s.mb.send(remoteMsg{&dp.RemoteAddresses{AttachmentId: at.ID, Attachments: others}})
		}
		maps.DeleteFunc(h.remotes, func(id string, _ string) bool { return !ids[id] })
	}
}
