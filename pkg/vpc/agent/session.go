// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// writerQueue is the most packets that wait for the writer of a session.
const writerQueue = 64

var errNoDataPath = errors.New("no data path")

// session is one relay session: a home session, which has the attachment of
// Config, or a visitor session, which uses the address of its home session on
// the relay of a visit.
type session struct {
	a      *Agent
	mb, up *mailbox
	d      *dialed
	rank   uint32
	vp     *visitParams // Nil for a home session.
	ctx    context.Context
	cancel context.CancelFunc
	tasks  int
	ending bool
	err    error

	rx    chan *dp.SessionResponse // From the stream reader.
	next  chan struct{}            // Lets the stream reader read after a RouteDelta.
	sw    *mailbox                 // The stream writer.
	w     chan func()              // The writer.
	drops int                      // Writes that the full writer queue dropped.

	attached bool
	id       string // Attachment ID.
	prefixes []netip.Prefix
	self     netip.Addr
	grant    ownGrant
	b        *psp.Binding
	link     *psp.Link
	peer     *psp.Peer
	pc       *peerconn.Conn
	setup    time.Duration
	draining bool
	alts     []endpoint
	homes    map[string]bool // Relays of the home sessions of the agent.

	routes                   routeTable
	waitRev                  uint64
	waiting, ackOK, routesOK bool

	mode          dp.Mode
	reason        dp.FallbackReason
	attempt       uint64      // The last attempt to change to PSP mode.
	att           *pspAttempt // The attempt that runs, or nil.
	probeID       uint64      // The probe that runs; an older result is stale.
	probing       bool
	pending       *probeResult // A probe result that came before the attach.
	passes        int
	wait          time.Duration
	retry         *time.Timer
	seen          netip.AddrPort // The address of the agent socket that the relay sees.
	counter       uint64         // The counter of the last path probe packet.
	chk           *check
	checks        map[*check]bool
	lanes         int // Send lanes: the lane ports that the relay took, plus 1.
	laneTk        *time.Ticker
	renewRefusals int
	staleOffers   int
	cur           []*extraConn
	extraConns    map[*extraConn]bool

	extras    map[string]*extra // By name.
	byID      map[string]*extra
	queue     []*xjob
	running   map[*xjob]bool
	joining   map[*xjob]bool
	detaching []*djob

	visits    map[string]*visitRec // By relay.
	resolving map[netip.Addr]bool
	visitTk   *time.Ticker
	vjoined   map[string]bool // Visitor: extra attachments in the visit, by ID.
	vqueue    []any           // Visitor: joins and leaves before the visit started.
}

// newSession returns the session on the connection d. A visitor session has
// vp. The session ends with ctx.
func newSession(a *Agent, ctx context.Context, up *mailbox, d *dialed, rank uint32, vp *visitParams) *session {
	s := &session{
		a: a, mb: newMailbox(), up: up, d: d, rank: rank, vp: vp,
		rx: make(chan *dp.SessionResponse, 1), next: make(chan struct{}, 1),
		mode: dp.Mode_MODE_QUIC, lanes: 1,
		checks: map[*check]bool{}, extraConns: map[*extraConn]bool{},
		extras: map[string]*extra{}, byID: map[string]*extra{},
		running: map[*xjob]bool{}, joining: map[*xjob]bool{},
		visits: map[string]*visitRec{}, resolving: map[netip.Addr]bool{}, vjoined: map[string]bool{},
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	return s
}

// visitor reports whether s is a visitor session.
func (s *session) visitor() bool { return s.vp != nil }

// addr returns the relay address as dialed.
func (s *session) addr() string { return s.d.ep.addr }

// task runs f in a goroutine and gives its result to the session.
func (s *session) task(f func() any) {
	s.tasks++
	mb := s.mb
	go func() { mb.send(taskDone{f()}) }()
}

// write gives f to the writer. A full queue drops it.
func (s *session) write(f func()) {
	if s.ending {
		return
	}
	select {
	case s.w <- f:
	default:
		s.drops++
	}
}

func (s *session) run() {
	s.start()
	for !s.ending || !s.idle() {
		var rx <-chan *dp.SessionResponse
		if !s.ending {
			rx = s.rx
		}
		select {
		case <-s.mb.wake:
			for _, m := range s.mb.take() {
				s.handle(m)
			}
		case m := <-rx:
			s.stream(m)
		case <-timerC(s.retry):
			s.retry = nil
			s.probeAgain()
		case <-s.attTimer():
			s.failAttempt(errors.New("wait for the relay SAs: time is up"))
		case <-tickerC(s.laneTk):
			b, to := s.b, s.d.relayAddr
			s.write(func() { b.KeepLanes(to) })
		case <-tickerC(s.visitTk):
			s.checkVisits()
		}
	}
	close(s.w)
	var link *psp.Link
	if !s.visitor() {
		link = s.link
	}
	s.up.send(sessEnded{s, s.err, link, s.peer})
}

// tickerC returns the channel of t, or nil.
func tickerC(t *time.Ticker) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}

// idle reports whether the session has no child and no task.
func (s *session) idle() bool {
	return s.tasks == 0 && len(s.checks) == 0 && len(s.extraConns) == 0 && len(s.visits) == 0
}

// start starts the long tasks, the attach and the first PSP probe. The probe
// runs while the relay attaches.
func (s *session) start() {
	s.read()
	s.sw = newMailbox()
	go writeStream(s.d.st, s.sw, s.mb)
	s.w = make(chan func(), writerQueue)
	go func(w chan func()) {
		for f := range w {
			f()
		}
	}(s.w)
	if !s.a.wantsPSP() {
		s.reason = dp.FallbackReason_FALLBACK_REASON_CONFIG
	}
	if s.visitor() {
		s.startVisit()
	} else {
		s.attachBase()
	}
	if s.a.wantsPSP() {
		// One pass is enough at the first probe of a session.
		s.passes, s.wait = pspPasses-1, s.a.retryMin
		s.startProbe()
	}
}

// read starts the stream reader. After a RouteDelta it waits for next, so the
// relay sees the backpressure of the callbacks.
func (s *session) read() {
	st, rx, next, ctx := s.d.st, s.rx, s.next, s.ctx
	s.task(func() any {
		for {
			m, err := st.Recv()
			if err != nil {
				return readerEnded{err}
			}
			select {
			case rx <- m:
			case <-ctx.Done():
				return readerEnded{ctx.Err()}
			}
			if m.GetRouteDelta() == nil {
				continue
			}
			select {
			case <-next:
			case <-ctx.Done():
				return readerEnded{ctx.Err()}
			}
		}
	})
}

// readerEnded is the result of the stream reader.
type readerEnded struct{ err error }

// ackMsg asks the stream writer for the Ack of a RouteDelta; ackSent is its answer.
type (
	ackMsg  struct{ rev uint64 }
	ackSent struct{ rev uint64 }
)

// writeStream sends the Acks on the Session stream until end or the end of
// the connection.
func writeStream(st interface {
	Send(*dp.SessionRequest) error
}, mb, up *mailbox) {
	for range mb.wake {
		for _, m := range mb.take() {
			switch m := m.(type) {
			case endMsg:
				return
			case ackMsg:
				if err := st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Ack{Ack: &dp.Ack{Rev: m.rev}}}); err != nil {
					return
				}
				up.send(ackSent{m.rev})
			}
		}
	}
}

// end starts the end of the session with the reason err.
func (s *session) end(err error) {
	if s.ending {
		return
	}
	s.ending, s.err = true, err
	s.cancel()
	s.d.cancel()
	reason := ""
	if errors.Is(err, errNoDataPath) {
		reason = err.Error()
	}
	qc := s.d.qc
	go func() { _ = qc.CloseWithError(0, reason) }()
	if s.pc != nil {
		_ = s.pc.Close()
	}
	for c := range s.checks {
		c.mb.send(endMsg{})
	}
	s.chk = nil
	for ec := range s.extraConns {
		ec.mb.send(endMsg{})
	}
	s.cur = nil
	for _, rec := range s.visits {
		rec.v.mb.send(endMsg{})
	}
	s.sw.send(endMsg{})
	if s.retry != nil {
		s.retry.Stop()
		s.retry = nil
	}
	if s.att != nil {
		s.att.timer.Stop()
		s.att = nil
	}
	s.stopLanes()
	if s.visitTk != nil {
		s.visitTk.Stop()
		s.visitTk = nil
	}
}

func (s *session) handle(m any) {
	switch m := m.(type) {
	case taskDone:
		s.tasks--
		if !s.ending {
			s.handle(m.m)
		}
		return
	case checkEnded:
		delete(s.checks, m.c)
		s.counter = max(s.counter, m.counter)
		return
	case extraEnded:
		delete(s.extraConns, m.ec)
		return
	case vEnded:
		s.visitEnded(m)
		return
	case endMsg:
		s.end(errAgentStopped)
		return
	}
	if s.ending {
		return
	}
	switch m := m.(type) {
	case readerEnded:
		err := m.err
		if cause := context.Cause(s.d.qc.Context()); cause != nil {
			err = cause
		}
		s.end(err)
	case ackSent:
		if m.rev == s.waitRev {
			s.ackOK = true
			s.readNext()
		}
	case routesDone:
		if m.rev == s.waitRev {
			s.routesOK = true
			s.readNext()
		}
	case baseAttached:
		s.baseAttached(m)
	case bindingMsg:
		s.bound(m)
	case homesMsg:
		s.homes = m.keys
	case probeDone:
		s.probeDone(m)
	case rekeyMsg:
		s.rekeyMsg(m)
	case rekeyDone:
		s.rekeyDone(m)
	case appliedMsg:
		s.applied(m)
	case lanesDone:
		s.lanesDone(m)
	case clampedMsg:
		s.clamped(m)
	case checkSend:
		if m.c == s.chk {
			tr, to := s.a.cfg.Transport, net.UDPAddrFromAddrPort(s.d.relayAddr)
			pkt := m.pkt
			s.write(func() { _, _ = tr.WriteTo(pkt, to) })
		}
	case checkSeen:
		if m.c == s.chk {
			s.seen = m.addr
			// The relay drops the lane ports at an address change.
			s.stopLanes()
		}
	case checkLost:
		if m.c == s.chk {
			s.chk = nil
			m.c.mb.send(endMsg{})
			s.useQUIC()
		}
	case extraUp:
		s.extraUp(m)
	case extraDown:
		if slices.Contains(s.cur, m.ec) {
			_ = s.pc.SetExtra(m.ec.i, nil)
		}
	default:
		s.handleExtras(m)
	}
}

// stream takes a message of the Session stream.
func (s *session) stream(m *dp.SessionResponse) {
	switch m := m.GetMsg().(type) {
	case *dp.SessionResponse_RouteDelta:
		s.routeDelta(m.RouteDelta)
	case *dp.SessionResponse_NoRoute:
		s.noRoute(m.NoRoute)
	case *dp.SessionResponse_Drain:
		s.drain(refEndpoints(m.Drain.GetAlternates()))
	case *dp.SessionResponse_Rekey:
		s.relayKeys(m.Rekey)
	case *dp.SessionResponse_RxReport:
		if s.peer != nil {
			s.up.send(reportMsg{s: s, peer: s.peer, sas: fromReport(m.RxReport)})
		}
	case *dp.SessionResponse_Config:
		if m.Config.GetMtu() != s.d.config.GetMtu() {
			slog.Info("VPC MTU changed; the new MTU applies after the agent restarts", "mtu", m.Config.GetMtu())
		}
	}
}

// routeDelta applies a RouteDelta to the route table. The reader reads on
// after the Ack went out and the callback of the change returned.
func (s *session) routeDelta(d *dp.RouteDelta) {
	first := !s.routes.synced
	changes := s.routes.apply(d, s.ownOrigin)
	s.waitRev, s.waiting, s.ackOK, s.routesOK = d.GetRev(), true, false, true
	s.sw.send(ackMsg{d.GetRev()})
	if s.visitor() {
		return
	}
	add, remove := prefixChanges(changes)
	s.routesOK = false
	s.up.send(routesMsg{s: s, add: add, remove: remove, first: first, delta: true, rev: d.GetRev()})
}

// readNext lets the reader read the next message.
func (s *session) readNext() {
	if s.waiting && s.ackOK && s.routesOK {
		s.waiting = false
		select {
		case s.next <- struct{}{}:
		default:
		}
	}
}

// ownOrigin reports whether origin is an attachment of this agent on s.
func (s *session) ownOrigin(origin string) bool {
	return origin == s.id || s.byID[origin] != nil
}

// drain marks the session draining when its relay drains. The root opens a
// session on another relay.
func (s *session) drain(alts []endpoint) {
	if s.visitor() || s.draining {
		return
	}
	s.draining, s.alts = true, alts
	if s.attached {
		s.up.send(drainedMsg{s, alts})
	}
	// An attempt that did not give its keys yet ends.
	if s.att != nil && s.att.rekeys == 0 {
		s.failAttempt(nil)
	}
}

// baseAttached is the result of the Attach call of the attachment of Config.
type baseAttached struct {
	id       string
	grant    ownGrant
	prefixes []netip.Prefix
	err      error
}

// attachBase starts the Attach call of the attachment of Config.
func (s *session) attachBase() {
	cfg, c, qc, ref, rank, addr, roots := &s.a.cfg, s.d.client, s.d.qc, s.d.config.GetVpc(), s.rank, s.addr(), s.d.roots
	req := &dp.AttachRequest{Vpc: ref, Name: cfg.Name, Labels: cfg.Labels, Routes: prefixStrings(cfg.Routes), Rank: rank}
	ctx := s.ctx
	s.task(func() any {
		ctx, cancel := context.WithTimeout(ctx, openTimeout)
		defer cancel()
		// A relay that does not answer in time ends the attach.
		stop := context.AfterFunc(ctx, func() { _ = qc.CloseWithError(0, "relay session did not attach in time") })
		defer stop()
		res, err := c.Attach(ctx, req)
		if err != nil {
			return baseAttached{err: attachError(qc, fmt.Errorf("attach: %w", err))}
		}
		logRefused(addr, req.GetName(), res.GetRoutes())
		// A bad relay cert fails the attach.
		claims, err := verifyOwn(addr, roots, res.GetGrant())
		if err != nil {
			return baseAttached{err: relayUpgrade(addr, err)}
		}
		prefixes, err := parsePrefixes(claims.GetAddresses())
		if err != nil {
			return baseAttached{err: err}
		}
		return baseAttached{id: claims.GetAttachmentId(), grant: newOwnGrant(res.GetGrant(), claims.GetAttachmentId()), prefixes: prefixes}
	})
}

func (s *session) baseAttached(m baseAttached) {
	if m.err != nil {
		s.end(m.err)
		return
	}
	s.id, s.grant, s.prefixes, s.self = m.id, m.grant, m.prefixes, overlayAddr(m.prefixes)
	// The routes that came for the attachment before the attach leave the table.
	if removed := s.routes.drop(m.id); len(removed) > 0 {
		s.up.send(routesMsg{s: s, remove: removed})
	}
	s.up.send(bindMsg{s, s.d.config})
}

// bound makes the link of the session in the binding, its relay peer and its
// QUIC data path.
func (s *session) bound(m bindingMsg) {
	if m.err != nil {
		s.end(m.err)
		return
	}
	b := m.b
	l, err := b.AddLink()
	if err != nil {
		s.end(err)
		return
	}
	s.b, s.link = b, l
	// The packets from the addresses of s go on s.
	for _, pfx := range s.prefixes {
		if err := l.AddSource(pfx); err != nil {
			s.end(fmt.Errorf("source %s: %w", pfx, err))
			return
		}
	}
	p, err := l.AddRelay(s.d.relayAddr)
	if err != nil {
		s.end(err)
		return
	}
	s.peer = p
	// The packets with no other route go to the relay.
	for _, pfx := range defaultRoutes {
		if err := b.AddRoute(pfx, p); err != nil {
			s.end(fmt.Errorf("default route %s: %w", pfx, err))
			return
		}
	}
	if err := s.useConn(); err != nil {
		s.end(err)
		return
	}
	s.setup = time.Since(s.d.begin)
	s.attached = true
	s.startExtras()
	s.status()
	if s.draining {
		s.up.send(drainedMsg{s, s.alts})
	}
	s.takePending()
}

// useConn makes the data frames of the relay peer go on the connection of s.
func (s *session) useConn() error {
	s.pc = peerconn.New(s.d.qc)
	s.pc.HandleData(s.link.HandleData)
	return s.peer.UseQUIC(s.pc)
}

// status gives the root the state of a home session.
func (s *session) status() {
	if s.visitor() {
		return
	}
	cfg := &s.a.cfg
	s.up.send(statusMsg{s, sessState{
		attached: s.attached, link: s.link, peer: s.peer,
		base: Attachment{
			Name: cfg.Name, Labels: maps.Clone(cfg.Labels), Routes: slices.Clone(cfg.Routes),
			ID: s.id, Address: s.self, Prefixes: slices.Clone(s.prefixes), Base: true, Relay: s.addr(),
		},
		mode: s.mode, reason: s.fallback(), connect: s.d.connect, setup: s.setup, rtt: s.d.rtt,
		dnsServers: s.d.config.GetDnsServers(), dnsSearch: s.d.config.GetDnsSearchDomains(),
	}})
}

// fallback returns why s is in QUIC mode: its config or a probe that failed. It
// returns no reason before the first probe result and in PSP mode.
func (s *session) fallback() dp.FallbackReason {
	if s.mode != dp.Mode_MODE_QUIC {
		return dp.FallbackReason_FALLBACK_REASON_UNSPECIFIED
	}
	return s.reason
}

// relayKeys takes relay SAs from the stream. The Offer of the attempt that
// runs has its generation; a renewal of the relay has generation 0.
func (s *session) relayKeys(m *dp.KeysRequest) {
	if s.peer == nil {
		return
	}
	gen := m.GetGeneration()
	req, err := keyproto.FromProto(m)
	switch {
	case s.att != nil && gen == s.att.n:
		if err != nil {
			s.failAttempt(fmt.Errorf("relay SAs: %w", err))
			return
		}
		s.up.send(applyMsg{s: s, peer: s.peer, attempt: gen, req: req})
	case gen == 0 || s.mode == dp.Mode_MODE_PSP && gen == s.attempt:
		if err != nil {
			slog.Warn("Failed to apply relay SAs", "relay", s.addr(), "error", err)
			return
		}
		s.up.send(applyMsg{s: s, peer: s.peer, req: req})
	default:
		// The relay revokes the SAs of an older attempt in its own tables.
		s.staleOffers++
		slog.Debug("Dropped relay SAs of an older attempt", "relay", s.addr(), "generation", gen, "attempt", s.attempt, "stale", s.staleOffers)
	}
}

// applied is the result of the relay SAs in the binding.
func (s *session) applied(m appliedMsg) {
	if m.peer != s.peer {
		s.toVisit(m.peer, m)
		return
	}
	err := m.err
	if err == nil && len(m.refused) > 0 {
		err = fmt.Errorf("SPIs %v are in use", m.refused)
	}
	if m.attempt == 0 || s.att == nil || m.attempt != s.att.n {
		if err != nil && m.attempt == 0 {
			slog.Warn("Failed to apply relay SAs", "relay", s.addr(), "error", err)
		}
		return
	}
	if err != nil {
		s.failAttempt(fmt.Errorf("apply relay SAs: %w", err))
		return
	}
	s.att.offerOK = true
	s.advance()
}

// localPort returns the port of the agent socket.
func (a *Agent) localPort() uint16 {
	if ua, ok := a.cfg.Transport.Conn.LocalAddr().(*net.UDPAddr); ok {
		return uint16(ua.Port)
	}
	return 0
}

// logRefused logs the advertised routes of the attachment name that the relay
// at addr refused. The attachment works without them.
func logRefused(addr, name string, routes []*dp.RouteStatus) {
	for _, r := range routes {
		if r.GetResult() != dp.RouteResult_ROUTE_RESULT_ACCEPTED {
			slog.Warn("Relay refused an advertised route", "relay", addr, "name", name, "route", r.GetPrefix(), "result", r.GetResult())
		}
	}
}

// attachError adds the close cause of qc to err.
func attachError(qc quic.Connection, err error) error {
	if cause := context.Cause(qc.Context()); cause != nil {
		return fmt.Errorf("%w (connection: %w)", err, cause)
	}
	return err
}

// rootsOf returns the relay roots of the cert in use.
func (a *Agent) rootsOf() *x509.CertPool {
	return a.relayRoots(a.cfg.Identity.Current())
}
