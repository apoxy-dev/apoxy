// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/types/known/emptypb"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/internal/proc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// peerCallTimeout limits a dial, a Hello, a Keys and a Candidates call of a pair.
	peerCallTimeout = 5 * time.Second
	// defaultPairOpenTimeout is the time that a new pair has to open its channel.
	defaultPairOpenTimeout = 30 * time.Second
	// maxPeerStreams is the most incoming streams of a channel.
	maxPeerStreams = 8
)

// peerQUIC is the QUIC config of the channels. A channel packet of 1248 B or less fits each path,
// so the channel has no path MTU discovery.
var peerQUIC = &quic.Config{
	Versions:                []quic.Version{quic.Version1},
	HandshakeIdleTimeout:    peerCallTimeout,
	KeepAlivePeriod:         5 * time.Second,
	MaxIdleTimeout:          15 * time.Second,
	InitialPacketSize:       1200,
	DisablePathMTUDiscovery: true,
	MaxIncomingStreams:      maxPeerStreams,
	MaxIncomingUniStreams:   -1,
}

// pairKey finds a pair after its Hello: the fingerprint of the peer leaf cert and the instance of
// the peer.
type pairKey struct {
	key  [32]byte
	inst uint64
}

// connAddrs are the overlay addresses of the QUIC client and the server of a channel.
type connAddrs struct{ client, server netip.Addr }

// less reports whether c has the lower client address, then the lower server address.
func (c connAddrs) less(o connAddrs) bool {
	if n := c.client.Compare(o.client); n != 0 {
		return n < 0
	}
	return c.server.Compare(o.server) < 0
}

// candsVal is the value of the own candidates and the own list. It does not change.
type candsVal struct {
	c   candidates
	own []netip.Prefix
}

// revLists is the value of the last revocation list of each session. It does not change.
type revLists struct {
	src   []*revokedList // The values of the sessions.
	lists [][]vpcv1alpha1.RevokedAgent
}

// revoked reports whether a list of l revokes leaf, the cert of the agent name.
func (l *revLists) revoked(leaf *x509.Certificate, name string) bool {
	if l == nil {
		return false
	}
	return slices.ContainsFunc(l.lists, func(list []vpcv1alpha1.RevokedAgent) bool { return identity.IsRevoked(leaf, name, list) })
}

// all returns the entries of all lists.
func (l *revLists) all() []vpcv1alpha1.RevokedAgent {
	if l == nil {
		return nil
	}
	var out []vpcv1alpha1.RevokedAgent
	for _, list := range l.lists {
		out = append(out, list...)
	}
	return out
}

// pairState is the state of a pair for Status. The root sets the direct routes of the pair while
// direct is set.
type pairState struct {
	open     bool
	noAnswer bool // A dial got no answer.
	probing  bool // A probe run or a PSP test runs, and the pair has no direct path.
	direct   bool
	addr     netip.AddrPort // The address of the direct path.
	rtt      time.Duration  // The time of the probe reply of addr.
	reason   string
}

// pairStart is what a new pair gets from the root.
type pairStart struct {
	flow  flow
	inst  uint64    // The own instance.
	relay *psp.Peer // The relay peer of the own end.
	b     chanNet
	dial  bool
	ref   *flowRef
	cands *candsVal
	lists *revLists
}

// chConn is one QUIC connection of a pair: a dial, an accept or the channel.
type chConn struct {
	qc     *quic.Conn
	rc     *rpc.Conn
	dialed bool // This agent dialed it.
	ctx    context.Context
	cancel context.CancelFunc // Ends the Hello call.
	late   *time.Timer        // The Hello deadline of an accepted connection.
	leaf   *x509.Certificate
	key    [32]byte
	name   string
	hello  bool // Its Hello passed.
	inst   uint64
	list   []netip.Prefix
}

// addrs returns the client and the server address of c on the flow f.
func (c *chConn) addrs(f flow) connAddrs {
	if c.dialed {
		return connAddrs{client: f.own, server: f.peer}
	}
	return connAddrs{client: f.peer, server: f.own}
}

// dialRef is one dial of a pair. cancel ends it.
type dialRef struct{ cancel context.CancelFunc }

// keyJob is one Keys call that waits: SAs for traffic from the peer.
type keyJob struct {
	attempt uint64
	req     keys.Request
}

// Task results and calls from the handlers of the channel.
type (
	dialDone struct {
		ref *dialRef
		qc  *quic.Conn
		err error
	}
	acceptDone struct {
		qc  *quic.Conn
		err error
	}
	helloDone struct {
		c   *chConn
		h   *dp.PeerHello
		err error
	}
	serveDone struct {
		c   *chConn
		err error
	}
	keysDone struct {
		attempt uint64
		refused []uint32
		err     error
	}
	candsDone struct{ err error }
	closeDone struct{}
	helloLate struct{ c *chConn }
	// callLate is a call of the peer that did not end in peerCallTimeout.
	callLate struct{ c *chConn }

	helloIn struct {
		c     *chConn
		h     *dp.PeerHello
		reply chan helloOut
	}
	helloOut struct {
		h   *dp.PeerHello
		err error
	}
	keysIn struct {
		c     *chConn
		req   *dp.KeysRequest
		reply chan keysOut
	}
	keysOut struct {
		refused []uint32
		err     error
	}
	candsIn struct {
		c     *chConn
		m     *dp.Candidates
		reply chan error
	}
)

// pair is the state of the agent for one peer agent: one channel, found by its flow and, after
// its Hello, by the fingerprint and the instance of the peer.
type pair struct {
	pairStart
	a      *Agent
	mb, up *proc.Mailbox
	ctx    context.Context
	cancel context.CancelFunc
	tasks  int
	ending bool
	// removed is set when the root removed the direct peer at the end.
	removed bool

	pc *chanConn
	tr *quic.Transport
	ln *quic.Listener
	// verified is the lists for the cert check of a handshake, which runs on a QUIC goroutine.
	verified atomic.Pointer[revLists]

	dialing *dialRef
	wait    time.Duration
	retry   *time.Timer
	openBy  *time.Timer
	certEnd *time.Timer
	st      pairState
	sent    pairState // The last state that the root got.

	cur       *chConn // The connection that the pair keeps now.
	committed bool    // pairOpen went for cur.
	open      bool
	peer      *psp.Peer
	probeKeys p2p.ProbeKeys

	keyN    uint64
	keyQ    []keyJob
	keyCall bool
	tries   map[uint64]int
	applies map[uint64]chan keysOut
	// heldKeys and heldCands are the calls of the peer before openOK. The peer can call as soon as
	// it opens, before this side has the Hello answer.
	heldKeys  []keysIn
	heldCands []candsIn

	round        uint32
	candCall     bool
	candWant     bool
	peerRound    uint32
	peerAddrs    []netip.AddrPort
	peerList     []netip.Prefix // The newest list of the peer.
	reportedList []netip.Prefix // The last list that the root got.
	observed     netip.AddrPort // The own address that the peer saw last.

	// The path manager: discovery and the check are child processes of the pair.
	role    probeRole
	disc    *discovery
	chk     *check // The check of the direct path, or nil.
	checks  int    // The checks that did not end yet.
	counter uint64 // The BFD counters of the last check that ended.
	highest uint64
	txReady bool                             // Apply of the SAs of the peer returned with no refusal.
	rxReady bool                             // The peer took the offer of this side with no refusal.
	runOn   bool                             // A probe run of a round or a challenge runs.
	passed  map[netip.AddrPort]time.Duration // Addresses that passed an outer probe, with the RTT.
	order   []netip.AddrPort                 // The addresses of passed, the first one first.
	testing map[netip.AddrPort]bool          // The PSP tests that run.
	next    netip.AddrPort                   // A tested address that waits for the end of the last check.
	nextRTT time.Duration
}

func newPair(a *Agent, up *proc.Mailbox, st pairStart) *pair {
	p := &pair{
		pairStart: st, a: a, mb: proc.NewMailbox(0), up: up, wait: minBackoff,
		tries: map[uint64]int{}, applies: map[uint64]chan keysOut{},
		passed: map[netip.AddrPort]time.Duration{}, testing: map[netip.AddrPort]bool{},
	}
	// The pair ends with endMsg, so the end of the root context does not end its tasks first.
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.verified.Store(st.lists)
	return p
}

// task runs f in a goroutine and gives its result to the pair.
func (p *pair) task(f func() any) {
	p.tasks++
	mb := p.mb
	go func() { mb.Send(taskDone{f()}) }()
}

func (p *pair) run() {
	p.start()
	for !p.ending || p.tasks > 0 || !p.removed || p.disc != nil || p.checks > 0 {
		select {
		case <-p.mb.Wake():
			for _, m := range p.mb.Take() {
				p.handle(m)
			}
		case <-timerC(p.retry):
			p.retry = nil
			p.startDial()
		case <-timerC(p.openBy):
			p.openBy = nil
			if !p.open {
				p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, "channel did not open in time")
			}
		case <-timerC(p.certEnd):
			p.certEnd = nil
			p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_CERT, "peer cert expired")
		}
	}
	p.mb.Close()
	p.up.Send(pairEnded{p})
}

// start opens the QUIC transport of the pair and its listener, and dials on the dial side.
func (p *pair) start() {
	p.pc = newChanConn(p.b, p.relay, p.flow, p.ref.rx)
	p.tr = &quic.Transport{Conn: p.pc}
	p.openBy = time.NewTimer(p.a.pairOpen)
	ln, err := p.tr.Listen(p.tlsConfig(false), peerQUIC)
	if err != nil {
		slog.Warn("Failed to start a peer channel", "peer", p.flow.peer, "error", err)
		p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, "")
		return
	}
	p.ln = ln
	p.accept()
	if p.dial {
		p.startDial()
	}
}

// tlsConfig returns the TLS config of a dial, or of the listener. The agent cert has no server
// name, so each side checks the chain of the other in verify.
func (p *pair) tlsConfig(dial bool) *tls.Config {
	c := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		NextProtos:             []string{dp.ALPNPeer},
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  p.verify,
	}
	if dial {
		c.InsecureSkipVerify = true
		c.GetClientCertificate = p.a.cfg.Identity.GetClientCertificate
	} else {
		c.ClientAuth = tls.RequireAnyClientCert
		c.GetCertificate = p.a.cfg.Identity.GetCertificate
	}
	return c
}

// verify checks the cert chain of the peer: the CA bundle, the project and the VPC of the own
// cert, client auth, and the revocation lists of the pair.
func (p *pair) verify(raw [][]byte, _ [][]*x509.Certificate) error {
	cred := p.a.cfg.Identity.Current()
	if cred == nil {
		return errors.New("agent credential is not loaded")
	}
	roots, err := identity.NewPool(cred.CABundle)
	if err != nil {
		return err
	}
	chain := make([]*x509.Certificate, 0, len(raw))
	for _, b := range raw {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return fmt.Errorf("parse peer cert: %w", err)
		}
		chain = append(chain, c)
	}
	_, err = identity.Verify(chain, identity.VerifyOptions{
		Roots: roots, Project: cred.ID.Project, VPC: cred.ID.VPC, Revoked: p.verified.Load().all(),
	})
	return err
}

func (p *pair) handle(m any) {
	switch m := m.(type) {
	case taskDone:
		p.tasks--
		p.handle(m.m)
		return
	case peerRemoved:
		p.removed = true
		return
	case discEnded:
		if m.d == p.disc {
			p.disc = nil
		}
		return
	case checkEnded:
		p.checkEnded(m)
		return
	case checkSend:
		if !p.ending && m.c == p.chk && p.st.direct {
			if _, err := p.a.cfg.Transport.WriteTo(m.pkt, net.UDPAddrFromAddrPort(p.st.addr)); err != nil {
				slog.Debug("Failed to send a BFD packet to a peer agent", "address", p.st.addr, "error", err)
			}
		}
		return
	case acceptDone:
		p.accepted(m)
		return
	case dialDone:
		p.dialed(m)
		return
	case helloIn:
		if p.ending {
			m.reply <- helloOut{err: rpc.Errorf(rpc.Unavailable, "pair ended")}
			return
		}
	case keysIn:
		if p.ending {
			m.reply <- keysOut{err: rpc.Errorf(rpc.Unavailable, "pair ended")}
			return
		}
	case candsIn:
		if p.ending {
			m.reply <- rpc.Errorf(rpc.Unavailable, "pair ended")
			return
		}
	}
	if p.ending {
		return
	}
	switch m := m.(type) {
	case helloDone:
		p.helloDone(m)
	case helloIn:
		p.helloIn(m)
	case callLate:
		if m.c == p.cur && p.committed {
			p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, "peer call did not end in time")
		} else {
			// The end of the connection gives its close error to connEnded, which retries a dial.
			p.closeConn(m.c.qc, dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, "peer call did not end in time")
		}
	case helloLate:
		if m.c == p.cur && !m.c.hello {
			p.drop(m.c, dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, "no Hello in time")
		}
	case serveDone:
		p.connEnded(m)
	case openOK:
		p.opened(m)
	case dupMsg:
		p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE, "agent keeps another channel with this peer")
	case heldMsg:
		// An accept pair can be another agent with the prefix: it gets the time of a dial and a Hello
		// after its last packet.
		quiet := time.Since(time.Unix(0, p.ref.used.Load())) >= peerCallTimeout
		if p.cur == nil && !p.committed && (p.dial || quiet) {
			p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE, "agent keeps another channel with this peer")
		}
	case evictMsg:
		p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, "agent has too many peers")
	case endMsg:
		p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, "agent stops")
	case identityMsg:
		p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_CERT, "agent cert changed")
	case revocationsMsg:
		p.revocations(m.v)
	case candidatesMsg:
		p.cands = m.v
		if p.open {
			p.candWant = true
			p.sendCands()
		}
	case useMsg:
		if p.disc != nil {
			p.disc.mb.Send(discUse{})
		}
	case discProbing:
		p.runOn = m.on
		p.status()
	case discRunEnded:
		p.runEnded(m)
	case discPassed:
		p.pathPassed(m)
	case discTested:
		p.tested(m)
	case discSeen:
		p.seen(m.addr)
	case discBFD:
		if p.chk != nil {
			p.chk.give(m.pkt)
		}
	case checkLost:
		p.lost(m.c)
	case rekeyMsg:
		p.rekeyMsg(m)
	case keysDone:
		p.keysDone(m)
	case keysIn:
		p.keysIn(m)
	case appliedMsg:
		if reply := p.applies[m.attempt]; reply != nil {
			delete(p.applies, m.attempt)
			reply <- keysOut{refused: m.refused, err: m.err}
		}
		if m.err == nil && len(m.refused) == 0 && !p.txReady {
			p.txReady = true
			p.tryTests()
		}
	case candsIn:
		p.candsIn(m)
	case candsDone:
		p.candCall = false
		if m.err != nil {
			p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, fmt.Sprint("Candidates call failed: ", m.err))
			return
		}
		p.sendCands()
	}
}

// accept starts the accept task of the listener.
func (p *pair) accept() {
	ln, ctx := p.ln, p.ctx
	p.task(func() any {
		qc, err := ln.Accept(ctx)
		return acceptDone{qc, err}
	})
}

// startDial starts a dial, unless the pair has a connection or a dial.
func (p *pair) startDial() {
	if p.ending || p.committed || p.cur != nil || p.dialing != nil {
		return
	}
	ctx, cancel := context.WithTimeout(p.ctx, peerCallTimeout)
	ref := &dialRef{cancel}
	p.dialing = ref
	tr, to, conf := p.tr, p.pc.remote, p.tlsConfig(true)
	p.task(func() any {
		defer cancel()
		qc, err := tr.Dial(ctx, to, conf, peerQUIC)
		return dialDone{ref, qc, err}
	})
}

// dialFailed waits for the next dial: 1, 2, 4 ... s. A dial with no answer goes in the status.
func (p *pair) dialFailed(err error) {
	if !p.dial || p.ending || p.committed {
		return
	}
	if ae := new(quic.ApplicationError); errors.As(err, &ae) && ae.Remote && ae.ErrorCode == quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE) {
		// The peer keeps another connection. Its dial on this flow, or the open deadline, ends the wait.
		slog.Debug("Peer channel dial ends: the peer keeps another connection", "peer", p.flow.peer)
		return
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, new(*quic.HandshakeTimeoutError)) || errors.As(err, new(*quic.IdleTimeoutError)) {
		p.st.noAnswer = true
		p.status()
	}
	slog.Debug("Peer channel dial failed", "peer", p.flow.peer, "wait", p.wait, "error", err)
	p.retry = time.NewTimer(p.wait)
	p.wait *= 2
}

// dialed takes the result of a dial.
func (p *pair) dialed(m dialDone) {
	current := m.ref == p.dialing
	if current {
		p.dialing = nil
	}
	if m.err != nil {
		if current {
			p.dialFailed(m.err)
		}
		return
	}
	if !current || p.ending || p.committed || p.cur != nil {
		p.closeConn(m.qc, dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE, "agent keeps another connection with this peer")
		return
	}
	c := p.newConn(m.qc, true)
	if c == nil {
		p.dialFailed(errors.New("peer cert is revoked"))
		return
	}
	p.cur = c
	p.serve(c)
	p.hello(c)
}

// accepted takes the result of the accept task. On one flow, the connection whose client has the
// lower address stays, and the other one closes with DUPLICATE.
func (p *pair) accepted(m acceptDone) {
	if m.err != nil {
		return
	}
	if p.ending {
		p.closeConn(m.qc, dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, "")
		return
	}
	p.accept()
	c := p.newConn(m.qc, false)
	if c == nil {
		return
	}
	ownLower := p.flow.own.Less(p.flow.peer)
	switch {
	case p.committed:
		p.drop(c, dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE, "agent keeps another connection with this peer")
		return
	case p.dialing != nil && ownLower:
		p.drop(c, dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE, "agent keeps its own dial")
		return
	case p.dialing != nil:
		// The result of the dial closes its connection.
		p.dialing.cancel()
		p.dialing = nil
	case p.cur != nil && p.cur.dialed && ownLower:
		p.drop(c, dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE, "agent keeps its own dial")
		return
	case p.cur != nil && p.cur.dialed:
		p.drop(p.cur, dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE, "agent keeps the dial of the peer")
	case p.cur != nil:
		p.drop(p.cur, dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, "peer dialed again")
	}
	p.cur = c
	p.serve(c)
	mb := p.mb
	c.late = time.AfterFunc(peerCallTimeout, func() { mb.Send(helloLate{c}) })
}

// newConn returns the record of a connection after its handshake, or nil and closes it with CERT
// when a list that came during the handshake revokes the peer.
func (p *pair) newConn(qc *quic.Conn, dialed bool) *chConn {
	certs := qc.ConnectionState().TLS.PeerCertificates
	if len(certs) == 0 {
		p.closeConn(qc, dp.PeerCloseCode_PEER_CLOSE_CODE_CERT, "no peer cert")
		return nil
	}
	leaf := certs[0]
	id, err := identity.IDFromCert(leaf)
	if err != nil || p.lists.revoked(leaf, id.Agent) {
		p.closeConn(qc, dp.PeerCloseCode_PEER_CLOSE_CODE_CERT, "peer cert is revoked")
		return nil
	}
	c := &chConn{qc: qc, dialed: dialed, leaf: leaf, key: sha256.Sum256(leaf.RawSubjectPublicKeyInfo), name: id.Agent}
	c.ctx, c.cancel = context.WithCancel(p.ctx)
	return c
}

// serve starts the task that serves the calls of the peer on c until c ends.
func (p *pair) serve(c *chConn) {
	mux := rpc.NewMux()
	dp.RegisterPeerServer(mux, &peerServer{mb: p.mb, c: c})
	c.rc = rpc.NewConn(c.qc, mux, rpc.WithHeaderTimeout(peerCallTimeout), rpc.WithStreams(callStreams{c.qc, p.mb, c}))
	rc, ctx := c.rc, p.ctx
	p.task(func() any {
		return serveDone{c, rc.Serve(ctx)}
	})
}

// ownHello returns the Hello of this agent.
func (p *pair) ownHello() *dp.PeerHello {
	return &dp.PeerHello{Version: p.a.ver, Prefixes: prefixStrings(p.cands.own), Instance: p.inst}
}

// hello starts the Hello call on a connection that this agent dialed.
func (p *pair) hello(c *chConn) {
	cl, ctx, h := dp.NewPeerClient(c.rc), c.ctx, p.ownHello()
	p.task(func() any {
		ctx, cancel := context.WithTimeout(ctx, peerCallTimeout)
		defer cancel()
		res, err := cl.Hello(ctx, h)
		return helloDone{c, res, err}
	})
}

func (p *pair) helloDone(m helloDone) {
	c := m.c
	if c != p.cur {
		return
	}
	if m.err != nil {
		err := connErr(c, m.err)
		p.drop(c, dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, "Hello failed")
		p.dialFailed(err)
		return
	}
	if code, err := p.takeHello(c, m.h); err != nil {
		p.drop(c, code, err.Error())
		p.dialFailed(err)
		return
	}
	p.commit(c)
}

func (p *pair) helloIn(m helloIn) {
	c := m.c
	if c != p.cur || c.hello || c.dialed {
		m.reply <- helloOut{err: rpc.Errorf(rpc.FailedPrecondition, "connection is not in use")}
		return
	}
	if code, err := p.takeHello(c, m.h); err != nil {
		m.reply <- helloOut{err: rpc.Errorf(rpc.FailedPrecondition, "%v", err)}
		p.drop(c, code, err.Error())
		return
	}
	stopLate(c)
	m.reply <- helloOut{h: p.ownHello()}
	p.commit(c)
}

// takeHello checks the Hello of the peer on c and keeps its list and instance.
func (p *pair) takeHello(c *chConn, h *dp.PeerHello) (dp.PeerCloseCode, error) {
	if rev := h.GetVersion().GetRevision(); rev < dp.MinRevision {
		return dp.PeerCloseCode_PEER_CLOSE_CODE_UPGRADE, fmt.Errorf("peer revision %d is below the minimum %d", rev, dp.MinRevision)
	}
	list, err := parseList(h.GetPrefixes())
	if err != nil {
		return dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, err
	}
	if !inPrefixes(list, p.flow.peer) {
		return dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, fmt.Errorf("peer list does not hold the channel address %s", p.flow.peer)
	}
	if h.GetInstance() == 0 {
		return dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, errors.New("peer Hello has no instance")
	}
	c.hello, c.inst, c.list = true, h.GetInstance(), list
	return 0, nil
}

// commit asks the root to open the channel c.
func (p *pair) commit(c *chConn) {
	p.committed = true
	if p.retry != nil {
		p.retry.Stop()
		p.retry = nil
	}
	p.peerList, p.reportedList = c.list, c.list
	p.certEnd = time.NewTimer(time.Until(c.leaf.NotAfter))
	p.up.Send(pairOpen{p: p, key: pairKey{c.key, c.inst}, name: c.name, list: slices.Clone(c.list), conn: c.addrs(p.flow)})
}

// opened takes the answer of the root to pairOpen: the channel opens.
func (p *pair) opened(m openOK) {
	if !p.committed || p.open || p.ending {
		return
	}
	keys, err := p2p.NewProbeKeys(p.cur.qc.ConnectionState().TLS)
	if err != nil {
		p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, "no probe keys")
		return
	}
	p.open, p.peer, p.probeKeys = true, m.peer, keys
	p.role = newProbeRole(keys, p.cur.dialed)
	p.startDiscovery()
	p.ref.open.Store(true)
	p.pc.routed.Store(true)
	if p.openBy != nil {
		p.openBy.Stop()
		p.openBy = nil
	}
	p.st = pairState{open: true}
	p.status()
	slog.Info("Opened a channel to a peer agent", "peer", p.cur.name, "address", p.flow.peer, "prefixes", p.peerList)
	if !slices.Equal(p.peerList, p.reportedList) {
		p.reportedList = p.peerList
		p.up.Send(peerList{p, slices.Clone(p.peerList)})
	}
	p.keyN++
	p.tries[p.keyN] = 0
	p.up.Send(offerMsg{pr: p, peer: p.peer, attempt: p.keyN})
	for _, k := range p.heldKeys {
		p.keysIn(k)
	}
	for _, c := range p.heldCands {
		p.candsIn(c)
	}
	p.heldKeys, p.heldCands = nil, nil
	if p.ending {
		return
	}
	p.candWant = true
	p.sendCands()
}

// connEnded takes the end of a connection. The end of the channel ends the pair.
func (p *pair) connEnded(m serveDone) {
	c := m.c
	if c != p.cur {
		return
	}
	if p.committed {
		p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, fmt.Sprint("channel ended: ", m.err))
		return
	}
	p.cur = nil
	if c.late != nil {
		c.late.Stop()
	}
	if c.dialed {
		p.dialFailed(connErr(c, m.err))
	}
}

// connErr returns the close error of c when it is closed, else err. A call or the accept can end
// with a context error before the close error of the connection.
func connErr(c *chConn, err error) error {
	if ctx := c.qc.Context(); ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return err
}

// drop closes c, which the pair does not keep.
func (p *pair) drop(c *chConn, code dp.PeerCloseCode, reason string) {
	c.cancel()
	if c.late != nil {
		c.late.Stop()
	}
	if p.cur == c {
		p.cur = nil
	}
	p.closeConn(c.qc, code, reason)
}

// closeConn closes qc in a task: the close waits until the close packet is sent.
func (p *pair) closeConn(qc *quic.Conn, code dp.PeerCloseCode, reason string) {
	p.task(func() any {
		_ = qc.CloseWithError(quic.ApplicationErrorCode(code), reason)
		return closeDone{}
	})
}

// revocations takes new lists. A match in one list ends the pair with CERT.
func (p *pair) revocations(v *revLists) {
	p.lists = v
	p.verified.Store(v)
	c := p.cur
	if c == nil || !v.revoked(c.leaf, c.name) {
		return
	}
	if p.committed {
		slog.Info("Peer agent cert is revoked; closed its channel", "peer", c.name, "address", p.flow.peer)
		p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_CERT, "peer cert is revoked")
		return
	}
	p.drop(c, dp.PeerCloseCode_PEER_CLOSE_CODE_CERT, "peer cert is revoked")
	if c.dialed {
		p.dialFailed(identity.ErrRevoked)
	}
}

// rekeyMsg takes new receive SAs from the root for a Keys call.
func (p *pair) rekeyMsg(m rekeyMsg) {
	if !p.open || m.peer != p.peer {
		return
	}
	if m.err != nil {
		p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, "failed to make receive SAs")
		return
	}
	attempt := m.attempt
	if attempt == 0 {
		// A renewal of Tick.
		p.keyN++
		attempt = p.keyN
		p.tries[attempt] = 0
	}
	p.keyQ = append(p.keyQ, keyJob{attempt, m.req})
	p.callKeys()
}

// callKeys starts the next Keys call, one at a time.
func (p *pair) callKeys() {
	if p.keyCall || len(p.keyQ) == 0 {
		return
	}
	job := p.keyQ[0]
	p.keyQ = p.keyQ[1:]
	p.keyCall = true
	cl, ctx, req := dp.NewPeerClient(p.cur.rc), p.ctx, keyproto.ToProto(job.req)
	p.task(func() any {
		ctx, cancel := context.WithTimeout(ctx, peerCallTimeout)
		defer cancel()
		res, err := cl.Keys(ctx, req)
		return keysDone{attempt: job.attempt, refused: res.GetRefusedSpis(), err: err}
	})
}

// keysDone takes the result of a Keys call. The pair offers new SAs for refused ones, at most
// maxRefusals times; a failed call ends the channel.
func (p *pair) keysDone(m keysDone) {
	p.keyCall = false
	switch {
	case m.err != nil:
		p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, fmt.Sprint("Keys call failed: ", m.err))
		return
	case len(m.refused) == 0:
		delete(p.tries, m.attempt)
		if !p.rxReady {
			p.rxReady = true
			p.tryTests()
		}
	case p.tries[m.attempt]+1 >= maxRefusals:
		p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, "peer refused the SAs too many times")
		return
	default:
		p.tries[m.attempt]++
		p.up.Send(refusedMsg{pr: p, peer: p.peer, attempt: m.attempt, spis: m.refused})
	}
	p.callKeys()
}

// keysIn takes SAs from the peer for traffic to it. They wait for openOK.
func (p *pair) keysIn(m keysIn) {
	if m.c != p.cur || p.ending {
		m.reply <- keysOut{err: rpc.Errorf(rpc.FailedPrecondition, "connection is not in use")}
		return
	}
	if !p.open {
		p.heldKeys = append(p.heldKeys, m)
		return
	}
	req, err := keyproto.FromProto(m.req)
	if err != nil {
		m.reply <- keysOut{err: rpc.Errorf(rpc.InvalidArgument, "%v", err)}
		return
	}
	p.keyN++
	p.applies[p.keyN] = m.reply
	p.up.Send(applyMsg{pr: p, peer: p.peer, attempt: p.keyN, req: req})
}

// sendCands starts a Candidates call with a new round when the value changed. One call runs at
// a time, and only the newest value waits.
func (p *pair) sendCands() {
	if !p.open || p.candCall || !p.candWant {
		return
	}
	p.candWant = false
	p.round++
	var addrs []string
	for _, a := range p.cands.c.round(p.observed) {
		addrs = append(addrs, a.String())
	}
	m := &dp.Candidates{Round: p.round, Addresses: addrs, Prefixes: prefixStrings(p.cands.own)}
	p.candCall = true
	cl, ctx := dp.NewPeerClient(p.cur.rc), p.ctx
	p.task(func() any {
		ctx, cancel := context.WithTimeout(ctx, peerCallTimeout)
		defer cancel()
		_, err := cl.Candidates(ctx, m)
		return candsDone{err}
	})
}

// seen takes the own address that the peer saw. Only an address that is not an own candidate is a
// candidate of the pair, and a new one goes in a new round.
func (p *pair) seen(a netip.AddrPort) {
	a = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
	if a == p.observed || slices.Contains(p.cands.c.reflexive, a) || slices.Contains(p.cands.c.host, a) {
		return
	}
	p.observed, p.candWant = a, true
	p.sendCands()
}

// candsIn takes a round of the peer. A higher round replaces its addresses and its list; a list
// without the peer end ends the pair.
func (p *pair) candsIn(m candsIn) {
	if m.c != p.cur || p.ending {
		m.reply <- rpc.Errorf(rpc.FailedPrecondition, "connection is not in use")
		return
	}
	if !p.open {
		p.heldCands = append(p.heldCands, m)
		return
	}
	if m.m.GetRound() <= p.peerRound {
		m.reply <- nil
		return
	}
	if len(m.m.GetAddresses()) > maxRound {
		m.reply <- rpc.Errorf(rpc.InvalidArgument, "round has %d addresses, more than %d", len(m.m.GetAddresses()), maxRound)
		return
	}
	addrs := make([]netip.AddrPort, 0, len(m.m.GetAddresses()))
	for _, s := range m.m.GetAddresses() {
		a, err := netip.ParseAddrPort(s)
		if err != nil {
			m.reply <- rpc.Errorf(rpc.InvalidArgument, "address %q: %v", s, err)
			return
		}
		addrs = append(addrs, a)
	}
	list, err := parseList(m.m.GetPrefixes())
	if err != nil {
		m.reply <- rpc.Errorf(rpc.InvalidArgument, "%v", err)
		return
	}
	m.reply <- nil
	p.peerRound, p.peerAddrs = m.m.GetRound(), addrs
	if !inPrefixes(list, p.flow.peer) {
		p.end(dp.PeerCloseCode_PEER_CLOSE_CODE_UNSPECIFIED, "peer list does not hold the channel address")
		return
	}
	if p.disc != nil {
		p.disc.mb.Send(discRound{round: p.peerRound, addrs: slices.Clone(addrs)})
	}
	p.peerList = list
	if p.open && !slices.Equal(list, p.reportedList) {
		p.reportedList = list
		p.up.Send(peerList{p, slices.Clone(list)})
	}
}

// status gives the root the state of the pair when it changed.
func (p *pair) status() {
	p.st.probing = p.open && !p.st.direct && (p.runOn || len(p.testing) > 0)
	if p.st != p.sent {
		p.sent = p.st
		p.up.Send(pairStatus{p, p.st})
	}
}

// startDiscovery starts the discovery of the direct paths of an open channel.
func (p *pair) startDiscovery() {
	src, dst, b := p.pc.src, p.pc.dst, p.b
	inner := func(v *psp.Peer, payload []byte, to netip.AddrPort) error {
		pkt, err := chanPacket(src, dst, payload)
		if err != nil {
			return err
		}
		return b.SendVia(v, pkt, to)
	}
	d := newDiscovery(p.mb, p.role, discIO{sock: p.a.cfg.Transport, inner: inner, mtu: probeMTU(b)}, discTimes{})
	p.disc = d
	p.ref.disc.Store(d)
	go d.run(&p.a.probes)
}

// pathPassed takes an address whose outer full-size probe passed: the first install condition.
func (p *pair) pathPassed(m discPassed) {
	if p.st.direct {
		return
	}
	if _, ok := p.passed[m.addr]; !ok {
		p.order = append(p.order, m.addr)
	}
	p.passed[m.addr] = m.rtt
	p.tryTests()
}

// tryTests starts the PSP test of each passed address while the pair has SAs both ways: the
// second install condition. The test is the third one.
func (p *pair) tryTests() {
	if !p.st.direct && p.txReady && p.rxReady && p.disc != nil {
		for _, a := range p.order {
			if !p.testing[a] {
				p.testing[a] = true
				p.disc.mb.Send(discTest{peer: p.peer, addr: a})
			}
		}
	}
	p.status()
}

// forget removes addr from the passed addresses. A new pass of addr can test it again.
func (p *pair) forget(addr netip.AddrPort) {
	delete(p.passed, addr)
	p.order = slices.DeleteFunc(p.order, func(a netip.AddrPort) bool { return a == addr })
}

// tested takes the result of a PSP test. The first address that passes it is the direct path.
func (p *pair) tested(m discTested) {
	if !p.testing[m.addr] {
		return
	}
	delete(p.testing, m.addr)
	rtt := p.passed[m.addr]
	p.forget(m.addr)
	switch {
	case p.st.direct || p.next.IsValid():
	case !m.ok:
		p.st.reason = ReasonPSPTestFailed
	case p.checks > 0:
		// The new check continues the counters of the last one, so it waits for its end.
		p.next, p.nextRTT = m.addr, rtt
	default:
		p.install(m.addr, rtt)
	}
	p.status()
}

// runEnded takes the end of the probe run of a round.
func (p *pair) runEnded(m discRunEnded) {
	switch {
	case p.st.direct, m.stopped:
	case !m.passed:
		p.st.reason = ReasonProbeFailed
	case !p.txReady || !p.rxReady:
		p.st.reason = ReasonNoSAs
	}
	p.status()
}

// install makes addr the direct path: the root sets the send address of the direct peer and the
// routes, and a new check runs BFD on the path.
func (p *pair) install(addr netip.AddrPort, rtt time.Duration) {
	p.st.direct, p.st.addr, p.st.rtt, p.st.reason = true, addr, rtt, ""
	clear(p.passed)
	clear(p.testing)
	p.order = nil
	p.chk = newPairCheck(p.mb, p.role, probeMTU(p.b), checkTx, p.counter, p.highest)
	p.checks++
	go p.chk.run(nil)
	p.disc.mb.Send(discDirect{on: true})
	slog.Info("Opened a direct path to a peer agent", "peer", p.cur.name, "address", addr, "rtt", rtt)
}

// lost takes the loss of the direct path: the routes go out, and data goes on the relay route.
// The SAs stay for a return, and a new install needs the PSP test again.
func (p *pair) lost(c *check) {
	if c != p.chk {
		return
	}
	slog.Info("Lost the direct path to a peer agent; its data goes on the relay route", "peer", p.cur.name, "address", p.st.addr)
	p.chk = nil
	c.mb.Send(endMsg{})
	p.st.direct, p.st.addr, p.st.rtt = false, netip.AddrPort{}, 0
	p.disc.mb.Send(discDirect{on: false})
	p.status()
}

// checkEnded takes the counters of a check that ended. A tested address that waited installs.
func (p *pair) checkEnded(m checkEnded) {
	p.checks--
	p.counter, p.highest = max(p.counter, m.counter), max(p.highest, m.highest)
	if next := p.next; next.IsValid() && p.checks == 0 {
		p.next = netip.AddrPort{}
		if !p.ending && !p.st.direct {
			p.install(next, p.nextRTT)
			p.status()
		}
	}
}

// end starts the one end sequence of the pair: the root removes the direct peer, the tasks end,
// and the close task closes the channel with code, then the QUIC transport and the socket of the
// pair. The pair sends no key operation after this.
func (p *pair) end(code dp.PeerCloseCode, reason string) {
	if p.ending {
		return
	}
	p.ending = true
	if p.open {
		slog.Info("Closed the channel to a peer agent", "peer", p.cur.name, "address", p.flow.peer, "code", code, "reason", reason)
	} else if reason != "" {
		slog.Debug("Peer channel ends", "peer", p.flow.peer, "code", code, "reason", reason)
	}
	p.up.Send(removePeerMsg{p})
	p.cancel()
	if d := p.disc; d != nil {
		p.ref.disc.Store(nil)
		d.mb.Send(endMsg{})
	}
	if c := p.chk; c != nil {
		p.chk = nil
		c.mb.Send(endMsg{})
	}
	for _, t := range []*time.Timer{p.retry, p.openBy, p.certEnd} {
		stopTimer(t)
	}
	p.retry, p.openBy, p.certEnd = nil, nil, nil
	var qc *quic.Conn
	if c := p.cur; c != nil {
		qc = c.qc
		if c.late != nil {
			c.late.Stop()
		}
	}
	tr, pc := p.tr, p.pc
	p.task(func() any {
		if qc != nil {
			_ = qc.CloseWithError(quic.ApplicationErrorCode(code), reason)
		}
		if tr != nil {
			_ = tr.Close()
		}
		if pc != nil {
			_ = pc.Close()
		}
		return closeDone{}
	})
}

// peerServer serves the Peer calls of one connection of a pair. Each call goes to the pair.
type peerServer struct {
	dp.UnimplementedPeerServer
	mb *proc.Mailbox
	c  *chConn
}

func (s *peerServer) Hello(ctx context.Context, in *dp.PeerHello) (*dp.PeerHello, error) {
	ctx, cancel := context.WithTimeout(ctx, peerCallTimeout)
	defer cancel()
	reply := make(chan helloOut, 1)
	if !s.mb.Send(helloIn{s.c, in, reply}) {
		return nil, rpc.Errorf(rpc.Unavailable, "pair ended")
	}
	select {
	case r := <-reply:
		return r.h, r.err
	case <-ctx.Done():
		s.mb.Send(callLate{s.c})
		return nil, ctx.Err()
	}
}

func (s *peerServer) Keys(ctx context.Context, in *dp.KeysRequest) (*dp.KeysResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, peerCallTimeout)
	defer cancel()
	reply := make(chan keysOut, 1)
	if !s.mb.Send(keysIn{s.c, in, reply}) {
		return nil, rpc.Errorf(rpc.Unavailable, "pair ended")
	}
	select {
	case r := <-reply:
		if r.err != nil {
			return nil, r.err
		}
		return &dp.KeysResponse{RefusedSpis: r.refused}, nil
	case <-ctx.Done():
		s.mb.Send(callLate{s.c})
		return nil, ctx.Err()
	}
}

func (s *peerServer) Candidates(ctx context.Context, in *dp.Candidates) (*emptypb.Empty, error) {
	ctx, cancel := context.WithTimeout(ctx, peerCallTimeout)
	defer cancel()
	reply := make(chan error, 1)
	if !s.mb.Send(candsIn{s.c, in, reply}) {
		return nil, rpc.Errorf(rpc.Unavailable, "pair ended")
	}
	select {
	case err := <-reply:
		if err != nil {
			return nil, err
		}
		return &emptypb.Empty{}, nil
	case <-ctx.Done():
		s.mb.Send(callLate{s.c})
		return nil, ctx.Err()
	}
}

// callStreams gives each call stream of the peer a deadline of peerCallTimeout from its accept for
// the request and the answer. A call that does not end in time ends the connection.
type callStreams struct {
	qc *quic.Conn
	mb *proc.Mailbox // The pair.
	c  *chConn
}

func (q callStreams) AcceptStream(ctx context.Context) (rpc.Stream, error) {
	str, err := q.qc.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	end := time.Now().Add(peerCallTimeout)
	_ = str.SetReadDeadline(end)
	_ = str.SetWriteDeadline(end)
	return &peerStream{Stream: str, end: end, late: func() { q.mb.Send(callLate{q.c}) }}, nil
}

func (q callStreams) OpenStreamSync(ctx context.Context) (rpc.Stream, error) {
	str, err := q.qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return str, nil
}

// peerStream is an accepted call stream whose deadlines are never after end.
type peerStream struct {
	*quic.Stream
	end  time.Time
	late func() // Tells the pair that the deadline came.
}

func (s *peerStream) Read(b []byte) (int, error) {
	n, err := s.Stream.Read(b)
	s.check(err)
	return n, err
}

func (s *peerStream) Write(b []byte) (int, error) {
	n, err := s.Stream.Write(b)
	s.check(err)
	return n, err
}

// check tells the pair about a call that did not end in time: the deadline came, or this side
// reset the stream at the end of the call context.
func (s *peerStream) check(err error) {
	var se *quic.StreamError
	if errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &se) && !se.Remote) {
		s.late()
	}
}

func (s *peerStream) SetReadDeadline(t time.Time) error {
	if t.IsZero() || t.After(s.end) {
		t = s.end
	}
	return s.Stream.SetReadDeadline(t)
}

// stopLate stops the Hello timer of c, if it has one.
func stopLate(c *chConn) {
	if c.late != nil {
		c.late.Stop()
	}
}
