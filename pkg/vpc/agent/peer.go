// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	keysTimeout = 10 * time.Second
	// duplicateWait limits the wait for the kept session after crossed dials.
	duplicateWait = 5 * time.Second
	// maxRefusals limits the offers of one key change that the peer refuses.
	maxRefusals = 3
)

// peerQUIC keeps peer session packets at the QUIC minimum of 1200 B.
var peerQUIC = &quic.Config{
	KeepAlivePeriod:         15 * time.Second,
	MaxIdleTimeout:          45 * time.Second,
	InitialPacketSize:       1200,
	DisablePathMTUDiscovery: true,
}

var errDuplicate = errors.New("both agents dialed; this session is not the one to keep")

var (
	// errAlreadyOpen refuses a second Open on one peer session.
	errAlreadyOpen = errors.New("peer session is already open")
	errPeerClosed  = errors.New("peer session closed")
)

// peer is one peer session with a remote agent of the VPC.
type peer struct {
	rc      *relayConn
	qc      quic.Connection
	conn    *rpc.Conn
	client  dp.PeerClient
	dialer  bool       // This agent dialed the session.
	dst     netip.Addr // Address that this agent dialed. Invalid when the peer dialed.
	subject string     // SPIFFE ID in the peer cert.

	ready     chan struct{} // Closed when Open passes.
	granted   chan struct{} // Closed when the grants of Open apply.
	keyed     chan struct{} // Closed when SAs from the peer first apply.
	keyedOnce sync.Once
	offered   chan struct{} // Closed when the peer takes the first offer.
	noData    chan struct{} // Closed when the peer refuses the first offer: it takes no SAs.

	// Set before ready closes, under Agent.mu.
	instance uint64
	version  *dp.Version // Version of the peer, from Open. Nil is revision 0.
	claims   *dp.GrantClaims
	prefixes []netip.Prefix
	addr     netip.Addr // Overlay address of the peer.
	bp       *psp.Peer
	// quic is true when one of the agents sends QUIC data frames. Then the
	// data goes through the relay, and bp is the relay peer.
	quic bool
	// down is true when the relay has no path to the peer, or when the peer has
	// no data path. A new session of the peer replaces it. Guarded by Agent.mu.
	down bool
	// advertised is the prefixes that the peer advertises and that route to bp.
	// Guarded by Agent.mu.
	advertised []netip.Prefix
	// extra is the prefixes of the other attachments of the peer, by
	// attachment ID. Guarded by Agent.mu.
	extra map[string][]netip.Prefix

	mu   sync.Mutex
	spis map[uint32]spiRow // SPIs registered at the relay.
	// Grant changes of this agent that wait to go to the peer.
	sendAdd    map[string]*extra
	sendRemove map[string]bool
	sending    bool
	noGrants   bool // The peer does not serve Grants.
}

// spiRow is an SPI that the relay forwards to the peer.
type spiRow struct {
	expires time.Time
	lane    int // Lane of the SA.
}

// routes reports whether the grants or the advertised prefixes of p cover addr.
func (p *peer) routes(addr netip.Addr) bool {
	has := func(pfx netip.Prefix) bool { return pfx.Contains(addr) }
	if slices.ContainsFunc(p.prefixes, has) || slices.ContainsFunc(p.advertised, has) {
		return true
	}
	for _, ps := range p.extra {
		if slices.ContainsFunc(ps, has) {
			return true
		}
	}
	return false
}

// has reports whether pfx is a prefix of a grant of p or a prefix that p
// advertises.
func (p *peer) has(pfx netip.Prefix) bool {
	if slices.Contains(p.prefixes, pfx) || slices.Contains(p.advertised, pfx) {
		return true
	}
	for _, ps := range p.extra {
		if slices.Contains(ps, pfx) {
			return true
		}
	}
	return false
}

// sameAttachment reports whether p is a session with the attachment id of
// subject, or with an attachment of subject that has one of prefixes. An agent
// has one attachment for each of its relay sessions, and each one is a peer
// of its own. Many agents can have one subject.
func (p *peer) sameAttachment(subject, id string, prefixes []netip.Prefix) bool {
	return p.subject == subject && (p.attachmentID() == id || slices.ContainsFunc(prefixes, p.has))
}

func (p *peer) attachmentID() string { return p.claims.GetAttachmentId() }

// origin reports whether id is an attachment of p.
func (p *peer) origin(id string) bool { return id == p.attachmentID() || p.extra[id] != nil }

// peerTLS is the peer session TLS config. Both sides check the agent cert.
func (a *Agent) peerTLS() *tls.Config {
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		NextProtos:           []string{dp.ALPNPeer},
		GetCertificate:       a.cfg.Identity.GetCertificate,
		GetClientCertificate: a.cfg.Identity.GetClientCertificate,
		ClientAuth:           tls.RequireAnyClientCert,
		// VerifyConnection checks the agent cert; there is no host name.
		InsecureSkipVerify: true,
		VerifyConnection:   a.verifyPeer,
	}
}

func (a *Agent) verifyPeer(cs tls.ConnectionState) error {
	cred := a.cfg.Identity.Current()
	roots, err := identity.NewPool(cred.CABundle)
	if err != nil {
		return err
	}
	_, err = identity.Verify(cs.PeerCertificates, identity.VerifyOptions{Roots: roots, Project: cred.ID.Project, VPC: cred.ID.VPC})
	return err
}

// accept serves the peer sessions that other agents dial to rc.
func (rc *relayConn) accept(ln *quic.Listener) {
	for {
		qc, err := ln.Accept(rc.ctx)
		if err != nil {
			return
		}
		if _, err := rc.a.newPeer(rc, qc, netip.Addr{}); err != nil {
			_ = qc.CloseWithError(quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_BAD_GRANT), err.Error())
		}
	}
}

// newPeer serves the Peer service on qc and adds the session to the agent.
// dst is the address that this agent dialed, or invalid when the peer dialed.
func (a *Agent) newPeer(rc *relayConn, qc quic.Connection, dst netip.Addr) (*peer, error) {
	id, err := identity.IDFromCert(qc.ConnectionState().TLS.PeerCertificates[0])
	if err != nil {
		return nil, err
	}
	p := &peer{
		rc:      rc,
		qc:      qc,
		dialer:  dst.IsValid(),
		dst:     dst.Unmap(),
		subject: id.String(),
		ready:   make(chan struct{}),
		granted: make(chan struct{}),
		keyed:   make(chan struct{}),
		offered: make(chan struct{}),
		noData:  make(chan struct{}),
		spis:    map[uint32]spiRow{},
	}
	p.conn = rpc.NewConn(qc, a.mux)
	p.client = dp.NewPeerClient(p.conn)
	a.mu.Lock()
	a.peers[p.conn] = p
	a.mu.Unlock()
	context.AfterFunc(qc.Context(), func() { a.dropPeer(p) })
	go func() { _ = p.conn.Serve(rc.ctx) }()
	return p, nil
}

// Connect opens a peer session to the agent at dst on the relay session with
// the lowest rank, and exchanges keys with it. It returns when PSP works in
// both directions.
func (a *Agent) Connect(ctx context.Context, dst netip.Addr) error {
	rc := a.primary()
	if rc == nil {
		return errNoRelay
	}
	return a.connect(ctx, rc, dst, nil)
}

// connect opens a peer session on rc to the agent at dst if none covers dst,
// and waits for its SAs. res is the ResolvePeer answer for dst, or nil.
func (a *Agent) connect(ctx context.Context, rc *relayConn, dst netip.Addr, res *dp.ResolvePeerResponse) error {
	a.mu.Lock()
	p := a.livePeerTo(rc, dst)
	a.mu.Unlock()
	if p == nil {
		var err error
		if res == nil {
			if res, err = rc.resolve(ctx, dst); err != nil {
				return err
			}
		}
		if res.GetReach() == dp.Reach_REACH_VISIT {
			// The relay cannot reach the relay of the peer, so the agents visit.
			return a.connectVisit(ctx, rc, dst, res.GetHomeRelay())
		}
		if p = a.waitGrant(ctx, rc, dst, res); p != nil {
			return a.waitKeys(ctx, p, dst)
		}
		p, err = a.dial(ctx, rc, dst, res)
		if errors.Is(err, errDuplicate) {
			// Both agents dialed. Use the session that the peer dialed.
			p, err = a.waitPeer(ctx, rc, dst)
		}
		if err != nil {
			return err
		}
	}
	return a.waitKeys(ctx, p, dst)
}

// waitKeys waits until both sides of p have SAs. If the other session of a
// crossed dial replaces p, it waits for that session.
func (a *Agent) waitKeys(ctx context.Context, p *peer, dst netip.Addr) error {
	for {
		err := p.wait(ctx)
		if err == nil || !replaced(p.qc) {
			return err
		}
		if p, err = a.waitPeer(ctx, p.rc, dst); err != nil {
			return err
		}
	}
}

// wait waits until both sides of p have SAs.
func (p *peer) wait(ctx context.Context) error {
	chans := []chan struct{}{p.keyed, p.offered}
	if p.quic {
		// Data frames need no SAs. A session in PSP mode needs the relay SAs.
		chans = nil
		if p.rc.dataMode() == dp.Mode_MODE_PSP {
			tx, rx := p.rc.bridge()
			chans = []chan struct{}{tx, rx}
		}
	}
	for _, ch := range chans {
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		case <-p.noData:
			return fmt.Errorf("peer %s: %w", p.addr, errVisitNoData)
		case <-p.qc.Context().Done():
			return fmt.Errorf("peer session closed: %w", context.Cause(p.qc.Context()))
		}
	}
	return nil
}

// replaced reports whether another session with the same peer replaced qc.
func replaced(qc quic.Connection) bool {
	var ae *quic.ApplicationError
	return errors.As(context.Cause(qc.Context()), &ae) &&
		ae.ErrorCode == quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE)
}

// closedError is the admit error for a closed session. It is errDuplicate when a
// crossed dial replaced the session, so that connect waits for the kept one.
func (p *peer) closedError() error {
	if replaced(p.qc) {
		return errDuplicate
	}
	return errPeerClosed
}

// gone reports whether p left the agent or its connection closed. a.mu must be held.
func (a *Agent) gone(p *peer) bool {
	return a.peers[p.conn] != p || p.qc.Context().Err() != nil
}

// peerTo returns the open peer session on rc whose grant covers dst. The
// caller holds a.mu.
func (a *Agent) peerTo(rc *relayConn, dst netip.Addr) *peer {
	for _, q := range a.peers {
		if q.rc == rc && q.bp != nil && q.qc.Context().Err() == nil && q.routes(dst) {
			return q
		}
	}
	return nil
}

// livePeerTo is peerTo for the sessions whose path is not down. The caller
// holds a.mu.
func (a *Agent) livePeerTo(rc *relayConn, dst netip.Addr) *peer {
	for _, q := range a.peers {
		if q.rc == rc && q.bp != nil && !q.down && q.qc.Context().Err() == nil && q.routes(dst) {
			return q
		}
	}
	return nil
}

// waitPeer waits until a peer session on rc that covers dst opens. For a
// visitor session, the session that the peer opened as a visitor counts too.
func (a *Agent) waitPeer(ctx context.Context, rc *relayConn, dst netip.Addr) (*peer, error) {
	ctx, cancel := context.WithTimeout(ctx, duplicateWait)
	defer cancel()
	for {
		a.mu.Lock()
		p, admitted := a.peerTo(rc, dst), a.admitted
		if p == nil && rc.visitor() {
			p = a.livePeerTo(rc.home, dst)
		}
		a.mu.Unlock()
		if p != nil {
			return p, nil
		}
		select {
		case <-admitted:
		case <-rc.ctx.Done():
			return nil, errors.New("relay session closed")
		case <-ctx.Done():
			return nil, fmt.Errorf("peer %s did not open its session: %w", dst, ctx.Err())
		}
	}
}

// refusedDuplicate reports whether the peer refused the Open on qc because it
// keeps the session that it dialed.
func refusedDuplicate(qc quic.Connection, err error) bool {
	if rpc.CodeOf(err) == rpc.AlreadyExists {
		return true
	}
	var ae *quic.ApplicationError
	// quic-go ends the call streams before it sets the close cause.
	if !errors.As(err, &ae) && !errors.As(context.Cause(qc.Context()), &ae) {
		return false
	}
	return ae.Remote && ae.ErrorCode == quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE)
}

// resolve asks the relay how it reaches dst.
func (rc *relayConn) resolve(ctx context.Context, dst netip.Addr) (*dp.ResolvePeerResponse, error) {
	res, err := rc.c.ResolvePeer(ctx, &dp.ResolvePeerRequest{Vpc: rc.ref, Address: dst.String()})
	if err != nil {
		return nil, fmt.Errorf("resolve peer %s: %w", dst, err)
	}
	return res, nil
}

// dial dials a peer session to dst, which ResolvePeer answered with res, and
// opens it.
func (a *Agent) dial(ctx context.Context, rc *relayConn, dst netip.Addr, res *dp.ResolvePeerResponse) (*peer, error) {
	// The relay carries the peer frames and the data to a peer on another relay,
	// so the session is the same as with a peer on this relay.
	if reach := res.GetReach(); reach != dp.Reach_REACH_LOCAL && reach != dp.Reach_REACH_TRUNK {
		return nil, fmt.Errorf("relay has no path to peer %s (%v)", dst, reach)
	}
	qc, err := rc.peerTr.Dial(ctx, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 0)), a.peerTLS(), peerQUIC)
	if err != nil {
		return nil, fmt.Errorf("dial peer %s: %w", dst, err)
	}
	p, err := a.newPeer(rc, qc, dst)
	if err != nil {
		_ = qc.CloseWithError(quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_BAD_GRANT), err.Error())
		return nil, err
	}
	a.mu.Lock()
	xs := a.openExtras(p)
	a.mu.Unlock()
	grant, grants, err := rc.openGrants(ctx, xs)
	if err != nil {
		_ = qc.CloseWithError(0, "")
		return nil, fmt.Errorf("open peer session to %s: %w", dst, err)
	}
	open, err := p.client.Open(ctx, &dp.OpenRequest{
		Grant: grant, Grants: grants, Instance: a.instance, Mode: rc.dataMode(), Lanes: rc.sendLanes(), Version: a.ver,
	})
	if err != nil {
		if refusedDuplicate(qc, err) {
			err = errDuplicate
		} else if reason, ok := refusedUpgrade(qc, err); ok {
			err = fmt.Errorf("%w: peer closed the session: %s", ErrUpgrade, reason)
		}
		_ = qc.CloseWithError(0, "")
		return nil, fmt.Errorf("open peer session to %s: %w", dst, err)
	}
	if err := a.admit(p, open.GetVersion(), open.GetGrant(), open.GetInstance(), open.GetMode(), open.GetLanes()); err != nil {
		_ = qc.CloseWithError(closeCode(err), err.Error())
		return nil, fmt.Errorf("peer %s: %w", dst, err)
	}
	a.grantsOfOpen(p, open.GetGrants())
	go p.offer()
	go p.sendReports()
	return p, nil
}

// admit checks the Open data of the peer, then adds it to the binding with
// the prefixes of its grant. The peer gets SAs for its send lanes.
func (a *Agent) admit(p *peer, v *dp.Version, g *dp.AttachmentGrant, instance uint64, mode dp.Mode, lanes uint32) error {
	a.admitMu.Lock()
	defer a.admitMu.Unlock()
	a.mu.Lock()
	open, gone := p.bp != nil, a.gone(p)
	a.mu.Unlock()
	if open {
		return errAlreadyOpen
	}
	if gone {
		return p.closedError()
	}
	if err := a.checkRevision(p, v); err != nil {
		return err
	}
	if mode != dp.Mode_MODE_PSP && mode != dp.Mode_MODE_QUIC {
		return fmt.Errorf("peer mode %v is not supported", mode)
	}
	if mode == dp.Mode_MODE_QUIC || p.rc.dataMode() == dp.Mode_MODE_QUIC {
		return a.admitQUIC(p, v, g, instance)
	}
	claims, prefixes, err := a.checkGrant(p, g)
	if err != nil {
		return err
	}

	a.mu.Lock()
	// away is a session with the attachment on the other relay session of a visit,
	// which has the same link. One whose path works comes before the others.
	var old, away *peer
	for _, q := range a.peers {
		if q == p || q.bp == nil || !q.sameAttachment(p.subject, claims.GetAttachmentId(), prefixes) {
			continue
		}
		switch {
		case q.rc == p.rc:
			old = q
		case q.rc.link == p.rc.link && q.rc.visitor() != p.rc.visitor() && (away == nil || away.down):
			away = q
		}
	}
	// When both agents dial, the session that the first agent dialed stays. A
	// session with the path down gives its place to each new session.
	if old != nil && !old.down && old.instance == instance && old.dialer != p.dialer && old.dialer == a.first(p.subject, instance) {
		a.mu.Unlock()
		return errDuplicate
	}
	// When both agents visit, the session on the relay of the higher address stays.
	if away != nil && !away.down && !keeps(p.rc, overlayAddr(prefixes)) {
		a.mu.Unlock()
		return errDuplicate
	}
	a.mu.Unlock()
	for _, q := range []*peer{old, away} {
		if q != nil {
			_ = q.qc.CloseWithError(quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE), "new session")
			a.dropPeer(q)
		}
	}

	bp, err := p.rc.link.AddPeerLanes(p.rc.relayAddr, int(min(max(lanes, 1), keys.MaxLanes)))
	if err != nil {
		return err
	}
	for _, pfx := range prefixes {
		if err := a.bind.AddRoute(pfx, bp); err != nil {
			a.bind.RemovePeer(bp)
			return fmt.Errorf("route %s: %w", pfx, err)
		}
	}
	a.mu.Lock()
	if a.gone(p) {
		// A dropPeer before this point did not see bp, so remove it here.
		a.bind.RemovePeer(bp)
		a.mu.Unlock()
		return p.closedError()
	}
	p.instance, p.version, p.claims, p.prefixes, p.addr, p.bp = instance, v, claims, prefixes, overlayAddr(prefixes), bp
	// Under a.mu, so that a move of the agent also sees bp.
	bp.SetLaneSockets(int(p.rc.sendLanes()))
	close(a.admitted)
	a.admitted = make(chan struct{})
	a.mu.Unlock()
	a.routeAdvertised(p)
	close(p.ready)
	slog.Info("Opened peer session", "peer", p.subject, "address", p.addr, "dialer", p.dialer)
	return nil
}

// first reports whether this agent is before the agent with subject and
// instance: the lower subject, or the lower instance when they have one subject.
func (a *Agent) first(subject string, instance uint64) bool {
	if own := a.cfg.Identity.Current().ID.String(); own != subject {
		return own < subject
	}
	return a.instance < instance
}

// checkGrant checks the grant of the peer and returns its claims and prefixes.
func (a *Agent) checkGrant(p *peer, g *dp.AttachmentGrant) (*dp.GrantClaims, []netip.Prefix, error) {
	claims, err := relay.VerifyGrant(g, p.rc.roots, time.Now())
	if errors.Is(err, relay.ErrGrantRevision) {
		// This agent is the verifier, so this agent is too old.
		return nil, nil, fmt.Errorf("%w: %w", ErrUpgrade, err)
	}
	if err != nil {
		return nil, nil, err
	}
	ref, vpc := p.rc.ref, claims.GetVpc()
	if vpc.GetProjectId() != ref.GetProjectId() || vpc.GetVpcUid() != ref.GetVpcUid() || vpc.GetNetworkId() != ref.GetNetworkId() {
		return nil, nil, errors.New("grant is for another VPC")
	}
	if claims.GetSubject() != p.subject {
		return nil, nil, fmt.Errorf("grant is for %s, not for the peer cert %s", claims.GetSubject(), p.subject)
	}
	prefixes, err := parsePrefixes(claims.GetAddresses())
	if err != nil {
		return nil, nil, err
	}
	return claims, prefixes, nil
}

// admitQUIC adds a peer session that sends data through the relay. It routes
// the peer prefixes to the relay peer, which other QUIC pairs share.
func (a *Agent) admitQUIC(p *peer, v *dp.Version, g *dp.AttachmentGrant, instance uint64) error {
	claims, prefixes, err := a.checkGrant(p, g)
	if err != nil {
		return err
	}
	// A PSP pair with the same attachment is from before the agent changed its mode.
	// An older QUIC pair that the same agent dialed is lost or moved; a crossed dial stays.
	// away is as in admit: a prefix has a route on one relay session of a link only.
	a.mu.Lock()
	var old []*peer
	var away *peer
	for _, q := range a.peers {
		if q == p || q.bp == nil || !q.sameAttachment(p.subject, claims.GetAttachmentId(), prefixes) {
			continue
		}
		switch {
		case q.rc == p.rc:
			if !q.quic || (q.dialer == p.dialer && q.instance == instance) {
				old = append(old, q)
			}
		case q.rc.link == p.rc.link && q.rc.visitor() != p.rc.visitor() && (away == nil || away.down):
			away = q
		}
	}
	// When both agents visit, the session on the relay of the higher address stays.
	if away != nil && !away.down && !keeps(p.rc, overlayAddr(prefixes)) {
		a.mu.Unlock()
		return errDuplicate
	}
	a.mu.Unlock()
	if away != nil {
		old = append(old, away)
	}
	for _, q := range old {
		_ = q.qc.CloseWithError(quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE), "new session")
		a.dropPeer(q)
	}

	a.mu.Lock()
	if a.peers[p.conn] != p || p.bp != nil {
		a.mu.Unlock()
		return errors.New("peer session is closed or already open")
	}
	for i, pfx := range prefixes {
		if err := a.bind.AddRoute(pfx, p.rc.relay); err != nil {
			a.unrouteQUIC(p, prefixes[:i])
			a.mu.Unlock()
			return fmt.Errorf("route %s: %w", pfx, err)
		}
	}
	p.instance, p.version, p.claims, p.prefixes, p.addr, p.bp, p.quic = instance, v, claims, prefixes, overlayAddr(prefixes), p.rc.relay, true
	close(a.admitted)
	a.admitted = make(chan struct{})
	a.mu.Unlock()
	a.routeAdvertised(p)
	close(p.ready)
	slog.Info("Opened peer session", "peer", p.subject, "address", p.addr, "dialer", p.dialer, "transport", "quic")
	return nil
}

// unrouteQUIC removes the routes of prefixes to the relay peer that no other
// QUIC pair of p.rc has. a.mu must be held.
func (a *Agent) unrouteQUIC(p *peer, prefixes []netip.Prefix) {
	for _, pfx := range prefixes {
		shared := false
		for _, q := range a.peers {
			if q != p && q.quic && q.rc == p.rc && q.has(pfx) {
				shared = true
				break
			}
		}
		if !shared {
			a.bind.RemoveRoute(pfx, p.rc.relay)
		}
	}
}

// closeCode is the peer session close code for an error from admit.
func closeCode(err error) quic.ApplicationErrorCode {
	switch {
	case errors.Is(err, errDuplicate):
		return quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE)
	case errors.Is(err, errRevision):
		return quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_UPGRADE)
	}
	return quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_BAD_GRANT)
}

// dropPeer removes p and its SAs before they expire. This is correct while
// peer sessions close only on an error or when the peer goes away.
func (a *Agent) dropPeer(p *peer) {
	a.mu.Lock()
	if a.peers[p.conn] != p {
		a.mu.Unlock()
		return
	}
	delete(a.peers, p.conn)
	bp := p.bp
	if p.quic {
		a.unrouteQUIC(p, p.prefixes)
		a.unrouteQUIC(p, p.advertised)
		for _, ps := range p.extra {
			a.unrouteQUIC(p, ps)
		}
	} else if bp != nil {
		// Remove the routes before a new session of the peer can add them.
		a.bind.RemovePeer(bp)
	}
	a.mu.Unlock()
	if bp == nil {
		return
	}
	p.mu.Lock()
	spis := make([]uint32, 0, len(p.spis))
	for spi := range p.spis {
		spis = append(spis, spi)
	}
	p.mu.Unlock()
	if len(spis) > 0 && p.rc.ctx.Err() == nil {
		go func() {
			ctx, cancel := context.WithTimeout(p.rc.ctx, keysTimeout)
			defer cancel()
			_, _ = p.rc.c.UnregisterSPI(ctx, &dp.UnregisterSPIRequest{Vpc: p.rc.ref, Spis: spis})
		}()
	}
	if reason, ok := refusedUpgrade(p.qc, nil); ok {
		slog.Warn("Peer closed the session: it needs a newer agent; upgrade this agent", "peer", p.subject, "reason", reason)
		return
	}
	slog.Info("Closed peer session", "peer", p.subject, "reason", context.Cause(p.qc.Context()))
}

func (a *Agent) closePeers(match func(*peer) bool, reason string) {
	a.closePeersWith(0, match, reason)
}

// closePeersWith closes the peer sessions of match with a close code.
func (a *Agent) closePeersWith(code dp.PeerCloseCode, match func(*peer) bool, reason string) {
	a.mu.Lock()
	var ps []*peer
	for _, p := range a.peers {
		if match(p) {
			ps = append(ps, p)
		}
	}
	a.mu.Unlock()
	for _, p := range ps {
		_ = p.qc.CloseWithError(quic.ApplicationErrorCode(code), reason)
		a.dropPeer(p)
	}
}

func (a *Agent) peerOf(ctx context.Context) *peer {
	conn := rpc.ConnFromContext(ctx)
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.peers[conn]
}

func (a *Agent) peerOfBinding(bp *psp.Peer) *peer {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.peers {
		if p.bp == bp && !p.quic {
			return p
		}
	}
	return nil
}

// offer gives the peer new SAs for traffic to this agent.
func (p *peer) offer() {
	if p.quic {
		return
	}
	req, err := p.bp.Offer(time.Now())
	if err != nil {
		slog.Warn("Failed to create receive SAs", "peer", p.subject, "error", err)
		return
	}
	switch err := p.sendKeys(req); {
	case err == nil:
		close(p.offered)
	case rpc.CodeOf(err) == rpc.FailedPrecondition:
		// The peer sends its data through the relay, so it takes no SAs.
		p.rc.a.noDataPath(p)
	}
}

// sendKeys sends a key change to the peer. It returns nil when the peer took it.
func (p *peer) sendKeys(req keys.Request) error {
	ctx, cancel := context.WithTimeout(p.rc.ctx, keysTimeout)
	defer cancel()
	err := giveKeys(ctx, p.bp, req, p.client.Keys)
	if err != nil && p.qc.Context().Err() == nil {
		slog.Warn("Failed to send keys to a peer", "peer", p.subject, "error", err)
	}
	return err
}

// giveKeys sends a key change of bp with send, and offers new SAs for the SPIs
// that the receiver refuses.
func giveKeys(ctx context.Context, bp *psp.Peer, req keys.Request, send func(context.Context, *dp.KeysRequest) (*dp.KeysResponse, error)) error {
	for range maxRefusals {
		res, err := send(ctx, keyproto.ToProto(req))
		if err != nil {
			return err
		}
		if len(res.GetRefusedSpis()) == 0 {
			return nil
		}
		if req, err = bp.Refused(res.GetRefusedSpis(), time.Now()); err != nil {
			return fmt.Errorf("replace refused SAs: %w", err)
		}
	}
	return errors.New("receiver refused the SAs too many times")
}

// register tells the relay to forward the SPIs of sas to the peer.
func (p *peer) register(ctx context.Context, sas []keys.SA) error {
	if len(sas) == 0 {
		return nil
	}
	var ttl time.Duration
	for _, sa := range sas {
		ttl = max(ttl, sa.ExpiresIn)
	}
	spis, lanes := spisOf(sas), make([]int, len(sas))
	for i, sa := range sas {
		lanes[i] = sa.Lane
	}
	if _, err := p.rc.c.RegisterSPI(ctx, p.registerRequest(spis, lanes, ttl)); err != nil {
		return err
	}
	expires := time.Now().Add(ttl)
	p.mu.Lock()
	for i, spi := range spis {
		p.spis[spi] = spiRow{expires, lanes[i]}
	}
	p.mu.Unlock()
	return nil
}

// registerRequest returns the RegisterSPI request for the SPIs of SA lanes.
// The relay gets the socket lane and the SA lane of each SPI, or no lanes when
// all are 0.
func (p *peer) registerRequest(spis []uint32, lanes []int, ttl time.Duration) *dp.RegisterSPIRequest {
	req := &dp.RegisterSPIRequest{Vpc: p.rc.ref, Destination: p.addr.String(), Spis: spis, ExpiresIn: durationpb.New(ttl)}
	sock, sa := make([]uint32, len(lanes)), make([]uint32, len(lanes))
	for i, l := range lanes {
		sock[i], sa[i] = uint32(p.bp.SendLane(l)), uint32(l)
	}
	nonZero := func(l uint32) bool { return l != 0 }
	if slices.ContainsFunc(sock, nonZero) {
		req.Lanes = sock
	}
	if slices.ContainsFunc(sa, nonZero) {
		req.SaLanes = sa
	}
	return req
}

// unregister tells the relay to stop forwarding the SPIs.
func (p *peer) unregister(ctx context.Context, spis []uint32) error {
	p.mu.Lock()
	for _, spi := range spis {
		delete(p.spis, spi)
	}
	p.mu.Unlock()
	_, err := p.rc.c.UnregisterSPI(ctx, &dp.UnregisterSPIRequest{Vpc: p.rc.ref, Spis: spis})
	return err
}

func spisOf(sas []keys.SA) []uint32 {
	spis := make([]uint32, len(sas))
	for i, sa := range sas {
		spis[i] = sa.SPI
	}
	return spis
}

// refreshSPIs registers the live SPIs again, so that idle rows stay. If the relay
// refuses an SPI as in use, it closes the session: the next session has new keys.
func (p *peer) refreshSPIs() {
	type group struct {
		spis  []uint32
		lanes []int
	}
	now := time.Now()
	byExpiry := map[time.Time]*group{}
	p.mu.Lock()
	for spi, w := range p.spis {
		if !w.expires.After(now) {
			delete(p.spis, spi)
			continue
		}
		g := byExpiry[w.expires]
		if g == nil {
			g = &group{}
			byExpiry[w.expires] = g
		}
		g.spis, g.lanes = append(g.spis, spi), append(g.lanes, w.lane)
	}
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(p.rc.ctx, keysTimeout)
	defer cancel()
	for exp, g := range byExpiry {
		_, err := p.rc.c.RegisterSPI(ctx, p.registerRequest(g.spis, g.lanes, exp.Sub(now)))
		if rpc.CodeOf(err) == rpc.AlreadyExists {
			// The relay has no row for the SPI, so it drops each packet of this session.
			slog.Info("Closing a peer session because the relay refused its SPI rows", "peer", p.subject, "error", err)
			_ = p.qc.CloseWithError(0, "relay refused the SPI rows")
			return
		}
		if err != nil {
			slog.Warn("Failed to refresh SPI rows at the relay", "peer", p.subject, "error", err)
		}
	}
}

type peerService struct {
	dp.UnimplementedPeerServer
	a *Agent
}

// Open checks the dialer and answers with the grant of this agent.
func (s *peerService) Open(ctx context.Context, in *dp.OpenRequest) (*dp.OpenResponse, error) {
	p := s.a.peerOf(ctx)
	if p == nil {
		return nil, rpc.Errorf(rpc.Unauthenticated, "no peer session")
	}
	if p.dialer {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "the dialer calls Open")
	}
	err := s.a.admit(p, in.GetVersion(), in.GetGrant(), in.GetInstance(), in.GetMode(), in.GetLanes())
	if errors.Is(err, errDuplicate) && s.a.cutFrom(ctx, p) {
		// The relay has no path to the peer, so the peer dialed as a visitor.
		err = s.a.admit(p, in.GetVersion(), in.GetGrant(), in.GetInstance(), in.GetMode(), in.GetLanes())
	}
	if err != nil {
		if errors.Is(err, errAlreadyOpen) {
			// The session stays open for the first Open.
			return nil, rpc.Errorf(rpc.FailedPrecondition, "%v", err)
		}
		slog.Info("Refused peer session", "peer", p.subject, "error", err)
		// The close can arrive before the call status, so it carries the reason.
		defer func() { _ = p.qc.CloseWithError(closeCode(err), err.Error()) }()
		switch {
		case errors.Is(err, errDuplicate):
			return nil, rpc.Errorf(rpc.AlreadyExists, "%v", err)
		case errors.Is(err, errRevision):
			return nil, rpc.Errorf(rpc.FailedPrecondition, "%v", err)
		}
		return nil, rpc.Errorf(rpc.PermissionDenied, "%v", err)
	}
	s.a.mu.Lock()
	xs := s.a.openExtras(p)
	s.a.mu.Unlock()
	grant, grants, err := p.rc.openGrants(ctx, xs)
	if err != nil {
		slog.Warn("Failed to get a grant for a peer session; closing the peer session", "peer", p.subject, "error", err)
		_ = p.qc.CloseWithError(0, "no grant")
		return nil, rpc.Errorf(rpc.Unavailable, "%v", err)
	}
	s.a.grantsOfOpen(p, in.GetGrants())
	go p.offer()
	go p.sendReports()
	return &dp.OpenResponse{
		Grant: grant, Grants: grants, Instance: s.a.instance, Mode: p.rc.dataMode(), Lanes: p.rc.sendLanes(), Version: s.a.ver,
	}, nil
}

// Keys applies SAs from the peer and registers their SPIs at the relay.
func (s *peerService) Keys(ctx context.Context, in *dp.KeysRequest) (*dp.KeysResponse, error) {
	p := s.a.peerOf(ctx)
	if p == nil {
		return nil, rpc.Errorf(rpc.Unauthenticated, "no peer session")
	}
	select {
	case <-p.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if p.quic {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "data to this peer goes through the relay")
	}
	req, err := keyproto.FromProto(in)
	if err != nil {
		return nil, rpc.Errorf(rpc.InvalidArgument, "%v", err)
	}
	return p.applyKeys(ctx, req)
}

// applyKeys applies a key change from the peer to the transmit SAs. The relay
// forwards an SPI before an SA sends with it, and until no SA sends with it.
func (p *peer) applyKeys(ctx context.Context, req keys.Request) (*dp.KeysResponse, error) {
	if req.Op == keys.OpRevoke {
		if _, err := p.bp.Apply(req, time.Now()); err != nil {
			return nil, rpc.Errorf(rpc.InvalidArgument, "%v", err)
		}
		if err := p.unregister(ctx, req.SPIs); err != nil {
			return nil, rpc.Errorf(rpc.Unavailable, "unregister SPIs at the relay: %v", err)
		}
		return &dp.KeysResponse{}, nil
	}
	if err := p.register(ctx, req.SAs); rpc.CodeOf(err) == rpc.AlreadyExists {
		// The relay forwards an SPI to another peer. The peer offers new SPIs.
		return &dp.KeysResponse{RefusedSpis: spisOf(req.SAs)}, nil
	} else if err != nil {
		return nil, rpc.Errorf(rpc.Unavailable, "register SPIs at the relay: %v", err)
	}
	refused, err := p.bp.Apply(req, time.Now())
	if err != nil {
		refused = spisOf(req.SAs)
	}
	if len(refused) > 0 {
		if err := p.unregister(ctx, refused); err != nil {
			slog.Warn("Failed to remove SPI rows at the relay", "peer", p.subject, "error", err)
		}
	}
	if err != nil {
		return nil, rpc.Errorf(rpc.InvalidArgument, "%v", err)
	}
	if len(refused) < len(req.SAs) {
		p.keyedOnce.Do(func() { close(p.keyed) })
	}
	return &dp.KeysResponse{RefusedSpis: refused}, nil
}
