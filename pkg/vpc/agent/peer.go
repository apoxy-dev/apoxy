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

// peer is one peer session with a remote agent of the VPC.
type peer struct {
	rc      *relayConn
	qc      quic.Connection
	conn    *rpc.Conn
	client  dp.PeerClient
	dialer  bool   // This agent dialed the session.
	subject string // SPIFFE ID in the peer cert.

	ready     chan struct{} // Closed when Open passes.
	keyed     chan struct{} // Closed when SAs from the peer first apply.
	keyedOnce sync.Once
	offered   chan struct{} // Closed when the peer takes the first offer.

	// Set before ready closes, under Agent.mu.
	instance uint64
	claims   *dp.GrantClaims
	prefixes []netip.Prefix
	addr     netip.Addr // Overlay address of the peer.
	bp       *psp.Peer
	// quic is true when one of the agents sends QUIC data frames. Then the
	// data goes through the relay, and bp is the relay peer.
	quic bool
	// advertised is the prefixes that the peer advertises and that route to bp.
	// Guarded by Agent.mu.
	advertised []netip.Prefix

	mu   sync.Mutex
	spis map[uint32]time.Time // SPIs registered at the relay, to their expiry.
}

// routes reports whether the grant or the advertised prefixes of p cover addr.
func (p *peer) routes(addr netip.Addr) bool {
	has := func(pfx netip.Prefix) bool { return pfx.Contains(addr) }
	return slices.ContainsFunc(p.prefixes, has) || slices.ContainsFunc(p.advertised, has)
}

func (p *peer) attachmentID() string { return p.claims.GetAttachmentId() }

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
		if _, err := rc.a.newPeer(rc, qc, false); err != nil {
			_ = qc.CloseWithError(quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_BAD_GRANT), err.Error())
		}
	}
}

// newPeer serves the Peer service on qc and adds the session to the agent.
func (a *Agent) newPeer(rc *relayConn, qc quic.Connection, dialer bool) (*peer, error) {
	id, err := identity.IDFromCert(qc.ConnectionState().TLS.PeerCertificates[0])
	if err != nil {
		return nil, err
	}
	p := &peer{
		rc:      rc,
		qc:      qc,
		dialer:  dialer,
		subject: id.String(),
		ready:   make(chan struct{}),
		keyed:   make(chan struct{}),
		offered: make(chan struct{}),
		spis:    map[uint32]time.Time{},
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

// Connect opens a peer session to the agent at dst and exchanges keys with
// it. It returns when PSP works in both directions.
func (a *Agent) Connect(ctx context.Context, dst netip.Addr) error {
	a.mu.Lock()
	rc := a.rc
	a.mu.Unlock()
	if rc == nil {
		return errNoRelay
	}
	return a.connect(ctx, rc, dst, nil)
}

// connect opens a peer session on rc to the agent at dst if none covers dst,
// and waits for its SAs. res is the ResolvePeer answer for dst, or nil.
func (a *Agent) connect(ctx context.Context, rc *relayConn, dst netip.Addr, res *dp.ResolvePeerResponse) error {
	a.mu.Lock()
	p := a.peerTo(rc, dst)
	a.mu.Unlock()
	if p == nil {
		var err error
		if res == nil {
			if res, err = rc.resolve(ctx, dst); err != nil {
				return err
			}
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
		chans = []chan struct{}{p.rc.bridgeTx, p.rc.bridgeRx}
	}
	for _, ch := range chans {
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
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

// waitPeer waits until a peer session on rc that covers dst opens.
func (a *Agent) waitPeer(ctx context.Context, rc *relayConn, dst netip.Addr) (*peer, error) {
	ctx, cancel := context.WithTimeout(ctx, duplicateWait)
	defer cancel()
	for {
		a.mu.Lock()
		p, admitted := a.peerTo(rc, dst), a.admitted
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
	return errors.As(context.Cause(qc.Context()), &ae) && ae.Remote &&
		ae.ErrorCode == quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE)
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
	if res.GetReach() != dp.Reach_REACH_LOCAL {
		return nil, fmt.Errorf("peer %s is not on this relay (%v)", dst, res.GetReach())
	}
	qc, err := rc.peerTr.Dial(ctx, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 0)), a.peerTLS(), peerQUIC)
	if err != nil {
		return nil, fmt.Errorf("dial peer %s: %w", dst, err)
	}
	p, err := a.newPeer(rc, qc, true)
	if err != nil {
		_ = qc.CloseWithError(quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_BAD_GRANT), err.Error())
		return nil, err
	}
	open, err := p.client.Open(ctx, &dp.OpenRequest{Grant: rc.grant, Instance: a.instance, Mode: rc.mode})
	if err != nil {
		if refusedDuplicate(qc, err) {
			err = errDuplicate
		}
		_ = qc.CloseWithError(0, "")
		return nil, fmt.Errorf("open peer session to %s: %w", dst, err)
	}
	if err := a.admit(p, open.GetGrant(), open.GetInstance(), open.GetMode()); err != nil {
		_ = qc.CloseWithError(closeCode(err), err.Error())
		return nil, fmt.Errorf("peer %s: %w", dst, err)
	}
	go p.offer()
	return p, nil
}

// admit checks the Open data of the peer, then adds it to the binding with
// the prefixes of its grant.
func (a *Agent) admit(p *peer, g *dp.AttachmentGrant, instance uint64, mode dp.Mode) error {
	if mode != dp.Mode_MODE_PSP && mode != dp.Mode_MODE_QUIC {
		return fmt.Errorf("peer mode %v is not supported", mode)
	}
	if mode == dp.Mode_MODE_QUIC || p.rc.mode == dp.Mode_MODE_QUIC {
		return a.admitQUIC(p, g, instance)
	}
	claims, prefixes, err := a.checkGrant(p, g)
	if err != nil {
		return err
	}

	a.mu.Lock()
	var old *peer
	for _, q := range a.peers {
		if q != p && q.rc == p.rc && q.bp != nil && q.subject == p.subject {
			old = q
		}
	}
	// When both agents dial, the session that the agent with the lower ID
	// dialed stays.
	if old != nil && old.instance == instance && old.dialer != p.dialer && old.dialer == (p.rc.cred.ID.String() < p.subject) {
		a.mu.Unlock()
		return errDuplicate
	}
	a.mu.Unlock()
	if old != nil {
		_ = old.qc.CloseWithError(quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE), "new session")
		a.dropPeer(old)
	}

	bp, err := a.bind.AddPeer(p.rc.relayAddr)
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
	p.instance, p.claims, p.prefixes, p.addr, p.bp = instance, claims, prefixes, overlayAddr(prefixes), bp
	close(a.admitted)
	a.admitted = make(chan struct{})
	a.mu.Unlock()
	a.routeAdvertised(p)
	close(p.ready)
	slog.Info("Opened peer session", "peer", p.subject, "address", p.addr, "dialer", p.dialer)
	return nil
}

// checkGrant checks the grant of the peer and returns its claims and prefixes.
func (a *Agent) checkGrant(p *peer, g *dp.AttachmentGrant) (*dp.GrantClaims, []netip.Prefix, error) {
	claims, err := relay.VerifyGrant(g, p.rc.roots, time.Now())
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
func (a *Agent) admitQUIC(p *peer, g *dp.AttachmentGrant, instance uint64) error {
	claims, prefixes, err := a.checkGrant(p, g)
	if err != nil {
		return err
	}
	// A PSP pair with the same peer is from before the peer changed its mode.
	a.mu.Lock()
	var old []*peer
	for _, q := range a.peers {
		if q != p && q.rc == p.rc && q.bp != nil && !q.quic && q.subject == p.subject {
			old = append(old, q)
		}
	}
	a.mu.Unlock()
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
	p.instance, p.claims, p.prefixes, p.addr, p.bp, p.quic = instance, claims, prefixes, overlayAddr(prefixes), p.rc.relay, true
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
			if q != p && q.quic && q.rc == p.rc && (slices.Contains(q.prefixes, pfx) || slices.Contains(q.advertised, pfx)) {
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
	if errors.Is(err, errDuplicate) {
		return quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE)
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
	}
	a.mu.Unlock()
	if bp == nil {
		return
	}
	if !p.quic {
		a.bind.RemovePeer(bp)
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
	slog.Info("Closed peer session", "peer", p.subject, "reason", context.Cause(p.qc.Context()))
}

func (a *Agent) closePeers(match func(*peer) bool, reason string) {
	a.mu.Lock()
	var ps []*peer
	for _, p := range a.peers {
		if match(p) {
			ps = append(ps, p)
		}
	}
	a.mu.Unlock()
	for _, p := range ps {
		_ = p.qc.CloseWithError(0, reason)
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
	if p.sendKeys(req) {
		close(p.offered)
	}
}

// sendKeys sends a key change to the peer. It reports whether the peer took it.
func (p *peer) sendKeys(req keys.Request) bool {
	ctx, cancel := context.WithTimeout(p.rc.ctx, keysTimeout)
	defer cancel()
	if err := giveKeys(ctx, p.bp, req, p.client.Keys); err != nil {
		if p.qc.Context().Err() == nil {
			slog.Warn("Failed to send keys to a peer", "peer", p.subject, "error", err)
		}
		return false
	}
	return true
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
	spis := spisOf(sas)
	if _, err := p.rc.c.RegisterSPI(ctx, &dp.RegisterSPIRequest{
		Vpc: p.rc.ref, Destination: p.addr.String(), Spis: spis, ExpiresIn: durationpb.New(ttl),
	}); err != nil {
		return err
	}
	expires := time.Now().Add(ttl)
	p.mu.Lock()
	for _, spi := range spis {
		p.spis[spi] = expires
	}
	p.mu.Unlock()
	return nil
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

// refreshSPIs registers the live SPIs again, so that idle rows stay.
func (p *peer) refreshSPIs() {
	now := time.Now()
	byExpiry := map[time.Time][]uint32{}
	p.mu.Lock()
	for spi, exp := range p.spis {
		if exp.After(now) {
			byExpiry[exp] = append(byExpiry[exp], spi)
		} else {
			delete(p.spis, spi)
		}
	}
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(p.rc.ctx, keysTimeout)
	defer cancel()
	for exp, spis := range byExpiry {
		if _, err := p.rc.c.RegisterSPI(ctx, &dp.RegisterSPIRequest{
			Vpc: p.rc.ref, Destination: p.addr.String(), Spis: spis, ExpiresIn: durationpb.New(exp.Sub(now)),
		}); err != nil {
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
	if err := s.a.admit(p, in.GetGrant(), in.GetInstance(), in.GetMode()); err != nil {
		slog.Info("Refused peer session", "peer", p.subject, "error", err)
		// The close can arrive before the call status, so it carries the reason.
		defer func() { _ = p.qc.CloseWithError(closeCode(err), err.Error()) }()
		if errors.Is(err, errDuplicate) {
			return nil, rpc.Errorf(rpc.AlreadyExists, "%v", err)
		}
		return nil, rpc.Errorf(rpc.PermissionDenied, "%v", err)
	}
	go p.offer()
	return &dp.OpenResponse{Grant: p.rc.grant, Instance: s.a.instance, Mode: p.rc.mode}, nil
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
