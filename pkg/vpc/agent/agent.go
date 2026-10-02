// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
	// After a session of this age, the next reconnect starts at minBackoff.
	stableSession = time.Minute
	openTimeout   = 10 * time.Second
	renewRetry    = time.Minute
	tickInterval  = time.Second
	// The relay removes SPI rows after 5 minutes with no traffic.
	spiRefresh = 2 * time.Minute
)

// relayQUIC is the QUIC config of relay sessions. See relay.MinPacketSize.
var relayQUIC = &quic.Config{
	EnableDatagrams:   true,
	KeepAlivePeriod:   5 * time.Second,
	MaxIdleTimeout:    15 * time.Second,
	InitialPacketSize: 1350,
}

type Config struct {
	// Identity keeps the agent cert. Run starts it.
	Identity *identity.Manager
	// Relay is the address of the relay, host:port.
	Relay string
	// RelayID is the DNS name of the relay cert. Empty means the host in Relay.
	RelayID string
	// RelayRoots check relay certs and peer grants. Nil means the system roots.
	RelayRoots *x509.CertPool
	// Transport is the agent socket for the relay sessions and PSP. New sets
	// its NonQUICPacketHandler, so it must not be in use yet.
	Transport *quic.Transport
	// Name, labels and advertised routes of the attachment.
	Name   string
	Labels map[string]string
	Routes []netip.Prefix
	// OnAttach gets the binding, the overlay address and the prefixes after
	// each attach.
	OnAttach func(b *psp.Binding, addr netip.Addr, prefixes []netip.Prefix)
}

// Agent keeps a relay session for one VPC and runs the peer sessions on it.
type Agent struct {
	cfg      Config
	instance uint64
	mux      *rpc.Mux // Peer service.
	demux    psp.Demux

	mu       sync.Mutex
	rc       *relayConn
	bind     *psp.Binding
	peers    map[*rpc.Conn]*peer
	admitted chan struct{} // Closed and replaced when a peer session opens.
}

// New returns an agent. Call Run to start it.
func New(cfg Config) *Agent {
	a := &Agent{cfg: cfg, instance: rand.Uint64(), peers: map[*rpc.Conn]*peer{}, admitted: make(chan struct{})}
	a.mux = rpc.NewMux()
	dp.RegisterPeerServer(a.mux, &peerService{a: a})
	if cfg.Transport != nil {
		cfg.Transport.NonQUICPacketHandler = a.demux.Handle
	}
	return a
}

// Run keeps a relay session until ctx ends. On a cert renew or a drain, it
// opens the new session before it closes the old one.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.cfg.Identity.Start(ctx); err != nil {
		return fmt.Errorf("agent cert: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
		a.close()
	}()
	wg.Go(func() { a.tick(ctx) })

	backoff := minBackoff
	for ctx.Err() == nil {
		rc, err := a.open(ctx, a.cfg.Relay, a.cfg.RelayID)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			slog.Warn("Failed to open relay session", "relay", a.cfg.Relay, "error", err)
			if certRefused(err) {
				a.renew(ctx)
			}
			wait := rand.N(backoff) + 1
			backoff = min(2*backoff, maxBackoff)
			select {
			case <-ctx.Done():
			case <-time.After(wait):
			}
			continue
		}
		start := time.Now()
		for rc != nil {
			a.use(rc)
			rc = a.serve(ctx, rc)
		}
		if time.Since(start) > stableSession {
			backoff = minBackoff
		}
	}
	return nil
}

// certRefused reports whether err shows that a relay refused the agent cert:
// a TLS alert from the relay, or a close with RELAY_CLOSE_CODE_CERT.
func certRefused(err error) bool {
	var te *quic.TransportError
	if errors.As(err, &te) {
		return te.Remote && te.ErrorCode.IsCryptoError()
	}
	var ae *quic.ApplicationError
	return errors.As(err, &ae) && ae.Remote && ae.ErrorCode == quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_CERT)
}

func (a *Agent) renew(ctx context.Context) {
	if err := a.cfg.Identity.Renew(ctx); err != nil {
		slog.Warn("Failed to renew agent cert", "error", err)
	}
}

// use makes rc the relay session of the agent and closes the one before.
func (a *Agent) use(rc *relayConn) {
	a.mu.Lock()
	old := a.rc
	a.rc = rc
	b := a.bind
	a.mu.Unlock()
	if old != nil {
		old.close()
	}
	slog.Info("Attached to the VPC", "relay", rc.addr, "address", rc.self, "prefixes", rc.prefixes)
	if a.cfg.OnAttach != nil {
		a.cfg.OnAttach(b, rc.self, rc.prefixes)
	}
}

// serve waits until rc ends, or until the agent must move to a new session.
// It returns the new session, or nil when rc ended or ctx ended.
func (a *Agent) serve(ctx context.Context, rc *relayConn) *relayConn {
	renew := time.NewTimer(time.Until(rc.cred.RenewAt()))
	defer renew.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-rc.qc.Context().Done():
			err := context.Cause(rc.qc.Context())
			slog.Info("Relay session ended", "relay", rc.addr, "error", err)
			if certRefused(err) {
				a.renew(ctx)
			}
			return nil
		case <-renew.C:
			if a.cfg.Identity.Current() == rc.cred {
				if err := a.cfg.Identity.Renew(ctx); err != nil {
					slog.Warn("Failed to renew agent cert", "error", err)
					renew.Reset(renewRetry)
					continue
				}
			}
			next, err := a.open(ctx, rc.addr, rc.name)
			if err != nil {
				slog.Warn("Failed to open a relay session with the new cert", "relay", rc.addr, "error", err)
				renew.Reset(renewRetry)
				continue
			}
			return next
		case alts := <-rc.drain:
			addr, name := rc.addr, rc.name
			if len(alts) > 0 && len(alts[0].GetAddresses()) > 0 {
				addr, name = alts[0].GetAddresses()[0], alts[0].GetId()
			}
			next, err := a.open(ctx, addr, name)
			if err != nil {
				// The relay closes rc when its drain ends. Then Run dials again.
				slog.Warn("Failed to move to another relay", "relay", addr, "error", err)
				continue
			}
			return next
		}
	}
}

// relayConn is one relay session with its attachment.
type relayConn struct {
	a      *Agent
	ctx    context.Context // Ends at close.
	cancel context.CancelFunc
	qc     quic.Connection
	c      dp.RelayClient
	st     rpc.BidiStreamClient[dp.SessionRequest, dp.SessionResponse]
	cred   *identity.Credential
	addr   string // Relay address as dialed.
	name   string // TLS name of the relay.

	relayAddr netip.AddrPort // Where PSP packets to peers go.
	ref       *dp.VPCRef
	mtu       uint32
	grant     *dp.AttachmentGrant
	claims    *dp.GrantClaims
	prefixes  []netip.Prefix
	self      netip.Addr // Overlay address of this agent.

	pc     *peerconn.Conn
	peerTr *quic.Transport
	drain  chan []*dp.RelayRef
}

// open dials the relay at addr with the TLS name name, opens the Session
// call and attaches. An empty name means the host in addr.
func (a *Agent) open(ctx context.Context, addr, name string) (*relayConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = host
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	cred := a.cfg.Identity.Current()
	octx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	qc, err := a.cfg.Transport.Dial(octx, ua, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      a.cfg.RelayRoots,
		ServerName:   name,
		NextProtos:   []string{dp.ALPNRelay},
		Certificates: []tls.Certificate{*cred.TLSCertificate()},
	}, relayQUIC)
	if err != nil {
		return nil, err
	}
	rc := &relayConn{
		a:         a,
		qc:        qc,
		c:         dp.NewRelayClient(rpc.NewConn(qc, nil)),
		cred:      cred,
		addr:      addr,
		name:      name,
		relayAddr: qc.RemoteAddr().(*net.UDPAddr).AddrPort(),
		drain:     make(chan []*dp.RelayRef, 1),
	}
	rc.ctx, rc.cancel = context.WithCancel(context.Background())
	// A relay that does not answer in time ends the open.
	stop := context.AfterFunc(octx, func() { _ = qc.CloseWithError(0, "relay session did not open in time") })
	defer stop()
	if err := rc.start(octx); err != nil {
		rc.close()
		if cause := context.Cause(qc.Context()); cause != nil {
			return nil, fmt.Errorf("%w (connection: %w)", err, cause)
		}
		return nil, err
	}
	return rc, nil
}

// start runs Hello, Attach and the peer listener of rc.
func (rc *relayConn) start(ctx context.Context) error {
	a := rc.a
	st, err := rc.c.Session(rc.ctx)
	if err != nil {
		return err
	}
	rc.st = st
	if err := st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{Mode: dp.Mode_MODE_PSP}}}); err != nil {
		return err
	}
	m, err := st.Recv()
	if err != nil {
		return err
	}
	if m.GetWelcome() == nil {
		return fmt.Errorf("relay sent %T before Welcome", m.GetMsg())
	}
	if m, err = st.Recv(); err != nil {
		return err
	}
	cfg := m.GetConfig()
	if cfg == nil {
		return fmt.Errorf("relay sent %T before Config", m.GetMsg())
	}
	rc.ref, rc.mtu = cfg.GetVpc(), cfg.GetMtu()
	routes := make([]string, len(a.cfg.Routes))
	for i, p := range a.cfg.Routes {
		routes[i] = p.String()
	}
	res, err := rc.c.Attach(ctx, &dp.AttachRequest{Vpc: rc.ref, Name: a.cfg.Name, Labels: a.cfg.Labels, Routes: routes})
	if err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	// A bad relay cert fails the attach, not each peer session.
	if rc.claims, err = relay.VerifyGrant(res.GetGrant(), a.cfg.RelayRoots, time.Now()); err != nil {
		return err
	}
	rc.grant = res.GetGrant()
	if rc.prefixes, err = parsePrefixes(rc.claims.GetAddresses()); err != nil {
		return err
	}
	rc.self = overlayAddr(rc.prefixes)
	if err := a.binding(cfg); err != nil {
		return err
	}
	rc.pc = peerconn.New(rc.qc, rc.self)
	rc.peerTr = &quic.Transport{Conn: rc.pc}
	ln, err := rc.peerTr.Listen(a.peerTLS(), peerQUIC)
	if err != nil {
		return err
	}
	go rc.accept(ln)
	go rc.sync()
	return nil
}

// binding makes the PSP binding of the VPC at the first attach.
func (a *Agent) binding(cfg *dp.Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.bind != nil {
		return nil
	}
	b, err := psp.New(psp.Config{Transport: a.cfg.Transport, Demux: &a.demux, VNI: cfg.GetVpc().GetNetworkId(), MTU: int(cfg.GetMtu())})
	if err != nil {
		return err
	}
	a.bind = b
	return nil
}

// sync applies the Sync messages of rc until the Session call ends.
func (rc *relayConn) sync() {
	for {
		m, err := rc.st.Recv()
		if err != nil {
			return
		}
		switch m := m.GetMsg().(type) {
		case *dp.SessionResponse_RouteDelta:
			rc.a.removeRoutes(rc, m.RouteDelta.GetRemove())
			if err := rc.st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Ack{Ack: &dp.Ack{Rev: m.RouteDelta.GetRev()}}}); err != nil {
				return
			}
		case *dp.SessionResponse_NoRoute:
			if addr, err := netip.ParseAddr(m.NoRoute.GetAddress()); err == nil {
				rc.a.closePeers(func(p *peer) bool { return p.rc == rc && p.routes(addr) }, "relay has no route to the peer")
			}
		case *dp.SessionResponse_Drain:
			select {
			case rc.drain <- m.Drain.GetAlternates():
			default:
			}
		case *dp.SessionResponse_Config:
			if m.Config.GetMtu() != rc.mtu {
				slog.Info("VPC MTU changed; the new MTU applies after the agent restarts", "mtu", m.Config.GetMtu())
			}
		}
	}
}

// removeRoutes closes the peer sessions of attachments that left the VPC.
func (a *Agent) removeRoutes(rc *relayConn, removed []*dp.Route) {
	gone := map[string]bool{}
	for _, r := range removed {
		gone[r.GetOrigin()] = true
	}
	a.closePeers(func(p *peer) bool { return p.rc == rc && gone[p.attachmentID()] }, "peer left the VPC")
}

// close ends rc, its peer sessions and its peer transport.
func (rc *relayConn) close() {
	rc.a.closePeers(func(p *peer) bool { return p.rc == rc }, "relay session closed")
	rc.cancel()
	if rc.peerTr != nil {
		// Close the packet connection first to end the transport read loop.
		_ = rc.pc.Close()
		_ = rc.peerTr.Close()
	}
	_ = rc.qc.CloseWithError(0, "")
}

// close ends the relay session and the binding at the end of Run.
func (a *Agent) close() {
	a.mu.Lock()
	rc, b := a.rc, a.bind
	a.rc = nil
	a.mu.Unlock()
	if rc != nil {
		rc.close()
	}
	if b != nil {
		_ = b.Close()
	}
}

// tick runs the key timers of the binding and refreshes SPI rows.
func (a *Agent) tick(ctx context.Context) {
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	refresh := time.NewTicker(spiRefresh)
	defer refresh.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			a.mu.Lock()
			b := a.bind
			a.mu.Unlock()
			if b == nil {
				continue
			}
			ups, err := b.Tick(now)
			if err != nil {
				slog.Warn("Failed to rekey receive SAs", "error", err)
			}
			for _, u := range ups {
				if p := a.peerOfBinding(u.Peer); p != nil {
					go p.sendKeys(u.Request)
				}
			}
		case <-refresh.C:
			a.mu.Lock()
			peers := make([]*peer, 0, len(a.peers))
			for _, p := range a.peers {
				peers = append(peers, p)
			}
			a.mu.Unlock()
			for _, p := range peers {
				go p.refreshSPIs()
			}
		}
	}
}

func parsePrefixes(ss []string) ([]netip.Prefix, error) {
	if len(ss) == 0 {
		return nil, errors.New("grant has no addresses")
	}
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("grant address: %w", err)
		}
		out[i] = p.Masked()
	}
	return out, nil
}

// overlayAddr is the first address after the base of the first prefix.
func overlayAddr(prefixes []netip.Prefix) netip.Addr {
	return prefixes[0].Addr().Next()
}
