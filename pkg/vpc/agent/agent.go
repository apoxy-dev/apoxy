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
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
	// After a session of this age, the next reconnect starts at minBackoff.
	stableSession = time.Minute
	// quicShards is the number of connections, with the session, that carry
	// data in QUIC mode.
	quicShards   = 2
	openTimeout  = 10 * time.Second
	renewRetry   = time.Minute
	tickInterval = time.Second
	// The relay removes SPI rows after 5 minutes with no traffic.
	spiRefresh = 2 * time.Minute
	// pspPasses is the number of PSP probes in a row that must pass before
	// the agent moves from QUIC mode back to PSP.
	pspPasses = 2
)

// In QUIC mode after a failed probe, the agent probes PSP again with backoff.
// Tests change these values.
var (
	pspRetryMin  = 30 * time.Second
	pspRetryMax  = 10 * time.Minute
	pspRetryNext = 5 * time.Second // From a probe that passes to the next probe.
)

// relayQUIC is the QUIC config of relay sessions. See relay.MinPacketSize.
var relayQUIC = &quic.Config{
	EnableDatagrams:   true,
	KeepAlivePeriod:   5 * time.Second,
	MaxIdleTimeout:    15 * time.Second,
	InitialPacketSize: 1350,
}

// TransportMode picks how an agent sends data.
type TransportMode int

const (
	// TransportAuto sends PSP, and QUIC data frames when PSP does not pass.
	TransportAuto TransportMode = iota
	// TransportPSP always sends PSP.
	TransportPSP
	// TransportQUIC always sends QUIC data frames on the relay session.
	TransportQUIC
)

type Config struct {
	// Identity keeps the agent cert. Run starts it.
	Identity *identity.Manager
	// Relay is the address of the relay, host:port.
	Relay string
	// Alternates are more relay addresses. When an open fails, the agent
	// dials the next address, and after the last one it dials Relay again.
	Alternates []string
	// RelayID is the DNS name of the relay cert. Empty means the host in the
	// relay address.
	RelayID string
	// RelayRoots check relay certs and peer grants. Nil means the system roots.
	RelayRoots *x509.CertPool
	// InsecureSkipVerify does not check relay certs, and checks grants with
	// the cert that the relay shows. Use it only with dev relays.
	InsecureSkipVerify bool
	// Transport is the agent socket for the relay sessions and PSP. New sets
	// its NonQUICPacketHandler and NonQUICBatchEnd, so it must not be in use yet.
	Transport *quic.Transport
	// TransportMode picks how data goes to peers. The zero value is auto.
	TransportMode TransportMode
	// Name, labels and advertised routes of the attachment.
	Name   string
	Labels map[string]string
	Routes []netip.Prefix
	// OnAttach gets the binding, the overlay address and the prefixes after
	// each attach.
	OnAttach func(b *psp.Binding, addr netip.Addr, prefixes []netip.Prefix)
	// OnRoutes gets the changes to the prefixes of the other attachments in
	// the VPC, after OnAttach. The agent calls it from one goroutine at a time.
	OnRoutes func(add, remove []netip.Prefix)
	// MTU sets the device MTU, from 1280 to the VPC MTU, with no path probe.
	// Zero means the VPC MTU if the path to the relay carries it, else 1280.
	MTU int
}

// Agent keeps a relay session for one VPC and runs the peer sessions on it.
type Agent struct {
	cfg      Config
	instance uint64
	mux      *rpc.Mux // Peer service.
	demux    psp.Demux
	probing  atomic.Pointer[pathProbe]
	holds    holds

	// Lock order: routeMu, then mu. holds.mu is never held with another lock.
	mu       sync.Mutex
	rc       *relayConn
	bind     *psp.Binding
	peers    map[*rpc.Conn]*peer
	admitted chan struct{} // Closed and replaced when a peer session opens.

	routeMu  sync.Mutex
	routesOf *relayConn            // Session that OnRoutes follows.
	reported map[netip.Prefix]bool // Prefixes that OnRoutes has.
}

// New returns an agent. Call Run to start it.
func New(cfg Config) *Agent {
	a := &Agent{cfg: cfg, instance: rand.Uint64(), peers: map[*rpc.Conn]*peer{}, admitted: make(chan struct{})}
	a.mux = rpc.NewMux()
	dp.RegisterPeerServer(a.mux, &peerService{a: a})
	a.demux.Probe = a.onProbe
	if cfg.Transport != nil {
		cfg.Transport.NonQUICPacketHandler = a.demux.Handle
		cfg.Transport.NonQUICBatchEnd = a.demux.BatchEnd
	}
	return a
}

// Run keeps a relay session until ctx ends. On a cert renew or a drain, it
// opens the new session before it closes the old one.
func (a *Agent) Run(ctx context.Context) error {
	if m := a.cfg.MTU; m != 0 && (m < psp.DefaultMTU || m > psp.MaxMTU) {
		return fmt.Errorf("MTU must be %d to %d, got %d", psp.DefaultMTU, psp.MaxMTU, m)
	}
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

	relays := append([]string{a.cfg.Relay}, a.cfg.Alternates...)
	backoff := minBackoff
	for i := 0; ctx.Err() == nil; {
		rc, err := a.open(ctx, relays[i], a.cfg.RelayID)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			slog.Warn("Failed to open relay session", "relay", relays[i], "error", err)
			if certRefused(err) {
				a.renew(ctx)
			}
			i = (i + 1) % len(relays)
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
	if rc.mode == dp.Mode_MODE_QUIC {
		b.UseQUIC(rc.pc)
	} else {
		b.UseQUIC(nil)
	}
	if old != nil {
		old.close()
	}
	slog.Info("Attached to the VPC", "relay", rc.addr, "address", rc.self, "prefixes", rc.prefixes,
		"transport", transportName(rc.mode), "fallback", rc.reason, "connect", rc.connect)
	if a.cfg.OnAttach != nil {
		a.cfg.OnAttach(b, rc.self, rc.prefixes)
	}
	a.useRoutes(rc)
}

// DNS returns the DNS servers and search domains of the VPC.
func (a *Agent) DNS() (servers, search []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.rc == nil {
		return nil, nil
	}
	return a.rc.dnsServers, a.rc.dnsSearch
}

// Status is the data transport of the current attachment.
type Status struct {
	Mode   dp.Mode           // Unspecified before the first attach.
	Reason dp.FallbackReason // Why Mode is QUIC.
	// Time to connect: from the start of the dial to the first Config.
	Connect time.Duration
}

// Status returns the data transport of the current attachment.
func (a *Agent) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.rc == nil {
		return Status{}
	}
	return Status{Mode: a.rc.mode, Reason: a.rc.reason, Connect: a.rc.connect}
}

func transportName(m dp.Mode) string {
	switch m {
	case dp.Mode_MODE_PSP:
		return "psp"
	case dp.Mode_MODE_QUIC:
		return "quic"
	}
	return "none"
}

// serve waits until rc ends, or until the agent must move to a new session.
// It returns the new session, or nil when rc ended or ctx ended.
func (a *Agent) serve(ctx context.Context, rc *relayConn) *relayConn {
	renew := time.NewTimer(time.Until(rc.cred.RenewAt()))
	defer renew.Stop()
	retry := time.NewTimer(pspRetryMin)
	defer retry.Stop()
	if rc.reason != dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT {
		retry.Stop()
	}
	wait, passes := pspRetryMin, 0
	var probed <-chan bool
	backoff := func() {
		passes, wait = 0, min(2*wait, pspRetryMax)
		retry.Reset(wait)
	}
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
		case <-retry.C:
			probed = rc.probe(rc.ctx, psp.DefaultMTU)
		case ok := <-probed:
			probed = nil
			if !ok {
				backoff()
				continue
			}
			if passes++; passes < pspPasses {
				retry.Reset(pspRetryNext)
				continue
			}
			// The new session probes again before it picks its mode.
			slog.Info("PSP probes to the relay pass; opening a PSP session", "relay", rc.addr)
			next, err := a.open(ctx, rc.addr, rc.name)
			if err == nil && next.mode == dp.Mode_MODE_PSP {
				return next
			}
			if err != nil {
				slog.Warn("Failed to open a relay session for PSP", "relay", rc.addr, "error", err)
			} else {
				next.close()
			}
			backoff()
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
	sendMu sync.Mutex     // Guards sends on st after start.
	local  netip.AddrPort // Local address at the last check. Only tick changes it after open.
	cred   *identity.Credential
	addr   string         // Relay address as dialed.
	name   string         // TLS name of the relay.
	roots  *x509.CertPool // Check grants. Nil means the system roots.

	relayAddr netip.AddrPort    // Where PSP packets to peers go.
	mode      dp.Mode           // Data mode of the Session call.
	reason    dp.FallbackReason // Why mode is QUIC.
	connect   time.Duration     // Time to connect: from the start of the dial to the first Config.
	ref       *dp.VPCRef
	mtu       uint32
	grant     *dp.AttachmentGrant
	claims    *dp.GrantClaims
	prefixes  []netip.Prefix
	self      netip.Addr // Overlay address of this agent.
	routes    routeTable // Guarded by Agent.routeMu.

	dnsServers, dnsSearch []string

	// relay is the relay as a peer of the binding. Packets for QUIC-mode peers
	// go to it, sealed with the SAs that the relay gives in PSP mode.
	relay *psp.Peer
	// bridgeTx closes when the relay SAs first apply. bridgeRx closes when the
	// relay first takes the SAs of this agent. QUIC pairs wait for both.
	bridgeTx, bridgeRx chan struct{}

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
	begin := time.Now()
	octx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	qc, err := a.cfg.Transport.Dial(octx, ua, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		RootCAs:            a.cfg.RelayRoots,
		ServerName:         name,
		NextProtos:         []string{dp.ALPNRelay},
		Certificates:       []tls.Certificate{*cred.TLSCertificate()},
		InsecureSkipVerify: a.cfg.InsecureSkipVerify,
	}, relayQUIC)
	if err != nil {
		return nil, err
	}
	roots := a.cfg.RelayRoots
	if a.cfg.InsecureSkipVerify {
		roots = x509.NewCertPool()
		roots.AddCert(qc.ConnectionState().TLS.PeerCertificates[0])
	}
	rc := &relayConn{
		a:         a,
		qc:        qc,
		c:         dp.NewRelayClient(rpc.NewConn(qc, nil)),
		cred:      cred,
		addr:      addr,
		name:      name,
		roots:     roots,
		relayAddr: qc.RemoteAddr().(*net.UDPAddr).AddrPort(),
		drain:     make(chan []*dp.RelayRef, 1),
		bridgeTx:  make(chan struct{}),
		bridgeRx:  make(chan struct{}),
	}
	rc.ctx, rc.cancel = context.WithCancel(context.Background())
	rc.local = rc.localAddr()
	// A relay that does not answer in time ends the open.
	stop := context.AfterFunc(octx, func() { _ = qc.CloseWithError(0, "relay session did not open in time") })
	defer stop()
	rc.mode, rc.reason = a.pickMode(octx, rc)
	if err := rc.start(octx, begin); err != nil {
		rc.close()
		if cause := context.Cause(qc.Context()); cause != nil {
			return nil, fmt.Errorf("%w (connection: %w)", err, cause)
		}
		return nil, err
	}
	return rc, nil
}

// pickMode returns the data mode of rc, and why it is QUIC. In auto mode, it
// sends PSP probes to the relay and picks QUIC if no reply comes.
func (a *Agent) pickMode(ctx context.Context, rc *relayConn) (dp.Mode, dp.FallbackReason) {
	switch a.cfg.TransportMode {
	case TransportQUIC:
		return dp.Mode_MODE_QUIC, dp.FallbackReason_FALLBACK_REASON_CONFIG
	case TransportAuto:
		if !<-rc.probe(ctx, psp.DefaultMTU) {
			return dp.Mode_MODE_QUIC, dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT
		}
	}
	return dp.Mode_MODE_PSP, dp.FallbackReason_FALLBACK_REASON_UNSPECIFIED
}

// start runs Hello, Attach and the peer listener of rc. The dial started at begin.
func (rc *relayConn) start(ctx context.Context, begin time.Time) error {
	a := rc.a
	st, err := rc.c.Session(rc.ctx)
	if err != nil {
		return err
	}
	rc.st = st
	if err := st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{Mode: rc.mode, FallbackReason: rc.reason}}}); err != nil {
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
	rc.connect = time.Since(begin)
	if err := st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Status{Status: &dp.Status{ConnectTime: durationpb.New(rc.connect)}}}); err != nil {
		return err
	}
	rc.ref, rc.mtu = cfg.GetVpc(), cfg.GetMtu()
	rc.dnsServers, rc.dnsSearch = cfg.GetDnsServers(), cfg.GetDnsSearchDomains()
	// The path probe runs while the relay attaches. QUIC mode sends no PSP.
	pathMTU := 0
	if rc.mode == dp.Mode_MODE_PSP {
		pathMTU = a.probeMTU(int(rc.mtu))
	}
	var probed <-chan bool
	if pathMTU != 0 {
		probed = rc.probe(ctx, pathMTU)
	}
	routes := make([]string, len(a.cfg.Routes))
	for i, p := range a.cfg.Routes {
		routes[i] = p.String()
	}
	res, err := rc.c.Attach(ctx, &dp.AttachRequest{Vpc: rc.ref, Name: a.cfg.Name, Labels: a.cfg.Labels, Routes: routes})
	if err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	// A bad relay cert fails the attach, not each peer session.
	if rc.claims, err = relay.VerifyGrant(res.GetGrant(), rc.roots, time.Now()); err != nil {
		return err
	}
	rc.grant = res.GetGrant()
	if rc.prefixes, err = parsePrefixes(rc.claims.GetAddresses()); err != nil {
		return err
	}
	rc.self = overlayAddr(rc.prefixes)
	if probed != nil && !<-probed {
		pathMTU = psp.DefaultMTU
	}
	b, err := a.binding(cfg, pathMTU)
	if err != nil {
		return err
	}
	if rc.relay, err = b.AddPeer(rc.relayAddr); err != nil {
		return err
	}
	rc.pc = peerconn.New(rc.qc, rc.self)
	rc.pc.HandleData(b.HandleData)
	rc.peerTr = &quic.Transport{Conn: rc.pc}
	ln, err := rc.peerTr.Listen(a.peerTLS(), peerQUIC)
	if err != nil {
		return err
	}
	go rc.accept(ln)
	go rc.sync()
	if rc.mode == dp.Mode_MODE_QUIC {
		// Data frames need no SAs.
		close(rc.bridgeTx)
		close(rc.bridgeRx)
		go rc.keepShards(quicShards)
	} else {
		go rc.giveRelayKeys()
	}
	return nil
}

// binding returns the PSP binding of the VPC. The first attach makes it.
// pathMTU is the MTU that the path probe found, or 0 if no probe ran.
func (a *Agent) binding(cfg *dp.Config, pathMTU int) (*psp.Binding, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.bind != nil {
		if pathMTU != 0 {
			a.setClamp(pathMTU)
		}
		return a.bind, nil
	}
	mtu := int(cfg.GetMtu())
	if mtu == 0 {
		mtu = psp.DefaultMTU
	}
	dev := mtu
	if a.cfg.MTU != 0 {
		dev = min(a.cfg.MTU, mtu)
	} else if pathMTU != 0 {
		dev = pathMTU
	}
	b, err := psp.New(psp.Config{
		Transport: a.cfg.Transport, Demux: &a.demux, VNI: cfg.GetVpc().GetNetworkId(), MTU: mtu, DeviceMTU: dev,
		NoRoute: a.onNoRoute,
	})
	if err != nil {
		return nil, err
	}
	if dev < mtu {
		slog.Info("Using a device MTU below the VPC MTU", "mtu", mtu, "device_mtu", dev)
	}
	a.bind = b
	return b, nil
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
			rc.a.applyRoutes(rc, m.RouteDelta)
			rc.a.removeRoutes(rc, m.RouteDelta.GetRemove())
			if err := rc.send(&dp.SessionRequest{Msg: &dp.SessionRequest_Ack{Ack: &dp.Ack{Rev: m.RouteDelta.GetRev()}}}); err != nil {
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
		case *dp.SessionResponse_Rekey:
			rc.applyRelayKeys(m.Rekey)
		case *dp.SessionResponse_Config:
			if m.Config.GetMtu() != rc.mtu {
				slog.Info("VPC MTU changed; the new MTU applies after the agent restarts", "mtu", m.Config.GetMtu())
			}
		}
	}
}

// send sends m on the Session call after start.
func (rc *relayConn) send(m *dp.SessionRequest) error {
	rc.sendMu.Lock()
	defer rc.sendMu.Unlock()
	return rc.st.Send(m)
}

// applyRelayKeys applies the relay SAs to the transmit SAs of the relay peer.
func (rc *relayConn) applyRelayKeys(m *dp.KeysRequest) {
	req, err := keyproto.FromProto(m)
	if err == nil {
		var refused []uint32
		if refused, err = rc.relay.Apply(req, time.Now()); err == nil && len(refused) > 0 {
			err = fmt.Errorf("SPIs %v are in use", refused)
		}
	}
	if err != nil {
		if !rc.ended() {
			slog.Warn("Failed to apply relay SAs", "relay", rc.addr, "error", err)
		}
		return
	}
	// Only sync calls this, so no other close can come between.
	select {
	case <-rc.bridgeTx:
	default:
		close(rc.bridgeTx)
	}
}

// giveRelayKeys gives the relay the SAs for bridged packets to this agent.
func (rc *relayConn) giveRelayKeys() {
	req, err := rc.relay.Offer(time.Now())
	if err != nil {
		if !rc.ended() {
			slog.Warn("Failed to create receive SAs for the relay", "relay", rc.addr, "error", err)
		}
		return
	}
	if rc.sendRelayKeys(req) {
		close(rc.bridgeRx)
	}
}

// sendRelayKeys sends a key change of the relay peer to the relay. It reports
// whether the relay took it.
func (rc *relayConn) sendRelayKeys(req keys.Request) bool {
	ctx, cancel := context.WithTimeout(rc.ctx, keysTimeout)
	defer cancel()
	if err := giveKeys(ctx, rc.relay, req, rc.c.Rekey); err != nil {
		// The call can fail with the close before qc.Context ends.
		var closed *quic.ApplicationError
		if !rc.ended() && !errors.As(err, &closed) {
			slog.Warn("Failed to give receive SAs to the relay", "relay", rc.addr, "error", err)
		}
		return false
	}
	return true
}

// ended reports whether the connection or the use of rc ended.
func (rc *relayConn) ended() bool {
	return rc.ctx.Err() != nil || rc.qc.Context().Err() != nil
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
	if rc.relay != nil {
		rc.a.bind.RemovePeer(rc.relay)
	}
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

// tick runs the key timers of the binding and the holds, checks the local
// address, and refreshes SPI rows.
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
			a.holds.sweep(now)
			a.checkMoved()
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
				} else if rc := a.relayOfBinding(u.Peer); rc != nil {
					go rc.sendRelayKeys(u.Request)
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

// relayOfBinding returns the current relay session if bp is its relay peer.
func (a *Agent) relayOfBinding(bp *psp.Peer) *relayConn {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.rc != nil && a.rc.relay == bp {
		return a.rc
	}
	return nil
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
