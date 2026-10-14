// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash/maphash"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/apoxy-dev/apoxy/build"
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
	tickInterval = time.Second
	// The relay removes SPI rows after 5 minutes with no traffic.
	spiRefresh = 2 * time.Minute
	// pspPasses is the number of PSP probes in a row that must pass, after a
	// probe that failed, before the agent changes from QUIC mode to PSP mode.
	pspPasses = 2
)

// In QUIC mode after a failed probe, the agent probes PSP again with backoff.
// Tests change these values.
var (
	pspRetryMin  = 30 * time.Second
	pspRetryMax  = 10 * time.Minute
	pspRetryNext = 5 * time.Second // From a probe that passes to the next probe.
	// txLanes returns the send lanes to a relay address.
	txLanes = psp.TxLanes
)

// defaultRoutes are the routes of each relay session to its relay.
var defaultRoutes = []netip.Prefix{netip.MustParsePrefix("::/0"), netip.MustParsePrefix("0.0.0.0/0")}

// relayQUIC is the QUIC config of relay sessions. Data is Not-ECT: the breaker
// reacts to congestion. The keep-alive opens a lost NAT entry again. The timers
// are those of BFD, so a session on a relay that stops ends after 6 s.
var relayQUIC = &quic.Config{
	EnableDatagrams:   true,
	KeepAlivePeriod:   2 * time.Second,
	MaxIdleTimeout:    6 * time.Second,
	InitialPacketSize: 1350,
	DisableECN:        true,
}

// TransportMode picks how an agent sends data.
type TransportMode int

const (
	// TransportAuto sends QUIC data frames at first, and PSP after the PSP path
	// to the relay passes a probe.
	TransportAuto TransportMode = iota
	// TransportQUIC always sends QUIC data frames on the relay session.
	TransportQUIC
)

type Config struct {
	// Identity keeps the agent cert and the relays from enroll. Run starts it.
	Identity *identity.Manager
	// Relays are the relays to dial, in place of the relays of the agent cert.
	// The agent attaches to the relays with the lowest round-trip times.
	Relays []identity.Relay
	// RelayRoots check relay certs and peer grants, in place of the roots of
	// the agent cert. With neither, the agent uses the system roots.
	RelayRoots *x509.CertPool
	// Sessions is the number of attached relay sessions to keep, 1 to 3, each on
	// its own relay. Each session has its own overlay address. Zero means 2.
	Sessions int
	// Transport is the agent socket. New sets its packet handlers, so it must
	// not be in use yet, and its port must not have an XDP program.
	Transport *quic.Transport
	// TransportMode picks how data goes to peers. The zero value is auto.
	TransportMode TransportMode
	// Name, labels and advertised routes of the attachment.
	Name   string
	Labels map[string]string
	Routes []netip.Prefix
	// OnAttach gets the binding, and the overlay address and the prefixes of a
	// relay session after it attaches: the agent has one more address.
	OnAttach func(b *psp.Binding, addr netip.Addr, prefixes []netip.Prefix)
	// OnRoutes gets the changes to the prefixes of the other attachments in
	// the VPC, after OnAttach. The agent calls it from one goroutine at a time.
	OnRoutes func(add, remove []netip.Prefix)
	// OnAttachment gets an extra attachment after it attaches on a relay
	// session: one call for each session.
	OnAttachment func(at Attachment)
	// OnDeprecated gets each attachment of a relay session that is not the
	// attached session with the lowest rank, for example one whose relay drains,
	// the attachment of Config too. New connections must not use its address.
	OnDeprecated func(at Attachment)
	// OnPreferred gets each attachment of OnDeprecated whose session became the
	// attached session with the lowest rank. New connections use its address again.
	OnPreferred func(at Attachment)
	// OnDetach gets each attachment whose address the agent lost, before a next OnAttach of that
	// address. The callbacks run in order, one at a time, and must not call Attach, Detach or Attachments.
	OnDetach func(at Attachment)
	// MTU sets the device MTU, from 1280 to the VPC MTU. Zero means the VPC MTU.
	// A PSP path that does not carry the device MTU gets a TCP MSS clamp.
	MTU int
	// LocalRoutesOnly asks each relay for the routes of its own attachments
	// only. A host with one agent for each relay sets it.
	LocalRoutesOnly bool
}

// Agent keeps attached relay sessions for one VPC, and runs the peer sessions
// on them.
type Agent struct {
	cfg      Config
	ver      *dp.Version // Protocol version of the agent. Nil is revision 0. Tests change it.
	instance uint64
	seed     maphash.Seed // Orders the relays of this agent.
	mux      *rpc.Mux     // Peer service.
	demux    psp.Demux
	starts   starts
	bfd      chan bfdIn    // BFD packets of the peer paths. readBFD reads them.
	quicCfg  *quic.Config  // relayQUIC with the loss tracer.
	quicLost atomic.Uint64 // 1-RTT packets that relay connections lost.
	// wake gets a value when a relay session ends or starts to drain. Run reads it.
	wake chan struct{}
	// expired is set when the cert of the identity file expired.
	expired atomic.Pointer[identity.ExpiredError]
	// watchers has the goroutines that follow the attached sessions. Run waits
	// for them.
	watchers sync.WaitGroup

	probeMu sync.Mutex
	probes  map[[8]byte]probeTaker // Path probes that run and PSP path checks, by SID.

	// admitMu orders the admits, so that a second session of a peer sees the
	// first as old.
	admitMu sync.Mutex

	// cbMu runs the callbacks in events one at a time.
	cbMu sync.Mutex
	// attMu guards specs and events. The writers of relayConn.extras hold it.
	attMu      sync.Mutex
	specs      map[string]*AttachmentSpec // Extra attachments to keep, by name.
	events     []func()                   // Callbacks that wait to run, in order.
	attachWake chan struct{}

	// Lock order: cbMu, then attMu or admitMu, then routeMu, then mu.
	// starts.mu is never held with another lock.
	mu sync.Mutex
	// conns has each relay session from its dial until it ends, in dial order:
	// the sessions with the attachments, and the visitor sessions.
	conns    []*relayConn
	stopped  bool // Run ended.
	bind     *psp.Binding
	peers    map[*rpc.Conn]*peer
	admitted chan struct{} // Closed and replaced when a peer session opens or gets grants.

	// visits has the visitor sessions, by relay key. Guarded by mu.
	visits map[string]*visit
	// Intervals of the visits. Tests change them before Run.
	visitCheck, visitAsk, visitWait time.Duration
	// The times of the PSP probes, from the package values at New.
	retryMin, retryMax, retryNext time.Duration
	// Band and wait of the relay choice. Tests change them before Run.
	rttBand, rttWaitMin, rttWaitMax time.Duration

	routeMu  sync.Mutex
	routesOf *relayConn            // Session that OnRoutes follows: the last primary session.
	reported map[netip.Prefix]bool // Prefixes that OnRoutes has.
}

// New returns an agent. Call Run to start it.
func New(cfg Config) *Agent {
	a := &Agent{
		cfg:      cfg,
		ver:      dp.LocalVersion(build.BuildVersion),
		instance: rand.Uint64(),
		seed:     maphash.MakeSeed(),
		wake:     make(chan struct{}, 1),
		bfd:      make(chan bfdIn, bfdQueue),
		probes:   map[[8]byte]probeTaker{},
		peers:    map[*rpc.Conn]*peer{},
		visits:   map[string]*visit{},
		admitted: make(chan struct{}),
	}
	a.specs, a.attachWake = map[string]*AttachmentSpec{}, make(chan struct{}, 1)
	a.visitCheck, a.visitAsk, a.visitWait = visitCheck, visitAsk, visitWait
	a.retryMin, a.retryMax, a.retryNext = pspRetryMin, pspRetryMax, pspRetryNext
	a.rttBand, a.rttWaitMin, a.rttWaitMax = rttBand, rttWaitMin, rttWaitMax
	a.mux = rpc.NewMux()
	dp.RegisterPeerServer(a.mux, &peerService{a: a})
	a.demux.Probe = a.onProbe
	a.quicCfg = relayQUIC.Clone()
	a.quicCfg.Tracer = a.traceLoss
	if cfg.Transport != nil {
		cfg.Transport.NonQUICPacketHandler = a.demux.Handle
		cfg.Transport.NonQUICBatchEnd = a.demux.BatchEnd
		// GRO joins the PSP packets of one read, so the read loop makes fewer syscalls.
		cfg.Transport.EnableGRO = true
	}
	return a
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

// DNS returns the DNS servers and search domains of the VPC.
func (a *Agent) DNS() (servers, search []string) {
	rc := a.primary()
	if rc == nil {
		return nil, nil
	}
	return rc.dnsServers, rc.dnsSearch
}

// Status is the data transport of the agent. The fields of one session are
// those of the session with the lowest rank that does not drain.
type Status struct {
	Mode   dp.Mode           // Unspecified before the first attach.
	Reason dp.FallbackReason // Why Mode is QUIC.
	// Time to connect: from the start of the dial to the first Config.
	Connect time.Duration
	// Time from the start of the connect to the end of the attach.
	Setup time.Duration
	// Open peer sessions on all relay sessions.
	Peers int
	// Smoothed round-trip time to the relay. Zero before the first sample
	// and after the relay session ends.
	RTT time.Duration
	// Connections has the attached and the draining relay sessions, in rank order.
	Connections []ConnStatus
}

// ConnStatus is one relay session of the agent with its address.
type ConnStatus struct {
	Relay   string     // Address of the relay.
	Address netip.Addr // Overlay address of the agent on this session.
	Rank    uint32     // The relays and the agent prefer the lowest rank.
	// Draining is true after the relay started to drain: the address is not
	// preferred, and the session ends when the relay closes it.
	Draining bool
	Mode     dp.Mode
	Reason   dp.FallbackReason // Why Mode is QUIC.
	RTT      time.Duration     // Smoothed round-trip time to the relay.
	Peers    int               // Open peer sessions on this session.
}

// Status returns the data transport of the agent.
func (a *Agent) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	var st Status
	if rc := a.primaryLocked(); rc != nil {
		st = Status{Mode: rc.dataMode(), Reason: rc.fallback(), Connect: rc.connect, Setup: rc.setup, RTT: rc.liveRTT()}
	}
	for _, rc := range a.sessionsLocked(connAttached, connDraining) {
		c := ConnStatus{
			Relay: rc.addr, Address: rc.self, Rank: rc.rank, Draining: rc.state == connDraining,
			Mode: rc.dataMode(), Reason: rc.fallback(), RTT: rc.liveRTT(),
		}
		for _, p := range a.peers {
			if p.rc == rc && p.bp != nil && p.qc.Context().Err() == nil {
				c.Peers++
			}
		}
		st.Peers += c.Peers
		st.Connections = append(st.Connections, c)
	}
	return st
}

// liveRTT returns the smoothed round-trip time of rc, or zero after rc ended.
func (rc *relayConn) liveRTT() time.Duration {
	if rc.ended() {
		return 0
	}
	return time.Duration(rc.rtt.Load())
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

// open runs the handshake with the relay of rc and the Session call up to
// Config. Then it starts the first PSP probe, which runs while the relay attaches.
func (rc *relayConn) open(ctx context.Context) error {
	a := rc.a
	ua, err := net.ResolveUDPAddr("udp", rc.addr)
	if err != nil {
		return err
	}
	begin := time.Now()
	ctx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	// The dial stops when the agent stops.
	defer context.AfterFunc(rc.ctx, cancel)()
	quicCfg := a.quicCfg.Clone()
	quicCfg.Tracer = a.traceSession(rc.rtt, &rc.lowRTT)
	qc, err := a.cfg.Transport.Dial(ctx, ua, &tls.Config{
		MinVersion:           tls.VersionTLS13,
		RootCAs:              rc.roots,
		ServerName:           rc.name,
		NextProtos:           []string{dp.ALPNRelay},
		GetClientCertificate: a.cfg.Identity.GetClientCertificate,
	}, quicCfg)
	if err != nil {
		return err
	}
	a.mu.Lock()
	rc.qc = qc
	a.mu.Unlock()
	rc.c = dp.NewRelayClient(rpc.NewConn(qc, nil))
	// A relay that does not answer in time ends the dial.
	defer context.AfterFunc(ctx, func() { _ = qc.CloseWithError(0, "relay session did not open in time") })()
	rc.mode.Store(int32(dp.Mode_MODE_QUIC))
	if !rc.wantsPSP() {
		rc.reason.Store(int32(dp.FallbackReason_FALLBACK_REASON_CONFIG))
	}
	if err := rc.hello(begin); err != nil {
		if cause := context.Cause(qc.Context()); cause != nil {
			err = fmt.Errorf("%w (connection: %w)", err, cause)
		}
		return relayUpgrade(rc.addr, err)
	}
	if rc.wantsPSP() {
		rc.first = rc.probe(rc.ctx, a.changeMTU(rc))
	}
	return nil
}

// relayRoots returns Config.RelayRoots, else the relay roots of cred. Nil
// means the system roots.
func (a *Agent) relayRoots(cred *identity.Credential) *x509.CertPool {
	if a.cfg.RelayRoots != nil {
		return a.cfg.RelayRoots
	}
	return cred.RelayPool()
}

// hello runs the Session call of rc up to Config and starts its Sync reader.
// The dial started at begin.
func (rc *relayConn) hello(begin time.Time) error {
	st, err := rc.c.Session(rc.ctx)
	if err != nil {
		return err
	}
	rc.st = st
	sent := time.Now()
	if err := st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{
		Mode: rc.wantedMode(), FallbackReason: rc.fallback(), Version: rc.a.ver, Name: rc.a.cfg.Name,
		// The relay tells two processes with one identity and one name apart by the instance.
		Instance: rc.a.instance,
		// A relay takes a Visit call only on a session with local routes.
		LocalRoutesOnly: rc.a.cfg.LocalRoutesOnly || rc.visitor(),
	}}}); err != nil {
		return err
	}
	m, err := st.Recv()
	if err != nil {
		return err
	}
	rc.helloRTT.Store(int64(time.Since(sent)))
	w := m.GetWelcome()
	if w == nil {
		return fmt.Errorf("relay sent %T before Welcome", m.GetMsg())
	}
	if rc.relayAddr, err = pspAddr(w, rc.qc.RemoteAddr().(*net.UDPAddr).AddrPort().Addr()); err != nil {
		return err
	}
	rc.maxLanes = w.GetMaxLanes()
	rc.version = w.GetVersion()
	// The dial fails for a relay that is too old, so the agent dials the next relay.
	if got, least := rc.version.GetRevision(), rc.a.ver.GetMinRevision(); got < least {
		return fmt.Errorf("relay revision %d is below the agent minimum %d", got, least)
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
	rc.vpcConfig, rc.ref, rc.mtu = cfg, cfg.GetVpc(), cfg.GetMtu()
	rc.dnsServers, rc.dnsSearch = cfg.GetDnsServers(), cfg.GetDnsSearchDomains()
	go rc.sync()
	return nil
}

// attach runs Attach on rc after hello, then makes the link of rc in the
// binding, the peer listener and the QUIC shards. The connect started at begin.
func (rc *relayConn) attach(ctx context.Context, begin time.Time) error {
	a := rc.a
	ctx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	// A relay that does not answer in time ends the attach.
	stop := context.AfterFunc(ctx, func() { _ = rc.qc.CloseWithError(0, "relay session did not attach in time") })
	defer stop()
	res, err := rc.c.Attach(ctx, &dp.AttachRequest{
		Vpc: rc.ref, Name: a.cfg.Name, Labels: a.cfg.Labels, Routes: prefixStrings(a.cfg.Routes), Rank: rc.rank,
	})
	if err != nil {
		return attachError(rc, fmt.Errorf("attach: %w", err))
	}
	rc.logRefused(a.cfg.Name, res.GetRoutes())
	// A bad relay cert fails the attach, not each peer session.
	if rc.claims, err = rc.verifyOwn(res.GetGrant()); err != nil {
		return relayUpgrade(rc.addr, err)
	}
	rc.grant = newOwnGrant(rc, res.GetGrant(), rc.claims.GetAttachmentId())
	prefixes, err := parsePrefixes(rc.claims.GetAddresses())
	if err != nil {
		return err
	}
	a.setAttachment(rc, rc.claims.GetAttachmentId(), prefixes)
	b, err := a.binding(rc.vpcConfig)
	if err != nil {
		return err
	}
	l, err := b.AddLink()
	if err != nil {
		return err
	}
	a.mu.Lock()
	rc.link = l
	a.mu.Unlock()
	// The packets from the addresses of rc go on rc.
	for _, pfx := range prefixes {
		if err := l.AddSource(pfx); err != nil {
			return fmt.Errorf("source %s: %w", pfx, err)
		}
	}
	p, err := l.AddRelay(rc.relayAddr)
	if err != nil {
		return err
	}
	rc.setRelayPeer(p)
	// The packets with no route to a peer that is up go to the relay.
	for _, pfx := range defaultRoutes {
		if err := b.AddRoute(pfx, p); err != nil {
			return fmt.Errorf("default route %s: %w", pfx, err)
		}
	}
	rc.pc = peerconn.New(rc.qc, rc.self)
	rc.pc.HandleData(l.HandleData)
	// A session in QUIC mode sends to its relay in data frames.
	if err := p.UseQUIC(rc.pc); err != nil {
		return err
	}
	rc.peerTr = &quic.Transport{Conn: rc.pc}
	ln, err := rc.peerTr.Listen(a.peerTLS(), peerQUIC)
	if err != nil {
		return err
	}
	go rc.accept(ln)
	// Data frames need no SAs. The relay gets the SAs when the PSP path passes.
	var shards context.Context
	shards, rc.stopShards = context.WithCancel(rc.ctx)
	go rc.keepShards(shards, quicShards)
	rc.setup = time.Since(begin)
	return nil
}

// registerLanes registers the lane ports of b at the relay. It does nothing
// when the relay takes none or sees another port than the local one.
func (rc *relayConn) registerLanes(ctx context.Context, b *psp.Binding) {
	n := min(int(rc.maxLanes)+1, txLanes(rc.relayAddr.Addr().Unmap()))
	seen := rc.seen.Load()
	if n < 2 || seen == nil || seen.Port() != rc.a.localPort() {
		return
	}
	ports := b.OpenLanes(n)
	if len(ports) == 0 {
		return
	}
	req := &dp.RegisterLanesRequest{Ports: make([]uint32, len(ports)), Receive: true}
	for i, p := range ports {
		req.Ports[i] = uint32(p)
	}
	if err := b.ReadLanes(); err != nil {
		slog.Warn("Failed to read the lane sockets; the relay sends on one port", "relay", rc.addr, "error", err)
		req.Receive = false
	}
	if _, err := rc.c.RegisterLanes(ctx, req); err != nil {
		slog.Info("Relay refused the lane ports; peers send on one port", "relay", rc.addr, "error", err)
		return
	}
	rc.lanes.Store(int32(len(ports) + 1))
	slog.Debug("Relay took the lane ports", "relay", rc.addr, "ports", ports, "receive", req.Receive)
	if req.Receive {
		b.KeepLanes(rc.relayAddr)
		go rc.keepLanes(b)
	}
}

// localPort returns the port of the agent socket.
func (a *Agent) localPort() uint16 {
	if ua, ok := a.cfg.Transport.Conn.LocalAddr().(*net.UDPAddr); ok {
		return uint16(ua.Port)
	}
	return 0
}

// stopLanes makes the peers of rc send from one socket, after the relay dropped
// the lane ports of rc.
func (a *Agent) stopLanes(rc *relayConn) {
	if rc.lanes.Swap(1) < 2 {
		return
	}
	slog.Info("Relay sees a new address of the agent; peers send on one port", "relay", rc.addr)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.peers {
		if p.rc == rc && p.bp != nil {
			p.bp.SetLaneSockets(1)
		}
	}
}

// keepLanes sends lane keepalives to the relay at the keepalive period of the
// relay session, until rc ends or stops its lanes.
func (rc *relayConn) keepLanes(b *psp.Binding) {
	t := time.NewTicker(relayQUIC.KeepAlivePeriod)
	defer t.Stop()
	for {
		select {
		case <-rc.ctx.Done():
			return
		case <-rc.qc.Context().Done():
			return
		case <-t.C:
			if rc.lanes.Load() < 2 {
				return
			}
			b.KeepLanes(rc.relayAddr)
		}
	}
}

// logRefused logs the advertised routes of the attachment name that the relay
// refused. The attachment works without them.
func (rc *relayConn) logRefused(name string, routes []*dp.RouteStatus) {
	for _, r := range routes {
		if r.GetResult() != dp.RouteResult_ROUTE_RESULT_ACCEPTED {
			slog.Warn("Relay refused an advertised route", "relay", rc.addr, "name", name, "route", r.GetPrefix(), "result", r.GetResult())
		}
	}
}

// sendLanes returns the send lanes of rc: 1 when the relay took no lane ports.
func (rc *relayConn) sendLanes() uint32 {
	return uint32(max(rc.lanes.Load(), 1))
}

// attachError adds the close cause of rc to err.
func attachError(rc *relayConn, err error) error {
	if cause := context.Cause(rc.qc.Context()); cause != nil {
		return fmt.Errorf("%w (connection: %w)", err, cause)
	}
	return err
}

// deviceMTU returns the device MTU of the binding, or the one that the binding
// gets for a VPC MTU. a.mu is held.
func (a *Agent) deviceMTU(vpcMTU int) int {
	if a.bind != nil {
		return a.bind.DeviceMTU()
	}
	if vpcMTU == 0 {
		vpcMTU = psp.DefaultMTU
	}
	if a.cfg.MTU != 0 {
		return min(a.cfg.MTU, vpcMTU)
	}
	return vpcMTU
}

// binding returns the PSP binding of the VPC. The first attach makes it.
func (a *Agent) binding(cfg *dp.Config) (*psp.Binding, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.bind != nil {
		return a.bind, nil
	}
	mtu := int(cfg.GetMtu())
	if mtu == 0 {
		mtu = psp.DefaultMTU
	}
	dev := a.deviceMTU(mtu)
	b, err := psp.New(psp.Config{
		Transport: a.cfg.Transport, Demux: &a.demux, VNI: cfg.GetVpc().GetNetworkId(), MTU: mtu, DeviceMTU: dev,
		NoPeer: a.onNoPeer,
		OnBFD:  a.onBFD,
		OnTrip: a.onTrip,
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
			rc.a.noRoute(rc, m.NoRoute)
		case *dp.SessionResponse_Drain:
			select {
			case rc.drained <- m.Drain.GetAlternates():
			default:
			}
		case *dp.SessionResponse_Rekey:
			rc.relayKeys(m.Rekey)
		case *dp.SessionResponse_RxReport:
			rc.relayReport(m.RxReport)
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

// relayKeys applies relay SAs. They come only after the Rekey of this agent,
// which is after the attach.
func (rc *relayConn) relayKeys(m *dp.KeysRequest) {
	rc.keyMu.Lock()
	defer rc.keyMu.Unlock()
	if rc.relay != nil {
		rc.applyRelayKeys(m)
	}
}

// relayReport gives the receive counters of the relay to the breaker of the
// relay peer. Before the attach, it drops them.
func (rc *relayConn) relayReport(m *dp.RxReport) {
	rc.keyMu.Lock()
	p := rc.relay
	rc.keyMu.Unlock()
	if p != nil {
		p.Report(time.Now(), fromReport(m))
	}
}

// setRelayPeer sets the relay peer.
func (rc *relayConn) setRelayPeer(p *psp.Peer) {
	rc.keyMu.Lock()
	defer rc.keyMu.Unlock()
	rc.relay = p
}

// applyRelayKeys applies the relay SAs to the transmit SAs of the relay peer.
// rc.keyMu is held.
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
	// rc.keyMu orders the close.
	select {
	case <-rc.bridgeTx:
	default:
		close(rc.bridgeTx)
	}
}

// giveRelayKeys gives the relay the SAs for bridged packets to this agent. It
// reports whether the relay took them.
func (rc *relayConn) giveRelayKeys() bool {
	req, err := rc.relay.Offer(time.Now())
	if err != nil {
		if !rc.ended() {
			slog.Warn("Failed to create receive SAs for the relay", "relay", rc.addr, "error", err)
		}
		return false
	}
	if !rc.sendRelayKeys(req) {
		return false
	}
	// A mode change that failed after this point gives the SAs again.
	rc.keyMu.Lock()
	defer rc.keyMu.Unlock()
	select {
	case <-rc.bridgeRx:
	default:
		close(rc.bridgeRx)
	}
	return true
}

// bridge returns bridgeTx and bridgeRx of rc.
func (rc *relayConn) bridge() (tx, rx chan struct{}) {
	rc.keyMu.Lock()
	defer rc.keyMu.Unlock()
	return rc.bridgeTx, rc.bridgeRx
}

// resetBridge makes bridgeTx and bridgeRx wait for the SAs of the next change
// to PSP mode.
func (rc *relayConn) resetBridge() {
	rc.keyMu.Lock()
	defer rc.keyMu.Unlock()
	rc.bridgeTx, rc.bridgeRx = make(chan struct{}), make(chan struct{})
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

// removeRoutes closes the peer sessions of attachments that left the VPC. When
// another attachment of a peer leaves, only its grant goes.
func (a *Agent) removeRoutes(rc *relayConn, removed []*dp.Route) {
	gone := map[string]bool{}
	var prefixes []netip.Prefix
	for _, r := range removed {
		gone[r.GetOrigin()] = true
		if pfx, err := netip.ParsePrefix(r.GetPrefix()); err == nil {
			prefixes = append(prefixes, pfx.Masked())
		}
	}
	a.closePeers(func(p *peer) bool { return p.rc == rc && gone[p.attachmentID()] }, "peer left the VPC")
	// The relay drops the packets to an address that left, so the peer gets no
	// more packets on such a session.
	a.closePeers(func(p *peer) bool {
		return p.rc == rc && slices.ContainsFunc(prefixes, func(pfx netip.Prefix) bool { return pfx.Contains(p.dst) })
	}, "dialed address left the VPC")
	a.routeMu.Lock()
	defer a.routeMu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.peers {
		if p.rc != rc || len(p.extra) == 0 {
			continue
		}
		for _, r := range removed {
			pfx, err := netip.ParsePrefix(r.GetPrefix())
			if err == nil && slices.Contains(p.extra[r.GetOrigin()], pfx.Masked()) {
				a.dropGrant(p, r.GetOrigin())
			}
		}
	}
}

// close closes the connection of rc, its peer sessions, its peer transport and
// its link. Only Agent.end calls it.
func (rc *relayConn) close() {
	rc.a.closePeers(func(p *peer) bool { return p.rc == rc }, "relay session closed")
	// The connection closes before its calls stop. A Session call that stops
	// first makes the relay close the connection with an error.
	if rc.qc != nil {
		_ = rc.qc.CloseWithError(0, "")
	}
	rc.cancel()
	if rc.relay != nil {
		rc.a.bind.RemovePeer(rc.relay)
	}
	if rc.peerTr != nil {
		// Close the packet connection first to end the transport read loop.
		_ = rc.pc.Close()
		_ = rc.peerTr.Close()
	}
	if rc.link != nil && !rc.visitor() {
		rc.a.bind.RemoveLink(rc.link)
	}
}

// close ends the relay sessions and the binding at the end of Run. The
// goroutine that dials a session ends it, so close only stops the dial.
func (a *Agent) close() {
	a.mu.Lock()
	a.stopped = true
	b := a.bind
	var dialing, open []*relayConn
	for _, rc := range a.conns {
		if rc.state == connDialing {
			dialing = append(dialing, rc)
		} else {
			open = append(open, rc)
		}
	}
	a.mu.Unlock()
	for _, rc := range dialing {
		rc.cancel()
	}
	for _, rc := range open {
		a.end(rc)
	}
	if b != nil {
		_ = b.Close()
	}
}

// tick runs the timers of the binding and the starts, checks the local address,
// refreshes SPI rows and gives the QUIC loss to the breaker.
func (a *Agent) tick(ctx context.Context) {
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	refresh := time.NewTicker(spiRefresh)
	defer refresh.Stop()
	report := time.NewTicker(reportInterval)
	defer report.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-report.C:
			a.mu.Lock()
			b := a.bind
			a.mu.Unlock()
			if b != nil {
				b.ReportQUIC(now, a.quicLost.Load())
			}
		case now := <-t.C:
			a.starts.sweep(now)
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
					go p.rekey(u.Request)
				} else if rc := a.relayOfBinding(u.Peer); rc != nil && rc.dataMode() == dp.Mode_MODE_PSP {
					// A Rekey call changes a session in QUIC mode, so only usePSP makes it there.
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

// relayOfBinding returns the attached session or the visitor session that
// has bp as its relay peer.
func (a *Agent) relayOfBinding(bp *psp.Peer) *relayConn {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, rc := range a.conns {
		if rc.state != connDialing && rc.relay == bp {
			return rc
		}
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

// overlayAddr is the address of the agent in the first prefix.
func overlayAddr(prefixes []netip.Prefix) netip.Addr {
	return relay.OverlayAddr(prefixes[0])
}
