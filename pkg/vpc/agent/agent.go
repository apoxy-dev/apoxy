// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"crypto/x509"
	"errors"
	"fmt"
	"hash/maphash"
	"math/rand/v2"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/build"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
	// After a session of this age, the next reconnect starts at minBackoff.
	stableSession = time.Minute
	openTimeout   = 10 * time.Second
	tickInterval  = time.Second
	// keysTimeout limits one change to PSP mode, from the Rekey call to the
	// SAs of the relay.
	keysTimeout = 10 * time.Second
	// maxRefusals is the most Rekey calls of one key change whose SPIs the
	// relay refuses.
	maxRefusals = 3
	// pspPasses is the number of PSP probes in a row that must pass, after a
	// probe that failed, before the agent changes from QUIC mode to PSP mode.
	pspPasses = 2
	// In QUIC mode after a failed probe, the agent probes PSP again with backoff.
	defaultPSPRetryMin  = 30 * time.Second
	defaultPSPRetryMax  = 10 * time.Minute
	defaultPSPRetryNext = 5 * time.Second // From a probe that passes to the next probe.
	// closeWrites is the time that the writes on the agent socket have at the
	// end of Run, so that a blocked write or close ends.
	closeWrites = time.Second
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
	// The tunneled flows control congestion; a second control under them only slows them.
	DisableCongestionControl: true,
}

var errNoRelay = errors.New("no relay session")

// TransportMode picks how an agent sends data.
type TransportMode int

const (
	// TransportAuto sends QUIC data frames at first, and PSP after the PSP path
	// to the relay passes a probe.
	TransportAuto TransportMode = iota
	// TransportQUIC always sends QUIC data frames on the relay session. Only
	// tests and benches use it.
	TransportQUIC
)

type Config struct {
	// Identity keeps the agent cert and the relays from enroll. Run starts it.
	Identity *identity.Manager
	// Relays are the relays to dial, in place of the relays of the agent cert.
	// The agent attaches to the relays with the lowest round-trip times.
	Relays []identity.Relay
	// RelayRoots check relay certs, in place of the roots of the
	// agent cert. With neither, the agent uses the system roots.
	RelayRoots *x509.CertPool
	// Sessions is the number of attached relay sessions to keep on the relays of
	// Relays or of the agent cert, 1 to 3, each on its own relay. Each session
	// has its own overlay address. Zero means 2. The agent also keeps a session
	// on each other relay that a route of its lowest-rank session names.
	Sessions int
	// Transport is the agent socket. New sets its packet handlers, so it must
	// not be in use yet, and its port must not have an XDP program. At the end
	// of Run the agent sets a write deadline on its Conn.
	Transport *quic.Transport
	// TransportMode picks how data goes to the relays. The zero value is auto.
	// Only tests and benches set it; the CLI always uses TransportAuto.
	TransportMode TransportMode
	// Name and labels of the attachment.
	Name   string
	Labels map[string]string
	// Routes are the prefixes of the attachment. The agent advertises the IPv6
	// prefixes and does not send an IPv4 prefix; a netstack host dials the IPv4
	// addresses of an IPv4 prefix for its /96.
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
	// address. The callbacks run in order, one at a time, and must not call Attach or Detach.
	OnDetach func(at Attachment)
	// MTU sets the device MTU, from 1280 to the VPC MTU. Zero means the VPC MTU.
	// A PSP path that does not carry the device MTU gets a TCP MSS clamp.
	MTU int
	// LocalRoutesOnly asks each relay for the routes of its own attachments
	// only. A host with one agent for each relay sets it.
	LocalRoutesOnly bool
	// PSPRetryMin and PSPRetryMax are the first and the longest wait for the
	// next PSP probe after a probe or a change to PSP mode failed. PSPRetryNext
	// is the wait from a probe that passed to the next one. Zero means 30 s,
	// 10 min and 5 s.
	PSPRetryMin, PSPRetryMax, PSPRetryNext time.Duration
	// RelistMin is the wait for a new relay list after all relays failed, and
	// RelistMax its longest wait after failed tries. Zero means 1 min and 10 min.
	RelistMin, RelistMax time.Duration
	// RTTBand is the difference of two relay round-trip times that counts as
	// equal. RTTWaitMin and RTTWaitMax limit the wait for the other relays
	// after the first answer. Zero means 10 ms, 20 ms and 40 ms.
	RTTBand, RTTWaitMin, RTTWaitMax time.Duration
	// Lanes is the number of send lanes to a relay. Zero means the queue
	// count of the link to the relay.
	Lanes int
}

// Agent keeps attached relay sessions for one VPC. Run starts its processes;
// the public calls read a snapshot or send a request to the root process.
type Agent struct {
	cfg      Config
	ver      *dp.Version // Protocol version of the agent.
	instance uint64
	seed     maphash.Seed // Orders the relays of this agent.
	demux    psp.Demux
	quicCfg  *quic.Config // Config of the relay connections.
	quicLost lossCount    // Packets that relay connections lost.
	probes   probeRegistry

	retryMin, retryMax, retryNext   time.Duration
	relistMin, relistMax            time.Duration
	rttBand, rttWaitMin, rttWaitMax time.Duration

	snap atomic.Pointer[snapshot]
	run  atomic.Pointer[runRef] // The root of the Run that runs, or nil.
}

// runRef is how the public calls reach the root of one Run.
type runRef struct {
	mb      *mailbox
	stopped chan struct{} // Closed when Run returns.
}

// New returns an agent. Call Run to start it.
func New(cfg Config) *Agent {
	a := &Agent{
		cfg:      cfg,
		ver:      dp.LocalVersion(build.BuildVersion),
		instance: rand.Uint64(),
		seed:     maphash.MakeSeed(),
	}
	a.retryMin = cmp.Or(cfg.PSPRetryMin, defaultPSPRetryMin)
	a.retryMax = cmp.Or(cfg.PSPRetryMax, defaultPSPRetryMax)
	a.retryNext = cmp.Or(cfg.PSPRetryNext, defaultPSPRetryNext)
	a.relistMin = cmp.Or(cfg.RelistMin, defaultRelistMin)
	a.relistMax = cmp.Or(cfg.RelistMax, defaultRelistMax)
	a.rttBand = cmp.Or(cfg.RTTBand, defaultRTTBand)
	a.rttWaitMin = cmp.Or(cfg.RTTWaitMin, defaultRTTWaitMin)
	a.rttWaitMax = cmp.Or(cfg.RTTWaitMax, defaultRTTWaitMax)
	a.demux.Probe = a.probes.take
	a.quicCfg = relayQUIC.Clone()
	if cfg.Transport != nil {
		cfg.Transport.NonQUICPacketHandler = a.demux.Handle
		cfg.Transport.NonQUICBatchEnd = a.demux.BatchEnd
		// GRO joins the PSP packets of one read, so the read loop makes fewer syscalls.
		cfg.Transport.EnableGRO = true
	}
	a.snap.Store(&snapshot{})
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
	c := a.snap.Load().primary()
	if c == nil {
		return nil, nil
	}
	return c.dnsServers, c.dnsSearch
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
}

// Status returns the data transport of the agent.
func (a *Agent) Status() Status {
	s := a.snap.Load()
	var st Status
	if c := s.primary(); c != nil {
		st = Status{Mode: c.mode, Reason: c.reason, Connect: c.connect, Setup: c.setup, RTT: c.liveRTT()}
	}
	for _, c := range s.conns {
		st.Connections = append(st.Connections, ConnStatus{
			Relay: c.relay, Address: c.base.Address, Rank: c.rank, Draining: c.draining,
			Mode: c.mode, Reason: c.reason, RTT: c.liveRTT(),
		})
	}
	return st
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

// relayRoots returns Config.RelayRoots, else the relay roots of cred. Nil
// means the system roots.
func (a *Agent) relayRoots(cred *identity.Credential) *x509.CertPool {
	if a.cfg.RelayRoots != nil {
		return a.cfg.RelayRoots
	}
	return cred.RelayPool()
}

// deviceMTU returns the device MTU that a binding gets for the VPC MTU vpcMTU.
func (a *Agent) deviceMTU(vpcMTU int) int {
	if vpcMTU == 0 {
		vpcMTU = psp.DefaultMTU
	}
	if a.cfg.MTU != 0 {
		return min(a.cfg.MTU, vpcMTU)
	}
	return vpcMTU
}

// wantsPSP reports whether a session changes to PSP mode when its PSP path passes.
func (a *Agent) wantsPSP() bool { return a.cfg.TransportMode != TransportQUIC }

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

func parsePrefixes(ss []string) ([]netip.Prefix, error) {
	if len(ss) == 0 {
		return nil, errors.New("attachment has no addresses")
	}
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("attachment address: %w", err)
		}
		out[i] = p.Masked()
	}
	return out, nil
}

// overlayAddr is the address of the agent in the first prefix.
func overlayAddr(prefixes []netip.Prefix) netip.Addr {
	return relay.OverlayAddr(prefixes[0])
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}
