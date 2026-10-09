// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	"github.com/quic-go/quic-go"
	"golang.org/x/time/rate"

	"github.com/apoxy-dev/apoxy/build"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// rowIdle is the time with no traffic after which a row is removed.
	rowIdle = 5 * time.Minute
	// rebindOverlap is the time that the previous source address of a sender
	// stays valid after its connection migrates.
	rebindOverlap = 5 * time.Second
	sweepInterval = time.Second
	minBurst      = 64 << 10
	// MaxLaneSources is the most lane ports of a session: lanes 1 and up.
	MaxLaneSources = keys.MaxLanes - 1
)

// VPCKey is the key of a routing domain: one VPC of one project. The VPC
// name and the network ID are not part of it.
type VPCKey struct {
	Project string
	UID     string
}

// KeyOf returns the key of ref.
func KeyOf(ref *dp.VPCRef) (VPCKey, error) {
	if ref.GetProjectId() == "" || ref.GetVpcUid() == "" {
		return VPCKey{}, rpc.Errorf(rpc.InvalidArgument, "vpc needs project_id and vpc_uid")
	}
	return VPCKey{Project: ref.GetProjectId(), UID: ref.GetVpcUid()}, nil
}

// Identity is the authenticated identity of a relay session.
type Identity struct {
	VPC VPCKey
	// ID is the SPIFFE ID in the agent certificate.
	ID string
}

// Permit tells if a sender in srcVPC with identity srcID can reach dst in dstVPC.
type Permit func(srcVPC VPCKey, srcID string, dstVPC VPCKey, dst netip.Addr) bool

// SameVPC is the MVP Permit rule: the source and the destination are in one VPC.
func SameVPC(srcVPC VPCKey, _ string, dstVPC VPCKey, _ netip.Addr) bool { return srcVPC == dstVPC }

// Config sets the meter of each lane (SPI row), the limit of each tunnel and
// the lane ports.
type Config struct {
	// LaneRate is the meter rate in bytes per second. Zero means no limit.
	LaneRate float64
	// LaneBurst is the meter burst in bytes. Zero means 100 ms of LaneRate.
	// It is at least 64 KiB.
	LaneBurst int
	// TunnelRate limits all data that one agent session sends through the
	// relay, in bytes per second. Zero means no limit.
	TunnelRate float64
	// TunnelBurst is the burst of the tunnel limit in bytes. Zero means 100 ms
	// of TunnelRate. It is at least 64 KiB.
	TunnelBurst int
	// LaneSources is the most lane ports that a session can register, at most
	// MaxLaneSources. Zero turns lane ports off. Set it only when all flows
	// from an agent address come to this relay.
	LaneSources int
}

// Verdict is the result of a forward lookup.
type Verdict uint8

const (
	// Pass sends the packet to the returned address.
	Pass Verdict = iota
	// DropUnknownSource drops a packet from an address of no sender.
	DropUnknownSource
	// DropUnknownSPI drops a packet with an SPI that the sender did not register.
	DropUnknownSPI
	// DropMeter drops a packet above the meter of its lane.
	DropMeter
	// DropTunnelLimit drops a packet above the limit of the sender's tunnel.
	DropTunnelLimit
	// DropTrunkMTU drops a packet for another relay that is too large for the
	// trunk to that relay.
	DropTrunkMTU
	// DropTrunkKeys drops a packet for another relay when the relay has no trunk
	// to it now, or no SA of it for a clear packet.
	DropTrunkKeys
)

// Router holds the routing domains, sessions and SPI rows of one relay.
type Router struct {
	cfg    Config
	trust  Trust
	ver    *dp.Version // Protocol version of the relay. Nil is revision 0.
	drops  [numDropReasons]atomic.Uint64
	sends  sendStats
	early  earlyList
	bridge atomic.Pointer[bridge]
	trunk  atomic.Pointer[trunk] // Trunk keys of the mesh members. Nil with no mesh.
	peers  peerTable             // Counters of the packets to and from each mesh member.
	onEnd  atomic.Pointer[func(AttachmentStats)]
	// epoch goes up at each change of a route, of Permit or of the attachments
	// of a member. The rows of the members do their checks again then.
	epoch atomic.Uint64
	// refusals counts the rows that the relay refused or ended for an SPI that
	// the relay of the receiver has in use.
	refusals [numRowRefusals]atomic.Uint64

	mu       sync.RWMutex
	permit   Permit
	domains  map[VPCKey]*domain
	sessions map[*Session]struct{}
	byConn   map[*rpc.Conn]*Session
	bySource map[netip.AddrPort]*Session
	probes   map[[8]byte]*Session
	attaches uint64 // Attach counter for Attachment.seq.
	xdp      *xdpSync
	xdpBase  xdpStats      // Counters of the XDP programs that stopped.
	xdpWake  chan struct{} // Has room for 1: XDP rows are marked.

	// What the mesh gets of the attachments, and what it gives. mu guards
	// these fields.
	gen      uint64                 // Last presence generation.
	tag      uint32                 // Last trunk tag that a session got.
	tags     map[uint32]struct{}    // Trunk tags of the sessions.
	presence func(*dp.Presence)     // Gets each new and each gone attachment.
	remotes  map[remoteKey]*Session // Records of the sessions of other relays that have routes.
	in       map[string]*inRows     // Rows that each member gave for its senders, by relay name.

	// statsMu guards attCount.last. Take it after mu.
	statsMu sync.Mutex
}

// NewRouter returns a Router with the SameVPC Permit rule. New sessions
// are checked with trust.
func NewRouter(trust Trust, cfg Config) *Router {
	if cfg.LaneRate > 0 && cfg.LaneBurst == 0 {
		cfg.LaneBurst = int(cfg.LaneRate / 10)
	}
	cfg.LaneBurst = max(cfg.LaneBurst, minBurst)
	if cfg.TunnelRate > 0 && cfg.TunnelBurst == 0 {
		cfg.TunnelBurst = int(cfg.TunnelRate / 10)
	}
	cfg.TunnelBurst = max(cfg.TunnelBurst, minBurst)
	cfg.LaneSources = min(max(cfg.LaneSources, 0), MaxLaneSources)
	return &Router{
		cfg:      cfg,
		trust:    trust,
		ver:      dp.LocalVersion(build.BuildVersion),
		permit:   SameVPC,
		domains:  map[VPCKey]*domain{},
		sessions: map[*Session]struct{}{},
		byConn:   map[*rpc.Conn]*Session{},
		bySource: map[netip.AddrPort]*Session{},
		probes:   map[[8]byte]*Session{},
		tags:     map[uint32]struct{}{},
		remotes:  map[remoteKey]*Session{},
		in:       map[string]*inRows{},
		xdpWake:  make(chan struct{}, 1),
	}
}

// Session is the relay side of one authenticated relay session. It is one
// sender: its rows are keyed on SPI.
type Session struct {
	id           Identity
	conn         *rpc.Conn
	remote       func() netip.AddrPort
	chain        []*x509.Certificate // Agent cert chain, leaf first.
	notAfter     time.Time           // The session closes at the NotAfter of the leaf.
	close        func(code dp.RelayCloseCode, msg string)
	sendDatagram func([]byte) error
	wake         chan struct{}               // Has room for 1: the sync queue changed.
	sources      func(netip.Addr) bool       // Allows the inner sources that route to s.
	udpAddr      atomic.Pointer[net.UDPAddr] // Last address that the bridge sent to.
	probe        *prober
	meter        *rate.Limiter // Tunnel limit. Nil means no limit. Shards use the meter of the owner.
	watching     atomic.Bool   // A watch follows the connection after Moved.
	rtt          *atomic.Int64 // Smoothed RTT of the connection in nanoseconds. Nil with no trace.

	// Guarded by Router.mu.
	addr        netip.AddrPort
	prev        netip.AddrPort // Valid until prevUntil after a migration.
	prevUntil   time.Time
	lanes       []netip.AddrPort  // Lane sources: lane i sends from lanes[i-1].
	receive     bool              // The agent reads its lane ports.
	laneSeen    uint32            // Bit i-1 is set after a keepalive from lanes[i-1].
	rows        map[uint32]*row   // Rows of this sender.
	inbound     map[*row]struct{} // Rows of senders to this session.
	routes      []netip.Prefix
	attachments []*Attachment
	closed      bool
	version     *dp.Version // Version of the agent, from Hello. Nil is revision 0.
	name        string      // Name of the agent, from Hello. Empty before revision 2.
	tag         uint32      // Trunk tag, from the first attach to the removal. Zero is no tag.
	home        string      // Relay name of the mesh member that has the session. Empty for a session of this relay.
	sync        syncState
	visit       atomic.Pointer[visit]        // Visit of s, or nil. Router.mu guards each write.
	shardOf     *Session                     // The owner session of a shard.
	twin        *Session                     // Older session of the agent socket. Forward also uses its rows.
	shards      [peerconn.MaxShards]*Session // Shards 1 and up of an owner.
	rx          *keys.Peer                   // Relay SAs for PSP packets from s.
	tx          *keys.TxPeer                 // SAs of s for PSP packets from the relay.
	relaySAs    map[uint32]time.Time         // End of each relay SA of s.
	rxRows      tally                        // Counts of the rows of s that ended.
	rxBase      counts                       // RX of s that its oldest attachment does not get.

	dropUnknownSPI, dropMeter, dropTunnel atomic.Uint64
	dropTrunk                             atomic.Uint64 // Packets that a trunk did not carry.
	dataSent, dataDrops                   atomic.Uint64
	// framePackets and frameBytes count the inner packets of the data frames
	// of s that the relay sent on.
	framePackets, frameBytes atomic.Uint64
}

// Identity returns the identity of s.
func (s *Session) Identity() Identity { return s.id }

// sameAgent reports whether s and o are sessions of one agent. Many agents
// can have one subject, each with its own name. A session with no name is of
// the same agent as each session of its subject. Router.mu must be held.
func (s *Session) sameAgent(o *Session) bool {
	return s.id.ID == o.id.ID && (s.name == o.name || s.name == "" || o.name == "")
}

// row forwards the packets of one sender lane (SPI) to one receiver.
type row struct {
	sender, receiver *Session
	spi              uint32
	vpc              VPCKey
	dst              netip.Addr
	lane             int       // Source of the sender: 0 is its address. Guarded by Router.mu.
	saLane           int       // SA lane at the receiver. Guarded by Router.mu.
	expires          time.Time // Guarded by Router.mu.
	meter            *rate.Limiter
	lastUsed         atomic.Int64 // Unix nanoseconds.
	att              *Attachment  // Attachment of dst at the receiver, or nil. Guarded by Router.mu.
	trunk            *trunkMember // Place of the relay that has the receiver, or nil. Guarded by Router.mu.
	done             tally        // Counts that the totals of the sender and of att have. Guarded by Router.mu.
	removed          bool         // The row ended. Guarded by Router.mu.

	packets, bytes, dropMeter, icvFailures atomic.Uint64
}

// route is one prefix in a domain and the attachment that advertises it.
type route struct {
	prefix netip.Prefix
	origin string
}

type domain struct {
	routes  map[netip.Prefix]owner
	lens    []int                   // Prefix lengths in use, longest first.
	fast    engine.Routes[*Session] // The same routes, for source checks with no lock.
	members map[*Session]struct{}
	// claims has the attachments of other relays that list each prefix.
	claims map[netip.Prefix][]*presenceEntry
	// visits has the visitor sessions: they are not in routes.
	visits visits
	// networkID is the network ID of the VPC, from a Session call on this
	// relay. It is valid when known is true.
	networkID uint32
	known     bool
}

type owner struct {
	s      *Session
	origin string
	// advertised is set for a prefix from Attachment.Routes. The newest live
	// attachment of the agent that lists it owns it.
	advertised bool
	// att is the attachment of the prefix. It is nil for a route from AddRoute.
	att *Attachment
}

// ownerOf returns the owner of the longest route to a, or the zero owner.
func (d *domain) ownerOf(a netip.Addr) owner {
	for _, n := range d.lens {
		if p, err := a.Prefix(n); err == nil {
			if o, ok := d.routes[p]; ok {
				return o
			}
		}
	}
	return owner{}
}

// lookup returns the session of the longest route to a.
func (d *domain) lookup(a netip.Addr) *Session { return d.ownerOf(a).s }

func (d *domain) usesLen(n int) bool {
	for p := range d.routes {
		if p.Bits() == n {
			return true
		}
	}
	return false
}

// AddSession checks the agent cert of conn and adds a relay session with its
// identity. The session ends when conn closes. On error, the caller closes conn.
func (r *Router) AddSession(conn *rpc.Conn) (*Session, error) {
	qc := conn.QUIC()
	tc := qc.ConnectionState().TLS
	if tc.NegotiatedProtocol != dp.ALPNRelay {
		return nil, fmt.Errorf("ALPN %q is not %s", tc.NegotiatedProtocol, dp.ALPNRelay)
	}
	now := time.Now()
	id, err := r.checkCert(tc.PeerCertificates, now)
	if err != nil {
		return nil, fmt.Errorf("agent cert rejected: %w", err)
	}
	s := newSession(Identity{VPC: VPCKey{Project: id.Project, UID: id.VPC}, ID: id.String()},
		func() netip.AddrPort { return addrPort(qc.RemoteAddr()) })
	s.conn = conn
	s.chain = tc.PeerCertificates
	s.notAfter = tc.PeerCertificates[0].NotAfter
	s.close = func(code dp.RelayCloseCode, msg string) {
		_ = qc.CloseWithError(quic.ApplicationErrorCode(code), msg)
	}
	s.sendDatagram = qc.SendDatagram
	s.rtt = rttOf(qc.Context())
	if s.probe, err = newProber(tc); err != nil {
		return nil, err
	}
	r.addSession(s, now)
	r.answerEarly(s)
	context.AfterFunc(qc.Context(), func() { r.removeSession(s) })
	return s, nil
}

func newSession(id Identity, remote func() netip.AddrPort) *Session {
	return &Session{
		id:           id,
		remote:       remote,
		close:        func(dp.RelayCloseCode, string) {},
		sendDatagram: func([]byte) error { return errNoDatagrams },
		wake:         make(chan struct{}, 1),
		rows:         map[uint32]*row{},
		inbound:      map[*row]struct{}{},
		sync:         syncState{routes: map[route]bool{}, noRoute: map[netip.Addr]time.Time{}},
	}
}

// addSession adds s to the router and to the domain of its VPC. The
// routes of the domain go to the sync queue of s.
func (r *Router) addSession(s *Session, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[s] = struct{}{}
	if r.cfg.TunnelRate > 0 {
		s.meter = rate.NewLimiter(rate.Limit(r.cfg.TunnelRate), r.cfg.TunnelBurst)
	}
	if s.conn != nil {
		r.byConn[s.conn] = s
	}
	r.setAddr(s, s.remote(), now)
	r.addProber(s)
	d := r.domain(s.id.VPC)
	d.members[s] = struct{}{}
	// All sessions of the subject can send from the routes of the subject.
	s.sources = func(a netip.Addr) bool {
		if o, ok := d.fast.Lookup(a); ok && (o == s || o.id.ID == s.id.ID) {
			return true
		}
		// A visitor sends from the prefix of its visit, which is not its route.
		v := s.visit.Load()
		return v != nil && v.prefix.Contains(a)
	}
	for p, o := range d.routes {
		s.queueRoute(route{p, o.origin}, o.s, true)
	}
}

func (r *Router) removeSession(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	r.markXDP(s)
	r.endVisit(s, "session closed")
	// The routes go first: a route that moves to another session takes its rows.
	for _, p := range slices.Clone(s.routes) {
		r.dropRoute(s, p)
	}
	// The attachments stay in s for their last counters, but they are gone.
	for _, a := range s.attachments {
		r.withdraw(a)
	}
	for _, w := range s.rows {
		r.removeRow(w)
	}
	for w := range s.inbound {
		r.removeRow(w)
	}
	// A later session can get the trunk tag of s. The other relays got the end
	// of the rows of s with the tag.
	delete(r.tags, s.tag)
	s.tag = 0
	for _, a := range []netip.AddrPort{s.addr, s.prev} {
		if o := r.bySource[a]; o == s {
			delete(r.bySource, a)
			r.passSource(s, a)
		} else if o != nil && o.twin == s {
			o.twin = nil
		}
	}
	r.dropLanes(s)
	s.twin = nil
	if d := r.domains[s.id.VPC]; d != nil {
		delete(d.members, s)
		r.dropDomain(s.id.VPC, d)
	}
	delete(r.sessions, s)
	delete(r.byConn, s.conn)
	r.removeProber(s)
}

// domain returns the domain of vpc and makes it if needed.
func (r *Router) domain(vpc VPCKey) *domain {
	d := r.domains[vpc]
	if d == nil {
		d = &domain{
			routes:  map[netip.Prefix]owner{},
			members: map[*Session]struct{}{},
			claims:  map[netip.Prefix][]*presenceEntry{},
		}
		r.domains[vpc] = d
	}
	return d
}

func (r *Router) dropDomain(vpc VPCKey, d *domain) {
	if len(d.routes) == 0 && len(d.members) == 0 && len(d.claims) == 0 {
		delete(r.domains, vpc)
	}
}

// setAddr moves s to source address a. The previous address stays valid
// for rebindOverlap.
func (r *Router) setAddr(s *Session, a netip.AddrPort, now time.Time) {
	if !a.IsValid() || a == s.addr {
		return
	}
	// The rows to s get a new next hop.
	r.markXDP(s)
	for w := range s.inbound {
		r.markXDP(w.sender)
	}
	if s.prev.IsValid() && r.bySource[s.prev] == s {
		delete(r.bySource, s.prev)
	}
	if s.addr.IsValid() {
		s.prev, s.prevUntil = s.addr, now.Add(rebindOverlap)
	}
	s.addr = a
	// The lane ports were at the old address.
	r.dropLanes(s)
	r.takeSource(s)
}

// takeSource gives the source address of s to s. A session with a Session
// call takes it from other sessions. Before its Hello, a session takes only a
// free address, because a shard from the same socket must not take it. An
// older session of the same agent with a Session call becomes the twin of s.
func (r *Router) takeSource(s *Session) {
	if !s.addr.IsValid() || s.shardOf != nil {
		return
	}
	o := r.bySource[s.addr]
	if o != nil && !s.sync.open {
		return
	}
	if o != nil && o != s && o.id == s.id && o.sync.open {
		s.twin = o
	}
	r.bySource[s.addr] = s
	r.markXDP(s)
}

// twinOf returns the other open session of the agent socket of c, or nil.
// Router.mu must be held.
func (r *Router) twinOf(c *Session) *Session {
	o := r.bySource[c.addr]
	if o == c {
		o = c.twin
	} else if o != nil && o.twin != c {
		o = nil
	}
	if o == nil || o.closed || o.addr != c.addr {
		return nil
	}
	return o
}

// passSource gives source address a of the closed session s to another
// session of the VPC at a with a Session call, as takeSource does. A shard
// dial does not get it. Router.mu must be held.
func (r *Router) passSource(s *Session, a netip.AddrPort) {
	d := r.domains[s.id.VPC]
	if d == nil || !a.IsValid() {
		return
	}
	for o := range d.members {
		if o != s && !o.closed && o.shardOf == nil && o.sync.open && o.addr == a {
			r.bySource[a] = o
			r.markXDP(o)
			return
		}
	}
}

// Addr returns the current source address of s.
func (r *Router) Addr(s *Session) netip.AddrPort {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return s.addr
}

// AddRoute routes prefix p in the VPC of s to s. origin is the attachment
// that advertises p. The other sessions in the VPC get the route in Sync.
func (r *Router) AddRoute(s *Session, p netip.Prefix, origin string) error {
	if !p.IsValid() {
		return rpc.Errorf(rpc.InvalidArgument, "prefix not valid")
	}
	p = p.Masked()
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed {
		return rpc.Errorf(rpc.FailedPrecondition, "session closed")
	}
	d := r.domain(s.id.VPC)
	// A session of this relay takes p from a session of another relay.
	if o, ok := d.routes[p]; ok && o.s.home == "" {
		if o.s == s {
			return nil
		}
		return rpc.Errorf(rpc.AlreadyExists, "route %s has another owner", p)
	}
	r.setOwner(d, p, owner{s: s, origin: origin})
	return nil
}

// setOwner routes the valid prefix p to o, and moves the rows to p from the
// owner before. Router.mu must be held.
func (r *Router) setOwner(d *domain, p netip.Prefix, o owner) {
	old, had := d.routes[p]
	if had {
		// Lookups with no lock do not find p between this Remove and the Add.
		d.fast.Remove(p, old.s)
		old.s.routes = slices.DeleteFunc(old.s.routes, func(q netip.Prefix) bool { return q == p })
		d.queueRoute(route{p, old.origin}, old.s, false)
	}
	_ = d.fast.Add(p, o.s) // p is valid and has no route now.
	d.routes[p] = o
	if !slices.Contains(d.lens, p.Bits()) {
		d.lens = append(d.lens, p.Bits())
		slices.SortFunc(d.lens, func(a, b int) int { return cmp.Compare(b, a) })
	}
	o.s.routes = append(o.s.routes, p)
	d.queueRoute(route{p, o.origin}, o.s, true)
	r.epoch.Add(1)
	r.displace(d, p, o.s)
	if had {
		// The rows to p go to the new session, or to its attachment.
		for w := range old.s.inbound {
			if to := r.ownerOf(w.vpc, w.dst); to.s == o.s && (w.receiver != to.s || w.att != to.att) {
				r.move(w, to)
			}
		}
		r.release(old.s)
	}
}

// dropRoute removes the route p of s. An advertised route goes to the newest
// live attachment of the agent that lists it, if there is one.
func (r *Router) dropRoute(s *Session, p netip.Prefix) {
	if d := r.domains[s.id.VPC]; d != nil {
		if o := d.routes[p]; o.s == s && o.advertised {
			if hs, ha := d.heir(s, p); hs != nil {
				r.setOwner(d, p, owner{hs, ha.ID, true, ha})
				return
			}
		}
	}
	r.deleteRoute(s, p)
	s.routes = slices.DeleteFunc(s.routes, func(q netip.Prefix) bool { return q == p })
}

// heir returns the newest attachment that lists the route p, on an open
// session of the agent of s.
func (d *domain) heir(s *Session, p netip.Prefix) (*Session, *Attachment) {
	var hs *Session
	var ha *Attachment
	for m := range d.members {
		if m.closed || !m.sameAgent(s) {
			continue
		}
		for _, a := range m.attachments {
			if (ha == nil || a.seq > ha.seq) && slices.Contains(a.Routes, p) {
				hs, ha = m, a
			}
		}
	}
	return hs, ha
}

// queueRoute gives a change of the route rt of owner to the sessions of d.
func (d *domain) queueRoute(rt route, owner *Session, add bool) {
	for m := range d.members {
		m.queueRoute(rt, owner, add)
	}
}

// RemoveRoute removes the route p of s and the rows that it carried.
func (r *Router) RemoveRoute(s *Session, p netip.Prefix) {
	p = p.Masked()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slices.Contains(s.routes, p) {
		return
	}
	r.deleteRoute(s, p)
	s.routes = slices.DeleteFunc(s.routes, func(q netip.Prefix) bool { return q == p })
	r.dropInbound(s)
}

// dropInbound removes the rows to s that s has no route for. A row whose
// route has another attachment of s now goes to that attachment. Router.mu
// must be held.
func (r *Router) dropInbound(s *Session) {
	for w := range s.inbound {
		if to := r.ownerOf(w.vpc, w.dst); to.s != s {
			r.removeRow(w)
		} else if to.att != w.att {
			r.retarget(w, to)
		}
	}
}

func (r *Router) deleteRoute(s *Session, p netip.Prefix) {
	d := r.domains[s.id.VPC]
	if d == nil {
		return
	}
	o, ok := d.routes[p]
	if !ok || o.s != s {
		return
	}
	delete(d.routes, p)
	d.fast.Remove(p, s)
	r.epoch.Add(1)
	if !d.usesLen(p.Bits()) {
		d.lens = slices.DeleteFunc(d.lens, func(n int) bool { return n == p.Bits() })
	}
	d.queueRoute(route{p, o.origin}, s, false)
	if s.home == "" {
		// An attachment of another relay that lists p gets it now.
		r.elect(d, p)
	}
	r.dropDomain(s.id.VPC, d)
}

func (r *Router) lookup(vpc VPCKey, a netip.Addr) *Session { return r.ownerOf(vpc, a).s }

// ownerOf returns the owner of the longest route to a in vpc, or the zero
// owner. Router.mu must be held.
func (r *Router) ownerOf(vpc VPCKey, a netip.Addr) owner {
	if d := r.domains[vpc]; d != nil {
		return d.ownerOf(a)
	}
	return owner{}
}

// localOwner is ownerOf for the sessions of this relay, for the paths that send
// nothing to another relay. Router.mu must be held.
func (r *Router) localOwner(vpc VPCKey, a netip.Addr) owner {
	if o := r.ownerOf(vpc, a); o.s != nil && o.s.home == "" {
		return o
	}
	return owner{}
}

// permitted returns the session that src reaches dst through, if Permit allows.
// It can be a visitor, or the record of a session of another relay.
func (r *Router) permitted(src *Session, dst netip.Addr) *Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.permit(src.id.VPC, src.id.ID, src.id.VPC, dst) {
		return nil
	}
	return r.reach(src, dst).s
}

// Route returns the session of this relay for packets from src to dst, if Permit
// allows. With no route, src gets a NoRoute in Sync, at most once a second per address.
func (r *Router) Route(src *Session, dst netip.Addr, now time.Time) *Session {
	dst = dst.Unmap()
	next := r.permitted(src, dst)
	switch {
	case next == nil:
		r.noRoute(src, dst, "", now)
		return nil
	case next.home != "":
		// The address has a route, so src gets a NoRoute only to visit that relay.
		r.noRoute(src, dst, next.home, now)
		return nil
	}
	return next
}

// removeRow removes w. Its counts go to the totals of its sender and of its
// attachment. Router.mu must be held.
func (r *Router) removeRow(w *row) {
	r.fold(w)
	w.removed = true
	if w.sender.rows[w.spi] == w {
		delete(w.sender.rows, w.spi)
	}
	delete(w.receiver.inbound, w)
	r.untrunk(w)
	r.markXDP(w.sender)
}

// SetPermit replaces the Permit rule and removes the rows that it denies. The
// packets of a row of another relay that it denies drop.
func (r *Router) SetPermit(p Permit) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.permit = p
	r.epoch.Add(1)
	for s := range r.sessions {
		for _, w := range s.rows {
			if !p(s.id.VPC, s.id.ID, w.vpc, w.dst) {
				r.removeRow(w)
			}
		}
	}
}

// Forward finds where to send a PSP packet with outer source src and SPI
// spi. It returns Pass and the address of the receiver, or a drop verdict. For
// a receiver on another relay, the address is the relay socket of that relay,
// which gets the packet with no change.
func (r *Router) Forward(src netip.AddrPort, spi uint32, size int, now time.Time) (netip.AddrPort, Verdict) {
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := r.bySource[src]
	if s == nil || !s.from(src, now) {
		r.drops[dropUnknownSource].Add(1)
		return netip.AddrPort{}, DropUnknownSource
	}
	w := s.rows[spi]
	if t := s.twin; (w == nil || now.After(w.expires)) && t != nil && !t.closed {
		// The older session keeps its rows until it closes.
		if tw := t.rows[spi]; tw != nil && t.from(src, now) {
			s, w = t, tw
		}
	}
	if w == nil || now.After(w.expires) {
		s.dropUnknownSPI.Add(1)
		r.drops[dropUnknownSPI].Add(1)
		return netip.AddrPort{}, DropUnknownSPI
	}
	var pair *trunkPair
	if m := w.trunk; m != nil {
		// The checks of the trunk come first: a packet that it cannot carry
		// takes nothing from the meters.
		pair = m.pair.Load()
		if v := r.trunkFits(s, m.name, pair, size); v != Pass {
			return netip.AddrPort{}, v
		}
	}
	if w.meter != nil && !w.meter.AllowN(now, size) {
		w.dropMeter.Add(1)
		s.dropMeter.Add(1)
		r.drops[dropLaneMeter].Add(1)
		return netip.AddrPort{}, DropMeter
	}
	if !r.allow(s, size, now) {
		return netip.AddrPort{}, DropTunnelLimit
	}
	w.lastUsed.Store(now.UnixNano())
	w.packets.Add(1)
	w.bytes.Add(uint64(size))
	if pair != nil {
		pair.stats.add(trunkTx, size)
		return pair.addr, Pass
	}
	return w.receiver.dst(w.saLane), Pass
}

// allow reports whether the tunnel limit of s lets size bytes through now. It
// counts the drop if not.
func (r *Router) allow(s *Session, size int, now time.Time) bool {
	if s.meter == nil || s.meter.AllowN(now, size) {
		return true
	}
	s.dropTunnel.Add(1)
	r.drops[dropTunnelLimit].Add(1)
	return false
}

// ReportStatus counts the ICV failures that receiver s reports on the
// lanes of the senders that registered those SPIs to s.
func (r *Router) ReportStatus(s *Session, st *dp.Status) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, f := range st.GetIcvFailures() {
		for w := range s.inbound {
			if w.spi == f.GetSpi() {
				w.icvFailures.Add(f.GetCount())
			}
		}
	}
}

// Sweep follows migrated connections, ends old source addresses and visits,
// removes expired and idle rows, and closes sessions at the NotAfter of their cert.
func (r *Router) Sweep(now time.Time) {
	idle := now.Add(-rowIdle).UnixNano()
	var expired []*Session
	r.mu.Lock()
	for s := range r.sessions {
		if !s.notAfter.IsZero() && !now.Before(s.notAfter) {
			expired = append(expired, s)
		}
		if v := s.visit.Load(); v != nil && !now.Before(v.notAfter) {
			r.endVisit(s, "grant ended")
		}
		if s.shardOf == nil {
			r.setAddr(s, s.remote(), now)
		}
		if s.prev.IsValid() && now.After(s.prevUntil) {
			if r.bySource[s.prev] == s {
				delete(r.bySource, s.prev)
			}
			s.prev = netip.AddrPort{}
		}
		for _, w := range s.rows {
			if w.lastUsed.Load() < idle {
				r.refreshUsedXDP(w)
			}
			if now.After(w.expires) || w.lastUsed.Load() < idle {
				r.removeRow(w)
			}
		}
		s.sweepNoRoute(now)
	}
	// The rows of the members have no idle time: the relay of the sender ends them.
	r.sweepIn(now)
	r.syncAllXDP(now)
	r.mu.Unlock()
	for _, s := range expired {
		s.close(dp.RelayCloseCode_RELAY_CLOSE_CODE_CERT, "agent cert expired")
	}
}

// Run sweeps the rows and rekeys the relay SAs each second until ctx ends.
func (r *Router) Run(ctx context.Context) {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			r.Sweep(now)
			r.tickBridge(now)
			r.sweepPeers()
		case <-r.xdpWake:
			r.mu.Lock()
			r.syncXDP(time.Now())
			r.mu.Unlock()
		}
	}
}

// LaneStats are the counters of one SPI row.
type LaneStats struct {
	SPI         uint32
	Destination netip.Addr
	Packets     uint64
	Bytes       uint64
	DropMeter   uint64
	ICVFailures uint64
}

// SenderStats are the counters of one sender.
type SenderStats struct {
	DropUnknownSPI uint64
	DropMeter      uint64
	// DropTunnelLimit counts the PSP packets, data frames and peer frames above
	// the tunnel limit. DataDrops does not count them.
	DropTunnelLimit uint64
	// DropTrunk counts the PSP packets and the inner packets for another relay
	// that the trunk to it did not carry: too large, no trunk now, or no SA.
	DropTrunk uint64
	Lanes     []LaneStats // Sorted by SPI.
	// DataSent and DataDrops count the data frames and the decrypted PSP
	// packets of the sender that the relay sent on or dropped.
	DataSent  uint64
	DataDrops uint64
}

// SenderStats returns the counters of sender s.
func (r *Router) SenderStats(s *Session) SenderStats {
	st := SenderStats{
		DropUnknownSPI:  s.dropUnknownSPI.Load(),
		DropMeter:       s.dropMeter.Load(),
		DropTunnelLimit: s.dropTunnel.Load(),
		DropTrunk:       s.dropTrunk.Load(),
		DataSent:        s.dataSent.Load(),
		DataDrops:       s.dataDrops.Load(),
	}
	r.mu.RLock()
	for _, w := range s.rows {
		x := r.xdpCountersOf(w)
		st.DropMeter += x.drops
		st.Lanes = append(st.Lanes, LaneStats{
			SPI:         w.spi,
			Destination: w.dst,
			Packets:     w.packets.Load() + x.packets,
			Bytes:       w.bytes.Load() + x.bytes,
			DropMeter:   w.dropMeter.Load() + x.drops,
			ICVFailures: w.icvFailures.Load(),
		})
	}
	st.DropTunnelLimit += r.xdpTunnelDrops(s)
	r.mu.RUnlock()
	slices.SortFunc(st.Lanes, func(a, b LaneStats) int { return cmp.Compare(a.SPI, b.SPI) })
	return st
}

// UnknownSourceDrops returns the number of packets from addresses of no sender.
func (r *Router) UnknownSourceDrops() uint64 { return r.drops[dropUnknownSource].Load() }

// MalformedDrops returns the number of non-QUIC packets that are not PSP and
// get no probe reply. Geneve packets that the kernel did not take count here,
// and also the packets of a mesh member that the trunk does not accept.
func (r *Router) MalformedDrops() uint64 { return r.drops[dropMalformed].Load() }

// ForwardStats are the sendmmsg calls of the socket path, their messages, and
// the packets that the socket took. A message is one packet or one GSO message.
type ForwardStats struct {
	Calls, Messages, Packets uint64
}

// ForwardStats returns the send counters of the socket path.
func (r *Router) ForwardStats() ForwardStats {
	return ForwardStats{r.sends.calls.Load(), r.sends.messages.Load(), r.sends.packets.Load()}
}

func addrPort(a net.Addr) netip.AddrPort {
	u, ok := a.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	ap := u.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
