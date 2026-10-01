// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// rowIdle is the time with no traffic after which a row is removed (D19).
	rowIdle = 5 * time.Minute
	// rebindOverlap is the time that the previous source address of a sender
	// stays valid after its connection migrates.
	rebindOverlap = 5 * time.Second
	sweepInterval = time.Second
	minLaneBurst  = 64 << 10
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
	// RelayOnly is set for a join-token identity, which gets no P2P.
	RelayOnly bool
}

// Permit tells if a sender in srcVPC with identity srcID can reach dst in dstVPC.
type Permit func(srcVPC VPCKey, srcID string, dstVPC VPCKey, dst netip.Addr) bool

// SameVPC is the MVP Permit rule: the source and the destination are in one VPC.
func SameVPC(srcVPC VPCKey, _ string, dstVPC VPCKey, _ netip.Addr) bool { return srcVPC == dstVPC }

// Config sets the meter of each lane (SPI row).
type Config struct {
	// LaneRate is the meter rate in bytes per second. Zero means no limit.
	LaneRate float64
	// LaneBurst is the meter burst in bytes. Zero means 100 ms of LaneRate.
	// It is at least 64 KiB.
	LaneBurst int
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
)

// Router holds the routing domains and SPI rows of one relay.
type Router struct {
	cfg           Config
	unknownSource atomic.Uint64

	mu       sync.RWMutex
	permit   Permit
	domains  map[VPCKey]*domain
	sessions map[*Session]struct{}
	byConn   map[*rpc.Conn]*Session
	bySource map[netip.AddrPort]*Session
}

// NewRouter returns a Router with the SameVPC Permit rule.
func NewRouter(cfg Config) *Router {
	if cfg.LaneRate > 0 && cfg.LaneBurst == 0 {
		cfg.LaneBurst = int(cfg.LaneRate / 10)
	}
	cfg.LaneBurst = max(cfg.LaneBurst, minLaneBurst)
	return &Router{
		cfg:      cfg,
		permit:   SameVPC,
		domains:  map[VPCKey]*domain{},
		sessions: map[*Session]struct{}{},
		byConn:   map[*rpc.Conn]*Session{},
		bySource: map[netip.AddrPort]*Session{},
	}
}

// Session is the relay side of one authenticated relay session. It is one
// sender: its rows are keyed on SPI.
type Session struct {
	id     Identity
	conn   *rpc.Conn
	remote func() netip.AddrPort

	// Guarded by Router.mu.
	addr      netip.AddrPort
	prev      netip.AddrPort // Valid until prevUntil after a migration.
	prevUntil time.Time
	rows      map[uint32]*row   // Rows of this sender.
	inbound   map[*row]struct{} // Rows of senders to this session.
	routes    []netip.Prefix
	closed    bool

	dropUnknownSPI, dropMeter atomic.Uint64
}

// Identity returns the identity of s.
func (s *Session) Identity() Identity { return s.id }

// row forwards the packets of one sender lane (SPI) to one receiver.
type row struct {
	sender, receiver *Session
	spi              uint32
	vpc              VPCKey
	dst              netip.Addr
	expires          time.Time // Guarded by Router.mu.
	meter            *rate.Limiter
	lastUsed         atomic.Int64 // Unix nanoseconds.

	packets, bytes, dropMeter, icvFailures atomic.Uint64
}

type domain struct {
	routes map[netip.Prefix]*Session
	lens   []int // Prefix lengths in use, longest first.
}

// lookup returns the session of the longest route to a.
func (d *domain) lookup(a netip.Addr) *Session {
	for _, n := range d.lens {
		if p, err := a.Prefix(n); err == nil {
			if s := d.routes[p]; s != nil {
				return s
			}
		}
	}
	return nil
}

func (d *domain) usesLen(n int) bool {
	for p := range d.routes {
		if p.Bits() == n {
			return true
		}
	}
	return false
}

// AddSession adds an authenticated relay session. The source of its data
// is the remote address of conn; Sweep follows it when the connection
// migrates. The session ends when conn closes.
func (r *Router) AddSession(conn *rpc.Conn, id Identity) (*Session, error) {
	qc := conn.QUIC()
	s, err := r.addSession(conn, id, func() netip.AddrPort { return addrPort(qc.RemoteAddr()) }, time.Now())
	if err != nil {
		return nil, err
	}
	context.AfterFunc(qc.Context(), func() { r.removeSession(s) })
	return s, nil
}

func (r *Router) addSession(conn *rpc.Conn, id Identity, remote func() netip.AddrPort, now time.Time) (*Session, error) {
	if id.VPC.Project == "" || id.VPC.UID == "" || id.ID == "" {
		return nil, errors.New("session identity needs a VPC and an ID")
	}
	s := &Session{id: id, conn: conn, remote: remote, rows: map[uint32]*row{}, inbound: map[*row]struct{}{}}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[s] = struct{}{}
	if conn != nil {
		r.byConn[conn] = s
	}
	r.setAddr(s, remote(), now)
	return s, nil
}

func (r *Router) removeSession(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for _, w := range s.rows {
		r.removeRow(w)
	}
	for w := range s.inbound {
		r.removeRow(w)
	}
	for _, p := range s.routes {
		r.deleteRoute(s, p)
	}
	for _, a := range []netip.AddrPort{s.addr, s.prev} {
		if r.bySource[a] == s {
			delete(r.bySource, a)
		}
	}
	delete(r.sessions, s)
	delete(r.byConn, s.conn)
}

// setAddr moves s to source address a. The previous address stays valid
// for rebindOverlap. The last session that validates an address owns it.
func (r *Router) setAddr(s *Session, a netip.AddrPort, now time.Time) {
	if !a.IsValid() || a == s.addr {
		return
	}
	if s.prev.IsValid() && r.bySource[s.prev] == s {
		delete(r.bySource, s.prev)
	}
	if s.addr.IsValid() {
		s.prev, s.prevUntil = s.addr, now.Add(rebindOverlap)
	}
	s.addr = a
	r.bySource[a] = s
}

// AddRoute routes prefix p in the VPC of s to s.
func (r *Router) AddRoute(s *Session, p netip.Prefix) error {
	if !p.IsValid() {
		return rpc.Errorf(rpc.InvalidArgument, "prefix not valid")
	}
	p = p.Masked()
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed {
		return rpc.Errorf(rpc.FailedPrecondition, "session closed")
	}
	d := r.domains[s.id.VPC]
	if d == nil {
		d = &domain{routes: map[netip.Prefix]*Session{}}
		r.domains[s.id.VPC] = d
	}
	switch d.routes[p] {
	case s:
		return nil
	case nil:
	default:
		return rpc.Errorf(rpc.AlreadyExists, "route %s has another owner", p)
	}
	d.routes[p] = s
	if !slices.Contains(d.lens, p.Bits()) {
		d.lens = append(d.lens, p.Bits())
		slices.SortFunc(d.lens, func(a, b int) int { return cmp.Compare(b, a) })
	}
	s.routes = append(s.routes, p)
	return nil
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
	for w := range s.inbound {
		if r.lookup(w.vpc, w.dst) != s {
			r.removeRow(w)
		}
	}
}

func (r *Router) deleteRoute(s *Session, p netip.Prefix) {
	d := r.domains[s.id.VPC]
	if d == nil || d.routes[p] != s {
		return
	}
	delete(d.routes, p)
	if !d.usesLen(p.Bits()) {
		d.lens = slices.DeleteFunc(d.lens, func(n int) bool { return n == p.Bits() })
	}
	if len(d.routes) == 0 {
		delete(r.domains, s.id.VPC)
	}
}

func (r *Router) lookup(vpc VPCKey, a netip.Addr) *Session {
	if d := r.domains[vpc]; d != nil {
		return d.lookup(a)
	}
	return nil
}

func (r *Router) removeRow(w *row) {
	if w.sender.rows[w.spi] == w {
		delete(w.sender.rows, w.spi)
	}
	delete(w.receiver.inbound, w)
}

// SetPermit replaces the Permit rule and removes the rows that it denies.
func (r *Router) SetPermit(p Permit) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.permit = p
	for s := range r.sessions {
		for _, w := range s.rows {
			if !p(s.id.VPC, s.id.ID, w.vpc, w.dst) {
				r.removeRow(w)
			}
		}
	}
}

// Forward finds where to send a PSP packet with outer source src and SPI
// spi. It returns Pass and the address of the receiver, or a drop verdict.
func (r *Router) Forward(src netip.AddrPort, spi uint32, size int, now time.Time) (netip.AddrPort, Verdict) {
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := r.bySource[src]
	if s == nil || (src != s.addr && now.After(s.prevUntil)) {
		r.unknownSource.Add(1)
		return netip.AddrPort{}, DropUnknownSource
	}
	w := s.rows[spi]
	if w == nil || now.After(w.expires) {
		s.dropUnknownSPI.Add(1)
		return netip.AddrPort{}, DropUnknownSPI
	}
	if w.meter != nil && !w.meter.AllowN(now, size) {
		w.dropMeter.Add(1)
		s.dropMeter.Add(1)
		return netip.AddrPort{}, DropMeter
	}
	w.lastUsed.Store(now.UnixNano())
	w.packets.Add(1)
	w.bytes.Add(uint64(size))
	return w.receiver.addr, Pass
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

// Sweep follows migrated connections, ends old source addresses, and
// removes expired and idle rows.
func (r *Router) Sweep(now time.Time) {
	idle := now.Add(-rowIdle).UnixNano()
	r.mu.Lock()
	defer r.mu.Unlock()
	for s := range r.sessions {
		r.setAddr(s, s.remote(), now)
		if s.prev.IsValid() && now.After(s.prevUntil) {
			if r.bySource[s.prev] == s {
				delete(r.bySource, s.prev)
			}
			s.prev = netip.AddrPort{}
		}
		for _, w := range s.rows {
			if now.After(w.expires) || w.lastUsed.Load() < idle {
				r.removeRow(w)
			}
		}
	}
}

// Run calls Sweep each second until ctx ends.
func (r *Router) Run(ctx context.Context) {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			r.Sweep(now)
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
	Lanes          []LaneStats // Sorted by SPI.
}

// SenderStats returns the counters of sender s.
func (r *Router) SenderStats(s *Session) SenderStats {
	st := SenderStats{DropUnknownSPI: s.dropUnknownSPI.Load(), DropMeter: s.dropMeter.Load()}
	r.mu.RLock()
	for _, w := range s.rows {
		st.Lanes = append(st.Lanes, LaneStats{
			SPI:         w.spi,
			Destination: w.dst,
			Packets:     w.packets.Load(),
			Bytes:       w.bytes.Load(),
			DropMeter:   w.dropMeter.Load(),
			ICVFailures: w.icvFailures.Load(),
		})
	}
	r.mu.RUnlock()
	slices.SortFunc(st.Lanes, func(a, b LaneStats) int { return cmp.Compare(a.SPI, b.SPI) })
	return st
}

// UnknownSourceDrops returns the number of packets from addresses of no sender.
func (r *Router) UnknownSourceDrops() uint64 { return r.unknownSource.Load() }

func addrPort(a net.Addr) netip.AddrPort {
	u, ok := a.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	ap := u.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
