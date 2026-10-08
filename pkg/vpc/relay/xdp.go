// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"log/slog"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
)

// XDPConfig sets where the XDP program of the relay runs.
type XDPConfig struct {
	// Port is the UDP port of the relay.
	Port uint16
	// Iface is the link that gets the PSP packets.
	Iface string
	// Chain, if set, runs a program on the packets that the XDP program of
	// Iface passes, and a nil program stops it. Else the relay program
	// attaches to Iface itself, in driver mode if the driver allows it.
	Chain func(*ebpf.Program) error
	// Generic attaches in generic mode only.
	Generic bool
	// Addrs are the addresses of the relay on Iface. The program forwards
	// only packets to one of them. Empty means all addresses of Iface.
	Addrs []netip.Addr
	// NextHopCache is the time that the program keeps the next hop of a row
	// after a route lookup. A change of a route or of a neighbor takes effect
	// after this time at most. Zero does a lookup for each packet.
	NextHopCache time.Duration
}

// xdpKey is the key of an XDP row: a sender address and an SPI.
type xdpKey struct {
	src netip.AddrPort
	spi uint32
}

// xdpRow is the next hop and the limits of an XDP row.
type xdpRow struct {
	next    netip.AddrPort
	tunnel  uint32 // 0 is no tunnel limit.
	expires time.Time
}

// xdpCounters are the counters of an XDP row.
type xdpCounters struct {
	packets, bytes, drops uint64
	used                  time.Time
}

// xdpStats are the counters of the XDP program.
type xdpStats struct {
	packets, bytes                              uint64
	laneDrops, tunnelDrops                      uint64
	noRow, expired, noRoute, malformed, tooLong uint64
}

func (s *xdpStats) add(o xdpStats) {
	s.packets += o.packets
	s.bytes += o.bytes
	s.laneDrops += o.laneDrops
	s.tunnelDrops += o.tunnelDrops
	s.noRow += o.noRow
	s.expired += o.expired
	s.noRoute += o.noRoute
	s.malformed += o.malformed
	s.tooLong += o.tooLong
}

// xdpTable is the row map and the counters of the XDP program.
type xdpTable interface {
	putRow(k xdpKey, w xdpRow) error
	deleteRow(k xdpKey) (xdpCounters, error)
	counters(k xdpKey) (xdpCounters, error)
	putTunnel(id uint32) error
	deleteTunnel(id uint32) (drops uint64, err error)
	tunnelDrops(id uint32) (uint64, error)
	stats() (xdpStats, error)
}

// xdpEntry is an installed XDP row and the row that it comes from.
type xdpEntry struct {
	xdpRow
	w *row
}

func (e xdpEntry) same(o xdpEntry) bool {
	return e.w == o.w && e.next == o.next && e.tunnel == o.tunnel && e.expires.Equal(o.expires)
}

type xdpTunnel struct {
	id   uint32
	rows int
}

// xdpSync keeps the XDP rows the same as the rows of the router. Router.mu
// guards it.
type xdpSync struct {
	t        xdpTable
	dirty    map[netip.AddrPort]struct{}
	rows     map[netip.AddrPort]map[uint32]xdpEntry
	tunnels  map[*Session]*xdpTunnel
	lastID   uint32
	warnedAt time.Time
	failures int  // Since warnedAt.
	paused   bool // All rows stay out: the link joins UDP packets.
}

func newXDPSync(t xdpTable) *xdpSync {
	return &xdpSync{
		t:       t,
		dirty:   map[netip.AddrPort]struct{}{},
		rows:    map[netip.AddrPort]map[uint32]xdpEntry{},
		tunnels: map[*Session]*xdpTunnel{},
	}
}

// setXDP starts the sync of the rows to t. Router.mu must not be held.
func (r *Router) setXDP(t xdpTable, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.xdp = newXDPSync(t)
	r.syncAllXDP(now)
}

// clearXDP removes all XDP rows and stops the sync. The counters go to the
// rows and to the router. Router.mu must not be held.
func (r *Router) clearXDP() {
	r.mu.Lock()
	defer r.mu.Unlock()
	x := r.xdp
	if x == nil {
		return
	}
	for a, es := range x.rows {
		for spi, e := range es {
			r.removeXDP(xdpKey{a, spi}, e)
		}
	}
	if st, err := x.t.stats(); err == nil {
		r.xdpBase.add(st)
	}
	r.xdp = nil
}

// pauseXDP takes all XDP rows out while on is true, and puts them back when
// it is false again. Router.mu must not be held.
func (r *Router) pauseXDP(on bool, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.xdp == nil || r.xdp.paused == on {
		return
	}
	r.xdp.paused = on
	r.syncAllXDP(now)
}

// markXDP marks the source addresses of s for the next XDP sync. Router.mu
// must be held.
func (r *Router) markXDP(s *Session) {
	if r.xdp == nil || s == nil {
		return
	}
	for _, a := range s.srcAddrs() {
		if a.IsValid() {
			r.xdp.dirty[a] = struct{}{}
		}
	}
	select {
	case r.xdpWake <- struct{}{}:
	default:
	}
}

// syncXDP syncs the XDP rows of the marked addresses. Router.mu must be held
// for writing.
func (r *Router) syncXDP(now time.Time) {
	x := r.xdp
	if x == nil {
		return
	}
	for a := range x.dirty {
		r.syncSource(a, now)
	}
	clear(x.dirty)
}

// syncAllXDP syncs the XDP rows of all addresses. Router.mu must be held for
// writing.
func (r *Router) syncAllXDP(now time.Time) {
	x := r.xdp
	if x == nil {
		return
	}
	for a := range r.bySource {
		x.dirty[a] = struct{}{}
	}
	for a := range x.rows {
		x.dirty[a] = struct{}{}
	}
	r.syncXDP(now)
}

func (r *Router) syncSource(a netip.AddrPort, now time.Time) {
	x := r.xdp
	var want map[uint32]xdpEntry
	if !x.paused {
		want = r.wantXDP(a, now)
	}
	for spi, e := range x.rows[a] {
		if n, ok := want[spi]; !ok || n.w != e.w {
			r.removeXDP(xdpKey{a, spi}, e)
		}
	}
	for spi, n := range want {
		e, ok := x.rows[a][spi]
		if ok {
			n.tunnel = e.tunnel
			if e.same(n) {
				continue
			}
		} else {
			var err error
			if n.tunnel, err = r.tunnelXDP(n.w.sender); err != nil {
				x.warn(err, now)
				continue
			}
		}
		if err := x.t.putRow(xdpKey{a, spi}, n.xdpRow); err != nil {
			// The old next hop must not stay. The socket path takes the row.
			if ok {
				r.removeXDP(xdpKey{a, spi}, e)
			} else {
				r.releaseTunnelXDP(n.w.sender)
			}
			x.warn(err, now)
			continue
		}
		if x.rows[a] == nil {
			x.rows[a] = map[uint32]xdpEntry{}
		}
		x.rows[a][spi] = n
	}
}

// wantXDP returns the rows that Forward uses for packets from a, by SPI. A row
// with no next hop, which goes to the relay, or with a next hop of the other
// family stays on the socket path. The tunnel is not set. Router.mu must be
// held.
func (r *Router) wantXDP(a netip.AddrPort, now time.Time) map[uint32]xdpEntry {
	s := r.bySource[a]
	if s == nil || s.closed {
		return nil
	}
	until, lane, ok := sourceEnd(s, a, now)
	if !ok {
		return nil
	}
	want := map[uint32]xdpEntry{}
	addWant(want, a, s, lane, until, now)
	// Forward also uses the rows of the older session of the socket.
	if t := s.twin; t != nil && !t.closed {
		if tu, tl, ok := sourceEnd(t, a, now); ok {
			if until.IsZero() || (!tu.IsZero() && tu.Before(until)) {
				until = tu
			}
			addWant(want, a, t, tl, until, now)
		}
	}
	for spi, e := range want {
		if !e.next.IsValid() {
			delete(want, spi)
		}
	}
	return want
}

// sourceEnd returns the time until which a is a source address of s, and its
// lane. The zero time is no end.
func sourceEnd(s *Session, a netip.AddrPort, now time.Time) (time.Time, int, bool) {
	lane, ok := s.laneOf(a, now)
	if ok && a != s.addr && lane == 0 {
		return s.prevUntil, 0, true
	}
	return time.Time{}, lane, ok
}

// addWant adds the live rows of s on lane to want for the SPIs that want does
// not have. A row of a lane with no port is on lane 0. A row that stays on the
// socket path gets no next hop.
func addWant(want map[uint32]xdpEntry, a netip.AddrPort, s *Session, lane int, until, now time.Time) {
	for spi, w := range s.rows {
		l := w.lane
		if l > len(s.lanes) {
			l = 0
		}
		if _, ok := want[spi]; ok || l != lane || now.After(w.expires) {
			continue
		}
		e := xdpEntry{xdpRow{expires: w.expires}, w}
		if next := w.receiver.dst(w.saLane); next.IsValid() && next.Addr().Is4() == a.Addr().Is4() {
			e.next = next
		}
		if !until.IsZero() && until.Before(e.expires) {
			e.expires = until
		}
		want[spi] = e
	}
}

// removeXDP removes an XDP row and adds its counters to the row of the router.
func (r *Router) removeXDP(k xdpKey, e xdpEntry) {
	x := r.xdp
	delete(x.rows[k.src], k.spi)
	if len(x.rows[k.src]) == 0 {
		delete(x.rows, k.src)
	}
	if e.tunnel != 0 {
		r.releaseTunnelXDP(e.w.sender)
	}
	c, err := x.t.deleteRow(k)
	if err != nil {
		return
	}
	e.w.packets.Add(c.packets)
	e.w.bytes.Add(c.bytes)
	e.w.dropMeter.Add(c.drops)
	e.w.sender.dropMeter.Add(c.drops)
	if u := c.used.UnixNano(); !c.used.IsZero() && u > e.w.lastUsed.Load() {
		e.w.lastUsed.Store(u)
	}
	if e.w.removed {
		// The row ended before, so its totals get these counts now.
		r.fold(e.w)
	}
}

// tunnelXDP returns the tunnel limit of the rows of s, or 0 for none. A
// tunnel limit needs a releaseTunnelXDP for each call.
func (r *Router) tunnelXDP(s *Session) (uint32, error) {
	x := r.xdp
	if s.meter == nil {
		return 0, nil
	}
	if t := x.tunnels[s]; t != nil {
		t.rows++
		return t.id, nil
	}
	x.lastID++
	if x.lastID == 0 {
		x.lastID++
	}
	if err := x.t.putTunnel(x.lastID); err != nil {
		return 0, err
	}
	x.tunnels[s] = &xdpTunnel{id: x.lastID, rows: 1}
	return x.lastID, nil
}

func (r *Router) releaseTunnelXDP(s *Session) {
	x := r.xdp
	t := x.tunnels[s]
	if t == nil {
		return
	}
	if t.rows--; t.rows > 0 {
		return
	}
	delete(x.tunnels, s)
	if drops, err := x.t.deleteTunnel(t.id); err == nil {
		s.dropTunnel.Add(drops)
	}
}

// warn logs a failed map update at most once in 10 seconds.
func (x *xdpSync) warn(err error, now time.Time) {
	x.failures++
	if now.Sub(x.warnedAt) < 10*time.Second {
		return
	}
	slog.Warn("Failed to update XDP relay rows; the socket path forwards their packets", "failures", x.failures, "error", err)
	x.warnedAt, x.failures = now, 0
}

// xdpCountersOf returns the XDP counters of w. Router.mu must be held.
func (r *Router) xdpCountersOf(w *row) xdpCounters {
	var sum xdpCounters
	x := r.xdp
	if x == nil {
		return sum
	}
	// The rows of s are at the source addresses of s, also as a twin.
	for _, a := range w.sender.srcAddrs() {
		if e, ok := x.rows[a][w.spi]; ok && e.w == w {
			c, err := x.t.counters(xdpKey{a, w.spi})
			if err != nil {
				continue
			}
			sum.packets += c.packets
			sum.bytes += c.bytes
			sum.drops += c.drops
			if c.used.After(sum.used) {
				sum.used = c.used
			}
		}
	}
	return sum
}

// xdpTunnelDrops returns the live XDP tunnel limit drops of s. Router.mu must
// be held.
func (r *Router) xdpTunnelDrops(s *Session) uint64 {
	if r.xdp == nil {
		return 0
	}
	if t := r.xdp.tunnels[s]; t != nil {
		if d, err := r.xdp.t.tunnelDrops(t.id); err == nil {
			return d
		}
	}
	return 0
}

// refreshUsedXDP sets the last use of w from its XDP rows. Router.mu must be
// held.
func (r *Router) refreshUsedXDP(w *row) {
	if r.xdp == nil {
		return
	}
	if c := r.xdpCountersOf(w); !c.used.IsZero() && c.used.UnixNano() > w.lastUsed.Load() {
		w.lastUsed.Store(c.used.UnixNano())
	}
}

// xdpStatsNow returns the counters of the XDP program, with the counters of
// the programs before it.
func (r *Router) xdpStatsNow() xdpStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st := r.xdpBase
	if r.xdp != nil {
		if s, err := r.xdp.t.stats(); err == nil {
			st.add(s)
		}
	}
	return st
}
