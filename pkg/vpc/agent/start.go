// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

const (
	// startEntries is the most addresses with no peer session that the agent keeps.
	startEntries = 1024
	// icmpInterval is the shortest time between ICMP errors for one address.
	icmpInterval = time.Second
)

var (
	errNoRelay = errors.New("no relay session")
	errNoPeer  = errors.New("no attachment routes the destination")
	// errRenewed is the cause of a start that a NoRoute replaced.
	errRenewed = errors.New("relay answered again for the address")
)

// startKey is an address on the link of one relay session. Each relay session
// has its own peer sessions.
type startKey struct {
	link *psp.Link
	addr netip.Addr
}

// starts runs one start of a peer session for each address that traffic goes
// to or comes from with no peer session. A failed start waits for the next try.
type starts struct {
	mu      sync.Mutex
	addrs   map[startKey]*start
	opening map[startKey]*opening // Peer sessions that open, by peer address.
	gen     uint64                // Generation of the last start, from 1.
}

// start is the state of one address with no peer session.
type start struct {
	running bool
	until   time.Time // The next try after a failed start.
	wait    time.Duration
	// gen is the generation of the start that runs or ran last, or 0 after a
	// renew ended it. The end of an older start changes nothing.
	gen    uint64
	cancel context.CancelCauseFunc // Ends the start that runs.
	// visit is true when the start that runs or waits is the visit of a NoRoute.
	visit bool
	// head is the start of a packet to the address since the last ICMP error,
	// for an ICMP error after a NoRoute of the relay.
	head     []byte
	lastICMP time.Time
}

// attempt is one start of an address. A renew cancels its context.
type attempt struct {
	ctx context.Context
	gen uint64
}

type opening struct {
	ctx  context.Context // Of the caller that opens.
	done chan struct{}
	err  error
}

// entry returns the state of key, or nil at the address limit. s.mu must be
// held.
func (s *starts) entry(key startKey) *start {
	st := s.addrs[key]
	if st == nil {
		if len(s.addrs) >= startEntries {
			return nil
		}
		if s.addrs == nil {
			s.addrs = map[startKey]*start{}
		}
		st = &start{}
		s.addrs[key] = st
	}
	return st
}

// run begins a start of st with a context from parent. s.mu must be held.
func (s *starts) run(st *start, parent context.Context, visit bool) attempt {
	ctx, cancel := context.WithCancelCause(parent)
	s.gen++
	st.running, st.gen, st.cancel, st.visit = true, s.gen, cancel, visit
	return attempt{ctx: ctx, gen: s.gen}
}

// stop cancels the start of st that runs and ends its wait. s.mu must be held.
func (s *starts) stop(st *start) {
	if st.running {
		st.cancel(errRenewed)
	}
	st.running, st.gen, st.cancel = false, 0, nil
	st.until, st.wait = time.Time{}, 0
}

// begin reports whether the caller starts a peer session for key now: no start
// runs and no failed start waits. It keeps the start of pkt, a packet to the
// address, for an ICMP error.
func (s *starts) begin(parent context.Context, key startKey, pkt []byte, now time.Time) (attempt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.entry(key)
	if st == nil {
		return attempt{}, false
	}
	if pkt != nil && st.head == nil {
		st.head = bytes.Clone(pkt[:min(len(pkt), maxICMPBody)])
	}
	if st.running || now.Before(st.until) {
		return attempt{}, false
	}
	return s.run(st, parent, false), true
}

// renew begins the visit of a NoRoute for key. The NoRoute is newer, so it
// ends a start of key or also that runs or waits. A NoRoute visit stays.
func (s *starts) renew(parent context.Context, key, also startKey, now time.Time) (attempt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.entry(key)
	if st == nil || st.visit && (st.running || now.Before(st.until)) {
		return attempt{}, false
	}
	// The NoRoute address can have its own start: see Agent.peerAddr.
	if o := s.addrs[also]; also != key && o != nil && !o.visit {
		s.stop(o)
	}
	s.stop(st)
	return s.run(st, parent, true), true
}

// end ends the start at of key. After an error, the next try waits from lo,
// twice as long for each error in a row, up to hi.
func (s *starts) end(key startKey, at attempt, err error, now time.Time, lo, hi time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.addrs[key]
	if st == nil || st.gen != at.gen {
		return
	}
	st.cancel(nil)
	st.running, st.cancel = false, nil
	if err == nil {
		st.until, st.wait = time.Time{}, 0
		return
	}
	st.wait = min(max(2*st.wait, lo), hi)
	st.until = now.Add(st.wait)
}

// icmp returns the kept packet start of key for an ICMP error, at most one each
// icmpInterval, or nil. The next packet to the address gives a new one.
func (s *starts) icmp(key startKey, now time.Time) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.addrs[key]
	if st == nil || st.head == nil || now.Sub(st.lastICMP) < icmpInterval {
		return nil
	}
	head := st.head
	st.head, st.lastICMP = nil, now
	return head
}

// once runs open for key, or waits for the open of key that runs. After an
// open that a renew ended, a caller with a live ctx runs open itself.
func (s *starts) once(ctx context.Context, key startKey, open func() error) error {
	s.mu.Lock()
	for o := s.opening[key]; o != nil; o = s.opening[key] {
		s.mu.Unlock()
		<-o.done
		if ctx.Err() != nil || !errors.Is(context.Cause(o.ctx), errRenewed) {
			return o.err
		}
		s.mu.Lock()
	}
	o := &opening{ctx: ctx, done: make(chan struct{})}
	if s.opening == nil {
		s.opening = map[startKey]*opening{}
	}
	s.opening[key] = o
	s.mu.Unlock()
	o.err = open()
	s.mu.Lock()
	delete(s.opening, key)
	s.mu.Unlock()
	close(o.done)
	return o.err
}

// sweep forgets the addresses with no start that runs or waits, after one
// wait more.
func (s *starts) sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, st := range s.addrs {
		if !st.running && now.After(st.until.Add(st.wait)) && now.Sub(st.lastICMP) >= icmpInterval {
			delete(s.addrs, key)
		}
	}
}

// onNoPeer gets the packets that a relay route carries to or from an address
// with no peer session on the link l. The first one starts a peer session, and
// the packets go on at once.
func (a *Agent) onNoPeer(l *psp.Link, pkt []byte, rx bool) {
	addr, ok := unicastDst(pkt)
	head := pkt
	if rx {
		addr, ok = unicastSrc(pkt)
		head = nil
	}
	if !ok {
		return
	}
	key := startKey{l, addr}
	if at, ok := a.starts.begin(context.Background(), key, head, time.Now()); ok {
		go a.start(key, at)
	}
}

// start opens a peer session for key. After an error, the next try waits.
func (a *Agent) start(key startKey, at attempt) {
	ctx, cancel := context.WithTimeout(at.ctx, keysTimeout)
	defer cancel()
	err := a.reach(ctx, key)
	switch {
	case errors.Is(err, ErrUpgrade):
		slog.Warn("Failed to reach a peer that needs a newer agent; upgrade this agent", "destination", key.addr, "error", err)
	case err != nil:
		slog.Debug("Failed to start a peer session; the packets use the default route", "address", key.addr, "error", err)
	}
	a.starts.end(key, at, err, time.Now(), a.retryMin, a.retryMax)
}

// sessionOf returns the attached or draining session with the link l, or nil.
// a.mu must be held.
func (a *Agent) sessionOf(l *psp.Link) *relayConn {
	// A visitor session uses the link of its home, and each other session has its own.
	for _, rc := range a.conns {
		if !rc.visitor() && rc.live() && rc.link == l {
			return rc
		}
	}
	return nil
}

// reach opens a peer session on the relay session of key.link to the
// attachment that routes key.addr, if none is open.
func (a *Agent) reach(ctx context.Context, key startKey) error {
	dst := key.addr
	a.mu.Lock()
	rc := a.sessionOf(key.link)
	var p *peer
	if rc != nil {
		p = a.livePeerTo(rc, dst)
	}
	// The agent does not open a peer session to itself.
	own := slices.ContainsFunc(a.conns, func(o *relayConn) bool { return o.live() && o.ownAddr(dst) })
	a.mu.Unlock()
	switch {
	case rc == nil:
		return errNoRelay
	case own:
		return errNoPeer
	case p != nil:
		return nil
	}
	addr, ok := a.peerAddr(rc, dst)
	if !ok {
		return errNoPeer
	}
	res, err := rc.resolve(ctx, dst)
	if err != nil {
		return err
	}
	return a.starts.once(ctx, startKey{rc.link, addr}, func() error {
		_, err := a.openPeer(ctx, rc, addr, res)
		return err
	})
}

// unreachable sends an ICMP error to the sender of a packet to dst on rc, after
// a NoRoute with no home relay. The code shows whether a Permit denies dst.
func (a *Agent) unreachable(rc *relayConn, dst netip.Addr) {
	head := a.starts.icmp(startKey{rc.link, dst}, time.Now())
	if head == nil {
		return
	}
	ctx, cancel := context.WithTimeout(rc.ctx, keysTimeout)
	defer cancel()
	_, err := rc.resolve(ctx, dst)
	denied := rpc.CodeOf(err) == rpc.PermissionDenied
	a.mu.Lock()
	b := a.bind
	a.mu.Unlock()
	if b == nil {
		return
	}
	if m := unreachable(head, rc.self, denied); m != nil {
		b.Deliver(m)
	}
}
