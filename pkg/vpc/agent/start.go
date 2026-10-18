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
	// peer is the address of the peer session that the last start opens.
	peer netip.Addr
	// head is the start of a packet to the address since the last ICMP error,
	// for an ICMP error after a NoRoute of the relay.
	head     []byte
	lastICMP time.Time
}

// attempt is one start of an address. A renew cancels its context.
type attempt struct {
	ctx context.Context
	gen uint64
	// open is the open that renew keeps for a NoRoute visit. The starts
	// that open the peer after the renew wait for it.
	open *opening
}

type opening struct {
	gen     uint64   // Of the start that opens, or 0.
	renewed bool     // A renew ended the start that opens.
	prev    *opening // The open that ends before a NoRoute visit opens.
	waits   int      // Callers that waited for the open.
	done    chan struct{}
	err     error
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
	st.peer = netip.Addr{}
	return attempt{ctx: ctx, gen: s.gen}
}

// stop cancels the start of st on link that runs and ends its wait. The
// callers that wait for its open go on to the next one. s.mu must be held.
func (s *starts) stop(link *psp.Link, st *start) {
	if st.running {
		st.cancel(errRenewed)
		k := startKey{link, st.peer}
		if o := s.opening[k]; o != nil && o.gen == st.gen {
			o.renewed = true
		}
	}
	st.running, st.gen, st.cancel, st.peer = false, 0, nil, netip.Addr{}
	st.until, st.wait = time.Time{}, 0
}

// record keeps peer as the address that the start at of key opens. It reports
// false after a renew ended the start.
func (s *starts) record(key startKey, at attempt, peer netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.addrs[key]
	if st == nil || st.gen != at.gen {
		return false
	}
	st.peer = peer
	return true
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

// renew ends the ordinary start of dst, the NoRoute address, and its wait
// while it has no peer. Then, if no NoRoute visit for key runs or waits, it
// ends the ordinary starts on the link of key that open key.addr, and their
// waits, and begins a visit for key.
func (s *starts) renew(parent context.Context, key startKey, dst netip.Addr,
	now time.Time) (attempt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// An address in a prefix of the peer has its own start: see peerAddr.
	o := s.addrs[startKey{key.link, dst}]
	if o != nil && !o.visit && !o.peer.IsValid() {
		s.stop(key.link, o)
	}
	st := s.entry(key)
	if st == nil || st.visit && (st.running || now.Before(st.until)) {
		return attempt{}, false
	}
	for k, o := range s.addrs {
		if k.link != key.link || o.visit || !o.running && o.wait == 0 {
			continue
		}
		if o.peer == key.addr {
			s.stop(key.link, o)
		}
	}
	s.stop(key.link, st)
	at := s.run(st, parent, true)
	// The visit opens after the open that runs. A start that opens the peer
	// later waits for the visit, so no ended start opens before it.
	at.open = &opening{gen: at.gen, prev: s.opening[key],
		done: make(chan struct{})}
	if s.opening == nil {
		s.opening = map[startKey]*opening{}
	}
	s.opening[key] = at.open
	return at, true
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

// once runs open for key, or waits for the open of key that runs. at is the
// start of the caller, or none. An ended start opens nothing. After an open
// that a renew ended, a caller with a live ctx goes on to the next open.
func (s *starts) once(ctx context.Context, key startKey, at attempt,
	open func() error) error {
	s.mu.Lock()
	o := at.open
	if o == nil {
		for o = s.opening[key]; o != nil; o = s.opening[key] {
			o.waits++
			s.mu.Unlock()
			<-o.done
			s.mu.Lock()
			if ctx.Err() != nil || !o.renewed {
				s.mu.Unlock()
				return o.err
			}
		}
		if ctx.Err() != nil {
			s.mu.Unlock()
			return context.Cause(ctx)
		}
		o = &opening{gen: at.gen, done: make(chan struct{})}
		if s.opening == nil {
			s.opening = map[startKey]*opening{}
		}
		s.opening[key] = o
	}
	prev := o.prev
	o.prev = nil
	s.mu.Unlock()
	if prev != nil {
		<-prev.done
	}
	o.err = open()
	s.mu.Lock()
	if s.opening[key] == o {
		delete(s.opening, key)
	}
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
	err := a.reach(ctx, key, at)
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
// attachment that routes key.addr, if none is open. at is the start of key.
func (a *Agent) reach(ctx context.Context, key startKey, at attempt) error {
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
	// A NoRoute for addr ends this start from here on: see starts.renew.
	if !a.starts.record(key, at, addr) {
		return errRenewed
	}
	res, err := rc.resolve(ctx, dst)
	if err != nil {
		return err
	}
	return a.starts.once(ctx, startKey{rc.link, addr}, at, func() error {
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
