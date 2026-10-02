// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

const (
	// holdPackets is the most packets that wait for one destination.
	holdPackets = 128
	// holdBytes is the most bytes that wait for all destinations.
	holdBytes = 4 << 20
	// holdEntries is the most destinations that wait or failed.
	holdEntries = 1024
	// holdTime is the time to open a peer session for waiting packets.
	holdTime = 5 * time.Second
	// After a failed open, packets to the destination drop for these times.
	notFoundWait = 5 * time.Second
	deniedWait   = 30 * time.Second
	minRetry     = time.Second
	maxRetry     = time.Minute
	// icmpInterval is the shortest time between ICMP errors for a destination
	// that failed.
	icmpInterval = time.Second
)

var (
	errNoRelay = errors.New("no relay session")
	errNoPeer  = errors.New("no attachment routes the destination")
)

// holds keeps the packets to destinations with no peer session while one
// opens, and the destinations that failed to open.
type holds struct {
	mu      sync.Mutex
	waiting map[netip.Addr][][]byte
	failed  map[netip.Addr]*failure
	opening map[netip.Addr]*opening // Peer sessions that open, by peer address.
	bytes   int                     // Bytes in waiting.
	drops   atomic.Uint64
}

// failure is a destination that failed to open, until a time.
type failure struct {
	until    time.Time
	wait     time.Duration
	denied   bool
	lastICMP time.Time
}

type opening struct {
	done chan struct{}
	err  error
}

// hold keeps pkt until a peer session for dst opens, and reports whether the
// caller must open it. When dst failed, it reports the ICMP error to send.
func (h *holds) hold(dst netip.Addr, pkt []byte, now time.Time) (open, icmp, denied bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if f := h.failed[dst]; f != nil && now.Before(f.until) {
		h.drops.Add(1)
		if now.Sub(f.lastICMP) < icmpInterval {
			return false, false, false
		}
		f.lastICMP = now
		return false, true, f.denied
	}
	q, ok := h.waiting[dst]
	if (!ok && len(h.waiting)+len(h.failed) >= holdEntries) || len(q) >= holdPackets || h.bytes+len(pkt) > holdBytes {
		h.drops.Add(1)
		return false, false, false
	}
	if h.waiting == nil {
		h.waiting = map[netip.Addr][][]byte{}
	}
	h.waiting[dst] = append(q, bytes.Clone(pkt))
	h.bytes += len(pkt)
	return !ok, false, false
}

// done removes the packets of dst and returns them. When err is not nil, dst
// fails for a time, and the packets drop.
func (h *holds) done(dst netip.Addr, err error, now time.Time) (pkts [][]byte, denied bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	pkts = h.waiting[dst]
	delete(h.waiting, dst)
	for _, p := range pkts {
		h.bytes -= len(p)
	}
	if err == nil {
		delete(h.failed, dst)
		return pkts, false
	}
	h.drops.Add(uint64(len(pkts)))
	return pkts, h.fail(dst, err, now)
}

// fail makes dst fail for the wait of err, and reports whether a Permit denied
// it. h.mu must be held.
func (h *holds) fail(dst netip.Addr, err error, now time.Time) bool {
	f := h.failed[dst]
	if f == nil {
		if h.failed == nil {
			h.failed = map[netip.Addr]*failure{}
		}
		f = &failure{}
		h.failed[dst] = f
	}
	f.denied = false
	switch {
	case rpc.CodeOf(err) == rpc.NotFound, errors.Is(err, psp.ErrNoRoute), errors.Is(err, errNoPeer):
		f.wait = notFoundWait
	case rpc.CodeOf(err) == rpc.PermissionDenied:
		f.wait, f.denied = deniedWait, true
	default:
		// The wait doubles for each failure in a row, from minRetry to maxRetry.
		f.wait = min(max(2*f.wait, minRetry), maxRetry)
	}
	f.until, f.lastICMP = now.Add(f.wait), now
	return f.denied
}

// once runs open for key, or waits for the open of key that runs.
func (h *holds) once(key netip.Addr, open func() error) error {
	h.mu.Lock()
	if o := h.opening[key]; o != nil {
		h.mu.Unlock()
		<-o.done
		return o.err
	}
	o := &opening{done: make(chan struct{})}
	if h.opening == nil {
		h.opening = map[netip.Addr]*opening{}
	}
	h.opening[key] = o
	h.mu.Unlock()
	o.err = open()
	h.mu.Lock()
	delete(h.opening, key)
	h.mu.Unlock()
	close(o.done)
	return o.err
}

// sweep forgets the failures that ended one wait ago.
func (h *holds) sweep(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for dst, f := range h.failed {
		if now.After(f.until.Add(f.wait)) {
			delete(h.failed, dst)
		}
	}
}

// Stats are the packet counters of the agent.
type Stats struct {
	// HoldDrops counts the packets to destinations with no peer session that
	// the agent did not send.
	HoldDrops uint64
}

// Stats returns the packet counters of the agent.
func (a *Agent) Stats() Stats {
	return Stats{HoldDrops: a.holds.drops.Load()}
}

// onNoRoute gets the packets that the binding has no route or no SA for. The
// first packet to a unicast destination opens a peer session for it.
func (a *Agent) onNoRoute(pkt []byte) {
	dst, ok := unicastDst(pkt)
	if !ok {
		return
	}
	open, icmp, denied := a.holds.hold(dst, pkt, time.Now())
	if icmp {
		go a.unreachable([][]byte{bytes.Clone(pkt[:min(len(pkt), maxICMPBody)])}, denied)
	}
	if open {
		go a.openHeld(dst)
	}
}

// openHeld opens a peer session for dst and sends the packets that wait for it.
// On an error it drops them and sends ICMP errors to their senders.
func (a *Agent) openHeld(dst netip.Addr) {
	ctx, cancel := context.WithTimeout(context.Background(), holdTime)
	defer cancel()
	err := a.reach(ctx, dst)
	pkts, denied := a.holds.done(dst, err, time.Now())
	if err == nil {
		a.mu.Lock()
		b := a.bind
		a.mu.Unlock()
		sent := 0
		if b == nil {
			err = errNoRelay
		} else if sent, err = b.Send(pkts); err == nil {
			return
		}
		pkts = pkts[sent:]
		a.holds.drops.Add(uint64(len(pkts)))
		a.holds.mu.Lock()
		denied = a.holds.fail(dst, err, time.Now())
		a.holds.mu.Unlock()
	}
	a.unreachable(pkts, denied)
}

// reach opens a peer session to the attachment that routes dst, if none is
// open, and waits for its SAs.
func (a *Agent) reach(ctx context.Context, dst netip.Addr) error {
	a.mu.Lock()
	rc := a.rc
	p := a.peerTo(rc, dst)
	a.mu.Unlock()
	if rc == nil {
		return errNoRelay
	}
	if p != nil {
		return a.waitKeys(ctx, p, dst)
	}
	addr, ok := a.peerAddr(rc, dst)
	if !ok {
		return errNoPeer
	}
	res, err := rc.resolve(ctx, dst)
	if err != nil {
		return err
	}
	return a.holds.once(addr, func() error { return a.connect(ctx, rc, addr, res) })
}

// unreachable sends an ICMP error for each packet to its sender.
func (a *Agent) unreachable(pkts [][]byte, denied bool) {
	a.mu.Lock()
	b, rc := a.bind, a.rc
	a.mu.Unlock()
	if b == nil || rc == nil {
		return
	}
	for _, pkt := range pkts {
		if m := unreachable(pkt, rc.self, denied); m != nil {
			b.Deliver(m)
		}
	}
}
