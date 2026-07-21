// Package conntrack provides a lightweight TCP connection tracker that
// implements connection.PacketObserver. It counts recently-active TCP flows
// by watching packet traffic, enabling early drain exit when all connections
// have closed or gone quiet.
package conntrack

import (
	"net/netip"
	"time"

	"sync"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

const (
	// activeWindow bounds how recently a flow must have carried a packet to
	// be counted by ActiveCount. Flows idle longer than this are not worth
	// holding a graceful drain open for, even if the connection is
	// technically still established.
	activeWindow = 30 * time.Second

	// evictAfter is how long an idle flow entry survives before being
	// removed from the map entirely. Flows that die without an observed
	// FIN/RST (agent tunnel drops, abandoned handshakes, lost FINs) have no
	// other eviction path, so this bounds map growth over a long-lived
	// process.
	evictAfter = 5 * time.Minute

	// sweepEvery rate-limits the eviction sweep performed inside OnPacket.
	sweepEvery = time.Minute
)

// flowKey identifies a TCP flow by its 4-tuple, canonicalized so that both
// directions of the same connection map to a single key. Endpoint "a" is
// always the smaller (addr, port) pair.
type flowKey struct {
	a, b netip.AddrPort
}

// canonicalKey builds the canonical flow key for a packet and reports the
// packet's direction relative to it: 0 if the packet was sent by endpoint
// "a", 1 if sent by endpoint "b".
func canonicalKey(info connection.PacketInfo) (flowKey, int) {
	src := netip.AddrPortFrom(info.SrcIP, info.SrcPort)
	dst := netip.AddrPortFrom(info.DstIP, info.DstPort)

	cmp := info.SrcIP.Compare(info.DstIP)
	if cmp < 0 || (cmp == 0 && info.SrcPort <= info.DstPort) {
		return flowKey{a: src, b: dst}, 0
	}
	return flowKey{a: dst, b: src}, 1
}

// flowState tracks half-close state and liveness for a TCP connection.
type flowState struct {
	finSeen  [2]bool // Indexed by canonical direction: [0] = from "a", [1] = from "b".
	lastSeen time.Time
}

// Tracker counts active TCP connections by observing packets via the
// PacketObserver interface. Safe for concurrent use.
type Tracker struct {
	mu        sync.Mutex
	flows     map[flowKey]*flowState
	nextSweep time.Time

	// now is the clock source, overridable in tests.
	now func() time.Time
}

var _ connection.PacketObserver = (*Tracker)(nil)

// NewTracker creates a new TCP connection tracker.
func NewTracker() *Tracker {
	return &Tracker{
		flows: make(map[flowKey]*flowState),
		now:   time.Now,
	}
}

// ActiveCount returns the number of tracked TCP connections that carried
// traffic within the last activeWindow. Flows idle longer than that are
// excluded: they are either dead without an observed teardown or quiet
// keepalive connections that a graceful drain should not wait on.
func (t *Tracker) ActiveCount() int {
	cutoff := t.now().Add(-activeWindow)

	t.mu.Lock()
	defer t.mu.Unlock()

	n := 0
	for _, fs := range t.flows {
		if fs.lastSeen.After(cutoff) {
			n++
		}
	}
	return n
}

// OnPacket implements connection.PacketObserver. It inspects TCP flags to
// track connection lifecycle (SYN opens, FIN/RST closes) and refreshes flow
// liveness on every observed packet. Both directions of a connection map to
// one tracked flow via the canonical key, so the SYN-ACK does not create a
// second entry and each side's FIN is recorded against the same flow.
func (t *Tracker) OnPacket(info connection.PacketInfo) {
	if info.Protocol != connection.ProtocolTCP {
		return
	}

	flags := info.TCPFlags
	key, dir := canonicalKey(info)
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	t.maybeSweep(now)

	if flags&connection.TCPFlagRST != 0 {
		// RST immediately kills the flow regardless of direction.
		delete(t.flows, key)
		return
	}

	if flags&connection.TCPFlagFIN != 0 {
		// FIN: mark half-close. Remove when both directions have FIN'd.
		if fs, ok := t.flows[key]; ok {
			fs.lastSeen = now
			fs.finSeen[dir] = true
			if fs.finSeen[0] && fs.finSeen[1] {
				delete(t.flows, key)
			}
		}
		return
	}

	if flags&connection.TCPFlagSYN != 0 && flags&connection.TCPFlagACK == 0 {
		// Initial SYN opens a new flow. This unconditionally resets any
		// existing entry: a 4-tuple reused after an unobserved close must
		// not inherit the previous connection's half-close state. The
		// SYN-ACK is deliberately not a creation trigger, so a retransmitted
		// SYN-ACK arriving after teardown cannot resurrect a phantom entry.
		t.flows[key] = &flowState{lastSeen: now}
		return
	}

	// Data/ACK/SYN-ACK traffic refreshes liveness for known flows. This is
	// what keeps an active flow counted by ActiveCount, so plain data
	// packets must reach this point rather than being filtered early.
	if fs, ok := t.flows[key]; ok {
		fs.lastSeen = now
	}
}

// maybeSweep evicts flows idle longer than evictAfter, at most once per
// sweepEvery. Called with t.mu held.
func (t *Tracker) maybeSweep(now time.Time) {
	if now.Before(t.nextSweep) {
		return
	}
	t.nextSweep = now.Add(sweepEvery)

	cutoff := now.Add(-evictAfter)
	for key, fs := range t.flows {
		if fs.lastSeen.Before(cutoff) {
			delete(t.flows, key)
		}
	}
}
