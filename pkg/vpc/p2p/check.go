// SPDX-License-Identifier: AGPL-3.0-only

package p2p

import (
	"math/rand/v2"
	"sync"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/bfdl"
)

// The values of the role label of the BFD metrics.
const (
	RoleAgent = "client"
	RoleRelay = "server"
)

// Check is one end of the BFD session that checks the PSP path of a relay
// connection. Its packets go in path probes: see Probe.BFD.
type Check struct {
	role   string
	s      *bfdl.Session
	detect time.Duration
	start  time.Time

	mu     sync.Mutex
	lost   bool // The path is lost. It stays true.
	closed bool
}

// NewCheck returns a check in the Down state that sends one packet each tx.
func NewCheck(role string, tx time.Duration) *Check {
	discr := rand.Uint32()
	for discr == 0 {
		discr = rand.Uint32()
	}
	c := &Check{
		role:   role,
		s:      bfdl.NewSession(discr, bfdl.DefaultDetectMult, tx),
		detect: bfdl.DefaultDetectMult * tx,
		start:  time.Now(),
	}
	// The session calls this with its lock held, from Receive and Lost.
	c.s.SetOnStateChange(func(old, new bfdl.State) {
		bfdl.BFDSessionsActive.WithLabelValues(role, old.String()).Dec()
		bfdl.BFDSessionsActive.WithLabelValues(role, new.String()).Inc()
		bfdl.BFDStateTransitions.WithLabelValues(role, old.String(), new.String()).Inc()
	})
	bfdl.BFDSessionsActive.WithLabelValues(role, bfdl.StateDown.String()).Inc()
	return c
}

// Close removes the session from the metrics.
func (c *Check) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		bfdl.BFDSessionsActive.WithLabelValues(c.role, c.s.State().String()).Dec()
	}
}

// Append appends the probe p with the next BFD packet, tagged with key.
func (c *Check) Append(b []byte, p Probe, key *[32]byte) []byte {
	var pkt bfdl.Packet
	c.s.BuildTx(&pkt)
	p.BFD = bfdl.Marshal(&pkt)
	bfdl.BFDPacketsTx.WithLabelValues(c.role).Inc()
	return AppendProbe(b, p, 0, key)
}

// Receive takes the BFD packet of the open probe p. It reports a state change:
// the caller then sends a packet at once, so that the other end sees the state.
func (c *Check) Receive(p Probe) bool {
	var pkt bfdl.Packet
	if err := bfdl.UnmarshalInto(&pkt, p.BFD); err != nil {
		bfdl.BFDPacketErrors.WithLabelValues(c.role, "rx").Inc()
		return false
	}
	bfdl.BFDPacketsRx.WithLabelValues(c.role).Inc()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	old := c.s.State()
	c.s.ProcessRx(&pkt, nil)
	state := c.s.State()
	if old == bfdl.StateUp && state != bfdl.StateUp {
		c.lost = true
	}
	return state != old
}

// Up reports whether each end hears the other one.
func (c *Check) Up() bool { return c.s.State() == bfdl.StateUp }

// Lost reports whether the path is lost at now: the other end said that it is
// Down, or no packet came in the detect time. The session is then Down.
func (c *Check) Lost(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lost || c.closed {
		return c.lost
	}
	last := c.s.LastRx()
	if last.IsZero() {
		// A session that never gets a packet is lost too.
		last = c.start
	}
	if now.Sub(last) <= c.detect {
		return false
	}
	c.lost = true
	bfdl.BFDDetectTimeouts.WithLabelValues(c.role).Inc()
	c.s.DetectTimeout()
	return true
}
