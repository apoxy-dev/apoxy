// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"log/slog"
	"net"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/bfdl"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// checkTx is the period of the BFD packets of a session in PSP mode. Tests
// change it.
var checkTx = bfdl.DefaultTxInterval

// pathCheck is the relay end of the BFD session of one agent session in PSP
// mode. Its packets go to the PSP address of the session in path probes.
type pathCheck struct {
	bfd  *p2p.Check
	tx   time.Duration // Period of the packets.
	done chan struct{} // Closed when the check ends.
}

// startCheck starts the PSP path check of s at its change to PSP mode.
// Router.mu must be held.
func (r *Router) startCheck(br *bridge, s *Session) {
	r.stopCheck(s)
	// The packets need the probe keys of the QUIC connection.
	if s.probe == nil {
		return
	}
	c := &pathCheck{bfd: p2p.NewCheck(p2p.RoleRelay, checkTx), tx: checkTx, done: make(chan struct{})}
	s.check = c
	go r.runCheck(br, s, c)
}

// stopCheck ends the PSP path check of s. Router.mu must be held.
func (r *Router) stopCheck(s *Session) {
	if c := s.check; c != nil {
		s.check = nil
		close(c.done)
		c.bfd.Close()
	}
}

// runCheck sends a BFD packet of c to the agent of s at each period, until c
// ends or the PSP path is lost.
func (r *Router) runCheck(br *bridge, s *Session, c *pathCheck) {
	t := time.NewTicker(c.tx)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case now := <-t.C:
			if c.bfd.Lost(now) {
				r.pathLost(br, s, c, now)
				return
			}
			r.sendCheck(br, s, c)
		}
	}
}

// sendCheck sends one BFD packet with the state of the relay end to the PSP
// address of s. The agent reads its own source address from the packet.
func (r *Router) sendCheck(br *bridge, s *Session, c *pathCheck) {
	r.mu.RLock()
	to := s.addr
	r.mu.RUnlock()
	if !to.IsValid() {
		return
	}
	k := &s.probe.keys
	_, _ = br.tr.WriteTo(c.bfd.Append(nil, p2p.Probe{Reply: true, SID: k.SID, Seen: to}, &k.Listener), net.UDPAddrFromAddrPort(to))
}

// checkPacket gives the BFD packet of the probe pr of s to its PSP path
// check. A session in QUIC mode has no check, and the packet drops.
func (r *Router) checkPacket(s *Session, pr p2p.Probe, now time.Time) {
	br := r.bridge.Load()
	r.mu.RLock()
	c := s.check
	r.mu.RUnlock()
	if c == nil || br == nil {
		return
	}
	changed := c.bfd.Receive(pr)
	switch {
	case c.bfd.Lost(now):
		r.pathLost(br, s, c, now)
	case changed:
		// The agent sees the new state at once, not at the next period.
		r.sendCheck(br, s, c)
	}
}

// pathLost changes s to QUIC mode after its PSP path check c failed. The relay
// SAs and their rekeys end. The agent changes from its own end of the check.
func (r *Router) pathLost(br *bridge, s *Session, c *pathCheck, now time.Time) {
	// The agent learns from this packet that the relay is Down.
	r.sendCheck(br, s, c)
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.check != c {
		return
	}
	r.stopCheck(s)
	if s.closed {
		return
	}
	s.sync.mode = dp.Mode_MODE_QUIC
	if s.rx != nil {
		r.dropRelaySAs(br, s, now)
	}
	if s.tx != nil {
		revokeTx(s.tx)
		s.tx = nil
	}
	slog.Info("PSP path to an agent stopped; changed its session from PSP mode to QUIC mode", "vpc", s.id.VPC.UID, "agent", s.name)
}
