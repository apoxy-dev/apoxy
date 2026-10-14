// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"log/slog"
	"sync/atomic"
	"time"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// The times of the announcer states. The QUIC keep-alive of the relay is the
// probe: an agent that answers sends a packet each AgentKeepAlive, or more often.
const (
	// AgentKeepAlive is the QUIC keep-alive period of the listener of a relay
	// for agent sessions.
	AgentKeepAlive = 2 * time.Second
	// livenessInterval is the time between two liveness checks.
	livenessInterval = 250 * time.Millisecond
	// suspectAfter is the time with no packet of an agent after which the
	// entries of its session are suspect.
	suspectAfter = 3 * AgentKeepAlive
	// normalAfter is the time for which a suspect agent must answer before its
	// entries are normal again: a packet must come this long after the first one.
	normalAfter = 4 * time.Second
	// normalQuiet is the longest time between two packets of an agent that
	// answers. A longer silence starts normalAfter again.
	normalQuiet = AgentKeepAlive * 3 / 2
	// holdTime is the time after an attach, or after a return to the normal
	// state, in which an entry does not replace a live active announcer.
	holdTime = 30 * time.Second
	// memberLostTime is the time after which the entries of a lost mesh member
	// go, if the member is still down.
	memberLostTime = 5 * time.Minute
)

const (
	stateNormal   = dp.AnnouncerState_ANNOUNCER_STATE_NORMAL
	stateDraining = dp.AnnouncerState_ANNOUNCER_STATE_DRAINING
	stateSuspect  = dp.AnnouncerState_ANNOUNCER_STATE_SUSPECT
	// numAnnouncerStates is the number of states that this build sets.
	numAnnouncerStates = 3
)

// liveness is what the relay knows of the packets of the agent of one session.
// Only checkLiveness writes the fields below heard. Each other reader holds
// Router.mu for writing.
type liveness struct {
	// heard is the mark that the tracer sets for each packet of the agent. It
	// is nil for a session with no trace, which is never suspect.
	heard *atomic.Bool
	last  time.Time // Time of the last check that found the mark.
	// since is the start of the packets that came with no silence above
	// normalQuiet between them.
	since  time.Time
	silent bool // The agent is silent, so its entries are suspect.
}

// observe takes the mark of the tracer at the check time now, and reports
// whether the agent is silent. Thus a time is that of a check, not of a packet.
func (l *liveness) observe(now time.Time) bool {
	if l.heard == nil {
		return false
	}
	switch {
	case l.heard.Swap(false):
		if now.Sub(l.last) > normalQuiet {
			l.since = now
		}
		l.last = now
		if now.Sub(l.since) >= normalAfter {
			l.silent = false
		}
	case now.Sub(l.last) >= suspectAfter:
		l.silent = true
	}
	return l.silent
}

// entryState returns the state that the entries of s must have now. Router.mu
// must be held.
func (r *Router) entryState(s *Session) dp.AnnouncerState {
	switch {
	case s.live.silent:
		return stateSuspect
	case r.draining:
		return stateDraining
	}
	return stateNormal
}

// checkLiveness gives the entries of each session of this relay the suspect
// state when its agent is silent for suspectAfter, and takes the state away
// when the agent answers again for normalAfter. One goroutine calls it: Run.
func (r *Router) checkLiveness(now time.Time) {
	var changed []*Session
	r.mu.RLock()
	for s := range r.sessions {
		if s.live.observe(now); r.entryState(s) != s.state {
			changed = append(changed, s)
		}
	}
	r.mu.RUnlock()
	if len(changed) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range changed {
		reason := "agent answers again"
		if s.live.silent {
			reason = "no packet from the agent"
		}
		r.setState(s, r.entryState(s), reason, now)
	}
}

// startDrain gives the entries of each session of this relay the draining
// state. A suspect session stays suspect. Router.mu must be held for writing.
func (r *Router) startDrain(now time.Time) {
	r.draining = true
	for s := range r.sessions {
		r.setState(s, r.entryState(s), "relay drains", now)
	}
}

// setState gives the record of each attachment of s the state, sends the
// attachments to the mesh, and selects again for each prefix of s. A return to
// the normal state starts a new hold time. Router.mu must be held for writing.
func (r *Router) setState(s *Session, state dp.AnnouncerState, reason string, now time.Time) {
	if s.closed || s.state == state {
		return
	}
	s.state = state
	for _, a := range s.attachments {
		a.gen = r.nextGen(now)
		a.cand.restate(state, now)
		r.announce(s, a)
	}
	if d := r.domains[s.id.VPC]; d != nil {
		// A prefix is in s.routes one time for each entry of s. The second
		// selection for it finds the same order.
		for _, p := range s.routes {
			set := d.routes[p]
			if set == nil {
				continue
			}
			for _, e := range set.entries {
				// An entry of AddRoute has no attachment: the entry has its own record.
				if e.s == s && e.att == nil {
					e.restate(state, now)
				}
			}
			r.restated(d, p, set)
		}
	}
	if len(s.routes) == 0 {
		return
	}
	r.stateChanges[state].Add(1)
	slog.Info("Changed the state of an agent session", "vpc", s.id.VPC.UID, "agent", s.name,
		"relay", r.name, "state", stateLabel(state), "reason", reason)
}
