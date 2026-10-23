// SPDX-License-Identifier: AGPL-3.0-only

package relay

import "time"

// The times of the announcer states. The QUIC keep-alive of the relay is the probe: an agent that
// answers sends a packet each AgentKeepAlive, or more often.
const (
	// AgentKeepAlive is the QUIC keep-alive period of the listener of a relay for agent
	// connections.
	AgentKeepAlive = 2 * time.Second
	// livenessInterval is the time between two liveness checks.
	livenessInterval = 250 * time.Millisecond
	// suspectAfter is the time with no packet of an agent after which its candidates are suspect.
	suspectAfter = 3 * AgentKeepAlive
	// normalAfter is the time for which a suspect agent must answer before its candidates are
	// normal again: a packet must come this long after the first one.
	normalAfter = 4 * time.Second
	// normalQuiet is the longest time between two packets of an agent that answers. A longer
	// silence starts normalAfter again.
	normalQuiet = AgentKeepAlive * 3 / 2
)

// liveness is the packet record of one agent connection. Only its A reads and writes it.
type liveness struct {
	// received returns the number of packets that QUIC received from the agent. It is nil for a
	// connection with no count, which is never suspect.
	received func() uint64
	count    uint64    // The number of packets at the last check that found a new packet.
	last     time.Time // Time of the last check that found a new packet.
	// since is the start of the packets that came with no silence above normalQuiet between them.
	since  time.Time
	silent bool // The agent is silent, so its candidates are suspect.
}

// observe reads the packet count at the check time now, and reports whether the agent is silent.
// Thus a time is that of a check, not of a packet.
func (l *liveness) observe(now time.Time) bool {
	if l.received == nil {
		return false
	}
	n := l.received()
	switch {
	case n != l.count:
		l.count = n
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
