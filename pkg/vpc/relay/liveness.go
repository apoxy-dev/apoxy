// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"

	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

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
	// heard is the mark that the tracer sets for each packet of the agent. It is nil for a
	// connection with no trace, which is never suspect.
	heard *atomic.Bool
	last  time.Time // Time of the last check that found the mark.
	// since is the start of the packets that came with no silence above normalQuiet between them.
	since  time.Time
	silent bool // The agent is silent, so its candidates are suspect.
}

// observe takes the mark of the tracer at the check time now, and reports whether the agent is
// silent. Thus a time is that of a check, not of a packet.
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

type traceKey struct{}

// connTrace is what the tracer of one connection keeps for its A.
type connTrace struct {
	rtt atomic.Int64 // Smoothed RTT in nanoseconds.
	// heard is set for each packet of an agent. The liveness check clears it.
	heard atomic.Bool
}

// TraceContext gives a new connection the place for what TraceRTT keeps. It is the ConnContext of
// the QUIC transport of a relay with TraceRTT.
func TraceContext(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
	return context.WithValue(ctx, traceKey{}, new(connTrace)), nil
}

// TraceRTT is the Tracer of a relay with TraceContext. It keeps the smoothed RTT for
// AttachmentStats and marks agent packets for liveness.
func TraceRTT(ctx context.Context, _ logging.Perspective, _ quic.ConnectionID) *logging.ConnectionTracer {
	tr := traceOf(ctx)
	if tr == nil {
		return nil
	}
	t := &logging.ConnectionTracer{
		UpdatedMetrics: func(s *logging.RTTStats, _, _ logging.ByteCount, _ int) {
			tr.rtt.Store(int64(s.SmoothedRTT()))
		},
	}
	// The received-packet hook costs a frame list for each packet, so only an agent connection
	// gets it. Hooks of one connection run in turn.
	t.ChoseALPN = func(alpn string) {
		if alpn == dpv1.ALPNRelay {
			t.ReceivedShortHeaderPacket = func(*logging.ShortHeader, logging.ByteCount, logging.ECN, []logging.Frame) {
				tr.heard.Store(true)
			}
		}
	}
	return t
}

// traceOf returns what the tracer keeps for the connection of ctx, or nil.
func traceOf(ctx context.Context) *connTrace {
	tr, _ := ctx.Value(traceKey{}).(*connTrace)
	return tr
}
