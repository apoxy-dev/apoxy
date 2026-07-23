package tunnel

import (
	"time"

	"github.com/quic-go/quic-go"
)

const (
	ApplicationCodeOK            quic.ApplicationErrorCode = quic.ApplicationErrorCode(quic.NoError)
	ApplicationCodeInternalError quic.ApplicationErrorCode = quic.ApplicationErrorCode(quic.InternalError)
)

// Same-server connection diversity. An agent process that dials a server
// already holding one of its connections is rejected with 409 Conflict and
// HeaderRejectReason set to RejectReasonAgentConnExists so it re-dials from a
// fresh UDP 4-tuple, giving the load balancer a chance to pick a different
// backend. Without this, min-conns > 1 buys no drain resilience: all of an
// agent's connections can hash onto one replica, and that replica's drain
// zeroes the agent's entire endpoint set. The client marks its last re-dial
// with QueryParamConnFinal, which the server honors unconditionally, so
// agents still connect when every dial lands on the same server (e.g. a
// single-replica region) and no shared retry-cap constant has to agree
// across independently deployed client and server binaries. Old clients
// never send the attempt param and are never rejected.
const (
	// QueryParamConnAttempt is the /connect query-string key carrying the
	// 0-based dial attempt number. Its presence signals that the client
	// understands same-server rejection.
	QueryParamConnAttempt = "conn_attempt"
	// QueryParamConnFinal, when set to "1", marks the client's final dial
	// attempt: the server must accept it even if it already holds a
	// connection from this agent process. The client owns "this is my last
	// try" — deriving it server-side from a shared constant would lock old
	// agents out under version skew.
	QueryParamConnFinal = "conn_final"
	// QueryParamReplacesConnID names a dead connection this dial replaces.
	// The server excludes it from the diversity check (an agent must not be
	// rejected against its own corpse while the server waits out the QUIC
	// idle timeout) and evicts it immediately.
	QueryParamReplacesConnID = "replaces_conn"
	// HeaderRejectReason is the response header carrying a machine-readable
	// reason for a rejected /connect request.
	HeaderRejectReason = "X-Apoxy-Reject-Reason"
	// RejectReasonAgentConnExists indicates the server already holds a live
	// connection from this agent process for this tunnel.
	RejectReasonAgentConnExists = "agent-conn-exists"
	// MaxSameServerDialAttempts is the total number of dials the client makes
	// before marking an attempt final and settling for a server that already
	// has one of its connections. Client-side knob only — the server keys
	// acceptance on QueryParamConnFinal, never on this constant.
	MaxSameServerDialAttempts = 5

	// sameServerRedialBackoffBase is the backoff before the first re-dial
	// after a same-server rejection. Each subsequent re-dial doubles it, with
	// up to 50% jitter added so simultaneously-rejected workers don't re-dial
	// in lockstep (worst-case total wait before the final attempt is ~2.2s).
	sameServerRedialBackoffBase = 100 * time.Millisecond
)

var quicConfig *quic.Config = &quic.Config{
	EnableDatagrams:                true,
	DisableCongestionControl:       true,
	InitialPacketSize:              1350,
	InitialConnectionReceiveWindow: 5 * 1000 * 1000,
	MaxConnectionReceiveWindow:     100 * 1000 * 1000,
	KeepAlivePeriod:                5 * time.Second,
	MaxIdleTimeout:                 15 * time.Second,
}
