package socksproxy

import (
	"net"
	"time"
)

// computeConnDeadline returns the deadline to apply to a proxied connection and
// whether any deadline applies at all. idle bounds zero-activity time (measured
// from now); maxLife bounds total lifetime (measured from start). The earlier
// of the two wins. A non-positive duration disables that bound; if both are
// disabled the second return value is false and no deadline should be set
// (preserving the original no-deadline behavior).
func computeConnDeadline(start time.Time, idle, maxLife time.Duration, now time.Time) (time.Time, bool) {
	var deadline time.Time
	set := false

	if idle > 0 {
		deadline = now.Add(idle)
		set = true
	}

	if maxLife > 0 {
		hard := start.Add(maxLife)
		if !set || hard.Before(deadline) {
			deadline = hard
			set = true
		}
	}

	return deadline, set
}

// keepAliver is implemented by *net.TCPConn (and any conn exposing the same
// surface). Netstack/gVisor conns that don't implement it simply skip keepalive
// and rely on the idle/max-lifetime deadlines instead.
type keepAliver interface {
	SetKeepAlive(bool) error
	SetKeepAlivePeriod(time.Duration) error
}

// applyKeepAlive toggles TCP keepalive on conn when supported — enabling it and
// setting the probe period, or actively disabling it. It is a no-op for conns
// that don't expose the keepalive surface (e.g. some netstack conns).
func applyKeepAlive(conn net.Conn, enabled bool, period time.Duration) {
	k, ok := conn.(keepAliver)
	if !ok {
		return
	}
	if !enabled {
		// Actively disable so WithKeepAlive(false) overrides any keepalive the
		// dialer/listener turned on by default, rather than silently leaving it on.
		_ = k.SetKeepAlive(false)
		return
	}
	_ = k.SetKeepAlive(true)
	if period > 0 {
		_ = k.SetKeepAlivePeriod(period)
	}
}

// deadlineGuard rolls an idle (and optional absolute max-lifetime) deadline
// forward on a connection as bytes flow, so a Read/Write that wedges on a
// vanished peer eventually returns os.ErrDeadlineExceeded. That error lets
// go-socks5's io.CopyBuffer return, which unwinds handleConnect and closes both
// ends.
//
// The deadline is re-armed in BOTH directions on every Read/Write (see touch).
// For Go connections (real sockets and gVisor netstack alike) SetDeadline only
// updates the runtime poller's timer — it is not a syscall — so per-call arming
// is cheap. Any active transfer in either direction keeps pushing the deadline
// out, while a connection wedged in both directions arms once and then fires
// after the idle window.
type deadlineGuard struct {
	idle    time.Duration
	maxLife time.Duration
	start   time.Time
}

func newDeadlineGuard(cfg *config, start time.Time) *deadlineGuard {
	return &deadlineGuard{idle: cfg.idleTimeout, maxLife: cfg.maxLifetime, start: start}
}

// touch re-arms the connection's deadline on activity in EITHER direction. It
// sets the read and write deadlines together (conn.SetDeadline) so that traffic
// in one direction keeps the other direction's blocked copy alive: go-socks5
// proxies each CONNECT with two goroutines that share this conn — one only
// reads it, the other only writes it — and a long one-directional transfer
// (download, SSE, server-push) would otherwise let the silent direction's
// deadline fire and tear the whole connection down mid-stream. A connection
// idle in BOTH directions still has its last-armed deadline expire after the
// idle window, which is what reaps the half-open leak.
func (g *deadlineGuard) touch(conn net.Conn) {
	if g.idle <= 0 && g.maxLife <= 0 {
		return
	}

	deadline, ok := computeConnDeadline(g.start, g.idle, g.maxLife, time.Now())
	if !ok {
		return
	}

	_ = conn.SetDeadline(deadline)
}
