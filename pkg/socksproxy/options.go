package socksproxy

import "time"

// Connection-lifecycle defaults.
//
// These exist because go-socks5 proxies each CONNECT with two io.CopyBuffer
// goroutines and only returns from ServeConn (closing the connection and
// releasing its 256KB buffers + fds) once BOTH directions finish. A peer that
// vanishes half-open (NAT idle-drop, client crash — no FIN) leaves a copy
// blocked on a Read that never errors, so the connection, its goroutines, and
// its buffers leak forever. The guards below give a wedged Read a way to
// eventually error so go-socks5 can unwind.
const (
	// defaultKeepAlive enables TCP keepalive so the kernel detects a dead peer
	// (unanswered probes) and errors the socket promptly, without disturbing a
	// genuinely idle-but-alive connection (which answers probes). It is the
	// behavior-preserving first line of defense for the half-open leak; the
	// idle timeout below is the deterministic backstop for what keepalive can't
	// catch (a peer whose kernel still ACKs probes but whose application is gone).
	defaultKeepAlive = true
	// defaultKeepAlivePeriod is the keepalive probe interval.
	defaultKeepAlivePeriod = 30 * time.Second
	// defaultIdleTimeout is the deterministic backstop: a proxied connection
	// with zero application bytes in EITHER direction for this long is
	// force-closed, EVEN IF TCP keepalive shows the peer is still alive. It is
	// therefore sized generously — far longer than typical app-level keepalive
	// intervals (ws pings, gRPC keepalive, SSH ServerAlive) so that sessions
	// with any periodic application traffic are spared — while still bounding
	// the hours-long fully-idle wedges that caused the production pile-up. NOTE:
	// a genuinely silent-but-alive connection (idle SSH without
	// ServerAliveInterval, a >10m long-poll) IS closed at this bound; raise it
	// via WithIdleTimeout or add an application-level heartbeat to keep such
	// connections open. Active one-directional streams are NOT affected — the
	// deadline guard re-arms on traffic in either direction (see lifecycle.go).
	defaultIdleTimeout = 10 * time.Minute
	// defaultMaxLifetime is disabled (0): an absolute cap would tear down
	// legitimately long-lived, actively-streaming connections. Operators who
	// want a hard ceiling can opt in via WithMaxLifetime.
	defaultMaxLifetime = 0
)

// config holds tunable connection-lifecycle parameters for a ProxyServer.
type config struct {
	idleTimeout     time.Duration
	maxLifetime     time.Duration
	keepAlive       bool
	keepAlivePeriod time.Duration
}

func defaultConfig() *config {
	return &config{
		idleTimeout:     defaultIdleTimeout,
		maxLifetime:     defaultMaxLifetime,
		keepAlive:       defaultKeepAlive,
		keepAlivePeriod: defaultKeepAlivePeriod,
	}
}

// Option configures a ProxyServer's connection lifecycle.
type Option func(*config)

// WithIdleTimeout bounds how long a proxied connection may transfer zero bytes
// in either direction before it is force-closed. A non-positive value disables
// the idle backstop (keepalive and any max-lifetime still apply).
func WithIdleTimeout(d time.Duration) Option {
	return func(c *config) { c.idleTimeout = d }
}

// WithMaxLifetime caps the absolute lifetime of a proxied connection measured
// from when it was accepted/dialed. A non-positive value (the default)
// disables the cap so long-lived active streams are not interrupted.
func WithMaxLifetime(d time.Duration) Option {
	return func(c *config) { c.maxLifetime = d }
}

// WithKeepAlive toggles TCP keepalive on proxied connections and sets the probe
// period. A non-positive period leaves the system default period in place.
func WithKeepAlive(enabled bool, period time.Duration) Option {
	return func(c *config) {
		c.keepAlive = enabled
		c.keepAlivePeriod = period
	}
}
