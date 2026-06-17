package socksproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"io"

	"github.com/dpeckett/network"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"
	"github.com/things-go/go-socks5/statute"
)

// ProxyServer is a SOCKS5 proxy server.
type ProxyServer struct {
	Addr           string
	server         *socks5.Server
	proxyCtx       context.Context
	proxyCtxCancel context.CancelFunc
	activeConns    int64 // atomic counter for active connections
	cfg            *config

	// conns tracks in-flight downstream connections so Close can reap any that
	// are still wedged at shutdown. Closing the downstream end unwinds
	// go-socks5's handleConnect, which closes the matching upstream end via its
	// deferred Close.
	mu      sync.Mutex
	conns   map[*downstreamConnWrapper]struct{}
	closing bool // set under mu once Close has snapshotted conns
}

// trackConn registers an in-flight connection for shutdown reaping. It returns
// false if the server is already closing, in which case the caller must close
// the connection itself — this closes the race where a connection accepted
// after Close's snapshot would otherwise be tracked but never reaped.
func (s *ProxyServer) trackConn(c *downstreamConnWrapper) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *ProxyServer) untrackConn(c *downstreamConnWrapper) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// NewServer creates a new SOCKS5 proxy server.
// Requests to private addresses (excluding loopback) will be forwarded to the upstream network.
// Requests to public addresses will be forwarded to the fallback network.
func NewServer(addr string, upstream network.Network, fallback network.Network, opts ...Option) *ProxyServer {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	options := []socks5.Option{
		socks5.WithDialAndRequest((&dialer{upstream: upstream, fallback: fallback, cfg: cfg}).DialContext),
		socks5.WithResolver(&resolver{net: upstream}),
		socks5.WithBufferPool(bufferpool.NewPool(256 * 1024)),
		socks5.WithLogger(&logger{}),
		// No auth as we'll be binding exclusively to a local interface.
		socks5.WithAuthMethods([]socks5.Authenticator{&authTracker{authenticator: socks5.NoAuthAuthenticator{}}}),
	}

	// Set up the context for the proxy server
	proxyCtx, proxyCtxCancel := context.WithCancel(context.Background())

	return &ProxyServer{
		Addr:           addr,
		server:         socks5.NewServer(options...),
		proxyCtx:       proxyCtx,
		proxyCtxCancel: proxyCtxCancel,
		cfg:            cfg,
		conns:          make(map[*downstreamConnWrapper]struct{}),
	}
}

func (s *ProxyServer) Close() error {
	s.proxyCtxCancel()

	// Reap any in-flight connections. Closing the downstream end makes
	// go-socks5's blocked io.CopyBuffer return, which unwinds handleConnect
	// (closing the upstream end via its deferred Close) and lets both proxy
	// goroutines exit. Mark closing and snapshot under the lock, then close
	// outside it so each wrapper's own Close (which deregisters) doesn't
	// deadlock on s.mu. Setting closing under the same lock makes trackConn
	// reject any connection accepted after this snapshot, so none can slip
	// through tracked-but-unreaped.
	s.mu.Lock()
	s.closing = true
	pending := make([]*downstreamConnWrapper, 0, len(s.conns))
	for c := range s.conns {
		pending = append(pending, c)
	}
	s.mu.Unlock()

	for _, c := range pending {
		_ = c.Close()
	}

	slog.Info("SOCKS proxy server closing",
		slog.String("addr", s.Addr),
		slog.Int("reaped_connections", len(pending)),
		slog.Int64("active_connections", atomic.LoadInt64(&s.activeConns)))
	return nil
}

func (s *ProxyServer) ListenAndServe(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	slog.Info("SOCKS proxy server started", slog.String("address", s.Addr))

	// Wrap the listener to track connections
	trackedListener := &connTrackingListener{
		Listener: lis,
		srv:      s,
	}

	go func() {
		select {
		case <-ctx.Done():
		case <-s.proxyCtx.Done():
		}

		slog.Info("SOCKS proxy server shutting down", slog.String("address", s.Addr))
		if err := trackedListener.Close(); err != nil {
			slog.Warn("failed to close listener", slog.Any("error", err))
		}
	}()

	if err := s.server.Serve(trackedListener); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}

// connTrackingListener wraps a net.Listener to track downstream connection metrics.
type connTrackingListener struct {
	net.Listener
	srv *ProxyServer
}

func (l *connTrackingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	s := l.srv
	SocksConnectionRequests.Inc()
	atomic.AddInt64(&s.activeConns, 1)
	SocksConnectionsActive.Inc()

	// Detect a dead/half-open downstream peer (unanswered keepalive probes) so a
	// wedged copy eventually errors instead of pinning the connection forever.
	applyKeepAlive(conn, s.cfg.keepAlive, s.cfg.keepAlivePeriod)

	now := time.Now()
	remoteAddr := conn.RemoteAddr().String()
	slog.Info("SOCKS connection accepted",
		slog.String("remote_addr", remoteAddr),
		slog.Int64("active_connections", atomic.LoadInt64(&s.activeConns)))

	wrapped := &downstreamConnWrapper{
		Conn:        conn,
		activeConns: &s.activeConns,
		startTime:   now,
		remoteAddr:  remoteAddr,
		guard:       newDeadlineGuard(s.cfg, now),
	}
	wrapped.onClose = func() { s.untrackConn(wrapped) }
	if !s.trackConn(wrapped) {
		// Server is shutting down; refuse the late connection and stop serving.
		// wrapped.Close balances the metric counters incremented above.
		_ = wrapped.Close()
		return nil, net.ErrClosed
	}

	return wrapped, nil
}

// downstreamConnWrapper wraps a net.Conn to track metrics for incoming SOCKS connections.
type downstreamConnWrapper struct {
	net.Conn
	activeConns  *int64
	startTime    time.Time
	remoteAddr   string
	bytesRead    int64
	bytesWritten int64
	destType     string // Set by dialer
	guard        *deadlineGuard
	onClose      func()
	closeOnce    sync.Once
	closeErr     error
}

func (c *downstreamConnWrapper) Read(b []byte) (int, error) {
	c.guard.touch(c.Conn)
	n, err := c.Conn.Read(b)
	atomic.AddInt64(&c.bytesRead, int64(n))
	return n, err
}

func (c *downstreamConnWrapper) Write(b []byte) (int, error) {
	c.guard.touch(c.Conn)
	n, err := c.Conn.Write(b)
	atomic.AddInt64(&c.bytesWritten, int64(n))
	return n, err
}

func (c *downstreamConnWrapper) Close() error {
	// Close is invoked both by go-socks5's ServeConn defer and by the server's
	// shutdown reaper, so it must be idempotent and concurrency-safe.
	c.closeOnce.Do(func() {
		duration := time.Since(c.startTime).Seconds()
		atomic.AddInt64(c.activeConns, -1)
		SocksConnectionsActive.Dec()

		if c.onClose != nil {
			c.onClose()
		}

		// Note: Data transfer metrics are handled by dialedConn now

		// Log connection closure at info level. Load the byte counters
		// atomically: the shutdown reaper can call Close while a Proxy
		// goroutine is still writing them via atomic.AddInt64.
		slog.Info("SOCKS connection closed",
			slog.Float64("duration_seconds", duration),
			slog.Int64("bytes_read", atomic.LoadInt64(&c.bytesRead)),
			slog.Int64("bytes_written", atomic.LoadInt64(&c.bytesWritten)),
			slog.String("destination_type", c.destType),
			slog.Int64("active_connections", atomic.LoadInt64(c.activeConns)))

		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

// upstreamConnWrapper wraps a net.Conn to track metrics for outgoing dialed connections.
type upstreamConnWrapper struct {
	net.Conn
	logger       *slog.Logger
	destType     string
	bytesRead    int64
	bytesWritten int64
	startTime    time.Time
	guard        *deadlineGuard
}

func (c *upstreamConnWrapper) Read(b []byte) (int, error) {
	c.guard.touch(c.Conn)
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(&c.bytesRead, int64(n))
		SocksBytesTransferred.WithLabelValues("received", c.destType).Add(float64(n))
	}
	return n, err
}

func (c *upstreamConnWrapper) Write(b []byte) (int, error) {
	c.guard.touch(c.Conn)
	n, err := c.Conn.Write(b)
	if n > 0 {
		atomic.AddInt64(&c.bytesWritten, int64(n))
		SocksBytesTransferred.WithLabelValues("sent", c.destType).Add(float64(n))
	}
	return n, err
}

func (c *upstreamConnWrapper) Close() error {
	if c.startTime.IsZero() {
		c.startTime = time.Now() // Fallback if not set
	}

	duration := time.Since(c.startTime).Seconds()
	SocksConnectionDuration.WithLabelValues(c.destType).Observe(duration)

	// Load atomically: handleConnect's deferred target.Close can run while the
	// sibling Proxy goroutine is still reading this upstream conn.
	c.logger.Debug("Dialed connection closed",
		slog.String("destination_type", c.destType),
		slog.Int64("bytes_read", atomic.LoadInt64(&c.bytesRead)),
		slog.Int64("bytes_written", atomic.LoadInt64(&c.bytesWritten)),
		slog.Float64("duration_s", duration))

	return c.Conn.Close()
}

type dialer struct {
	upstream network.Network
	fallback network.Network
	cfg      *config
}

func (d *dialer) DialContext(ctx context.Context, network, address string, req *socks5.Request) (net.Conn, error) {
	logger := slog.With(slog.String("address", address))
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		logger.Error("Failed to parse address", slog.Any("error", err))
		SocksErrors.WithLabelValues("parse_error").Inc()
		SocksConnectionFailures.WithLabelValues("parse_error").Inc()
		return nil, fmt.Errorf("could not parse address %s: %w", address, err)
	}

	// Track SOCKS command
	cmdType := "connect" // Default for most cases
	clientAddr := "unknown"
	if req != nil {
		switch req.Command {
		case statute.CommandConnect:
			cmdType = "connect"
		case statute.CommandBind:
			cmdType = "bind"
		case statute.CommandAssociate:
			cmdType = "udp"
		}
		clientAddr = req.RemoteAddr.String()
	}

	logger.Info("SOCKS connection request",
		slog.String("command", cmdType),
		slog.String("client_addr", clientAddr))

	addr, err := netip.ParseAddr(host)
	if err != nil { // Need DNS resolution.
		dnsStart := time.Now()
		addrs, err := d.upstream.LookupHost(ctx, host)
		dnsDuration := time.Since(dnsStart).Seconds()
		SocksDNSLatency.Observe(dnsDuration)

		if err != nil {
			logger.Error("failed to resolve hostname", slog.String("host", host), slog.Any("error", err))
			SocksDNSRequests.WithLabelValues("failure").Inc()
			SocksErrors.WithLabelValues("resolve_error").Inc()
			SocksConnectionFailures.WithLabelValues("dns_failure").Inc()
			SocksCommands.WithLabelValues(cmdType, "failure").Inc()
			return nil, fmt.Errorf("could not resolve hostname %s: %w", host, err)
		}
		if len(addrs) == 0 {
			logger.Error("host not found", slog.String("host", host))
			SocksDNSRequests.WithLabelValues("no_addresses").Inc()
			SocksConnectionFailures.WithLabelValues("no_addresses").Inc()
			SocksCommands.WithLabelValues(cmdType, "failure").Inc()
			return nil, fmt.Errorf("host not found")
		}

		SocksDNSRequests.WithLabelValues("success").Inc()
		addr, err = netip.ParseAddr(addrs[0])
		if err != nil {
			logger.Error("Failed to parse IP address", slog.Any("resolved_addrs", addrs), slog.Any("error", err))
			SocksErrors.WithLabelValues("parse_error").Inc()
			SocksConnectionFailures.WithLabelValues("parse_error").Inc()
			SocksCommands.WithLabelValues(cmdType, "failure").Inc()
			return nil, fmt.Errorf("could not parse IP address %s: %w", addrs[0], err)
		}

		logger.Info("DNS resolved",
			slog.String("hostname", host),
			slog.String("resolved_ip", addr.String()),
			slog.Float64("dns_latency_seconds", dnsDuration))
	}

	logger = logger.With(
		slog.String("ip", addr.String()),
		slog.String("port", port))

	var (
		conn      net.Conn
		dialStart = time.Now()
		destType  = "upstream"
	)
	if addr.IsLoopback() {
		destType = "fallback"
		logger.Info("Dialing loopback address (fallback)")
		conn, err = d.fallback.DialContext(ctx, network, address)
	} else {
		logger.Info("Dialing upstream address")
		conn, err = d.upstream.DialContext(ctx, network, address)
	}

	dialDur := time.Since(dialStart).Seconds()

	if err != nil {
		logger.Error("Failed to dial",
			slog.String("destination_type", destType),
			slog.Any("error", err),
			slog.Float64("dial_duration_s", dialDur))
		SocksErrors.WithLabelValues("dial_error").Inc()
		SocksConnectionFailures.WithLabelValues("dial_failure").Inc()
		SocksCommands.WithLabelValues(cmdType, "failure").Inc()
		return nil, err
	}

	logger.Info("Successfully dialed",
		slog.String("destination_type", destType),
		slog.Float64("dial_duration_s", dialDur))

	SocksCommands.WithLabelValues(cmdType, "success").Inc()

	// Detect a dead/half-open upstream peer so a wedged copy eventually errors.
	applyKeepAlive(conn, d.cfg.keepAlive, d.cfg.keepAlivePeriod)

	return &upstreamConnWrapper{
		Conn:      conn,
		logger:    logger,
		destType:  destType,
		startTime: dialStart,
		guard:     newDeadlineGuard(d.cfg, dialStart),
	}, nil
}

type resolver struct {
	net network.Network
}

// Resolve implements socks5.NameResolver which is the weirdest interface known to man:
// https://pkg.go.dev/github.com/things-go/go-socks5@v0.0.5#NameResolver
func (r *resolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	startTime := time.Now()
	slog.Info("DNS lookup request", slog.String("name", name))

	addrs, err := r.net.LookupHost(ctx, name)
	duration := time.Since(startTime).Seconds()
	SocksDNSLatency.Observe(duration)

	if err != nil {
		slog.Error("DNS lookup failed",
			slog.String("name", name),
			slog.Any("error", err),
			slog.Float64("duration_seconds", duration))
		SocksDNSRequests.WithLabelValues("failure").Inc()
		return ctx, nil, err
	}
	if len(addrs) == 0 {
		slog.Warn("No addresses found",
			slog.String("name", name),
			slog.Float64("duration_seconds", duration))
		SocksDNSRequests.WithLabelValues("no_addresses").Inc()
		return ctx, nil, fmt.Errorf("no addresses found for %s", name)
	}

	ip := net.ParseIP(addrs[0])
	if ip == nil {
		slog.Error("Failed to parse resolved IP",
			slog.String("name", name),
			slog.String("address", addrs[0]))
		SocksDNSRequests.WithLabelValues("failure").Inc()
		return ctx, nil, fmt.Errorf("failed to parse IP address %s", addrs[0])
	}

	slog.Info("DNS lookup successful",
		slog.String("name", name),
		slog.String("resolved_ip", ip.String()),
		slog.Float64("duration_seconds", duration))
	SocksDNSRequests.WithLabelValues("success").Inc()

	return ctx, ip, nil
}

// authTracker wraps an authenticator to track metrics
type authTracker struct {
	authenticator socks5.Authenticator
}

func (a *authTracker) Authenticate(reader io.Reader, writer io.Writer, userAddr string) (*socks5.AuthContext, error) {
	authMethod := "none" // Since we're using NoAuthAuthenticator
	result, err := a.authenticator.Authenticate(reader, writer, userAddr)

	if err != nil {
		slog.Warn("Authentication failed",
			slog.String("method", authMethod),
			slog.String("user_addr", userAddr),
			slog.Any("error", err))
		SocksAuthAttempts.WithLabelValues(authMethod, "failure").Inc()
		return nil, err
	}

	slog.Info("Authentication successful",
		slog.String("method", authMethod),
		slog.String("user_addr", userAddr))
	SocksAuthAttempts.WithLabelValues(authMethod, "success").Inc()
	return result, nil
}

func (a *authTracker) GetCode() byte {
	return a.authenticator.GetCode()
}

type logger struct{}

func (l *logger) Errorf(format string, arg ...any) {
	slog.Error(fmt.Sprintf(format, arg...))
	SocksErrors.WithLabelValues("internal_error").Inc()
}
