package dns

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/cache"
	"golang.org/x/sync/errgroup"
)

// options holds the DNS server configuration.
type options struct {
	// plugins is a list of DNS plugins to add to the server chain.
	plugins []plugin.Plugin
	// blockNonGlobalIPs controls whether responses containing non-global unicast IPs
	// (private, loopback, ULA addresses) should be blocked and return NXDOMAIN.
	blockNonGlobalIPs bool
}

// Option configures the DNS server.
type Option func(*options)

// WithBlockNonGlobalIPs blocks responses containing non-global unicast IPs.
func WithBlockNonGlobalIPs() Option {
	return func(o *options) {
		o.blockNonGlobalIPs = true
	}
}

// WithPlugins adds DNS plugins to the server chain.
func WithPlugins(p ...plugin.Plugin) Option {
	return func(o *options) {
		o.plugins = append(o.plugins, p...)
	}
}

// newServer assembles a CoreDNS server whose plugin chain is
// caller plugins -> cache -> upstream. host and port only label the server's
// config; they are used for binding only by ListenAndServe.
func newServer(host, port string, sOpts options) (*dnsserver.Server, error) {
	up := &upstream{
		BlockNonGlobalIPs: sOpts.blockNonGlobalIPs,
	}
	if err := up.LoadResolvConf(); err != nil {
		return nil, err
	}

	upChain := cache.New()
	upChain.Next = up

	c := &dnsserver.Config{
		Zone:        ".",
		Transport:   "dns",
		ListenHosts: []string{host},
		Port:        port,
		Debug:       true,
	}
	var stack plugin.Handler = upChain
	for i := len(sOpts.plugins) - 1; i >= 0; i-- {
		stack = sOpts.plugins[i](stack)
	}
	c.AddPlugin(func(next plugin.Handler) plugin.Handler { return stack })

	return dnsserver.NewServer("dns://"+net.JoinHostPort(host, port), []*dnsserver.Config{c})
}

// ListenAndServe starts a DNS server on addr (UDP and TCP) with the given
// options and blocks until a listener fails.
func ListenAndServe(addr string, opts ...Option) error {
	var sOpts options
	for _, opt := range opts {
		opt(&sOpts)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	slog.Info("Starting DNS server", "host", host, "port", port)

	// Local, not shared state: ListenAndServe is called once per DNS server
	// (e.g. one per project) and each call owns its own server instance.
	srv, err := newServer(host, port, sOpts)
	if err != nil {
		return err
	}

	eg := errgroup.Group{}
	if udp, err := srv.ListenPacket(); err != nil {
		return fmt.Errorf("failed to listen on udp: %w", err)
	} else {
		eg.Go(func() error {
			return srv.ServePacket(udp)
		})
	}
	if tcp, err := srv.Listen(); err != nil {
		return fmt.Errorf("failed to listen on tcp: %w", err)
	} else {
		eg.Go(func() error {
			return srv.Serve(tcp)
		})
	}

	return eg.Wait()
}

// PacketServer is a constructed DNS server ready to serve over a packet conn.
// Construction (which loads resolv.conf for the upstream plugin) is separated
// from serving so a caller that runs the serve loop in a goroutine can still
// surface construction errors synchronously — a silently-failed server would
// bind a socket that never answers, stalling every query to timeout.
type PacketServer struct {
	srv *dnsserver.Server
}

// NewPacketServer constructs a DNS server for serving over a packet conn (UDP
// semantics only — no TCP twin), returning any construction error (e.g.
// resolv.conf load failure) synchronously. Call Serve to run it.
func NewPacketServer(opts ...Option) (*PacketServer, error) {
	var sOpts options
	for _, opt := range opts {
		opt(&sOpts)
	}
	srv, err := newServer("127.0.0.1", "0", sOpts)
	if err != nil {
		return nil, err
	}
	return &PacketServer{srv: srv}, nil
}

// Serve serves DNS over pc and blocks until pc fails or is closed. The caller
// owns pc's lifecycle: closing it is the shutdown path, after which Serve
// returns the resulting read error.
func (p *PacketServer) Serve(pc net.PacketConn) error {
	slog.Info("Starting DNS server", "addr", pc.LocalAddr())
	return p.srv.ServePacket(pc)
}

// ServePacket constructs and serves DNS over pc in one call. Prefer
// NewPacketServer + Serve when the serve loop runs in a goroutine, so
// construction errors surface synchronously.
func ServePacket(pc net.PacketConn, opts ...Option) error {
	s, err := NewPacketServer(opts...)
	if err != nil {
		return err
	}
	return s.Serve(pc)
}
