package socksproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/dpeckett/network"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"
)

// ProxyServer is a SOCKS5 proxy server.
type ProxyServer struct {
	Addr           string
	server         *socks5.Server
	proxyCtx       context.Context
	proxyCtxCancel context.CancelFunc
}

// NewServer creates a new SOCKS5 proxy server.
// Requests to private addresses (excluding loopback) will be forwarded to the upstream network.
// Requests to public addresses will be forwarded to the fallback network.
func NewServer(addr string, upstream network.Network, fallback network.Network) *ProxyServer {
	options := []socks5.Option{
		socks5.WithDial((&dialer{upstream: upstream, fallback: fallback}).DialContext),
		socks5.WithResolver(&resolver{net: upstream}),
		socks5.WithBufferPool(bufferpool.NewPool(256 * 1024)),
		socks5.WithLogger(&logger{}),
		// No auth as we'll be binding exclusively to a local interface.
		socks5.WithAuthMethods([]socks5.Authenticator{socks5.NoAuthAuthenticator{}}),
	}

	// Set up the context for the proxy server
	proxyCtx, proxyCtxCancel := context.WithCancel(context.Background())

	return &ProxyServer{
		Addr:           addr,
		server:         socks5.NewServer(options...),
		proxyCtx:       proxyCtx,
		proxyCtxCancel: proxyCtxCancel,
	}
}

func (s *ProxyServer) Close() error {
	s.proxyCtxCancel()
	return nil
}

func (s *ProxyServer) ListenAndServe(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	go func() {
		select {
		case <-ctx.Done():
		case <-s.proxyCtx.Done():
		}

		if err := lis.Close(); err != nil {
			slog.Warn("failed to close listener", slog.Any("error", err))
		}
	}()

	if err := s.server.Serve(lis); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}

type dialer struct {
	upstream network.Network
	fallback network.Network
}

func (d *dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		slog.Error("failed to parse address", slog.String("address", address), slog.Any("error", err))
		return nil, fmt.Errorf("could not parse address %s: %w", address, err)
	}

	slog.Debug("Resolving address", slog.String("address", address))

	addr, err := netip.ParseAddr(host)
	if err != nil {
		addrs, err := d.upstream.LookupHost(ctx, host)
		if err != nil {
			slog.Error("failed to resolve hostname", slog.String("host", host), slog.Any("error", err))
			return nil, fmt.Errorf("could not resolve hostname %s: %w", host, err)
		}
		if len(addrs) == 0 {
			slog.Error("host not found", slog.String("host", host))
			return nil, fmt.Errorf("host not found")
		}

		addr, err = netip.ParseAddr(addrs[0])
		if err != nil {
			slog.Error("failed to parse IP address", slog.String("address", addrs[0]), slog.Any("error", err))
			return nil, fmt.Errorf("could not parse IP address %s: %w", addrs[0], err)
		}
	}

	slog.Debug("Resolved address", slog.String("address", addr.String()))

	if addr.IsLoopback() {
		slog.Debug("Address is loopback - dialing directly", slog.String("address", addr.String()))
		return d.fallback.DialContext(ctx, network, address)
	}

	slog.Debug("Dialing upstream", slog.String("address", addr.String()))

	return d.upstream.DialContext(ctx, network, address)
}

type resolver struct {
	net network.Network
}

// Resolve implements socks5.NameResolver which is the weirdest interface known to man:
// https://pkg.go.dev/github.com/things-go/go-socks5@v0.0.5#NameResolver
func (r *resolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	slog.Debug("looking up host", slog.String("name", name))

	addrs, err := r.net.LookupHost(ctx, name)
	if err != nil {
		return ctx, nil, err
	}
	if len(addrs) == 0 {
		return ctx, nil, fmt.Errorf("no addresses found for %s", name)
	}

	ip := net.ParseIP(addrs[0])
	if ip == nil {
		return ctx, nil, fmt.Errorf("failed to parse IP address %s", addrs[0])
	}

	return ctx, ip, nil
}

type logger struct{}

func (l *logger) Errorf(format string, arg ...any) {
	slog.Error(fmt.Sprintf(format, arg...))
}
