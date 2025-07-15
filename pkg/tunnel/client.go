package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/dpeckett/network"
	"github.com/google/uuid"
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
)

var (
	ErrNotConnected = errors.New("not connected")
)

type TunnelClientOption func(*tunnelClientOptions)

type TunnelClientMode string

const (
	// TunnelClientModeKernel indicates that the tunnel client will use the kernel mode router.
	// This mode requires root privileges and is more efficient for routing traffic.
	TunnelClientModeKernel TunnelClientMode = "kernel"
	// TunnelClientModeUser indicates that the tunnel client will use the user mode router.
	TunnelClientModeUser TunnelClientMode = "user"
)

// TunnelClientModeFromStringreturns the tunnel client mode for the given string.
func TunnelClientModeFromString(mode string) (TunnelClientMode, error) {
	switch mode {
	case string(TunnelClientModeKernel):
		return TunnelClientModeKernel, nil
	case string(TunnelClientModeUser):
		return TunnelClientModeUser, nil
	default:
		return "", fmt.Errorf("invalid tunnel client mode: %s", mode)
	}
}

type tunnelClientOptions struct {
	authToken          string
	mode               TunnelClientMode
	insecureSkipVerify bool
	rootCAs            *x509.CertPool
	pcapPath           string
	// Kernel mode options
	extIfaceName string
	tunIfaceName string
	// Userspace options
	socksListenAddr       string
	preserveDefaultGwDsts []netip.Prefix
}

func defaultClientOptions() *tunnelClientOptions {
	return &tunnelClientOptions{
		mode: TunnelClientModeUser,
	}
}

// WithAuthToken sets the authentication token for the tunnel client.
func WithAuthToken(token string) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.authToken = token
	}
}

// WithMode sets the mode of the tunnel client (kernel or userspace).
func WithMode(mode TunnelClientMode) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.mode = mode
	}
}

// WithInsecureSkipVerify skips TLS certificate verification of the server.
func WithInsecureSkipVerify(skip bool) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.insecureSkipVerify = skip
	}
}

// WithRootCAs sets the optional root CA certificates for TLS verification.
func WithRootCAs(caCerts *x509.CertPool) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.rootCAs = caCerts
	}
}

// WithPcapPath sets the optional path to a packet capture file for the tunnel client.
func WithPcapPath(path string) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.pcapPath = path
	}
}

// WithExternalInterface sets the external interface name.
// This is only valid in kernel mode.
func WithExternalInterface(name string) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.extIfaceName = name
	}
}

// WithTunnelInterface sets the tunnel interface name.
// This is only valid in kernel mode.
func WithTunnelInterface(name string) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.tunIfaceName = name
	}
}

// WithSocksListenAddr sets the listen address for the local SOCKS5 proxy server.
// Only valid in user mode.
func WithSocksListenAddr(addr string) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.socksListenAddr = addr
	}
}

// WithPreserveDefaultGatewayDestinations sets destinations for which the existing
// default gateway will be preserved.
func WithPreserveDefaultGatewayDestinations(dsts []netip.Prefix) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.preserveDefaultGwDsts = dsts
	}
}

// BuildClientRouter builds a router for the client tunnel side using provided
// options and sane defaults.
func BuildClientRouter(opts ...TunnelClientOption) (router.Router, error) {
	options := &tunnelClientOptions{}
	for _, opt := range opts {
		opt(options)
	}

	resolveConf := &network.ResolveConfig{
		// TODO: Use flags.
		//Nameservers:   ...
		//SearchDomains: ...
		// NDots:
	}

	slog.Info("Using DNS configuration",
		slog.Any("nameservers", resolveConf.Nameservers),
		slog.Any("searchDomains", resolveConf.SearchDomains),
		slog.Any("nDots", resolveConf.NDots))

	routerOpts := []router.Option{
		router.WithResolveConfig(resolveConf),
		router.WithPcapPath(options.pcapPath),
	}
	if options.extIfaceName != "" {
		routerOpts = append(routerOpts, router.WithExternalInterface(options.extIfaceName))
	}
	if options.tunIfaceName != "" {
		routerOpts = append(routerOpts, router.WithTunnelInterface(options.tunIfaceName))
	}
	if options.socksListenAddr != "" {
		routerOpts = append(routerOpts, router.WithSocksListenAddr(options.socksListenAddr))
	}

	switch options.mode {
	case TunnelClientModeKernel:
		routerOpts = append(routerOpts, router.WithPreserveDefaultGwDsts(options.preserveDefaultGwDsts))
		return router.NewClientNetlinkRouter(routerOpts...)
	case TunnelClientModeUser:
		return router.NewNetstackRouter(routerOpts...)
	default:
		return nil, fmt.Errorf("invalid tunnel client mode: %v", options.mode)
	}
	//nolint:unreachable
	panic("unreachable")
}

// TunnelDialer dials a tunnel connection. Must be started before use.
type TunnelDialer struct {
	Router router.Router

	routerMu   sync.Mutex
	routerOnce sync.Once
	routerErr  error
}

// Dial dials the TunnelNode server, establishes tunnel connection and sets
// up client-side routing.
func (d *TunnelDialer) Dial(
	ctx context.Context,
	id uuid.UUID,
	addr string,
	opts ...TunnelClientOption,
) (*Conn, error) {
	d.routerMu.Lock()
	if d.Router == nil {
		d.routerOnce.Do(func() {
			d.Router, d.routerErr = BuildClientRouter()
			if d.routerErr != nil {
				return
			}
			go func() {
				if err := d.Router.Start(context.Background()); err != nil {
					slog.Error("router failed", "error", err)
				}
			}()
		})
	}
	if d.routerErr != nil {
		d.routerMu.Unlock()
		return nil, d.routerErr
	}
	d.routerMu.Unlock()

	options := defaultClientOptions()
	for _, opt := range opts {
		opt(options)
	}

	tlsConfig := &tls.Config{
		ServerName:         "proxy",
		NextProtos:         []string{http3.NextProtoH3},
		RootCAs:            options.rootCAs,
		InsecureSkipVerify: options.insecureSkipVerify,
	}

	if saddr, _, err := net.SplitHostPort(addr); err == nil && net.ParseIP(saddr) == nil {
		tlsConfig.ServerName = saddr
	}

	qConn, err := quic.DialAddr(
		ctx,
		addr,
		tlsConfig,
		quicConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial QUIC connection: %w", err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	hConn := tr.NewClientConn(qConn)

	addrUrl := &url.URL{
		Scheme: "https",
		Host:   "proxy",
		Path:   "/connect/" + id.String(),
	}
	q := addrUrl.Query()
	if options.authToken != "" {
		q.Add("token", options.authToken)
		addrUrl.RawQuery = q.Encode()
	}
	addrUrl.RawQuery = addrUrl.Query().Encode()

	tmpl, err := uritemplate.New(addrUrl.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI template: %w", err)
	}
	conn, rsp, err := connectip.Dial(ctx, hConn, tmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to dial connect-ip connection: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
	}

	slog.Info("Connected to server", slog.String("addr", addr))

	routes, err := conn.Routes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get routes: %w", err)
	}

	for _, route := range routes {
		for _, p := range route.Prefixes() {
			if err := d.Router.AddRoute(p); err != nil {
				return nil, fmt.Errorf("failed to add route %s: %w", p.String(), err)
			}
		}
	}

	connUUID, err := uuid.Parse(rsp.Header.Get("X-Apoxy-Connection-UUID"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection UUID: %w", err)
	}

	c := &Conn{
		UUID: connUUID,

		conn:      conn,
		hConn:     hConn,
		router:    d.Router,
		closeOnce: sync.Once{},
	}
	go c.run(ctx)
	return c, nil
}

type Conn struct {
	UUID uuid.UUID

	conn      *connectip.Conn
	hConn     *http3.ClientConn
	router    router.Router
	closeOnce sync.Once

	mu    sync.RWMutex
	addrs []netip.Prefix
}

func (c *Conn) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
			addrs, err := c.conn.LocalPrefixes(ctx)
			if err != nil {
				slog.Error("Failed to get local prefixes", slog.Any("error", err))
				continue
			}

			slog.Info("Updating local prefixes", slog.Any("prefixes", addrs))

			c.mu.Lock()
			newAddrs := sets.New[netip.Prefix](addrs...)
			oldAddrs := sets.New[netip.Prefix](c.addrs...)
			for _, addr := range newAddrs.Difference(oldAddrs).UnsortedList() {
				slog.Info("Adding local prefix", slog.Any("prefix", addr))
				c.router.AddAddr(addr, c.conn)
			}
			for _, addr := range oldAddrs.Difference(newAddrs).UnsortedList() {
				slog.Info("Removing local prefix", slog.Any("prefix", addr))
				c.router.DelAddr(addr)
			}
			c.addrs = addrs
			c.mu.Unlock()

			slog.Info("Local prefixes updated", slog.Any("prefixes", addrs))
		}
	}
}

func (c *Conn) LocalAddrs() ([]netip.Prefix, error) {
	if c.conn == nil {
		return nil, ErrNotConnected
	}

	c.mu.RLock()
	addrs := make([]netip.Prefix, len(c.addrs))
	copy(addrs, c.addrs)
	c.mu.RUnlock()

	return addrs, nil
}

func (c *Conn) Close() error {
	var firstErr error
	c.closeOnce.Do(func() {
		if c.conn != nil {
			if err := c.conn.Close(); err != nil {
				slog.Error("Failed to close connect-ip connection", slog.Any("error", err))
				if firstErr == nil {
					firstErr = fmt.Errorf("failed to close connect-ip connection: %w", err)
				}
			}
		}

		if c.hConn != nil {
			if err := c.hConn.CloseWithError(ApplicationCodeOK, ""); err != nil {
				slog.Error("Failed to close HTTP/3 connection", slog.Any("error", err))
				if firstErr == nil {
					firstErr = fmt.Errorf("failed to close HTTP/3 connection: %w", err)
				}
			}
		}
	})
	return firstErr
}
