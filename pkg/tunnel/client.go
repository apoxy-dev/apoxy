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
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/dpeckett/network"
	"github.com/google/uuid"
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
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
	serverAddr         string
	uuid               uuid.UUID
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
		serverAddr: "localhost:9443",
		mode:       TunnelClientModeUser,
	}
}

// WithServerAddr sets the server address that the tunnel client will connect to.
// The address should be in the format "host:port".
func WithServerAddr(addr string) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.serverAddr = addr
	}
}

// WithUUID sets the UUID for the tunnel client.
func WithUUID(uuid uuid.UUID) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.uuid = uuid
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

const ApplicationCodeOK quic.ApplicationErrorCode = 0x0

// TunnelClient implements a TunnelNode client.
type TunnelClient struct {
	options            *tunnelClientOptions
	insecureSkipVerify bool
	uuid               uuid.UUID
	authToken          string
	rootCAs            *x509.CertPool
	router             router.Router

	hConn *http3.ClientConn
	conn  *connectip.Conn

	closeOnce sync.Once
}

// NewTunnelClient creates a new TunnelClient instance with the provided options.
func NewTunnelClient(opts ...TunnelClientOption) (*TunnelClient, error) {
	options := defaultClientOptions()
	for _, opt := range opts {
		opt(options)
	}

	if options.uuid == uuid.Nil {
		return nil, fmt.Errorf("uuid is required")
	}
	if options.authToken == "" {
		return nil, fmt.Errorf("auth token is required")
	}

	client := &TunnelClient{
		options:            options,
		uuid:               options.uuid,
		authToken:          options.authToken,
		rootCAs:            options.rootCAs,
		insecureSkipVerify: options.insecureSkipVerify,
	}

	return client, nil
}

// Start dials the TunnelNode server, establishes tunnel connection and sets
// up client-side routing.
func (c *TunnelClient) Start(ctx context.Context) error {
	tlsConfig := &tls.Config{
		ServerName:         "proxy",
		NextProtos:         []string{http3.NextProtoH3},
		RootCAs:            c.rootCAs,
		InsecureSkipVerify: c.insecureSkipVerify,
	}

	if addr, _, err := net.SplitHostPort(c.options.serverAddr); err == nil && net.ParseIP(addr) == nil {
		tlsConfig.ServerName = addr
	}

	qConn, err := quic.DialAddr(
		ctx,
		c.options.serverAddr,
		tlsConfig,
		&quic.Config{
			EnableDatagrams:                true,
			InitialPacketSize:              1350,
			InitialConnectionReceiveWindow: 5 * 1000 * 1000,
			MaxConnectionReceiveWindow:     100 * 1000 * 1000,
			KeepAlivePeriod:                1 * time.Second,
			MaxIdleTimeout:                 15 * time.Second,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to dial QUIC connection: %w", err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	c.hConn = tr.NewClientConn(qConn)

	template := uritemplate.MustNew(fmt.Sprintf("https://proxy/connect/%s?token=%s", c.uuid, c.authToken))

	var rsp *http.Response
	c.conn, rsp, err = connectip.Dial(ctx, c.hConn, template)
	if err != nil {
		return fmt.Errorf("failed to dial connect-ip connection: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
	}

	slog.Info("Connected to server", slog.String("addr", c.options.serverAddr))

	resolveConf := &network.ResolveConfig{
		Nameservers:   rsp.Header.Values("X-Apoxy-Nameservers"),
		SearchDomains: rsp.Header.Values("X-Apoxy-DNS-SearchDomains"),
	}

	if opts := rsp.Header.Values("X-Apoxy-DNS-Options"); len(opts) > 0 {
		for _, opt := range opts {
			if strings.HasPrefix(opt, "ndots:") {
				var ndots int
				if n, err := fmt.Sscanf(opt[6:], "%d", &ndots); err != nil || n != 1 {
					ndots = 1
				}
				resolveConf.NDots = &ndots
			}
		}
	}

	slog.Info("Using DNS configuration",
		slog.Any("nameservers", resolveConf.Nameservers),
		slog.Any("searchDomains", resolveConf.SearchDomains),
		slog.Any("nDots", resolveConf.NDots))

	routerOpts := []router.Option{
		router.WithResolveConfig(resolveConf),
	}
	if c.options.pcapPath != "" {
		routerOpts = append(routerOpts, router.WithPcapPath(c.options.pcapPath))
	}
	if c.options.extIfaceName != "" {
		routerOpts = append(routerOpts, router.WithExternalInterface(c.options.extIfaceName))
	}
	if c.options.tunIfaceName != "" {
		routerOpts = append(routerOpts, router.WithTunnelInterface(c.options.tunIfaceName))
	}
	if c.options.socksListenAddr != "" {
		routerOpts = append(routerOpts, router.WithSocksListenAddr(c.options.socksListenAddr))
	}
	if c.options.mode == TunnelClientModeKernel {
		routerOpts = append(routerOpts, router.WithPreserveDefaultGwDsts(c.options.preserveDefaultGwDsts))
		c.router, err = router.NewClientNetlinkRouter(routerOpts...)
		if err != nil {
			return fmt.Errorf("failed to create kernel router: %w", err)
		}
	} else if c.options.mode == TunnelClientModeUser {
		c.router, err = router.NewNetstackRouter(routerOpts...)
		if err != nil {
			return fmt.Errorf("failed to create user mode router: %w", err)
		}
	}

	localPrefixes, err := c.conn.LocalPrefixes(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local IP addresses: %w", err)
	}
	if len(localPrefixes) == 0 {
		return errors.New("no local IP addresses available")
	}

	for _, lp := range localPrefixes {
		if err := c.router.AddAddr(lp, c.conn); err != nil {
			return fmt.Errorf("failed to add route %s: %w", lp.String(), err)
		}
	}

	routes, err := c.conn.Routes(ctx)
	if err != nil {
		return fmt.Errorf("failed to get routes: %w", err)
	}

	for _, route := range routes {
		for _, p := range route.Prefixes() {
			if err := c.router.AddRoute(p); err != nil {
				return fmt.Errorf("failed to add route %s: %w", p.String(), err)
			}
		}
	}

	slog.Info("Starting router")

	if err := c.router.Start(ctx); err != nil {
		return fmt.Errorf("failed to start router: %w", err)
	}

	return nil
}

func (c *TunnelClient) Close() error {
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

		if err := c.router.Close(); err != nil {
			slog.Error("Failed to close router", slog.Any("error", err))
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to close router: %w", err)
			}
		}
	})
	return firstErr
}

func (c *TunnelClient) LocalAddresses() ([]netip.Prefix, error) {
	if c.router == nil || reflect.ValueOf(c.router).IsNil() {
		return nil, nil
	}

	return c.router.LocalAddresses()
}
