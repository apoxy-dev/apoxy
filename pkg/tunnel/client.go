package tunnel

import (
	"bytes"
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
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dpeckett/network"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"k8s.io/apimachinery/pkg/util/sets"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/apoxy-dev/apoxy/build"
	alog "github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/bfdl"
	tunnelconn "github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
)

// LabelKeyVersion is the agent label that carries the CLI build version.
// Always sent by Dial so AgentStatus.Labels can surface the agent's version.
const LabelKeyVersion = "apoxy.dev/version"

var (
	ErrNotConnected = errors.New("not connected")
)

// ErrRateLimited is returned by Dial when the server responds with HTTP 429
// on the /connect stream. Callers can inspect RetryAfter (populated from the
// Retry-After response header; zero when the header is missing or unparsable)
// to back off. The current worker loop in cmd/tunnel/run.go does not act on
// this yet; the typed error exists so smart backoff can land without another
// wire-format change.
type ErrRateLimited struct {
	RetryAfter time.Duration
}

func (e *ErrRateLimited) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("tunnel dial rate-limited: retry after %s", e.RetryAfter)
	}
	return "tunnel dial rate-limited"
}

// parseRetryAfterHeader parses an HTTP Retry-After value. RFC 7231 allows
// both an integer seconds count and an HTTP-date; the server only sends the
// integer form, so we try that first and fall back to http.ParseTime for
// defensive compatibility. Returns 0 if the value is missing or unparsable —
// callers should treat 0 as "back off on your own schedule."
func parseRetryAfterHeader(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

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
	// Packet observer for TUI
	packetObserver tunnelconn.PacketObserver
	// Labels to send on tunnel connections.
	labels map[string]string
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

// WithMode sets the mode of the tunnel client (kernel or user).
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

// WithPacketObserver sets the packet observer for the tunnel client.
// The observer will receive notifications for each packet passing through the tunnel.
func WithPacketObserver(obs tunnelconn.PacketObserver) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.packetObserver = obs
	}
}

// WithLabels sets metadata labels to send on tunnel connections.
func WithLabels(labels map[string]string) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.labels = labels
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
	if options.packetObserver != nil {
		routerOpts = append(routerOpts, router.WithPacketObserver(options.packetObserver))
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

	addrUrl := &url.URL{
		Scheme: "https",
		Host:   "proxy",
		Path:   "/connect/" + id.String(),
	}
	q := addrUrl.Query()
	if options.authToken != "" {
		q.Add("token", options.authToken)
	}
	for k, v := range options.labels {
		q.Add("label."+k, v)
	}
	// Always advertise the CLI build version so it surfaces in AgentStatus.
	// Caller-provided label wins (server reads values[0]) so tests/overrides
	// can substitute a value.
	if _, ok := options.labels[LabelKeyVersion]; !ok {
		q.Add("label."+LabelKeyVersion, build.BuildVersion)
	}
	q.Add(metrics.QueryParamAgentProcessID, metrics.AgentProcessID())
	addrUrl.RawQuery = q.Encode()

	tmpl, err := uritemplate.New(addrUrl.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI template: %w", err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	hConn := tr.NewClientConn(qConn)

	conn, rsp, err := connectip.Dial(ctx, hConn, tmpl)
	if err != nil {
		// connect-ip-go returns a non-nil rsp on non-2xx responses even when
		// err is set. Translate 429 into the typed ErrRateLimited so callers
		// can later back off on the server-signalled delay.
		if rsp != nil && rsp.StatusCode == http.StatusTooManyRequests {
			retryAfter := parseRetryAfterHeader(rsp.Header.Get("Retry-After"))
			hConn.CloseWithError(ApplicationCodeOK, "rate-limited")
			return nil, &ErrRateLimited{RetryAfter: retryAfter}
		}
		hConn.CloseWithError(ApplicationCodeOK, fmt.Sprintf("failed to dial connect-ip connection: %v", err))
		return nil, fmt.Errorf("failed to dial connect-ip connection: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		hConn.CloseWithError(ApplicationCodeOK, fmt.Sprintf("unexpected status code: %d", rsp.StatusCode))
		return nil, fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
	}

	connUUID, err := uuid.Parse(rsp.Header.Get("X-Apoxy-Connection-UUID"))
	if err != nil {
		hConn.CloseWithError(ApplicationCodeInternalError, fmt.Sprintf("failed to parse connection UUID: %v", err))
		return nil, fmt.Errorf("failed to parse connection UUID: %w", err)
	}

	slog.Info("Connected to server", slog.String("addr", addr), slog.String("connection_uuid", connUUID.String()))

	routes, err := conn.Routes(ctx)
	if err != nil {
		hConn.CloseWithError(ApplicationCodeInternalError, fmt.Sprintf("failed to setup routes: %v", err))
		return nil, fmt.Errorf("failed to get routes: %w", err)
	}

	for _, route := range routes {
		for _, p := range route.Prefixes() {
			if err := d.Router.AddRoute(p); err != nil {
				hConn.CloseWithError(ApplicationCodeInternalError, fmt.Sprintf("failed to setup route %s: %v", p.String(), err))
				return nil, fmt.Errorf("failed to add route %s: %w", p.String(), err)
			}
		}
	}

	c := &Conn{
		UUID: connUUID,

		conn:      conn,
		hConn:     hConn,
		router:    d.Router,
		closeOnce: sync.Once{},
	}
	go c.run(alog.IntoContext(ctx, slog.With("conn", connUUID.String())))
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

	bfdClient atomic.Pointer[bfdl.Client]
}

// BFDState returns the current BFD session state for this connection.
func (c *Conn) BFDState() bfdl.State {
	if b := c.bfdClient.Load(); b != nil {
		return b.State()
	}
	return bfdl.StateDown
}

// LastAlive returns when the last valid BFD packet was received from the server.
func (c *Conn) LastAlive() time.Time {
	if b := c.bfdClient.Load(); b != nil {
		return b.LastAlive()
	}
	return time.Time{}
}

type connWrapper struct {
	*connectip.Conn

	addr netip.Prefix
}

func (cw *connWrapper) String() string {
	return fmt.Sprintf("conn: %v", cw.addr)
}

func (c *Conn) run(ctx context.Context) {
	// Derive a connection-scoped context so that child goroutines (BFD client,
	// prefix fetcher) are stopped when this function returns — regardless of
	// whether the exit was triggered by BFD, QUIC close, or parent cancel.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	log := alog.FromContext(ctx)

	// Cleanup: remove all addresses from router when connection closes.
	defer func() {
		c.mu.RLock()
		addrs := make([]netip.Prefix, len(c.addrs))
		copy(addrs, c.addrs)
		c.mu.RUnlock()

		for _, addr := range addrs {
			log.Info("Removing local prefix on connection close", slog.Any("prefix", addr))
			c.router.DelAddr(addr)
		}
	}()

	// Push metrics to the server periodically over the existing HTTP/3 connection.
	go c.startMetricsPush(ctx, 15*time.Second)

	bfdStarted := false
	var bfdDown <-chan struct{} // Nil until BFD client starts.

	// LocalPrefixes() blocks until the peer sends a new address assignment
	// capsule (it is designed to be called in a loop per its docstring). We
	// run it in a goroutine so the main select stays responsive to bfdDown,
	// context cancellation, and connection close. After each result is
	// consumed we re-launch the goroutine to wait for the next change.
	type prefixResult struct {
		addrs []netip.Prefix
		err   error
	}
	prefixCh := make(chan prefixResult, 1)
	fetchPrefixes := func() {
		addrs, err := c.conn.LocalPrefixes(ctx)
		prefixCh <- prefixResult{addrs, err}
	}
	go fetchPrefixes()

	for {
		select {
		case <-ctx.Done():
			log.Info("Context canceled")
			return
		case <-c.hConn.Context().Done():
			log.Info("HTTP3 connection closed")
			return
		case <-bfdDown:
			log.Warn("BFD session down, closing connection")
			c.Close()
			return
		case res := <-prefixCh:
			if res.err != nil {
				if errors.Is(res.err, net.ErrClosed) {
					log.Error("Connection closed", slog.Any("error", res.err))
					return
				}
				log.Error("Failed to get local prefixes", slog.Any("error", res.err))
				go fetchPrefixes()
				continue
			}

			addrs := res.addrs
			log.Info("Updating local prefixes", slog.Any("prefixes", addrs))

			c.mu.Lock()
			newAddrs := sets.New[netip.Prefix](addrs...)
			oldAddrs := sets.New[netip.Prefix](c.addrs...)
			for _, addr := range newAddrs.Difference(oldAddrs).UnsortedList() {
				log.Info("Adding local prefix", slog.Any("prefix", addr))
				c.router.AddAddr(addr, &connWrapper{Conn: c.conn, addr: addr})
			}
			for _, addr := range oldAddrs.Difference(newAddrs).UnsortedList() {
				log.Info("Removing local prefix", slog.Any("prefix", addr))
				c.router.DelAddr(addr)
			}
			c.addrs = addrs
			c.mu.Unlock()

			// Start BFD client after first IPv6 address is assigned.
			if !bfdStarted {
				for _, addr := range newAddrs.Difference(oldAddrs).UnsortedList() {
					if !addr.Addr().Is6() {
						continue
					}
					if dialer, ok := c.router.(router.OverlayDialer); ok {
						pktConn, err := dialer.ListenPacket(netip.AddrPortFrom(addr.Addr(), 0))
						if err != nil {
							log.Error("Failed to create BFD socket", slog.Any("error", err))
							break
						}
						client := bfdl.NewClient(pktConn, netip.AddrPortFrom(bfdl.BFDServerAddr, bfdl.BFDPort))
						c.bfdClient.Store(client)
						go client.Run(ctx)
						bfdDown = client.Down()
						bfdStarted = true
						log.Info("BFD client started", slog.Any("localAddr", addr))
					}
					break
				}
			}

			log.Info("Local prefixes updated", slog.Any("prefixes", addrs))
			// Fetch next prefix update asynchronously.
			go fetchPrefixes()
		}
	}
}

// Context returns the context of the underlying connection that is
// canceled when the connection is closed.
func (c *Conn) Context() context.Context {
	return c.hConn.Context() // Context of the underlying QUIC connection.
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

// startMetricsPush periodically collects metrics from the local Prometheus
// registry and pushes them to the server over the existing HTTP/3 connection.
// This runs until ctx is cancelled (connection close).
func (c *Conn) startMetricsPush(ctx context.Context, interval time.Duration) {
	log := alog.FromContext(ctx)

	// Wait a short period before the first push to let the connection stabilize.
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
	}

	if err := c.pushMetrics(ctx); err != nil {
		log.Warn("Failed initial metrics push", slog.Any("error", err))
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.pushMetrics(ctx); err != nil {
				log.Debug("Failed to push metrics", slog.Any("error", err))
			}
		}
	}
}

// pushMetrics gathers all metrics from the controller-runtime registry,
// encodes them in Prometheus text format, and POSTs to the server.
func (c *Conn) pushMetrics(ctx context.Context) error {
	gatherer, ok := crmetrics.Registry.(prometheus.Gatherer)
	if !ok {
		return fmt.Errorf("metrics registry does not implement Gatherer")
	}

	families, err := gatherer.Gather()
	if err != nil {
		return fmt.Errorf("gathering metrics: %w", err)
	}

	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range families {
		if err := enc.Encode(mf); err != nil {
			return fmt.Errorf("encoding metric %s: %w", mf.GetName(), err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://proxy/metrics/push", &buf)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", string(expfmt.NewFormat(expfmt.TypeTextPlain)))

	resp, err := c.hConn.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("round trip: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	return nil
}
