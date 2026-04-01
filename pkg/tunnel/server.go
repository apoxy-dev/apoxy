package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/google/uuid"
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/sync/errgroup"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/bfdl"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/conntrack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

var (
	connectTmpl = uritemplate.MustNew("https://proxy/connect")
)

type TunnelServerOption func(*tunnelServerOptions)

// OnConnectFunc is called when a tunnel connection is established.
// The connID is a UUID identifying the connection, and tn is the TunnelNode object.
type OnConnectFunc func(ctx context.Context, connID string, tn *corev1alpha.TunnelNode)

// OnDisconnectFunc is called when a tunnel connection is closed.
// The connID is the same UUID that was passed to OnConnectFunc.
type OnDisconnectFunc func(ctx context.Context, connID string)

type tunnelServerOptions struct {
	proxyAddr    string
	publicAddr   string
	ulaPrefix    netip.Prefix
	certPath     string
	keyPath      string
	extAddrs     []netip.Prefix
	selector     string
	ipamv4       tunnet.IPAM
	keyLogPath   string
	onConnect    OnConnectFunc
	onDisconnect OnDisconnectFunc

	// BFD options.
	bfdListenAddr netip.Addr      // If set, enables BFD server.
	onAlive       bfdl.OnAliveFunc // Called on each valid BFD Rx.

	// TCP connection tracker for drain support.
	connTracker *conntrack.Tracker

	// Metrics scraping for connected agents.
	metricsScraper  *metrics.AgentScraper
	projectIDLookup func(tunnelUID string) string // Optional: resolves tunnel UID to project ID.
}

func defaultServerOptions() *tunnelServerOptions {
	return &tunnelServerOptions{
		proxyAddr:  "0.0.0.0:9443",
		publicAddr: "",
		ulaPrefix:  netip.MustParsePrefix("fd00::/64"),
		certPath:   "/etc/apoxy/certs/tunnelproxy.crt",
		keyPath:    "/etc/apoxy/certs/tunnelproxy.key",
		extAddrs:   []netip.Prefix{},
		selector:   "",
		ipamv4:     tunnet.NewIPAMv4(context.Background()),
		keyLogPath: "",
	}
}

// WithProxyAddr sets the address to bind the proxy to.
func WithProxyAddr(addr string) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.proxyAddr = addr
	}
}

// WithPublicAddr sets the address tunnel proxy is reachable at. This
// address will be set on the TunnelNode objects that this proxy is serving.
func WithPublicAddr(addr string) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.publicAddr = addr
	}
}

// WithULAPrefix sets the Unique Local Address prefix.
func WithULAPrefix(prefix netip.Prefix) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.ulaPrefix = prefix
	}
}

// WithCertPath sets the path to the TLS certificate.
func WithCertPath(path string) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.certPath = path
	}
}

// WithKeyPath sets the path to the TLS key.
func WithKeyPath(path string) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.keyPath = path
	}
}

// WithExternalAddr sets the external IPv6 prefix. This is the IPv6 prefix used to
// send traffic through the tunnel.
func WithExternalAddrs(addrs ...netip.Prefix) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.extAddrs = addrs
	}
}

// WithLabelSelector sets the label selector to filter TunnelNodes.
func WithLabelSelector(labelSelector string) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.selector = labelSelector
	}
}

// WithIPAMv4 sets the IPv4 IPAM.
func WithIPAMv4(ipamv4 tunnet.IPAM) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.ipamv4 = ipamv4
	}
}

// WithKeyLogPath sets the path to the TLS key log (disabled by default).
func WithKeyLogPath(path string) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.keyLogPath = path
	}
}

// WithOnConnect sets a callback that is invoked when a tunnel connection is established.
func WithOnConnect(fn OnConnectFunc) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.onConnect = fn
	}
}

// WithOnDisconnect sets a callback that is invoked when a tunnel connection is closed.
func WithOnDisconnect(fn OnDisconnectFunc) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.onDisconnect = fn
	}
}

// WithBFDListenAddr enables the BFD server on the given overlay address.
func WithBFDListenAddr(addr netip.Addr) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.bfdListenAddr = addr
	}
}

// WithOnAlive sets a callback invoked on each valid BFD Rx from a client.
func WithOnAlive(fn bfdl.OnAliveFunc) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.onAlive = fn
	}
}

// WithConnTracker sets an externally-created TCP connection tracker. If set,
// it is used for ActiveTCPConns() reporting during graceful drain.
func WithConnTracker(ct *conntrack.Tracker) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.connTracker = ct
	}
}

// WithAgentScraper enables periodic metrics scraping from connected agents
// via their overlay addresses. The scraper must be started separately.
func WithAgentScraper(s *metrics.AgentScraper) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.metricsScraper = s
	}
}

// WithProjectIDLookup sets a function that resolves a tunnel UID to its project ID.
// Used by the metrics scraper to label scraped metrics with the owning project.
func WithProjectIDLookup(fn func(tunnelUID string) string) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.projectIDLookup = fn
	}
}

type conn struct {
	*connectip.Conn
	connID         string
	obj            *corev1alpha.TunnelNode
	addrv4, addrv6 netip.Prefix
	cancel         context.CancelFunc
	labels         map[string]string
}

func (c *conn) String() string {
	return fmt.Sprintf("%s [%s]: %v %v", c.obj.Name, c.connID, c.addrv4, c.addrv6)
}

// ClientGetter provides access to Kubernetes clients.
// In single-cluster mode, the tunnel UUID is ignored and the default client is returned.
// In multi-cluster mode, the tunnel UUID is used to look up which cluster's client to use.
type ClientGetter interface {
	// GetClient returns a client for the given tunnel UUID.
	GetClient(ctx context.Context, tunUID uuid.UUID) (client.Client, error)
}

// SingleClusterClientGetter wraps a single client.Client for use with ClientGetter.
type SingleClusterClientGetter struct {
	Client client.Client
}

// GetClient returns the wrapped client, ignoring the tunnel UUID.
func (s *SingleClusterClientGetter) GetClient(_ context.Context, _ uuid.UUID) (client.Client, error) {
	return s.Client, nil
}

// TunnelServer manages QUIC tunnel connections and routes traffic via CONNECT-IP.
// It exposes ReconcileWithClient for use by reconcilers (standard or multicluster).
type TunnelServer struct {
	options *tunnelServerOptions

	clientGetter ClientGetter
	jwtValidator token.JWTValidator
	ln           *quic.EarlyListener
	router       router.Router
	bfdServer    *bfdl.Server
	connTracker  *conntrack.Tracker

	// tunnels maps tunnel UIDs to tunnel instances.
	tunnels *haxmap.Map[string, *corev1alpha.TunnelNode]
	// conns maps tunnel connection IDs to connection instances.
	conns *haxmap.Map[string, *conn]

	stopMu        sync.Mutex
	stopped       bool
	draining      bool
	rejectNewConn bool

	// drainCancel cancels the drainCtx, which controls the lifetime of
	// the router and BFD server. Only called after Drain() force-closes
	// all connections.
	drainCancel context.CancelFunc
}

// NewTunnelServer creates a new server proxy that routes traffic via
// QUIC tunnels.
func NewTunnelServer(
	cg ClientGetter,
	v token.JWTValidator,
	r router.Router,
	opts ...TunnelServerOption,
) (*TunnelServer, error) {
	options := defaultServerOptions()
	for _, opt := range opts {
		opt(options)
	}

	ct := options.connTracker
	if ct == nil {
		ct = conntrack.NewTracker()
	}

	s := &TunnelServer{
		options: options,

		clientGetter: cg,
		jwtValidator: v,
		router:       r,
		connTracker:  ct,

		tunnels: haxmap.New[string, *corev1alpha.TunnelNode](),
		conns:   haxmap.New[string, *conn](),
	}

	return s, nil
}

// MetricsScraper returns the agent metrics scraper, if configured.
func (t *TunnelServer) MetricsScraper() *metrics.AgentScraper {
	return t.options.metricsScraper
}

// SetupWithManager sets up the TunnelServer as a reconciler with the manager.
func SetupWithManager(mgr ctrl.Manager, srv *TunnelServer) error {
	lss, err := metav1.ParseToLabelSelector(srv.options.selector)
	if err != nil {
		return fmt.Errorf("failed to parse label selector: %w", err)
	}
	ls, err := predicate.LabelSelectorPredicate(*lss)
	if err != nil {
		return fmt.Errorf("failed to create label selector predicate: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha.TunnelNode{},
			builder.WithPredicates(
				&predicate.ResourceVersionChangedPredicate{},
				ls,
			),
		).
		Complete(reconcile.Func(func(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
			return srv.ReconcileWithClient(ctx, mgr.GetClient(), req)
		}))
}

// LabelSelector returns the label selector configured for this server.
func (srv *TunnelServer) LabelSelector() string {
	return srv.options.selector
}

// Predicates returns the predicates to use when setting up the controller.
// This is useful when integrating with multicluster-runtime.
func (t *TunnelServer) Predicates() ([]predicate.Predicate, error) {
	preds := []predicate.Predicate{
		&predicate.ResourceVersionChangedPredicate{},
	}
	if t.options.selector != "" {
		lss, err := metav1.ParseToLabelSelector(t.options.selector)
		if err != nil {
			return nil, fmt.Errorf("failed to parse label selector: %w", err)
		}
		ls, err := predicate.LabelSelectorPredicate(*lss)
		if err != nil {
			return nil, fmt.Errorf("failed to create label selector predicate: %w", err)
		}
		preds = append(preds, ls)
	}
	return preds, nil
}

func (t *TunnelServer) Start(ctx context.Context) error {
	bindTo, err := netip.ParseAddrPort(t.options.proxyAddr)
	if err != nil {
		return fmt.Errorf("failed to parse bind address: %w", err)
	}
	udpConn, err := net.ListenUDP(
		"udp",
		&net.UDPAddr{
			IP:   bindTo.Addr().AsSlice(),
			Port: int(bindTo.Port()),
		},
	)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	defer udpConn.Close()

	cert, err := tls.LoadX509KeyPair(t.options.certPath, t.options.keyPath)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	if t.options.keyLogPath != "" {
		keyLogFile, err := os.Create("quic_keylog.txt")
		if err != nil {
			return fmt.Errorf("failed to create key log file: %w", err)
		}
		defer keyLogFile.Close()
		tlsConfig.KeyLogWriter = keyLogFile
	}

	qc := quicConfig
	qc.Tracer = qlog.DefaultConnectionTracer

	if t.ln, err = quic.ListenEarly(
		udpConn,
		http3.ConfigureTLSConfig(tlsConfig),
		qc,
	); err != nil {
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}

	// Create BFD server if configured.
	if t.options.bfdListenAddr.IsValid() {
		t.bfdServer = bfdl.NewServer(t.options.bfdListenAddr, t.options.onAlive)
	}

	// drainCtx controls the lifetime of the router and BFD server. It
	// survives SIGTERM and is only cancelled after Drain() force-closes
	// all connections (or if no drain happens, by Stop()).
	drainCtx, drainCancel := context.WithCancel(context.Background())
	t.drainCancel = drainCancel

	// serverCtx is derived from the parent ctx and is used for the accept
	// loop. When SIGTERM fires (parent ctx cancelled), the accept loop
	// exits. Connection handlers and the router use independent contexts
	// so they survive shutdown during graceful drain.
	g, serverCtx := errgroup.WithContext(ctx)
	// When the server context is cancelled (SIGTERM), wait for Drain()
	// or Stop() to shut down the listener. If draining, we must NOT close
	// the listener here because the UDP socket is shared with existing
	// QUIC connections. Instead, Drain()/Stop() will close it when done.
	g.Go(func() error {
		<-serverCtx.Done()
		// The accept loop checks serverCtx.Err() and will exit once
		// it gets an error from Accept(). We need to unblock Accept()
		// by either closing the listener (non-drain) or waiting for
		// Drain() to do it (drain path). For non-drain, Stop() is
		// called from the main errgroup which closes the listener.
		// For drain, the accept loop will keep accepting but rejecting
		// new connections until Drain() closes the listener.
		return nil
	})
	// HTTP/3 server loop.
	g.Go(func() error {
		slog.Info("Serving HTTP/3", slog.String("addr", t.ln.Addr().String()))
		for {
			conn, err := t.ln.Accept(serverCtx)
			if errors.Is(err, quic.ErrServerClosed) || serverCtx.Err() != nil {
				slog.Info("QUIC listener closed or context canceled")
				return nil
			}
			if err != nil {
				slog.Error("Failed to accept QUIC connection", slog.Any("error", err))
				continue
			}

			// Reject new connections during drain.
			t.stopMu.Lock()
			reject := t.rejectNewConn
			t.stopMu.Unlock()
			if reject {
				conn.CloseWithError(quic.ApplicationErrorCode(0), "draining")
				continue
			}

			// Serves a single CONNECT-IP connection over HTTP/3.
			// Pass the original (non-errgroup) ctx so connections are NOT
			// cancelled by the server shutdown — drain controls their lifetime.
			oneShotSrv := &http3.Server{
				EnableDatagrams: true,
				Handler:         t.makeSingleConnectHandler(ctx, conn),
			}

			g.Go(func() error {
				if err := oneShotSrv.ServeQUICConn(conn); err != nil {
					slog.Error("Failed to serve QUIC connection", slog.Any("error", err))
				}
				return nil
			})
		}
	})
	// Start the router to handle network traffic. Uses drainCtx so it
	// stays alive during graceful drain (cancelled by Drain() or Stop()).
	g.Go(func() error {
		return t.router.Start(drainCtx)
	})
	// Start BFD server if configured. Uses drainCtx for same reason.
	if t.bfdServer != nil {
		g.Go(func() error {
			return t.bfdServer.Start(drainCtx)
		})
	}

	return g.Wait()
}

func upsertAgentStatus(s *corev1alpha.TunnelNodeStatus, agent *corev1alpha.AgentStatus) {
	for i := range s.Agents {
		if s.Agents[i].Name == agent.Name {
			s.Agents[i] = *agent
			return
		}
	}

	s.Agents = append(s.Agents, *agent)
}

// BFDServer returns the BFD server instance, or nil if BFD is not enabled.
// Useful for testing (e.g. suppressing heartbeats for specific connections).
func (t *TunnelServer) BFDServer() *bfdl.Server {
	return t.bfdServer
}

func (t *TunnelServer) Stop() error {
	t.stopMu.Lock()
	draining := t.draining
	if t.stopped {
		t.stopMu.Unlock()
		return nil
	}
	t.stopped = true
	t.stopMu.Unlock()

	slog.Info("Stopping Tunnel server")

	if err := t.ln.Close(); err != nil {
		slog.Error("Failed to close listener", slog.Any("error", err))
	}

	if !draining {
		// No drain in progress — force-close everything immediately.
		t.conns.ForEach(func(connID string, c *conn) bool {
			c.cancel()
			return true
		})
		if t.drainCancel != nil {
			t.drainCancel()
		}
	}
	// If draining, Drain() manages connection and router lifecycle.

	return nil
}

// BeginDrain signals that a graceful drain is in progress. Must be called
// before the server's context is cancelled so that Stop() knows not to
// force-close connections and the router.
func (t *TunnelServer) BeginDrain() {
	t.stopMu.Lock()
	t.draining = true
	t.stopMu.Unlock()
	slog.Info("Tunnel server entering drain mode")
}

// StopAccepting stops accepting new tunnel connections. Existing QUIC
// connections remain alive (the listener is NOT closed, to preserve the
// underlying UDP socket that existing connections are multiplexed on).
func (t *TunnelServer) StopAccepting() {
	t.stopMu.Lock()
	t.rejectNewConn = true
	t.stopMu.Unlock()
	slog.Info("Rejecting new tunnel connections (drain mode)")
}

// Drain sends BFD AdminDown to all peers, waits for the context to expire,
// then force-closes all remaining connections and the router.
func (t *TunnelServer) Drain(ctx context.Context) {
	// Send BFD AdminDown to notify clients.
	if t.bfdServer != nil {
		t.bfdServer.Drain()
	}

	// Wait for the caller's timeout.
	<-ctx.Done()

	// Force-close all remaining connections.
	t.conns.ForEach(func(connID string, c *conn) bool {
		slog.Info("Force-closing connection during drain", slog.String("connID", connID))
		c.cancel()
		return true
	})

	// Close the QUIC listener (and its underlying UDP socket).
	if t.ln != nil {
		t.ln.Close()
	}

	// Cancel drainCtx to shut down the router and BFD server.
	if t.drainCancel != nil {
		t.drainCancel()
	}
}

// ActiveTCPConns returns the number of active TCP connections being tracked
// across all tunnels.
func (t *TunnelServer) ActiveTCPConns() int {
	return t.connTracker.ActiveCount()
}

// ConnTracker returns the TCP connection tracker for integration with the
// router's packet forwarding path.
func (t *TunnelServer) ConnTracker() *conntrack.Tracker {
	return t.connTracker
}

func iproutesFromPrefixes(ps []netip.Prefix) []connectip.IPRoute {
	routes := make([]connectip.IPRoute, len(ps))
	for i, p := range ps {
		routes[i] = connectip.IPRoute{
			StartIP:    p.Masked().Addr(),
			EndIP:      tunnet.LastIP(p.Masked()),
			IPProtocol: 0, // Allow all protocols.
		}
	}
	return routes
}

// makeSingleConnectHandler creates a handler that serves /ping for latency probes
// and /connect for CONNECT-IP connections.
func (t *TunnelServer) makeSingleConnectHandler(ctx context.Context, qConn quic.Connection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Handle /ping for latency probes - no auth required.
		if r.URL.Path == "/ping" {
			metrics.TunnelPingRequests.Inc()
			w.Header().Set("X-Apoxy-Server-Time", time.Now().UTC().Format(time.RFC3339Nano))
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("pong"))
			return // Don't close QUIC connection for ping requests.
		}

		// All other requests close the QUIC connection when done.
		defer qConn.CloseWithError(ApplicationCodeOK, "")

		tunUID, err := uuid.Parse(strings.TrimPrefix(r.URL.Path, "/connect/"))
		if err != nil {
			slog.Error("Failed to parse UUID", slog.Any("error", err), slog.String("remote", r.RemoteAddr))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Get the appropriate client for this tunnel.
		clusterClient, err := t.clientGetter.GetClient(ctx, tunUID)
		if err != nil {
			slog.Error("Failed to get client for tunnel", slog.Any("error", err), slog.String("tunUID", tunUID.String()))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		metrics.TunnelConnectionRequests.Inc()

		logger := slog.With(slog.String("tunUUID", tunUID.String()))
		logger.Info("Received connection request",
			slog.String("URI", r.URL.String()),
			slog.String("remote", r.RemoteAddr))

		authToken := r.URL.Query().Get("token")
		if authToken == "" {
			logger.Error("Missing token in connection request")
			metrics.TunnelConnectionFailures.WithLabelValues("missing_token").Inc()
			w.WriteHeader(http.StatusForbidden)
			return
		}

		tn, ok := t.tunnels.Get(tunUID.String())
		if !ok {
			logger.Error("Tunnel not found")
			metrics.TunnelConnectionFailures.WithLabelValues("tunnel_not_found").Inc()
			w.WriteHeader(http.StatusNotFound)
			return
		}

		logger = logger.With(slog.String("name", tn.Name))
		if tn.Status.Credentials == nil || tn.Status.Credentials.Token == "" {
			logger.Error("Missing credentials for TunnelNode")
			metrics.TunnelConnectionFailures.WithLabelValues("missing_credentials").Inc()
			w.WriteHeader(http.StatusForbidden)
			return
		}

		claims, err := t.jwtValidator.Validate(authToken)
		if err != nil {
			logger.Error("Failed to validate token", slog.Any("error", err))
			metrics.TunnelConnectionFailures.WithLabelValues("invalid_token").Inc()
			w.WriteHeader(http.StatusForbidden)
			return
		}

		tokenSubj, err := claims.GetSubject()
		if err != nil {
			logger.Error("Failed to get subject from token claims", slog.Any("error", err))
			metrics.TunnelConnectionFailures.WithLabelValues("token_subject_error").Inc()
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if tokenSubj != tunUID.String() {
			logger.Error("Token subject does not match TunnelNode ID",
				slog.String("expected", tunUID.String()),
				slog.String("got", tokenSubj),
			)
			metrics.TunnelConnectionFailures.WithLabelValues("token_subject_mismatch").Inc()
			w.WriteHeader(http.StatusForbidden)
			return
		}

		logger.Info("Validated token for UUID")

		req, err := connectip.ParseRequest(r, connectTmpl)
		if err != nil {
			logger.Error("Failed to parse request", slog.Any("error", err))
			metrics.TunnelConnectionFailures.WithLabelValues("bad_request").Inc()
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		labels := make(map[string]string)
		for key, values := range r.URL.Query() {
			if strings.HasPrefix(key, "label.") && len(values) > 0 {
				labels[strings.TrimPrefix(key, "label.")] = values[0]
			}
		}

		connID := uuid.NewString()
		// Sends connection ID information to the client so that it can
		// track its connection status. This must be done before initializing the proxy.
		w.Header().Add("X-Apoxy-Connection-UUID", connID)
		logger = logger.With(slog.String("connUUID", connID))
		logger.Info("Establishing CONNECT-IP connection")

		// Connection context is independent of the server lifecycle so that
		// existing connections survive SIGTERM during graceful drain. The
		// connection is closed explicitly by Drain() calling c.cancel().
		connCtx, connCancel := context.WithCancel(context.Background())
		defer connCancel()

		conn := &conn{
			connID: connID,
			obj:    tn.DeepCopy(),
			cancel: connCancel,
			labels: labels,
		}
		p := connectip.Proxy{}
		if conn.Conn, err = p.Proxy(w, req); err != nil {
			logger.Error("Failed to proxy request", slog.Any("error", err))
			metrics.TunnelConnectionFailures.WithLabelValues("proxy_error").Inc()
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		t.conns.Set(connID, conn)

		// Register the agent in TunnelNode status before allocating the
		// endpoint so the InfraEndpointReconciler can find the agent when
		// it writes the overlay address.
		logger.Info("Updating agent status")

		agent := &corev1alpha.AgentStatus{
			Name:        connID,
			ConnectedAt: ptr.To(metav1.Now()),
			Labels:      labels,
		}
		// TODO(dilyevsky): Support multiple external addresses in the Status.
		if len(t.options.extAddrs) > 0 && t.options.extAddrs[0].IsValid() {
			agent.PrivateAddress = t.options.extAddrs[0].Addr().String()
		}
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			upd := &corev1alpha.TunnelNode{}
			if err := clusterClient.Get(r.Context(), types.NamespacedName{Name: tn.Name}, upd); apierrors.IsNotFound(err) {
				logger.Warn("Node not found while adding agent")
				return errors.New("node not found")
			} else if err != nil {
				logger.Error("Failed to get node", slog.Any("error", err))
				return err
			}

			upsertAgentStatus(&upd.Status, agent)

			return clusterClient.Status().Update(r.Context(), upd)
		}); err != nil {
			logger.Error("Failed to update agent status", slog.Any("error", err))
		}

		// Invoke onConnect callback if configured.
		// This triggers endpoint allocation; agent must be in TunnelNode
		// status first so the address reconciler can find it.
		if t.options.onConnect != nil {
			t.options.onConnect(ctx, connID, tn)
		}

		// Blocking wait for the lifetime of the tunnel connection.
		select {
		case <-r.Context().Done():
			logger.Info("Tunnel connection closed")
		case <-connCtx.Done():
			logger.Info("Connection context canceled", slog.Any("error", connCtx.Err()))
		}

		if err := conn.Close(); err != nil &&
			!strings.Contains(err.Error(), "close called for canceled stream") {
			logger.Error("Failed to close connection", slog.Any("error", err))
		}

		metrics.TunnelConnectionsActive.Dec()

		// Invoke onDisconnect callback if configured.
		if t.options.onDisconnect != nil {
			t.options.onDisconnect(context.Background(), connID)
		}

		// Unregister from agent metrics scraper.
		if t.options.metricsScraper != nil {
			t.options.metricsScraper.Unregister(connID)
		}

		if conn, exists := t.conns.Get(connID); !exists {
			logger.Error("Tunnel connection not found", slog.Any("connUUID", connID))
		} else {
			// Remove BFD peer before cleaning up routes.
			if t.bfdServer != nil && conn.addrv6.IsValid() {
				t.bfdServer.RemovePeer(conn.addrv6.Addr())
			}

			if conn.addrv6.IsValid() {
				logger.Info("Removing peer address", slog.Any("addr", conn.addrv6))

				if err := t.router.DelAddr(conn.addrv6); err != nil {
					logger.Error("Failed to remove peer address", slog.Any("error", err), slog.Any("addr", conn.addrv6))
				}
				if err := t.router.DelRoute(conn.addrv6); err != nil {
					logger.Error("Failed to remove route", slog.Any("error", err), slog.Any("addr", conn.addrv6))
				}
			}

			if conn.addrv4.IsValid() {
				logger.Info("Removing peer address", slog.Any("addr", conn.addrv4))

				if err := t.router.DelAddr(conn.addrv4); err != nil {
					logger.Error("Failed to remove peer address", slog.Any("error", err), slog.Any("addr", conn.addrv4))
				}
				if err := t.router.DelRoute(conn.addrv4); err != nil {
					logger.Error("Failed to remove route", slog.Any("error", err), slog.Any("addr", conn.addrv4))
				}
			}
		}

		t.conns.Del(connID)

		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			upd := &corev1alpha.TunnelNode{}
			nn := types.NamespacedName{Name: tn.Name}
			// Background context because we want this to be executed even if
			// connection context is canceled.
			ctx := context.Background()
			if err := clusterClient.Get(ctx, nn, upd); apierrors.IsNotFound(err) {
				logger.Warn("Node not found")
				return errors.New("node not found")
			} else if err != nil {
				logger.Error("Failed to get node", slog.Any("error", err))
				return err
			}

			for i, a := range upd.Status.Agents {
				if a.Name == agent.Name {
					upd.Status.Agents = append(upd.Status.Agents[:i], upd.Status.Agents[i+1:]...)
					break
				}
			}

			return clusterClient.Status().Update(ctx, upd)
		}); err != nil {
			logger.Error("Failed to update agent status", slog.Any("error", err))
		}

		logger.Info("Agent disconnected")
	}
}

// setupConn sets up routing for an agent connection with the given addresses.
// Called when an overlay address is allocated for a connected agent.
// The connID is the connection UUID (same as agent.Name in TunnelNode status).
// addrv6 is the allocated ULA prefix (e.g., fd61:706f:7879:...::/96).
// addrv4 is optional and can be an invalid prefix if not needed.
func (t *TunnelServer) setupConn(
	ctx context.Context,
	connID string,
	addrv6 netip.Prefix,
	addrv4 netip.Prefix,
) error {
	log := log.FromContext(ctx).WithValues("connID", connID, "addrv6", addrv6, "addrv4", addrv4)

	conn, exists := t.conns.Get(connID)
	if !exists {
		return fmt.Errorf("connection %s not found", connID)
	}

	// Check if addresses are already configured.
	if conn.addrv6.IsValid() && conn.addrv6 == addrv6 {
		log.V(1).Info("Agent address already configured")
		return nil
	}

	// Set addresses on connection.
	conn.addrv6 = addrv6
	if addrv4.IsValid() {
		conn.addrv4 = addrv4
	}
	t.conns.Set(connID, conn)

	// Assign addresses to CONNECT-IP connection.
	addrs := []netip.Prefix{addrv6}
	if addrv4.IsValid() {
		addrs = append(addrs, addrv4)
	}
	if err := conn.AssignAddresses(ctx, addrs); err != nil {
		return fmt.Errorf("failed to assign addresses: %w", err)
	}

	// Add to router.
	if err := t.router.AddAddr(addrv6, conn); err != nil {
		return fmt.Errorf("failed to add IPv6 addr: %w", err)
	}
	if err := t.router.AddRoute(addrv6); err != nil {
		return fmt.Errorf("failed to add IPv6 route: %w", err)
	}
	if addrv4.IsValid() {
		if err := t.router.AddAddr(addrv4, conn); err != nil {
			return fmt.Errorf("failed to add IPv4 addr: %w", err)
		}
		if err := t.router.AddRoute(addrv4); err != nil {
			return fmt.Errorf("failed to add IPv4 route: %w", err)
		}
	}

	metrics.TunnelConnectionsActive.Inc()

	// Register BFD peer so the server can track liveness.
	if t.bfdServer != nil {
		t.bfdServer.AddPeer(addrv6.Addr(), connID)
	}

	// Register with agent metrics scraper now that the overlay address is known.
	if t.options.metricsScraper != nil {
		var projectID string
		if t.options.projectIDLookup != nil {
			projectID = t.options.projectIDLookup(string(conn.obj.UID))
		}
		var metricsPort int
		if portStr, ok := conn.labels[metrics.LabelMetricsPort]; ok {
			if p, err := strconv.Atoi(portStr); err == nil {
				metricsPort = p
			}
		}
		t.options.metricsScraper.Register(metrics.ScrapeTarget{
			ConnID:      connID,
			TunnelNode:  conn.obj.Name,
			AgentName:   connID,
			ProjectID:   projectID,
			OverlayAddr: addrv6.Addr().String(),
			MetricsPort: metricsPort,
		})
	}

	log.Info("Client addresses assigned")

	// Advertise routes to client.
	advRoutes := []netip.Prefix{netip.PrefixFrom(addrv6.Addr(), 128)}
	// Always include the network prefix so the agent can reach other endpoints
	// in the same overlay network (e.g. backplane services).
	if ula, err := tunnet.ULAFromPrefix(ctx, addrv6); err == nil {
		advRoutes = append(advRoutes, ula.NetPrefix())
	}
	if conn.obj.Spec.EgressGateway != nil && conn.obj.Spec.EgressGateway.Enabled {
		log.Info("Enabling egress gateway")
		advRoutes = append(advRoutes,
			netip.PrefixFrom(netip.IPv4Unspecified(), 0),
			netip.PrefixFrom(netip.IPv6Unspecified(), 0),
		)
	}

	log.Info("Advertising routes", "routes", advRoutes)

	if err := conn.AdvertiseRoute(ctx, iproutesFromPrefixes(advRoutes)); err != nil {
		return fmt.Errorf("failed to advertise routes: %w", err)
	}

	return nil
}

// CloseConnection closes the tunnel connection with the given ID.
// No-op if the connection does not exist.
func (t *TunnelServer) CloseConnection(connID string) {
	if c, exists := t.conns.Get(connID); exists {
		slog.Info("Closing connection by ID", slog.String("connID", connID))
		c.cancel()
	}
}

// CloseConnectionsByName closes all active connections for the TunnelNode with the given name.
// WARNING: In multi-tenant environments, multiple TunnelNodes across different
// projects can share the same name. Prefer CloseConnectionsByUID to avoid
// cross-project collisions.
func (t *TunnelServer) CloseConnectionsByName(name string) {
	t.conns.ForEach(func(connID string, c *conn) bool {
		if c.obj.Name == name {
			slog.Info("Closing connection for removed TunnelNode",
				slog.String("connID", connID),
				slog.String("tunnelNode", name),
			)
			c.cancel()
		}
		return true
	})
	// Remove from tunnels map by scanning for the name.
	t.tunnels.ForEach(func(uid string, tn *corev1alpha.TunnelNode) bool {
		if tn.Name == name {
			t.tunnels.Del(uid)
		}
		return true
	})
}

// CloseConnectionsByUID closes all active connections for the TunnelNode with
// the given UID. This is safe in multi-tenant environments where multiple
// projects may have TunnelNodes with the same name but different UIDs.
func (t *TunnelServer) CloseConnectionsByUID(uid string) {
	t.conns.ForEach(func(connID string, c *conn) bool {
		if string(c.obj.UID) == uid {
			slog.Info("Closing connection for removed TunnelNode",
				slog.String("connID", connID),
				slog.String("tunnelNode", c.obj.Name),
				slog.String("uid", uid),
			)
			c.cancel()
		}
		return true
	})
	t.tunnels.Del(uid)
}

// ReconcileWithClient reconciles a TunnelNode using the provided client.
// This method can be used by both standard reconcilers and multicluster reconcilers.
func (t *TunnelServer) ReconcileWithClient(ctx context.Context, c client.Client, request reconcile.Request) (reconcile.Result, error) {
	defer metrics.TunnelNodesManaged.Set(float64(t.tunnels.Len()))

	node := &corev1alpha.TunnelNode{}
	if err := c.Get(ctx, request.NamespacedName, node); apierrors.IsNotFound(err) {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get TunnelNode: %w", err)
	}

	log := log.FromContext(ctx, "name", node.Name, "uid", node.UID)
	log.Info("Reconciling TunnelNode")

	if !node.DeletionTimestamp.IsZero() {
		log.Info("Deleting TunnelNode")

		// Close all active connections for this tunnel node.
		t.conns.ForEach(func(connID string, c *conn) bool {
			if c.obj.UID == node.UID {
				log.Info("Closing connection for deleted TunnelNode", "connID", connID)
				c.cancel()
			}
			return true
		})

		t.tunnels.Del(string(node.UID))

		return reconcile.Result{}, nil
	}

	t.tunnels.Set(string(node.UID), node)

	// Configure agent addresses from TunnelNode status.
	var pendingAddress bool
	for _, agent := range node.Status.Agents {
		log := log.WithValues("agent", agent.Name)

		// Check if connection exists for this agent.
		if _, exists := t.conns.Get(agent.Name); !exists {
			log.V(1).Info("Connection not found")
			continue
		}

		// Parse IPv6 address from agent status.
		if agent.AgentAddress == "" {
			log.Info("Agent address is empty, will requeue")
			pendingAddress = true
			continue
		}
		addrv6, err := netip.ParseAddr(agent.AgentAddress)
		if err != nil {
			log.Error(err, "Failed to parse agent address", "address", agent.AgentAddress)
			continue
		}

		// Parse IPv4 address from agent addresses if available.
		var addrv4 netip.Prefix
		for _, agentAddr := range agent.AgentAddresses {
			if addr, err := netip.ParseAddr(agentAddr); err == nil && addr.Is4() {
				addrv4 = netip.PrefixFrom(addr, 32)
				break
			}
		}

		if err := t.setupConn(ctx, agent.Name, netip.PrefixFrom(addrv6, 96), addrv4); err != nil {
			log.Error(err, "Failed to configure agent address")
			metrics.TunnelConnectionFailures.WithLabelValues("address_configuration_failed").Inc()
			continue
		}
	}

	if pendingAddress {
		return ctrl.Result{RequeueAfter: 1 * time.Second}, nil
	}

	return ctrl.Result{}, nil
}
