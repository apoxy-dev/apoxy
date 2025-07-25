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
	"slices"
	"strings"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/google/uuid"
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
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

type tunnelServerOptions struct {
	proxyAddr  string
	publicAddr string
	ulaPrefix  netip.Prefix
	certPath   string
	keyPath    string
	extPrefix  netip.Prefix
	selector   string
	ipamv4     tunnet.IPAM
}

func defaultServerOptions() *tunnelServerOptions {
	return &tunnelServerOptions{
		proxyAddr:  "0.0.0.0:9443",
		publicAddr: "",
		ulaPrefix:  netip.MustParsePrefix("fd00::/64"),
		certPath:   "/etc/apoxy/certs/tunnelproxy.crt",
		keyPath:    "/etc/apoxy/certs/tunnelproxy.key",
		selector:   "",
		ipamv4:     tunnet.NewIPAMv4(context.Background()),
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
func WithExternalAddr(prefix netip.Prefix) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.extPrefix = prefix
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

type conn struct {
	*connectip.Conn
	obj            *corev1alpha.TunnelNode
	addrv4, addrv6 netip.Prefix
}

type TunnelServer struct {
	http3.Server
	client.Client

	options *tunnelServerOptions

	jwtValidator token.JWTValidator
	ln           *quic.EarlyListener
	router       router.Router

	// tunnels maps tunnel UIDs to tunnel instances.
	tunnels *haxmap.Map[string, *corev1alpha.TunnelNode]
	// conns maps tunnel connection IDs to connection instances.
	conns *haxmap.Map[string, *conn]
}

// NewTunnelServer creates a new server proxy that routes traffic via
// QUIC tunnels.
func NewTunnelServer(
	client client.Client,
	v token.JWTValidator,
	r router.Router,
	opts ...TunnelServerOption,
) (*TunnelServer, error) {
	options := defaultServerOptions()
	for _, opt := range opts {
		opt(options)
	}

	s := &TunnelServer{
		Client: client,
		Server: http3.Server{
			EnableDatagrams: true,
		},

		options: options,

		jwtValidator: v,
		router:       r,

		tunnels: haxmap.New[string, *corev1alpha.TunnelNode](),
		conns:   haxmap.New[string, *conn](),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/connect/", s.handleConnect)
	s.Handler = mux

	return s, nil
}

func (t *TunnelServer) SetupWithManager(mgr ctrl.Manager) error {
	lss, err := metav1.ParseToLabelSelector(t.options.selector)
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
		Complete(reconcile.Func(t.reconcile)) // Using this contraption to keep reconcile method private.
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

	if t.ln, err = quic.ListenEarly(
		udpConn,
		http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		quicConfig,
	); err != nil {
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()

		if err := t.Stop(); err != nil {
			return fmt.Errorf("failed to shutdown QUIC server: %w", err)
		}

		return nil
	})

	g.Go(func() error {
		slog.Info("Starting HTTP/3 server", slog.String("addr", t.ln.Addr().String()))
		return t.ServeListener(t.ln)
	})

	// Start the router to handle network traffic.
	g.Go(func() error {
		return t.router.Start(ctx)
	})

	return g.Wait()
}

func upsertAgentStatus(s *corev1alpha.TunnelNodeStatus, agent *corev1alpha.AgentStatus) {
	for _, a := range s.Agents {
		if a.Name == agent.Name {
			a = *agent
			return
		}
	}

	s.Agents = append(s.Agents, *agent)
}

func (t *TunnelServer) Stop() error {
	slog.Info("Stopping Tunnel server", slog.String("addr", t.ln.Addr().String()))

	if err := t.router.Close(); err != nil {
		slog.Error("Failed to close router", slog.Any("error", err))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := t.Shutdown(shutdownCtx); err != nil {
		slog.Error("Failed to shutdown server", slog.Any("error", err))
	}

	return t.Server.Close()
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

func (t *TunnelServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	nodeID, err := uuid.Parse(strings.TrimPrefix(r.URL.Path, "/connect/"))
	if err != nil {
		slog.Error("Failed to parse UUID", slog.Any("error", err), slog.String("remote", r.RemoteAddr))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	metrics.TunnelConnectionRequests.Inc()

	logger := slog.With(slog.String("uuid", nodeID.String()))
	logger.Info("Received connection request", slog.String("URI", r.URL.String()))

	authToken := r.URL.Query().Get("token")
	if authToken == "" {
		logger.Error("Missing token in connection request")
		metrics.TunnelConnectionFailures.WithLabelValues("missing_token").Inc()
		w.WriteHeader(http.StatusForbidden)
		return
	}

	tn, ok := t.tunnels.Get(nodeID.String())
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

	if _, err := t.jwtValidator.Validate(authToken, nodeID.String()); err != nil {
		logger.Error("Failed to validate token", slog.Any("error", err))
		metrics.TunnelConnectionFailures.WithLabelValues("invalid_token").Inc()
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

	connID := uuid.NewString()
	// Sends connection ID information to the client so that it can
	// track its connection status. This must be done before initializing the proxy.
	w.Header().Add("X-Apoxy-Connection-UUID", connID)

	conn := &conn{
		obj: tn.DeepCopy(),
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

	agent := &corev1alpha.AgentStatus{
		Name:        connID,
		ConnectedAt: ptr.To(metav1.Now()),
	}
	if t.options.extPrefix.IsValid() {
		agent.PrivateAddress = t.options.extPrefix.Addr().String()
	}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		upd := &corev1alpha.TunnelNode{}
		if err := t.Get(r.Context(), types.NamespacedName{Name: tn.Name}, upd); apierrors.IsNotFound(err) {
			logger.Warn("Node not found while adding agent")
			return errors.New("node not found")
		} else if err != nil {
			logger.Error("Failed to get node", slog.Any("error", err))
			return err
		}

		upsertAgentStatus(&upd.Status, agent)

		return t.Status().Update(r.Context(), upd)
	}); err != nil {
		logger.Error("Failed to update agent status", slog.Any("error", err))
	}

	// Blocking wait for the lifetime of the tunnel connection.
	<-r.Context().Done()

	if err := conn.Close(); err != nil &&
		!strings.Contains(err.Error(), "close called for canceled stream") {
		logger.Error("Failed to close connection", slog.Any("error", err))
	}

	if conn, exists := t.conns.Get(connID); !exists {
		logger.Error("Tunnel connection not found", slog.Any("connUUID", connID))
	} else {
		if conn.addrv6.IsValid() {
			if err := t.router.DelAddr(conn.addrv6); err != nil {
				logger.Error("Failed to remove peer address", slog.Any("error", err), slog.Any("addr", conn.addrv6))
			}
			if err := t.router.DelRoute(conn.addrv6); err != nil {
				logger.Error("Failed to remove route", slog.Any("error", err), slog.Any("addr", conn.addrv6))
			}
		}
		if conn.addrv4.IsValid() {
			if err := t.router.DelAddr(conn.addrv4); err != nil {
				logger.Error("Failed to remove peer address", slog.Any("error", err), slog.Any("addr", conn.addrv4))
			}
			if err := t.router.DelRoute(conn.addrv4); err != nil {
				logger.Error("Failed to remove route", slog.Any("error", err), slog.Any("addr", conn.addrv4))
			}
		}
	}

	t.conns.Del(connID)

	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		upd := &corev1alpha.TunnelNode{}
		nn := types.NamespacedName{Name: tn.Name}
		if err := t.Get(context.Background(), nn, upd); apierrors.IsNotFound(err) {
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

		return t.Status().Update(context.Background(), upd)
	}); err != nil {
		logger.Error("Failed to update agent status", slog.Any("error", err))
	}

	logger.Info("Agent disconnected", slog.String("name", agent.Name))
}

func (t *TunnelServer) reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	defer metrics.TunnelNodesManaged.Set(float64(t.tunnels.Len()))

	node := &corev1alpha.TunnelNode{}
	if err := t.Get(ctx, request.NamespacedName, node); apierrors.IsNotFound(err) {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get TunnelNode: %w", err)
	}

	log := log.FromContext(ctx, "name", node.Name, "uid", node.UID)
	log.Info("Reconciling TunnelNode")

	if !node.DeletionTimestamp.IsZero() {
		log.Info("Deleting TunnelNode")

		// TODO: Send GOAWAY to all connected clients for the associated tunnel node.

		t.RemoveTunnelNode(node)

		return reconcile.Result{}, nil
	}

	t.tunnels.Set(string(node.UID), node)

	if t.options.publicAddr != "" {
		var updated bool
		if !slices.Contains(node.Status.Addresses, t.options.publicAddr) {
			node.Status.Addresses = append(node.Status.Addresses, t.options.publicAddr)
			updated = true
		}
		if updated {
			if err := t.Status().Update(ctx, node); err != nil {
				return reconcile.Result{}, fmt.Errorf("failed to update TunnelNode status: %w", err)
			}
		}
	}

	for _, agent := range node.Status.Agents {
		// TODO(dilyevsky): Agent status should have a tunnel proxy
		// info to which agent is connected. Right now we just assume
		// that if agent name (conn uuid) is missing from t.conns,
		// then it belongs to a different node.
		conn, exists := t.conns.GetOrSet(agent.Name, &conn{
			obj: node,
		})
		if !exists { // Connection belongs to a different node.
			log.V(1).Info("Connection not found", "agent", agent.Name)
			continue
		}

		// Check if we already allocated and assigned addresses.
		if conn.addrv6.IsValid() && conn.addrv4.IsValid() {
			log.V(1).Info("Agent address is already assigned", "agent", agent.Name)
			continue
		}

		if agent.AgentAddress == "" {
			log.Info("Agent address is empty", "agent", agent.Name)
			continue
		}

		if !conn.addrv6.IsValid() {
			var err error
			conn.addrv6, err = netip.ParsePrefix(agent.AgentAddress)
			if err != nil {
				log.Error(err, "Failed to parse agent address", "agent", agent.Name)
				continue
			}
		}
		t.conns.Set(agent.Name, conn)

		// TODO(dilyevsky): v4 prefix should also be delivered via agent status
		// struct (needs api change to support multiple addresses).
		if !conn.addrv4.IsValid() {
			var err error
			conn.addrv4, err = t.options.ipamv4.Allocate()
			if err != nil {
				log.Error(err, "Failed to allocate IPv4 address", "agent", agent.Name)
				continue
			}
		}
		t.conns.Set(agent.Name, conn)

		if err := conn.AssignAddresses(ctx, []netip.Prefix{
			conn.addrv6,
			conn.addrv4,
		}); err != nil {
			log.Error(err, "Failed to assign address to connection", "agent", agent.Name)
			metrics.TunnelConnectionFailures.WithLabelValues("address_assignment_failed").Inc()
			return reconcile.Result{}, nil
		}

		if err := t.router.AddAddr(conn.addrv6, conn); err != nil {
			log.Error(err, "Failed to add TUN peer")
			metrics.TunnelConnectionFailures.WithLabelValues("tun_peer_add_failed").Inc()
			return reconcile.Result{}, nil
		}
		if err := t.router.AddRoute(conn.addrv6); err != nil {
			log.Error(err, "Failed to add route")
			metrics.TunnelConnectionFailures.WithLabelValues("route_addition_failed").Inc()
			return reconcile.Result{}, nil
		}
		if err := t.router.AddAddr(conn.addrv4, conn); err != nil {
			log.Error(err, "Failed to add TUN peer")
			metrics.TunnelConnectionFailures.WithLabelValues("tun_peer_add_failed").Inc()
			return reconcile.Result{}, nil
		}
		if err := t.router.AddRoute(conn.addrv4); err != nil {
			log.Error(err, "Failed to add route")
			metrics.TunnelConnectionFailures.WithLabelValues("route_addition_failed").Inc()
			return reconcile.Result{}, nil
		}

		metrics.TunnelConnectionsActive.Inc()
		defer metrics.TunnelConnectionsActive.Dec()

		log.Info("Client addresses assigned", "ipv4", conn.addrv4, "ipv6", conn.addrv6)

		var advRoutes []netip.Prefix
		if t.options.extPrefix.IsValid() {
			advRoutes = append(advRoutes, t.options.extPrefix)
		} else {
			log.Info("WARNING: External IPv6 prefix not configured")
		}
		// If egress gateway is enabled, route 0.0.0.0/0 via the tunnel.
		if conn.obj.Spec.EgressGateway != nil && conn.obj.Spec.EgressGateway.Enabled {
			advRoutes = append(advRoutes,
				netip.PrefixFrom(netip.IPv4Unspecified(), 0),
				netip.PrefixFrom(netip.IPv6Unspecified(), 0),
			)
		}

		log.Info("Advertising routes", "routes", advRoutes)

		if err := conn.AdvertiseRoute(ctx, iproutesFromPrefixes(advRoutes)); err != nil {
			log.Error(err, "Failed to advertise route to connection")
			metrics.TunnelConnectionFailures.WithLabelValues("route_advertisement_failed").Inc()
			conn.Close()
			return reconcile.Result{}, nil
		}

		// TODO(dilyevsky): Add agent status Phase and update it here. Consider creating
		// a whole separate top-level object for Agent-TunnelProxy connections.
	}

	return ctrl.Result{}, nil
}

// AddTunnelNode adds a TunnelNode to the server.
// This is visible for testing purposes, it is usually called as part of
// the reconcile loop.
func (t *TunnelServer) AddTunnelNode(node *corev1alpha.TunnelNode) {
	t.tunnels.Set(string(node.UID), node)
}

// RemoveTunnelNode removes a TunnelNode from the server.
// This is visible for testing purposes, it is usually called as part of
// the reconcile loop.
func (t *TunnelServer) RemoveTunnelNode(node *corev1alpha.TunnelNode) {
	t.tunnels.Del(string(node.UID))
}
