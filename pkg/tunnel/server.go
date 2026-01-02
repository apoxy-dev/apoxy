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
	"slices"
	"strings"

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
	"sigs.k8s.io/controller-runtime/pkg/handler"
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
	extAddrs   []netip.Prefix
	selector   string
	ipamv4     tunnet.IPAM
	keyLogPath string
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

type conn struct {
	*connectip.Conn
	connID         string
	obj            *corev1alpha.TunnelNode
	addrv4, addrv6 netip.Prefix
}

func (c *conn) String() string {
	return fmt.Sprintf("%s [%s]: %v %v", c.obj.Name, c.connID, c.addrv4, c.addrv6)
}

// ClientGetter is an interface for obtaining a Kubernetes client.
// This abstraction allows the TunnelServer to work with both single-cluster
// and multi-cluster setups (e.g., multicluster-runtime).
type ClientGetter interface {
	// GetClient returns a client for the given context.
	// In single-cluster mode, clusterName can be empty.
	// In multi-cluster mode, clusterName identifies the target cluster.
	GetClient(ctx context.Context, clusterName string) (client.Client, error)
}

// SingleClusterClientGetter wraps a single client.Client for use with ClientGetter.
type SingleClusterClientGetter struct {
	Client client.Client
}

// GetClient returns the wrapped client, ignoring the clusterName.
func (s *SingleClusterClientGetter) GetClient(ctx context.Context, clusterName string) (client.Client, error) {
	return s.Client, nil
}

// TunnelServer manages QUIC tunnel connections and routes traffic via CONNECT-IP.
// It is designed to be used with a separate TunnelNodeReconciler that handles
// Kubernetes reconciliation, making it compatible with multicluster-runtime.
type TunnelServer struct {
	options *tunnelServerOptions

	clientGetter ClientGetter
	jwtValidator token.JWTValidator
	ln           *quic.EarlyListener
	router       router.Router
	handler      http.Handler

	// tunnels maps tunnel UIDs to tunnel instances.
	tunnels *haxmap.Map[string, *corev1alpha.TunnelNode]
	// conns maps tunnel connection IDs to connection instances.
	conns *haxmap.Map[string, *conn]
}

// TunnelNodeReconciler reconciles TunnelNode objects and delegates connection
// management to a TunnelServer. This reconciler can be used with multicluster-runtime
// by using the EngageWithManager method instead of SetupWithManager.
type TunnelNodeReconciler struct {
	client        client.Client
	server        *TunnelServer
	labelSelector string
}

// NewTunnelServer creates a new server proxy that routes traffic via
// QUIC tunnels.
func NewTunnelServer(
	clientGetter ClientGetter,
	v token.JWTValidator,
	r router.Router,
	opts ...TunnelServerOption,
) (*TunnelServer, error) {
	options := defaultServerOptions()
	for _, opt := range opts {
		opt(options)
	}

	s := &TunnelServer{
		options: options,

		clientGetter: clientGetter,
		jwtValidator: v,
		router:       r,

		tunnels: haxmap.New[string, *corev1alpha.TunnelNode](),
		conns:   haxmap.New[string, *conn](),
	}

	return s, nil
}

// NewTunnelNodeReconciler creates a new reconciler for TunnelNode objects.
// The reconciler delegates connection management to the provided TunnelServer.
// For multicluster-runtime, use NewTunnelNodeReconcilerWithClientGetter instead.
func NewTunnelNodeReconciler(c client.Client, server *TunnelServer, labelSelector string) *TunnelNodeReconciler {
	return &TunnelNodeReconciler{
		client:        c,
		server:        server,
		labelSelector: labelSelector,
	}
}

// SetupWithManager sets up the reconciler with a standard controller-runtime manager.
// For multicluster-runtime compatibility, use EngageWithManager instead.
func (r *TunnelNodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	lss, err := metav1.ParseToLabelSelector(r.labelSelector)
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
		Complete(r)
}

// EngageWithManager returns a builder that can be used with multicluster-runtime.
// The caller is responsible for completing the builder with a cluster-aware handler.
//
// Example usage with multicluster-runtime:
//
//	import mcbuilder "sigs.k8s.io/multicluster-runtime/pkg/builder"
//
//	reconciler := tunnel.NewTunnelNodeReconciler(server, labelSelector)
//	err := mcbuilder.ControllerManagedBy(mgr).
//	    For(&corev1alpha.TunnelNode{}, reconciler.Predicates()...).
//	    Complete(reconciler)
func (r *TunnelNodeReconciler) EngageWithManager(mgr ctrl.Manager) *builder.Builder {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha.TunnelNode{})
}

// Predicates returns the predicates to use when setting up the controller.
// This is useful when using EngageWithManager or multicluster-runtime.
func (r *TunnelNodeReconciler) Predicates() []predicate.Predicate {
	preds := []predicate.Predicate{
		&predicate.ResourceVersionChangedPredicate{},
	}
	if r.labelSelector != "" {
		lss, err := metav1.ParseToLabelSelector(r.labelSelector)
		if err == nil {
			if ls, err := predicate.LabelSelectorPredicate(*lss); err == nil {
				preds = append(preds, ls)
			}
		}
	}
	return preds
}

// EventHandler returns an event handler that enqueues reconcile requests.
// This is useful when setting up watches in multicluster scenarios.
func (r *TunnelNodeReconciler) EventHandler() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		return []reconcile.Request{
			{NamespacedName: types.NamespacedName{Name: obj.GetName()}},
		}
	})
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

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		<-ctx.Done()

		if err := t.Stop(); err != nil {
			return fmt.Errorf("failed to shutdown QUIC server: %w", err)
		}

		return nil
	})
	// HTTP/3 server loop.
	g.Go(func() error {
		slog.Info("Serving HTTP/3", slog.String("addr", t.ln.Addr().String()))
		for {
			conn, err := t.ln.Accept(ctx)
			if errors.Is(err, quic.ErrServerClosed) || ctx.Err() != nil {
				slog.Info("QUIC listener closed or context canceled")
				return nil
			}
			if err != nil {
				slog.Error("Failed to accept QUIC connection", slog.Any("error", err))
				continue
			}

			// Serves a single CONNECT-IP connection over HTTP/3.
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

	if err := t.ln.Close(); err != nil {
		slog.Error("Failed to close listener", slog.Any("error", err))
	}

	return nil
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

// makeSingleConnectHandler creates a /connect handler that serves a single CONNECT-IP
// connection and then closes the connection.
func (t *TunnelServer) makeSingleConnectHandler(ctx context.Context, qConn quic.Connection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer qConn.CloseWithError(ApplicationCodeOK, "")

		tunUID, err := uuid.Parse(strings.TrimPrefix(r.URL.Path, "/connect/"))
		if err != nil {
			slog.Error("Failed to parse UUID", slog.Any("error", err), slog.String("remote", r.RemoteAddr))
			w.WriteHeader(http.StatusBadRequest)
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

		connID := uuid.NewString()
		// Sends connection ID information to the client so that it can
		// track its connection status. This must be done before initializing the proxy.
		w.Header().Add("X-Apoxy-Connection-UUID", connID)
		logger = logger.With(slog.String("connUUID", connID))
		logger.Info("Establishing CONNECT-IP connection")

		conn := &conn{
			connID: connID,
			obj:    tn.DeepCopy(),
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

		logger.Info("Updating agent status")

		agent := &corev1alpha.AgentStatus{
			Name:        connID,
			ConnectedAt: ptr.To(metav1.Now()),
		}
		// TODO(dilyevsky): Support multiple external addresses in the Status.
		if len(t.options.extAddrs) > 0 && t.options.extAddrs[0].IsValid() {
			agent.PrivateAddress = t.options.extAddrs[0].Addr().String()
		}
		c, err := t.clientGetter.GetClient(r.Context(), "")
		if err != nil {
			logger.Error("Failed to get client", slog.Any("error", err))
		} else if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			upd := &corev1alpha.TunnelNode{}
			if err := c.Get(r.Context(), types.NamespacedName{Name: tn.Name}, upd); apierrors.IsNotFound(err) {
				logger.Warn("Node not found while adding agent")
				return errors.New("node not found")
			} else if err != nil {
				logger.Error("Failed to get node", slog.Any("error", err))
				return err
			}

			upsertAgentStatus(&upd.Status, agent)

			return c.Status().Update(r.Context(), upd)
		}); err != nil {
			logger.Error("Failed to update agent status", slog.Any("error", err))
		}

		// Blocking wait for the lifetime of the tunnel connection.
		select {
		case <-r.Context().Done():
			logger.Info("Tunnel connection closed")
		case <-ctx.Done():
			logger.Info("Server context closed", slog.Any("error", ctx.Err()))
		}

		if err := conn.Close(); err != nil &&
			!strings.Contains(err.Error(), "close called for canceled stream") {
			logger.Error("Failed to close connection", slog.Any("error", err))
		}

		if conn, exists := t.conns.Get(connID); !exists {
			logger.Error("Tunnel connection not found", slog.Any("connUUID", connID))
		} else {
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

		cleanupClient, cleanupErr := t.clientGetter.GetClient(context.Background(), "")
		if cleanupErr != nil {
			logger.Error("Failed to get client for cleanup", slog.Any("error", cleanupErr))
		} else if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			upd := &corev1alpha.TunnelNode{}
			nn := types.NamespacedName{Name: tn.Name}
			if err := cleanupClient.Get(context.Background(), nn, upd); apierrors.IsNotFound(err) {
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

			return cleanupClient.Status().Update(context.Background(), upd)
		}); err != nil {
			logger.Error("Failed to update agent status", slog.Any("error", err))
		}

		logger.Info("Agent disconnected")
	}
}

// Reconcile implements reconcile.Reconciler for TunnelNodeReconciler.
func (r *TunnelNodeReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	return r.server.reconcileTunnelNode(ctx, r.client, request)
}

// reconcileTunnelNode handles the reconciliation logic for a TunnelNode.
// This method is called by the TunnelNodeReconciler with the appropriate client.
func (t *TunnelServer) reconcileTunnelNode(ctx context.Context, c client.Client, request reconcile.Request) (reconcile.Result, error) {
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
			if err := c.Status().Update(ctx, node); err != nil {
				return reconcile.Result{}, fmt.Errorf("failed to update TunnelNode status: %w", err)
			}
		}
	}

	for _, agent := range node.Status.Agents {
		log := log.WithValues("agent", agent.Name)
		// TODO(dilyevsky): Agent status should have a tunnel proxy
		// info to which agent is connected. Right now we just assume
		// that if agent name (conn uuid) is missing from t.conns,
		// then it belongs to a different node.
		conn, exists := t.conns.GetOrSet(agent.Name, &conn{
			obj: node,
		})
		if !exists { // Connection belongs to a different node.
			log.V(1).Info("Connection not found")
			continue
		}

		// Check if we already allocated and assigned addresses.
		if conn.addrv6.IsValid() && conn.addrv4.IsValid() {
			log.V(1).Info("Agent address is already assigned")
			continue
		}

		if agent.AgentAddress == "" {
			log.Info("Agent address is empty")
			continue
		}

		if !conn.addrv6.IsValid() {
			addr, err := netip.ParseAddr(agent.AgentAddress)
			if err != nil {
				log.Error(err, "Failed to parse agent address", "address", agent.AgentAddress)
				continue
			}
			conn.addrv6 = netip.PrefixFrom(addr, 96)
		}
		t.conns.Set(agent.Name, conn)

		if !conn.addrv4.IsValid() {
			for _, agentAddr := range agent.AgentAddresses {
				if addr, err := netip.ParseAddr(agentAddr); err == nil && addr.Is4() {
					conn.addrv4 = netip.PrefixFrom(addr, 32)
					break
				}
			}
			if !conn.addrv4.IsValid() {
				log.Info("No IPv4 address allocated")
				continue
			}
		}
		t.conns.Set(agent.Name, conn)

		log.Info("Assigned addresses to connection",
			"ipv6", conn.addrv6, "ipv4", conn.addrv4)

		if err := conn.AssignAddresses(ctx, []netip.Prefix{
			conn.addrv6,
			conn.addrv4,
		}); err != nil {
			log.Error(err, "Failed to assign address to connection")
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

		advRoutes := []netip.Prefix{
			conn.addrv6,
		}
		for i, advRoute := range advRoutes {
			if !advRoute.IsValid() {
				log.Info("WARNING: route to be advertised is invalid", "route", advRoute.String())
				continue
			}
			// We'll only advertise single-IP routes so extend the bitmask to max.
			if advRoute.Addr().Is4() {
				advRoutes[i] = netip.PrefixFrom(advRoute.Addr(), 32)
			} else {
				advRoutes[i] = netip.PrefixFrom(advRoute.Addr(), 128)
			}
		}
		// If egress gateway is enabled, route 0.0.0.0/0 via the tunnel.
		if conn.obj.Spec.EgressGateway != nil && conn.obj.Spec.EgressGateway.Enabled {
			log.Info("Enabling egress gateway")
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
