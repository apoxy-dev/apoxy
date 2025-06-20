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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
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
	proxyAddr     string
	ulaPrefix     netip.Prefix
	certPath      string
	keyPath       string
	ipam          tunnet.IPAM
	extIPv6Prefix netip.Prefix
}

func defaultServerOptions() *tunnelServerOptions {
	return &tunnelServerOptions{
		proxyAddr:     "0.0.0.0:9443",
		ulaPrefix:     netip.MustParsePrefix("fd00::/64"),
		certPath:      "/etc/apoxy/certs/tunnelproxy.crt",
		keyPath:       "/etc/apoxy/certs/tunnelproxy.key",
		ipam:          tunnet.NewRandomULA(),
		extIPv6Prefix: netip.MustParsePrefix("fd00::/64"),
	}
}

// WithProxyAddr sets the address to bind the proxy to.
func WithProxyAddr(addr string) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.proxyAddr = addr
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

// WithIPAM sets the IPAM to use.
func WithIPAM(ipam tunnet.IPAM) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.ipam = ipam
	}
}

// WithExternalIPv6Prefix sets the external IPv6 prefix. This is the IPv6 prefix used to
// send traffic through the tunnel.
func WithExternalIPv6Prefix(prefix netip.Prefix) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.extIPv6Prefix = prefix
	}
}

type TunnelServer struct {
	http3.Server
	client.Client

	options      *tunnelServerOptions
	jwtValidator token.JWTValidator
	ln           *quic.EarlyListener
	router       router.Router

	// Connections
	mux *connection.MuxedConn
	// Maps
	tunnelNodes *haxmap.Map[string, *corev1alpha.TunnelNode]
}

// NewTunnelServer creates a new server proxy that routes traffic via
// QUIC tunnels.
func NewTunnelServer(
	client client.Client,
	v token.JWTValidator,
	r router.Router,
	opts ...TunnelServerOption,
) *TunnelServer {
	options := defaultServerOptions()
	for _, opt := range opts {
		opt(options)
	}

	s := &TunnelServer{
		Client: client,
		Server: http3.Server{
			EnableDatagrams: true,
		},

		options:      options,
		jwtValidator: v,
		router:       r,

		mux:         connection.NewMuxedConn(),
		tunnelNodes: haxmap.New[string, *corev1alpha.TunnelNode](),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/connect/", s.handleConnect)
	s.Handler = mux

	return s
}

func (t *TunnelServer) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha.TunnelNode{}).
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
		&quic.Config{EnableDatagrams: true},
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
	id, err := uuid.Parse(strings.TrimPrefix(r.URL.Path, "/connect/"))
	if err != nil {
		slog.Error("Failed to parse UUID", slog.Any("error", err), slog.String("remote", r.RemoteAddr))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	logger := slog.With(slog.String("uuid", id.String()))
	logger.Info("Received connection request")

	authToken := r.URL.Query().Get("token")
	if authToken == "" {
		logger.Error("Missing token in connection request")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	tn, ok := t.tunnelNodes.Get(id.String())
	if !ok {
		logger.Error("Tunnel not found")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	logger = logger.With(slog.String("name", tn.Name))
	if tn.Status.Credentials == nil || tn.Status.Credentials.Token == "" {
		logger.Error("Missing credentials for TunnelNode")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if _, err := t.jwtValidator.Validate(authToken, id.String()); err != nil {
		logger.Error("Failed to validate token", slog.Any("error", err))
		w.WriteHeader(http.StatusForbidden)
		return
	}

	logger.Info("Validated token for UUID")

	req, err := connectip.ParseRequest(r, connectTmpl)
	if err != nil {
		logger.Error("Failed to parse request", slog.Any("error", err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	p := connectip.Proxy{}
	conn, err := p.Proxy(w, req)
	if err != nil {
		logger.Error("Failed to proxy request", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	peerV6 := t.options.ipam.AllocateV6(r)
	peerV4 := t.options.ipam.AllocateV4(r)

	if err := conn.AssignAddresses(r.Context(), []netip.Prefix{
		peerV6,
		peerV4,
	}); err != nil {
		logger.Error("Failed to assign address to connection", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	if err := t.router.Add(peerV6, conn); err != nil {
		logger.Error("Failed to add TUN peer", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	if err := t.router.Add(peerV4, conn); err != nil {
		logger.Error("Failed to add TUN peer", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	logger.Info("Client addresses assigned",
		slog.String("ipv4", peerV4.String()),
		slog.String("ipv6", peerV6.String()))

	advRoutes := []netip.Prefix{
		t.options.extIPv6Prefix,
	}
	// If egress gateway is enabled, route 0.0.0.0/0 via the tunnel.
	if tn.Spec.EgressGateway != nil && tn.Spec.EgressGateway.Enabled {
		advRoutes = append(advRoutes,
			netip.PrefixFrom(netip.IPv4Unspecified(), 0),
			netip.PrefixFrom(netip.IPv6Unspecified(), 0),
		)
	}

	logger.Info("Advertising routes", slog.Any("routes", advRoutes))

	if err := conn.AdvertiseRoute(r.Context(), iproutesFromPrefixes(advRoutes)); err != nil {
		logger.Error("Failed to advertise route to connection", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	agent := &corev1alpha.AgentStatus{
		Name:           uuid.NewString(),
		ConnectedAt:    ptr.To(metav1.Now()),
		PrivateAddress: t.options.extIPv6Prefix.Addr().String(),
		AgentAddress:   r.RemoteAddr,
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

	if err := t.options.ipam.Release(peerV6); err != nil {
		logger.Error("Failed to deallocate IP address", slog.Any("error", err))
	}

	if err := t.router.DelAll(peerV6); err != nil {
		logger.Error("Failed to remove TUN peer", slog.Any("error", err))
	}
	if err := t.router.DelAll(peerV4); err != nil {
		logger.Error("Failed to remove TUN peer", slog.Any("error", err))
	}

	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		upd := &corev1alpha.TunnelNode{}
		if err := t.Get(context.Background(), types.NamespacedName{Name: tn.Name}, upd); apierrors.IsNotFound(err) {
			logger.Warn("Node not found")
			return errors.New("node not found")
		} else if err != nil {
			logger.Error("Failed to get node", slog.Any("error", err))
			return err
		}

		// Find and remove the agent from the status
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

	logger.Info("Agent removed", slog.String("name", agent.Name))
}

func (t *TunnelServer) reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
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

	t.AddTunnelNode(node)

	return ctrl.Result{}, nil
}

// AddTunnelNode adds a TunnelNode to the server.
// This is visible for testing purposes, it is usually called as part of
// the reconcile loop.
func (t *TunnelServer) AddTunnelNode(node *corev1alpha.TunnelNode) {
	t.tunnelNodes.Set(string(node.UID), node)
}

// RemoveTunnelNode removes a TunnelNode from the server.
// This is visible for testing purposes, it is usually called as part of
// the reconcile loop.
func (t *TunnelServer) RemoveTunnelNode(node *corev1alpha.TunnelNode) {
	t.tunnelNodes.Del(string(node.UID))
}
