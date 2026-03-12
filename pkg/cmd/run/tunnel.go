package run

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	k8srest "k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy/client/versioned"
	"github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/endpointselect"
)

var tunnelBackoff = wait.NewExponentialBackoffManager(
	1*time.Second,
	30*time.Second,
	2*time.Second,
	retry.DefaultBackoff.Factor,
	retry.DefaultBackoff.Jitter,
	clock.RealClock{},
)

func resolveTunnelConfig(in *configv1alpha1.TunnelConfig) *configv1alpha1.TunnelConfig {
	out := in.DeepCopy()
	if out.Mode == "" {
		out.Mode = configv1alpha1.TunnelModeUserspace
	}
	if out.MinConns == nil {
		out.MinConns = ptr.To(1)
	}
	if out.HealthAddr == "" {
		out.HealthAddr = ":8080"
	}
	if out.MetricsAddr == "" {
		out.MetricsAddr = ":8081"
	}
	if out.EndpointSelection == "" {
		out.EndpointSelection = "latency"
	}
	if out.SocksPort == nil {
		out.SocksPort = ptr.To(1080)
	}
	return out
}

func validateTunnelConfig(cfg *configv1alpha1.Config, tc *configv1alpha1.TunnelConfig) error {
	if tc.Name == "" {
		return fmt.Errorf("name must be set")
	}
	if cfg.CurrentProject.String() == "00000000-0000-0000-0000-000000000000" {
		return fmt.Errorf("currentProject must be set in config")
	}
	switch tc.Mode {
	case configv1alpha1.TunnelModeKernel, configv1alpha1.TunnelModeUserspace:
	default:
		return fmt.Errorf("invalid tunnel mode %q: must be one of kernel, user", tc.Mode)
	}
	if _, err := endpointselect.ParseStrategy(tc.EndpointSelection); err != nil {
		return fmt.Errorf("invalid endpointSelection %q: %w", tc.EndpointSelection, err)
	}
	return nil
}

func ensureRuntimeTunnelNode(
	ctx context.Context,
	a3y versioned.Interface,
	tc *configv1alpha1.TunnelConfig,
) (*corev1alpha.TunnelNode, error) {
	var tunnelNode *corev1alpha.TunnelNode
	err := wait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (bool, error) {
		tn, err := a3y.CoreV1alpha().TunnelNodes().Get(ctx, tc.Name, metav1.GetOptions{})
		if err == nil {
			tunnelNode = tn
			return true, nil
		}

		if errors.IsNotFound(err) {
			if !tc.AutoCreate {
				return false, err
			}

			slog.Info("TunnelNode not found, auto-creating", slog.String("name", tc.Name))
			tn, createErr := a3y.CoreV1alpha().TunnelNodes().Create(ctx, &corev1alpha.TunnelNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: tc.Name,
				},
				Spec: corev1alpha.TunnelNodeSpec{},
			}, metav1.CreateOptions{})
			if createErr == nil {
				tunnelNode = tn
				return true, nil
			}
			if errors.IsAlreadyExists(createErr) || errors.IsNotFound(createErr) || isRetryableTunnelNodeError(createErr) {
				slog.Info("TunnelNode API not ready yet, retrying auto-create", slog.Any("error", createErr))
				return false, nil
			}
			return false, createErr
		}

		if isRetryableTunnelNodeError(err) {
			slog.Info("TunnelNode API not ready yet, retrying", slog.Any("error", err))
			return false, nil
		}

		return false, err
	})
	if err != nil {
		return nil, err
	}

	return tunnelNode, nil
}

func isRetryableTunnelNodeError(err error) bool {
	return errors.IsServiceUnavailable(err) ||
		errors.IsServerTimeout(err) ||
		errors.IsTimeout(err) ||
		errors.IsTooManyRequests(err)
}

// runtimeTunConn represents a single tunnel connection worker.
type runtimeTunConn struct {
	id          uuid.UUID
	conn        *tunnel.Conn
	stopCh      chan struct{}
	connectedAt time.Time
}

// runtimeTunnelReconciler manages tunnel connections as a runtime component.
type runtimeTunnelReconciler struct {
	client.Client

	scheme   *runtime.Scheme
	runCtx   context.Context
	cfg      *configv1alpha1.Config
	tunCfg   *configv1alpha1.TunnelConfig
	minConns int

	tunDialer *tunnel.TunnelDialer
	tunMu     sync.RWMutex
	tunConns  []*runtimeTunConn

	endpointSelector endpointselect.Selector

	// Dial parameters protected by dialMu.
	dialMu     sync.RWMutex
	tunnelUID  uuid.UUID
	srvAddr    string
	clientOpts []tunnel.TunnelClientOption
}

func (r *runtimeTunnelReconciler) setupWithManager(
	mgr ctrl.Manager,
	tunnelNodeName string,
) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(
			&corev1alpha.TunnelNode{},
			builder.WithPredicates(
				predicate.ResourceVersionChangedPredicate{},
				predicate.NewPredicateFuncs(func(obj client.Object) bool {
					return obj != nil && obj.GetName() == tunnelNodeName
				}),
			),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
			CacheSyncTimeout:        30 * time.Second,
		}).
		Complete(reconcile.Func(r.reconcile))
}

func (r *runtimeTunnelReconciler) reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	l.Info("Reconciling TunnelNode")

	var tunnelNode corev1alpha.TunnelNode
	if err := r.Get(ctx, req.NamespacedName, &tunnelNode); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return ctrl.Result{}, nil
		}
		l.Error("Failed to get TunnelNode", "error", err)
		return ctrl.Result{}, err
	}

	// 1. Update stored tunnel info.
	cOpts := []tunnel.TunnelClientOption{}
	tnUUID, err := uuid.Parse(string(tunnelNode.ObjectMeta.UID))
	if err != nil {
		l.Error("Failed to parse UID", slog.Any("error", err))
		return ctrl.Result{}, err
	}
	if tunnelNode.Status.Credentials == nil || tunnelNode.Status.Credentials.Token == "" {
		l.Error("TunnelNode has no credentials, waiting for credentials")
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	cOpts = append(cOpts, tunnel.WithAuthToken(tunnelNode.Status.Credentials.Token))

	var srvAddr string
	if !r.cfg.IsLocalMode {
		if len(tunnelNode.Status.Addresses) == 0 {
			l.Error("TunnelNode has no addresses")
			return ctrl.Result{RequeueAfter: time.Second}, nil
		} else if len(tunnelNode.Status.Addresses) == 1 {
			srvAddr = tunnelNode.Status.Addresses[0]
		} else {
			selected, err := r.endpointSelector.Select(ctx, tunnelNode.Status.Addresses)
			if err != nil {
				l.Warn("Endpoint selection failed, using random", slog.Any("error", err))
				srvAddr = tunnelNode.Status.Addresses[rand.Intn(len(tunnelNode.Status.Addresses))]
			} else {
				srvAddr = selected
			}
		}
	} else {
		apiServerHost := "localhost"
		if os.Getenv("APOXY_API_SERVER_HOST") != "" {
			apiServerHost = os.Getenv("APOXY_API_SERVER_HOST")
		}
		srvAddr = apiServerHost + ":9443"
	}

	if r.cfg.IsLocalMode || r.tunCfg.InsecureSkipVerify {
		cOpts = append(cOpts, tunnel.WithInsecureSkipVerify(true))
	}

	r.dialMu.Lock()
	r.tunnelUID = tnUUID
	r.srvAddr = srvAddr
	r.clientOpts = cOpts
	r.dialMu.Unlock()

	// 2. Manage connection count.
	r.tunMu.Lock()
	defer r.tunMu.Unlock()
	n := len(r.tunConns)
	if r.minConns-n < 0 {
		excess := n - r.minConns
		l.Info("Too many connections, cancelling excess", slog.Int("excess", excess))
		for _, conn := range r.tunConns[:excess] {
			l.Info("Cancelling connection", slog.String("id", conn.id.String()))
			close(conn.stopCh)
		}
		r.tunConns = r.tunConns[excess:]
	} else if r.minConns-n > 0 {
		l.Info("Not enough connections, establishing more",
			slog.Int("min", r.minConns), slog.Int("cur", n))

		for i := 0; i < r.minConns-n; i++ {
			conn := &runtimeTunConn{
				id:     uuid.New(),
				stopCh: make(chan struct{}),
			}
			r.tunConns = append(r.tunConns, conn)
			go func(conn *runtimeTunConn) {
				wait.BackoffUntil(func() {
					r.dialMu.RLock()
					tunnelUID := r.tunnelUID
					srvAddr := r.srvAddr
					clientOpts := make([]tunnel.TunnelClientOption, len(r.clientOpts))
					copy(clientOpts, r.clientOpts)
					r.dialMu.RUnlock()

					slog.Info("Connecting to tunnel server", slog.String("address", srvAddr))

					dialCtx := r.runCtx
					if dialCtx == nil {
						dialCtx = ctx
					}

					c, err := r.tunDialer.Dial(dialCtx, tunnelUID, srvAddr, clientOpts...)
					if err != nil {
						slog.Error("Failed to dial tunnel", slog.Any("error", err))
						return
					}

					slog.Info("Tunnel connected", slog.String("uuid", c.UUID.String()))

					conn.id = c.UUID
					conn.conn = c
					conn.connectedAt = time.Now()

					<-c.Context().Done()

					slog.Info("Tunnel disconnected",
						slog.String("uuid", c.UUID.String()),
						slog.Any("error", c.Context().Err()))
				}, tunnelBackoff, false, conn.stopCh)
			}(conn)
		}
	} else {
		l.Info("Matching tunnel connections", slog.Int("min", r.minConns), slog.Int("cur", n))
	}

	return ctrl.Result{}, nil
}

func (r *runtimeTunnelReconciler) healthHandler(w http.ResponseWriter, _ *http.Request) {
	r.tunMu.RLock()
	defer r.tunMu.RUnlock()

	activeConns := 0
	healthyConns := 0
	var allAddrs []string
	var connDetails []string

	for _, conn := range r.tunConns {
		if conn.conn == nil {
			continue
		}
		if conn.conn.Context().Err() != nil {
			continue
		}
		activeConns++

		addrs, err := conn.conn.LocalAddrs()
		if err != nil || len(addrs) == 0 {
			connDetails = append(connDetails, fmt.Sprintf("  - %s: no addresses", conn.id.String()[:8]))
			continue
		}
		healthyConns++

		var addrStrs []string
		for _, addr := range addrs {
			addrStrs = append(addrStrs, addr.String())
			allAddrs = append(allAddrs, addr.String())
		}
		uptime := time.Since(conn.connectedAt).Truncate(time.Second)
		connDetails = append(connDetails, fmt.Sprintf("  - %s: %v (uptime: %s)", conn.id.String()[:8], addrStrs, uptime))
	}

	if healthyConns > 0 {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK\n\nStatus: healthy\nConnections: %d healthy, %d active\nTunnel IPs: %v\n", healthyConns, activeConns, allAddrs)
	} else if activeConns > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "UNHEALTHY\n\nStatus: degraded\nConnections: %d active but none have addresses assigned\n", activeConns)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "UNHEALTHY\n\nStatus: disconnected\nConnections: none active\n")
	}

	if len(connDetails) > 0 {
		fmt.Fprintf(w, "\nConnection Details:\n")
		for _, detail := range connDetails {
			fmt.Fprintf(w, "%s\n", detail)
		}
	}
}

func runTunnel(ctx context.Context, cfg *configv1alpha1.Config, tc *configv1alpha1.TunnelConfig) error {
	slog.Info("Starting tunnel component",
		slog.String("tunnelNodeName", tc.Name),
		slog.String("mode", string(tc.Mode)))

	kCluster, err := k8srest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("unable to create in-cluster config: %w", err)
	}

	a3y, err := versioned.NewForConfig(kCluster)
	if err != nil {
		return fmt.Errorf("unable to create API client: %w", err)
	}

	// Wait for the aggregated API to come up, then fetch or auto-create the TunnelNode.
	tn, err := ensureRuntimeTunnelNode(ctx, a3y, tc)
	if err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("unable to get TunnelNode: %w", err)
		}
		return fmt.Errorf("unable to ensure TunnelNode: %w", err)
	}

	// Create endpoint selector.
	strategy, err := endpointselect.ParseStrategy(tc.EndpointSelection)
	if err != nil {
		return fmt.Errorf("unable to parse endpoint selection strategy: %w", err)
	}
	selectorOpts := []endpointselect.Option{
		endpointselect.WithPingsPerEndpoint(3),
	}
	if tc.InsecureSkipVerify {
		selectorOpts = append(selectorOpts, endpointselect.WithInsecureSkipVerify(true))
	}
	selector, err := endpointselect.NewSelector(strategy, selectorOpts...)
	if err != nil {
		return fmt.Errorf("unable to create endpoint selector: %w", err)
	}

	// Parse tunnel mode.
	tunnelMode, err := tunnel.TunnelClientModeFromString(string(tc.Mode))
	if err != nil {
		return fmt.Errorf("unable to parse tunnel mode: %w", err)
	}

	// Build client router.
	socksAddr := fmt.Sprintf(":%d", *tc.SocksPort)
	routerOpts := []tunnel.TunnelClientOption{
		tunnel.WithPcapPath(tc.PacketCapturePath),
		tunnel.WithMode(tunnelMode),
		tunnel.WithSocksListenAddr(socksAddr),
	}

	r, err := tunnel.BuildClientRouter(routerOpts...)
	if err != nil {
		return fmt.Errorf("unable to build client router: %w", err)
	}

	// Set up controller-runtime manager.
	tunScheme := runtime.NewScheme()
	utilruntime.Must(corev1alpha.Install(tunScheme))

	mgr, err := ctrl.NewManager(kCluster, ctrl.Options{
		Scheme:         tunScheme,
		LeaderElection: false,
		Metrics: metricsserver.Options{
			BindAddress: tc.MetricsAddr,
		},
		Cache: cache.Options{
			SyncPeriod: ptr.To(30 * time.Second),
		},
	})
	if err != nil {
		return fmt.Errorf("unable to set up controller manager: %w", err)
	}

	rec := &runtimeTunnelReconciler{
		Client:           mgr.GetClient(),
		scheme:           tunScheme,
		runCtx:           ctx,
		cfg:              cfg,
		tunCfg:           tc,
		minConns:         *tc.MinConns,
		endpointSelector: selector,
		tunConns:         make([]*runtimeTunConn, 0),
		tunDialer:        &tunnel.TunnelDialer{Router: r},
	}

	if err := rec.setupWithManager(mgr, tn.Name); err != nil {
		return fmt.Errorf("unable to set up tunnel reconciler: %w", err)
	}

	g, gctx := errgroup.WithContext(ctx)

	// Start router.
	g.Go(func() error {
		if err := r.Start(gctx); err != nil {
			slog.Error("Router exited with error", slog.Any("error", err))
		}
		return nil
	})

	// Start controller manager.
	g.Go(func() error {
		return mgr.Start(gctx)
	})

	// Start health endpoint server if configured.
	if tc.HealthAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", rec.healthHandler)

		healthServer := &http.Server{
			Addr:    tc.HealthAddr,
			Handler: mux,
		}

		g.Go(func() error {
			slog.Info("Starting health endpoint server", slog.String("address", tc.HealthAddr))
			if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("Health server failed", slog.Any("error", err))
				return err
			}
			return nil
		})

		g.Go(func() error {
			<-gctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return healthServer.Shutdown(shutdownCtx)
		})
	}

	return g.Wait()
}
