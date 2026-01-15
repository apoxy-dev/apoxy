package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.org/x/term"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
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

	"github.com/apoxy-dev/apoxy/client/versioned"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/cmd/tunnel/tui"
	"github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/apoxy-dev/apoxy/pkg/net/dns"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

const (
	matchingTunnelNodesIndex = "remoteTunnelNodeIndex"

	tunnelNodeEpochLabel = "core.apoxy.dev/tunnelnode-epoch"
)

var (
	scheme       = runtime.NewScheme()
	codecFactory = serializer.NewCodecFactory(scheme)
	decodeFn     = codecFactory.UniversalDeserializer().Decode

	backoff = wait.NewExponentialBackoffManager(
		1*time.Second,
		30*time.Second,
		2*time.Second,
		retry.DefaultBackoff.Factor,
		retry.DefaultBackoff.Jitter,
		clock.RealClock{},
	)

	// Flags.
	tunnelNodePcapPath string
	tunnelModeS        string
	tunnelMode         tunnel.TunnelClientMode
	insecureSkipVerify bool
	preserveDefaultGw  []string
	socksListenAddr    string
	minConns           int
	dnsListenAddr      string
	autoCreate         bool
	healthAddr         string
	metricsAddr        string

	preserveDefaultGwDsts []netip.Prefix
)

func init() {
	utilruntime.Must(corev1alpha.Install(scheme))
}

type tunConn struct {
	id          uuid.UUID
	conn        *tunnel.Conn
	stopCh      chan struct{}
	connectedAt time.Time
}

type tunnelNodeReconciler struct {
	client.Client

	scheme *runtime.Scheme
	cfg    *configv1alpha1.Config
	a3y    versioned.Interface

	tunDialer        *tunnel.TunnelDialer
	tunMu            sync.RWMutex
	tunDialerWorkers []*tunConn

	// Dial parameters protected by dialMu
	dialMu     sync.RWMutex
	tunnelUID  uuid.UUID
	srvAddr    string
	clientOpts []tunnel.TunnelClientOption

	// TUI status fields
	tunnelName string
	hasToken   bool
	useTUI     bool
}

var tunnelRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a tunnel",
	Long:  "Create a secure tunnel to the remote Apoxy Edge fabric.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		var err error
		tunnelMode, err = tunnel.TunnelClientModeFromString(tunnelModeS)
		if err != nil {
			return fmt.Errorf("unable to parse tunnel client mode: %w", err)
		}

		for _, dstS := range preserveDefaultGw {
			dst, err := netip.ParsePrefix(dstS)
			if err != nil {
				return fmt.Errorf("unable to parse default gateway address: %w", err)
			}

			preserveDefaultGwDsts = append(preserveDefaultGwDsts, dst)
		}

		cmd.SilenceUsage = true

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("unable to load config: %w", err)
		}

		if cfg.IsLocalMode {
			slog.Info("Running in local mode!")
		}

		a3y, err := config.DefaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		go func() {
			// Launch an internal recursive DNS resolver used
			// to resolve addresses of IPv4 services.
			if err := dns.ListenAndServe(dnsListenAddr); err != nil {
				slog.Error("Failed to start DNS server", slog.Any("error", err))
				os.Exit(1)
			}
		}()

		tunnelNodeName := args[0]

		tn, err := getTunnelNode(ctx, a3y, tunnelNodeName)
		if err != nil {
			return fmt.Errorf("unable to get TunnelNode: %w", err)
		}

		tun := &tunnelNodeReconciler{
			scheme: scheme,
			cfg:    cfg,
			a3y:    a3y,

			tunDialerWorkers: make([]*tunConn, 0),
		}
		return tun.run(ctx, tn)
	},
}

// getTunnelNode gets a TunnelNode by name.
// If autoCreate is true, it will create a new TunnelNode if it doesn't exist
// and return it.
func getTunnelNode(
	ctx context.Context,
	a3y versioned.Interface,
	name string,
) (*corev1alpha.TunnelNode, error) {
	tn, err := a3y.CoreV1alpha().TunnelNodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil && errors.IsNotFound(err) && autoCreate {
		return a3y.CoreV1alpha().TunnelNodes().Create(ctx, &corev1alpha.TunnelNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Spec: corev1alpha.TunnelNodeSpec{
				// Use default values for auto-created TunnelNode
			},
		}, metav1.CreateOptions{})
	}
	return tn, err
}

func (t *tunnelNodeReconciler) run(ctx context.Context, tn *corev1alpha.TunnelNode) error {
	// Determine if we should use TUI
	// Auto-detect non-interactive mode (no TTY on stdin or stdout)
	stdoutTTY := term.IsTerminal(int(os.Stdout.Fd()))
	stdinTTY := term.IsTerminal(int(os.Stdin.Fd()))
	useTUI := stdoutTTY && stdinTTY && !noTUI
	t.useTUI = useTUI

	if !useTUI {
		slog.Info("Running TunnelNode controller", slog.String("name", tn.Name))
	}

	client, err := config.DefaultAPIClient()
	if err != nil {
		return fmt.Errorf("unable to create API client: %w", err)
	}

	mgr, err := ctrl.NewManager(client.RESTConfig, ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		Cache: cache.Options{
			SyncPeriod: ptr.To(30 * time.Second),
		},
	})
	if err != nil {
		return fmt.Errorf("unable to set up overall controller manager: %w", err)
	}

	// When TUI is active, suppress logging to avoid garbling the display
	if useTUI {
		// Disable slog default logger output
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	l := log.New(t.cfg.Verbose && !useTUI)
	ctrl.SetLogger(l)
	klog.SetLogger(l)

	t.Client = mgr.GetClient()
	t.tunnelName = tn.Name
	if err := t.setupWithManager(ctx, mgr, tn.Name); err != nil {
		return fmt.Errorf("unable to set up controller: %w", err)
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return mgr.Start(gctx)
	})

	// Start health endpoint server if configured
	if healthAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", t.healthHandler)

		healthServer := &http.Server{
			Addr:    healthAddr,
			Handler: mux,
		}

		g.Go(func() error {
			if !useTUI {
				slog.Info("Starting health endpoint server", slog.String("address", healthAddr))
			}
			if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				if !useTUI {
					slog.Error("Health server failed", slog.Any("error", err))
				}
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

	// Setup packet observer and channel for TUI
	var packetsCh chan connection.PacketInfo
	var observer *tui.TUIPacketObserver
	if useTUI {
		packetsCh = make(chan connection.PacketInfo, 100)
		observer = tui.NewPacketObserver(packetsCh)
	}

	routerOpts := []tunnel.TunnelClientOption{
		tunnel.WithPcapPath(tunnelNodePcapPath),
		tunnel.WithMode(tunnelMode),
		tunnel.WithPreserveDefaultGatewayDestinations(preserveDefaultGwDsts),
		tunnel.WithSocksListenAddr(socksListenAddr),
	}
	if observer != nil {
		routerOpts = append(routerOpts, tunnel.WithPacketObserver(observer))
	}

	r, err := tunnel.BuildClientRouter(routerOpts...)
	if err != nil {
		return fmt.Errorf("unable to build client router: %w", err)
	}
	g.Go(func() error {
		if err := r.Start(gctx); err != nil {
			if !useTUI {
				slog.Error("Router exited non-zero", slog.Any("error", err))
			}
		}
		return nil
	})
	t.tunDialer = &tunnel.TunnelDialer{Router: r}

	// Print startup summary in non-TUI mode
	if !useTUI {
		printStartupSummary(t.GetTunnelInfo(), minConns)
	}

	// Start TUI if enabled
	if useTUI {
		g.Go(func() error {
			defer close(packetsCh)
			if err := tui.Run(gctx, packetsCh, t); err != nil {
				return err
			}
			// TUI exited normally (user quit) - cancel context to stop other goroutines
			return context.Canceled
		})
	}

	if err := g.Wait(); err != nil && err != context.Canceled {
		return err
	}
	return nil
}

func targetRefPredicate(tunnelNodeName string) predicate.Funcs {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if obj == nil {
			return false
		}
		return obj.GetName() == tunnelNodeName
	})
}

func (t *tunnelNodeReconciler) setupWithManager(
	ctx context.Context,
	mgr ctrl.Manager,
	tunnelNodeName string,
) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(
			&corev1alpha.TunnelNode{},
			builder.WithPredicates(
				predicate.ResourceVersionChangedPredicate{},
				targetRefPredicate(tunnelNodeName),
			),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
			CacheSyncTimeout:        30 * time.Second,
		}).
		Complete(reconcile.Func(t.reconcile))
}

func (t *tunnelNodeReconciler) reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.Info("Reconciling TunnelNode")

	var tunnelNode corev1alpha.TunnelNode
	if err := t.Get(ctx, req.NamespacedName, &tunnelNode); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return ctrl.Result{}, nil
		}
		log.Error("Failed to get TunnelNode", "error", err)
		return ctrl.Result{}, err
	}

	log.Info("TunnelNode found")

	// 1. First update stored tunnel info.

	cOpts := []tunnel.TunnelClientOption{}
	tnUUID, err := uuid.Parse(string(tunnelNode.ObjectMeta.UID))
	if err != nil { // This can only happen in a test environment.
		log.Error("Failed to parse UID", slog.Any("error", err))
		return ctrl.Result{}, err
	}
	if tunnelNode.Status.Credentials == nil || tunnelNode.Status.Credentials.Token == "" {
		log.Error("TunnelNode has no credentials, waiting for credentials")
		return ctrl.Result{
			RequeueAfter: time.Second,
		}, nil
	} else {
		cOpts = append(cOpts, tunnel.WithAuthToken(tunnelNode.Status.Credentials.Token))
	}

	var srvAddr string
	if !t.cfg.IsLocalMode {
		if len(tunnelNode.Status.Addresses) == 0 {
			log.Error("TunnelNode has no addresses")
			return ctrl.Result{
				RequeueAfter: time.Second,
			}, nil
		} else {
			// TODO: Pick unused address at random if available.
			srvAddr = tunnelNode.Status.Addresses[rand.Intn(len(tunnelNode.Status.Addresses))]
		}
	} else {
		apiServerHost := "localhost"
		if os.Getenv("APOXY_API_SERVER_HOST") != "" {
			apiServerHost = os.Getenv("APOXY_API_SERVER_HOST")
		}
		srvAddr = apiServerHost + ":9443"
	}

	if t.cfg.IsLocalMode || insecureSkipVerify {
		cOpts = append(cOpts, tunnel.WithInsecureSkipVerify(true))
	}

	t.dialMu.Lock()
	t.tunnelUID = tnUUID
	t.srvAddr = srvAddr
	t.clientOpts = cOpts
	t.tunnelName = tunnelNode.Name
	t.hasToken = tunnelNode.Status.Credentials != nil && tunnelNode.Status.Credentials.Token != ""
	t.dialMu.Unlock()

	// 2. Calculate how many connections are needed vs how many are already established.

	t.tunMu.Lock()
	defer t.tunMu.Unlock()
	n := len(t.tunDialerWorkers)
	if minConns-n < 0 { // Cancel excess connections.
		excess := n - minConns
		log.Info("Too many connections to this TunnelNode, cancelling excess",
			slog.Int("excess", excess))
		// XXX: Is earliest-first the best method?
		for _, conn := range t.tunDialerWorkers[:excess] {
			log.Info("Cancelling connection", slog.String("id", conn.id.String()))
			close(conn.stopCh)
		}
		t.tunDialerWorkers = t.tunDialerWorkers[:excess]
	} else if minConns-n > 0 {
		log.Info("Not enough connections to this TunnelNode, attempting to establish more",
			slog.Int("min", minConns), slog.Int("cur", n))

		for i := 0; i < minConns-n; i++ {
			conn := &tunConn{
				id:     uuid.New(),
				stopCh: make(chan struct{}),
			}
			t.tunDialerWorkers = append(t.tunDialerWorkers, conn)
			go func(conn *tunConn) {
				wait.BackoffUntil(func() {
					// Read dial parameters with read lock
					t.dialMu.RLock()
					tunnelUID := t.tunnelUID
					srvAddr := t.srvAddr
					clientOpts := make([]tunnel.TunnelClientOption, len(t.clientOpts))
					copy(clientOpts, t.clientOpts)
					t.dialMu.RUnlock()

					if !t.useTUI {
						fmt.Printf("[%s] Connecting to %s...\n", time.Now().Format("15:04:05"), srvAddr)
					}
					log.Info("Dialing tunnel proxy server address", slog.String("address", srvAddr))

					c, err := t.tunDialer.Dial(ctx, tunnelUID, srvAddr, clientOpts...)
					if err != nil {
						if !t.useTUI {
							fmt.Printf("[%s] Connection failed: %v\n", time.Now().Format("15:04:05"), err)
						}
						log.Error("failed to start tunnel client", slog.Any("error", err))
						return
					}

					if !t.useTUI {
						fmt.Printf("[%s] Connected (id: %s)\n", time.Now().Format("15:04:05"), c.UUID.String()[:8])
					}
					log.Info("Tunnel client connected", slog.String("uuid", c.UUID.String()))

					conn.id = c.UUID
					conn.conn = c
					conn.connectedAt = time.Now()

					<-c.Context().Done() // Wait for the connection to close.

					if !t.useTUI {
						fmt.Printf("[%s] Disconnected (id: %s): %v\n", time.Now().Format("15:04:05"), c.UUID.String()[:8], c.Context().Err())
					}
					log.Error("Tunnel client disconnected", slog.String("uuid", c.UUID.String()), slog.Any("error", c.Context().Err()))
				}, backoff, false, conn.stopCh)
			}(conn)
		}
	} else {
		log.Info("Matching tunnel connections", slog.Int("min", minConns), slog.Int("cur", n))
	}

	return ctrl.Result{}, nil
}

// healthHandler returns 200 OK when at least one tunnel connection is active, 503 otherwise.
// This endpoint is used for health checks to determine if the tunnel node has active connections.
// The health endpoint is only started when the --health-endpoint flag is provided with a valid
// address (e.g., ":8080" or "0.0.0.0:8080").
//
// Response codes:
//   - 200 OK: At least one tunnel connection is active
//   - 503 Service Unavailable: No active tunnel connections
func (t *tunnelNodeReconciler) healthHandler(w http.ResponseWriter, r *http.Request) {
	t.tunMu.RLock()
	defer t.tunMu.RUnlock()

	// Check if we have at least one active connection
	activeConns := 0
	for _, conn := range t.tunDialerWorkers {
		if conn.conn != nil && conn.conn.Context().Err() == nil {
			activeConns++
		}
	}

	if activeConns > 0 {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK - %d active connection(s)\n", activeConns)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "UNHEALTHY - no active connections\n")
	}
}

// GetTunnelInfo returns the current tunnel info for the TUI.
func (t *tunnelNodeReconciler) GetTunnelInfo() tui.TunnelInfo {
	t.dialMu.RLock()
	defer t.dialMu.RUnlock()

	return tui.TunnelInfo{
		Name:       t.tunnelName,
		UID:        t.tunnelUID.String(),
		ServerAddr: t.srvAddr,
		HasToken:   t.hasToken,
		Mode:       tunnelModeS,
		DNSAddr:    dnsListenAddr,
		HealthAddr: healthAddr,
	}
}

// GetConnections returns the current connection status for the TUI.
func (t *tunnelNodeReconciler) GetConnections() []tui.ConnectionStatus {
	t.tunMu.RLock()
	defer t.tunMu.RUnlock()

	var conns []tui.ConnectionStatus
	for _, conn := range t.tunDialerWorkers {
		isHealthy := conn.conn != nil && conn.conn.Context().Err() == nil

		var localAddrs []string
		if conn.conn != nil {
			if addrs, err := conn.conn.LocalAddrs(); err == nil {
				for _, addr := range addrs {
					localAddrs = append(localAddrs, addr.String())
				}
			}
		}

		conns = append(conns, tui.ConnectionStatus{
			ID:          conn.id.String()[:8],
			IsHealthy:   isHealthy,
			ConnectedAt: conn.connectedAt,
			LocalAddrs:  localAddrs,
		})
	}
	return conns
}

// printStartupSummary prints a summary box for non-TUI mode.
func printStartupSummary(info tui.TunnelInfo, minConns int) {
	fmt.Println("╭─ TUNNEL ──────────────────────────────────────────────────╮")
	fmt.Printf("│  Name:       %-44s │\n", info.Name)
	fmt.Printf("│  Server:     %-44s │\n", info.ServerAddr)
	fmt.Printf("│  Mode:       %-44s │\n", info.Mode)
	fmt.Printf("│  DNS:        %-44s │\n", info.DNSAddr)
	fmt.Printf("│  Health:     %-44s │\n", info.HealthAddr)
	fmt.Printf("│  Min Conns:  %-44d │\n", minConns)
	fmt.Println("╰───────────────────────────────────────────────────────────╯")
	fmt.Println()
}
