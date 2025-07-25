package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net/netip"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/apoxy-dev/apoxy/client/versioned"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/apoxy-dev/apoxy/pkg/net/dns"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"

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

	// Flags.
	tunnelNodePcapPath string
	tunnelModeS        string
	tunnelMode         tunnel.TunnelClientMode
	insecureSkipVerify bool
	preserveDefaultGw  []string
	socksListenAddr    string
	minConns           int
	dnsListenAddr      string

	preserveDefaultGwDsts []netip.Prefix
)

func init() {
	utilruntime.Must(corev1alpha.Install(scheme))
}

type tunnelNodeReconciler struct {
	client.Client

	scheme *runtime.Scheme
	cfg    *configv1alpha1.Config
	a3y    versioned.Interface

	tunDialer *tunnel.TunnelDialer
	tunConns  map[uuid.UUID]*tunnel.Conn
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
			log.Infof("Running in local mode!")
		}

		a3y, err := config.DefaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		go func() {
			// Launch an internal recursive DNS resolver used
			// to resolve addresses of IPv4 services.
			if err := dns.ListenAndServe(dnsListenAddr); err != nil {
				log.Fatalf("failed to start DNS server: %v", err)
			}
		}()

		tunnelNodeName := args[0]
		log.Infof("Running TunnelNode controller %s", tunnelNodeName)
		tn, err := a3y.CoreV1alpha().TunnelNodes().Get(ctx, tunnelNodeName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("unable to get TunnelNode: %w", err)
		}
		log.Infof("TunnelNode found %+v", tn)

		tun := &tunnelNodeReconciler{
			scheme: scheme,
			cfg:    cfg,
			a3y:    a3y,

			tunConns: make(map[uuid.UUID]*tunnel.Conn),
		}
		return tun.run(ctx, tn)
	},
}

func (t *tunnelNodeReconciler) run(ctx context.Context, tn *corev1alpha.TunnelNode) error {
	log.Infof("Running TunnelNode controller %s", tn.Name)

	client, err := config.DefaultAPIClient()
	if err != nil {
		return fmt.Errorf("unable to create API client: %w", err)
	}

	mgr, err := ctrl.NewManager(client.RESTConfig, ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	})
	if err != nil {
		return fmt.Errorf("unable to set up overall controller manager: %w", err)
	}

	l := log.New(t.cfg.Verbose)
	ctrl.SetLogger(l)
	klog.SetLogger(l)

	t.Client = mgr.GetClient()
	if err := t.setupWithManager(ctx, mgr, tn.Name); err != nil {
		return fmt.Errorf("unable to set up controller: %w", err)
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if err := mgr.Start(gctx); err != nil {
			slog.Error("Manager exited non-zero", slog.Any("error", err))
		}
		return nil
	})

	r, err := tunnel.BuildClientRouter(
		tunnel.WithPcapPath(tunnelNodePcapPath),
		tunnel.WithMode(tunnelMode),
		tunnel.WithPreserveDefaultGatewayDestinations(preserveDefaultGwDsts),
		tunnel.WithSocksListenAddr(socksListenAddr),
	)
	if err != nil {
		return fmt.Errorf("unable to build client router: %w", err)
	}
	g.Go(func() error {
		if err := r.Start(gctx); err != nil {
			slog.Error("Router exited non-zero", slog.Any("error", err))
		}
		return nil
	})
	t.tunDialer = &tunnel.TunnelDialer{Router: r}

	return g.Wait()
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
				predicate.GenerationChangedPredicate{},
				targetRefPredicate(tunnelNodeName),
			),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
		}).
		Complete(t)
}

func (t *tunnelNodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log.Infof("Reconciling TunnelNodes")

	var tunnelNode corev1alpha.TunnelNode
	if err := t.Get(ctx, req.NamespacedName, &tunnelNode); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return ctrl.Result{}, nil
		}
		log.Errorf("Failed to get TunnelNode: %v", err)
		return ctrl.Result{}, err
	}

	log.Infof("TunnelNode found %+v", tunnelNode)

	remoteConns := sets.New[uuid.UUID]()
	for _, agent := range tunnelNode.Status.Agents {
		agentUUID, err := uuid.Parse(agent.Name)
		if err != nil {
			log.Errorf("Failed to parse agent UUID: %v", err)
			continue
		}
		remoteConns.Insert(agentUUID)
	}
	allLocalConns := sets.KeySet[uuid.UUID, *tunnel.Conn](t.tunConns)
	// Local connections that belong to this specific TunnelNode.
	tnLocalConns := allLocalConns.Intersection(remoteConns)

	n := tnLocalConns.Len()
	if n >= minConns { // Already enough connections to this TunnelNode, do nothing.
		return ctrl.Result{}, nil
	}

	log.Infof("Not enough connections to this TunnelNode, attempting to establish more, min: %d, cur: %d", minConns, n)

	cOpts := []tunnel.TunnelClientOption{}
	tnUUID, err := uuid.Parse(string(tunnelNode.ObjectMeta.UID))
	if err != nil { // This can only happen in a test environment.
		log.Errorf("Failed to parse UID: %v", err)
		return ctrl.Result{}, err
	}
	if tunnelNode.Status.Credentials == nil || tunnelNode.Status.Credentials.Token == "" {
		log.Errorf("TunnelNode has no credentials, waiting for credentials")
		return ctrl.Result{
			RequeueAfter: time.Second,
		}, nil
	} else {
		cOpts = append(cOpts, tunnel.WithAuthToken(tunnelNode.Status.Credentials.Token))
	}

	var srvAddr string
	log.Infof("config: %+v", t.cfg)
	if !t.cfg.IsLocalMode {
		if len(tunnelNode.Status.Addresses) == 0 {
			log.Errorf("TunnelNode has no addresses")
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
		log.Infof("Using tunnel proxy server address %s", srvAddr)
	}

	if t.cfg.IsLocalMode || insecureSkipVerify {
		cOpts = append(cOpts, tunnel.WithInsecureSkipVerify(true))
	}

	for i := 0; i < minConns-n; i++ {
		conn, err := t.tunDialer.Dial(ctx, tnUUID, srvAddr, cOpts...)
		if err != nil {
			log.Errorf("Failed to start tunnel client: %v", err)
			return ctrl.Result{}, err
		}

		t.tunConns[conn.UUID] = conn
	}

	return ctrl.Result{}, nil
}
