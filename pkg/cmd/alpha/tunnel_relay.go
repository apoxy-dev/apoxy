package alpha

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	goruntime "runtime"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/apoxy-dev/icx"

	apoxycoordv1 "github.com/apoxy-dev/apoxy/api/coordination/v1"
	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/cert/reload"
	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/bifurcate"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/hasher"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/ipalloc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/vni"
)

var (
	relayDevMode         bool   // whether to run in development mode (testing only)
	relayName            string // the name for the relay
	extIfaceName         string // the external interface name
	listenAddress        string // the address to listen on for incoming connections
	userMode             bool   // whether to use user-mode routing (no special privileges required)
	relaySocksListenAddr string // when using user-mode routing, the address to listen on for SOCKS5 connections
	relayPcapPath        string // optional pcap path
	certFile             string // path to TLS certificate (PEM) used when not in dev mode
	keyFile              string // path to TLS private key (PEM) used when not in dev mode
	idSecretFile         string // path to secret for the ID hasher used when not in dev mode
	relayMetricsAddr     string   // bind address for the metrics endpoint
	relayHealthAddr      string   // bind address for the health/ready probes
	labelSelector        string   // network selector for the relay's served VPCNetworks
	relayAddresses       []string // underlay endpoints agents dial (Relay.Spec.Addresses)
)

var tunnelRelayCmd = &cobra.Command{
	Use:    "relay",
	Short:  "Run a tunnel relay",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		routerOpts := []router.Option{
			router.WithExternalInterface(extIfaceName),
			router.WithEgressGateway(true),
			router.WithSocksListenAddr(relaySocksListenAddr), // only used in user-mode
		}

		if relayPcapPath != "" {
			routerOpts = append(routerOpts, router.WithPcapPath(relayPcapPath))
		}

		// One UDP socket shared between Geneve (data) and QUIC (control).
		lis, err := net.ListenPacket("udp", listenAddress)
		if err != nil {
			return fmt.Errorf("failed to create UDP listener: %w", err)
		}

		pc, err := batchpc.New("udp", lis)
		if err != nil {
			return fmt.Errorf("failed to create batch packet conn: %w", err)
		}

		pcGeneve, pcQuic := bifurcate.Bifurcate(pc)
		defer pcGeneve.Close()
		defer pcQuic.Close()

		var rtr router.Router
		var handler *icx.Handler
		if userMode {
			routerOpts = append(routerOpts, router.WithPacketConn(pcGeneve))

			r, err := router.NewICXNetstackRouter(routerOpts...)
			if err != nil {
				return fmt.Errorf("failed to create router: %w", err)
			}
			rtr = r
			handler = r.Handler
		} else {
			r, err := router.NewICXNetlinkRouter(routerOpts...)
			if err != nil {
				return fmt.Errorf("failed to create router: %w", err)
			}
			rtr = r
			handler = r.Handler
		}

		var (
			idHasher      *hasher.Hasher
			cert          tls.Certificate
			relayReloader *reload.Reloader
		)

		// Use a self-signed cert and a fixed hasher secret in dev mode.
		if relayDevMode {
			idHasher = hasher.NewHasher([]byte("C0rr3ct-Horse-Battery-Staple_But_Salty_1x9Q7p3Z"))

			_, c, err := cryptoutils.GenerateSelfSignedTLSCert(relayName)
			if err != nil {
				return fmt.Errorf("failed to generate self-signed TLS cert: %w", err)
			}
			cert = c
		} else {
			if idSecretFile == "" {
				return fmt.Errorf("when not in development mode, --id-secret-file is required")
			}
			if certFile == "" || keyFile == "" {
				return fmt.Errorf("when not in development mode, both --cert-file and --key-file are required")
			}

			secret, err := os.ReadFile(idSecretFile)
			if err != nil {
				return fmt.Errorf("failed to read id hasher secret file: %w", err)
			}
			idHasher = hasher.NewHasher(bytes.TrimSpace(secret))

			c, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return fmt.Errorf("failed to load TLS certificate/key pair: %w", err)
			}
			cert = c

			// Hot-reload the relay's serving cert so cert-manager rotations
			// take effect without restarting the relay.
			relayReloader, err = reload.NewReloader(reload.Paths{Cert: certFile, Key: keyFile}, "tunnel-relay")
			if err != nil {
				return fmt.Errorf("failed to set up relay cert reloader: %w", err)
			}
		}

		relay := tunnel.NewRelay(relayName, pcQuic, cert, handler, idHasher, rtr)

		g, ctx := errgroup.WithContext(cmd.Context())

		if relayReloader != nil {
			relay.SetCertProvider(relayReloader.GetCertificate)
			g.Go(func() error { return relayReloader.Start(ctx) })
		}

		clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		)

		config, err := clientConfig.ClientConfig()
		if err != nil {
			return fmt.Errorf("loading kubeconfig: %w", err)
		}

		scheme := runtime.NewScheme()
		if err := vpcv1alpha1.Install(scheme); err != nil {
			return fmt.Errorf("installing vpc scheme: %w", err)
		}
		if err := apoxycoordv1.Install(scheme); err != nil {
			return fmt.Errorf("installing coordination scheme: %w", err)
		}

		ctrl.SetLogger(logr.FromSlogHandler(slog.Default().Handler()))

		mgr, err := ctrl.NewManager(config, ctrl.Options{
			Cache: cache.Options{
				SyncPeriod: ptr.To(30 * time.Second),
			},
			Scheme:                 scheme,
			LeaderElection:         false,
			Metrics:                metricsserver.Options{BindAddress: relayMetricsAddr},
			HealthProbeBindAddress: relayHealthAddr,
		})
		if err != nil {
			return fmt.Errorf("unable to start manager: %w", err)
		}

		if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
			return fmt.Errorf("failed to add healthz check: %w", err)
		}

		if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
			return fmt.Errorf("failed to add readyz check: %w", err)
		}

		// The publisher owns connect/disconnect: it allocates each connection's
		// addresses in-process from a leased /80 block plus a relay-local VNI,
		// and writes the single-writer Tunnel object (APO-825 §2.4/§2.8).
		leaser := ipalloc.NewLocalBlockLeaser(ctx)
		vnis := vni.NewVNIAllocator()
		publisher := controllers.NewTunnelPublisher(mgr.GetClient(), relay, leaser, vnis)

		// The VPCNetwork watcher feeds the relay each network's connect credential
		// and resolves network names to NetworkIDs for the publisher.
		vpcNetworkReconciler := controllers.NewVPCNetworkReconciler(mgr.GetClient(), relay, publisher)
		if err := vpcNetworkReconciler.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("failed to setup VPCNetwork watcher: %w", err)
		}

		// A label selector scopes which networks this relay serves (nil = all).
		var networkSelector *metav1.LabelSelector
		if labelSelector != "" {
			networkSelector, err = metav1.ParseToLabelSelector(labelSelector)
			if err != nil {
				return fmt.Errorf("failed to parse network selector: %w", err)
			}
		}

		// The registrar creates the write-once Relay object and renews its lease
		// so the apiserver lease watcher can track relay liveness (§2.3).
		addresses := relayAddresses
		if len(addresses) == 0 {
			addresses = []string{listenAddress}
		}
		registrar := controllers.NewRelayRegistrar(mgr.GetClient(), mgr.GetClient(), relay, addresses, networkSelector)
		if err := mgr.Add(registrar); err != nil {
			return fmt.Errorf("failed to add relay registrar: %w", err)
		}

		// Drain (§5): deregister the relay and release its leased blocks at
		// shutdown. SetOnShutdown is single-callback, so compose both here.
		relay.SetOnShutdown(func(ctx context.Context) {
			registrar.Drain(ctx)
			publisher.ReleaseAll(ctx)
		})

		g.Go(func() error {
			return mgr.Start(ctx)
		})

		g.Go(func() error {
			return relay.Start(ctx)
		})

		if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("failed to run relay: %w", err)
		}

		return nil
	},
}

func init() {
	tunnelRelayCmd.Flags().StringVarP(&relayName, "name", "n", "dev", "The name of the relay.")
	tunnelRelayCmd.Flags().BoolVar(&relayDevMode, "dev", false, "Run the relay in development mode (insecure).")
	tunnelRelayCmd.Flags().StringVar(&extIfaceName, "ext-iface", "eth0", "External interface name (when not using --user-mode).")
	tunnelRelayCmd.Flags().StringVar(&listenAddress, "listen-addr", "127.0.0.1:6081", "The address to listen on for incoming connections.")
	tunnelRelayCmd.Flags().BoolVar(&userMode, "user-mode", goruntime.GOOS != "linux", "Use user-mode routing (no special privileges required).")
	tunnelRelayCmd.Flags().StringVar(&relaySocksListenAddr, "socks-addr", "localhost:1080", "When using user-mode routing, the address to listen on for SOCKS5 connections.")
	tunnelRelayCmd.Flags().StringVarP(&relayPcapPath, "pcap", "p", "", "Path to an optional packet capture file to write.")
	tunnelRelayCmd.Flags().StringVar(&certFile, "cert-file", "", "Path to a TLS certificate (PEM). Required when not running with --dev.")
	tunnelRelayCmd.Flags().StringVar(&keyFile, "key-file", "", "Path to a TLS private key (PEM). Required when not running with --dev.")
	tunnelRelayCmd.Flags().StringVar(&idSecretFile, "id-secret-file", "", "Path to the secret used for stable ID hashing. Required when not running with --dev.")
	tunnelRelayCmd.Flags().StringVar(&relayMetricsAddr, "metrics-addr", "127.0.0.1:8081", "Bind address for the metrics endpoint.")
	tunnelRelayCmd.Flags().StringVar(&relayHealthAddr, "health-addr", "127.0.0.1:8080", "Bind address for the health and readiness probes.")
	tunnelRelayCmd.Flags().StringVar(&labelSelector, "label-selector", "", "Label selector scoping which VPCNetworks this relay serves (e.g. 'tier=prod'). Empty serves all.")
	tunnelRelayCmd.Flags().StringSliceVar(&relayAddresses, "addresses", nil, "Underlay endpoints agents dial to reach this relay (Relay.Spec.Addresses). Defaults to --listen-addr.")

	tunnelCmd.AddCommand(tunnelRelayCmd)
}
