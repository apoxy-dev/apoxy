//go:build linux

package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/apoxy-dev/apoxy/pkg/apiserver"
	"github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	tunnelproxy "github.com/apoxy-dev/apoxy/pkg/tunnel/proxy"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy/api/controllers/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(corev1alpha.Install(scheme))
	utilruntime.Must(ctrlv1alpha1.Install(scheme))
}

var (
	devMode  = flag.Bool("dev", false, "Enable development mode.")
	logLevel = flag.String("log_level", "info", "Log level.")

	healthProbePort = flag.Int("health_probe_port", 8080, "Port for the health probe.")
	readyProbePort  = flag.Int("ready_probe_port", 8083, "Port for the ready probe.")
	metricsPort     = flag.Int("metrics_port", 8081, "Port for the metrics endpoint.")

	apiServerAddr = flag.String("apiserver_addr", "host.docker.internal:8443", "APIServer address.")
	jwksURLs      = flag.String("jwks_urls", "", "Comma-separated URLs of the JWKS endpoints.")

	networkID          = flag.String("network_id", "", "Network ID for IPAM. Must be a 6-character hex string.")
	tunnelNodeSelector = flag.String("label_selector", "", "Label selector for TunnelNode objects.")
	publicAddr         = flag.String("public_addr", "", "Public address of the tunnel proxy.")
	extIface           = flag.String("ext_iface", "eth0", "External interface name.")
	cksumRecalc        = flag.Bool("cksum_recalc", false, "Recalculate checksum.")
)

func main() {
	flag.Parse()
	var lOpts []log.Option
	if *devMode {
		lOpts = append(lOpts, log.WithDevMode(), log.WithAlsoLogToStderr())
	} else if *logLevel != "" {
		lOpts = append(lOpts, log.WithLevelString(*logLevel))
	}
	log.Init(lOpts...)
	ctx := signals.SetupSignalHandler()

	if *apiServerAddr == "" {
		log.Fatalf("--apiserver_addr must be set")
	}
	if *jwksURLs == "" {
		log.Fatalf("--jwks_urls must be set")
	}

	log.Infof("Setting up managers")

	ctrl.SetLogger(zap.New(zap.UseDevMode(true))) // TODO(dilyevsky): Use default golang logger.
	rC := apiserver.NewClientConfig(apiserver.WithClientHost(*apiServerAddr))
	mgr, err := ctrl.NewManager(rC, ctrl.Options{
		Cache: cache.Options{
			SyncPeriod: ptr.To(30 * time.Second),
		},
		Scheme:         scheme,
		LeaderElection: false,
		Metrics: metricsserver.Options{
			BindAddress: fmt.Sprintf(":%d", *metricsPort),
		},
		HealthProbeBindAddress: fmt.Sprintf(":%d", *healthProbePort),
	})
	if err != nil {
		log.Fatalf("Unable to start manager: %v", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Fatalf("Failed to add healthz check: %v", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Fatalf("Failed to add readyz check: %v", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	jwtValidator, err := token.NewRemoteValidator(ctx, strings.Split(*jwksURLs, ","))
	if err != nil {
		log.Fatalf("Failed to create JWT validator: %v", err)
	}

	var (
		extIPv4Prefix netip.Prefix
		extIPv6Prefix netip.Prefix
	)
	extAddrs, err := tunnet.GetGlobalUnicastAddresses(*extIface)
	if err != nil {
		log.Warnf("Failed to get local IPv6 address: %v", err)
	} else {
		for _, addr := range extAddrs {
			if addr.Addr().Is4() {
				extIPv4Prefix = addr
				log.Infof("External IPv4 prefix: %s", extIPv4Prefix.String())
				break
			}
		}
		for _, addr := range extAddrs {
			if addr.Addr().Is6() {
				extIPv6Prefix = addr
				log.Infof("External IPv6 prefix: %s", extIPv6Prefix.String())
				break
			}
		}
	}

	rOpts := []router.Option{
		router.WithExternalIPv6Prefix(extIPv6Prefix),
		router.WithChecksumRecalculation(*cksumRecalc),
		router.WithExternalInterface(*extIface),
	}
	r, err := router.NewNetlinkRouter(rOpts...)
	if err != nil {
		log.Fatalf("Failed to create netlink router: %v", err)
	}

	if *networkID == "" {
		podUID := os.Getenv("K8S_POD_UID")
		if podUID == "" {
			log.Fatalf("--network_id must be set or K8S_POD_UID environment variable must be available")
		}
		_, err := uuid.Parse(podUID)
		if err != nil {
			log.Fatalf("Failed to parse K8S_POD_UID (%s): %v", podUID, err)
		}
		*networkID = podUID[len(podUID)-6:]
		log.Infof("Using network ID from K8S_POD_UID: %s", *networkID)
	}

	srv, err := tunnel.NewTunnelServer(
		mgr.GetClient(),
		jwtValidator,
		r,
		tunnel.WithExternalAddrs(extIPv4Prefix),
		tunnel.WithLabelSelector(*tunnelNodeSelector),
		tunnel.WithPublicAddr(*publicAddr),
		tunnel.WithIPAMv4(tunnet.NewIPAMv4(ctx)),
	)
	if err != nil {
		log.Fatalf("Failed to create tunnel server: %v", err)
	}
	if err := srv.SetupWithManager(mgr); err != nil {
		log.Fatalf("Unable to setup Tunnel Proxy server: %v", err)
	}

	if err := tunnelproxy.NewProxyTunnelReconciler(
		mgr.GetClient(),
		extIPv4Prefix.Addr(),
	).SetupWithManager(ctx, mgr); err != nil {
		log.Fatalf("Unable to setup Proxy Tunnel reconciler: %v", err)
	}

	g.Go(func() error {
		log.Infof("Starting Tunnel Proxy server")

		return srv.Start(ctx)
	})

	g.Go(func() error {
		log.Infof("Starting manager")

		return mgr.Start(ctx)
	})

	if err := g.Wait(); err != nil {
		log.Fatalf("Exited with error: %v", err)
	}
}
