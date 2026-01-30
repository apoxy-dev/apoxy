package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/coredns/coredns/plugin"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/apoxy-dev/apoxy/pkg/apiserver"
	bpctrl "github.com/apoxy-dev/apoxy/pkg/backplane/controllers"
	"github.com/apoxy-dev/apoxy/pkg/backplane/healthchecker"
	"github.com/apoxy-dev/apoxy/pkg/backplane/kvstore"
	"github.com/apoxy-dev/apoxy/pkg/backplane/metrics"
	"github.com/apoxy-dev/apoxy/pkg/backplane/wasm/ext_proc"
	"github.com/apoxy-dev/apoxy/pkg/backplane/wasm/manifest"
	edgefuncctrl "github.com/apoxy-dev/apoxy/pkg/edgefunc/controller"
	"github.com/apoxy-dev/apoxy/pkg/edgefunc/runc"
	"github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/apoxy-dev/apoxy/pkg/net/dns"
	tundns "github.com/apoxy-dev/apoxy/pkg/tunnel/dns"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	extensionv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	gatewayv1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(corev1alpha.AddToScheme(scheme))
	utilruntime.Must(corev1alpha2.AddToScheme(scheme))
	utilruntime.Must(extensionv1alpha2.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.AddToScheme(scheme))
}

var (
	devMode  = flag.Bool("dev", false, "Enable development mode.")
	logLevel = flag.String("log_level", "info", "Log level.")

	projectID = flag.String("project_id", "", "Apoxy project UUID.")

	proxyName       = flag.String("proxy", "", "Name of the Proxy to manage. Must not be used with --proxy_path.")
	replicaName     = flag.String("replica", os.Getenv("HOSTNAME"), "Name of the replica to manage.")
	envoyReleaseURL = flag.String("envoy_release_url", "", "URL to the Envoy release tarball.")
	downloadEnvoy   = flag.Bool("download_envoy_only", false, "Whether to just download Envoy from the release URL and exit.")

	apiServerAddr         = flag.String("apiserver_addr", "host.docker.internal:8443", "APIServer address.")
	healthProbePort       = flag.Int("health_probe_port", 8080, "Port for the health probe.")
	readyProbePort        = flag.Int("ready_probe_port", 8083, "Port for the ready probe.")
	controllerMetricsPort = flag.Int("controller_metrics_port", 8081, "Port for the controller metrics endpoint.")
	metricsPort           = flag.Int("metrics_port", 8888, "Port for the metrics proxy endpoint.")

	chAddrs  = flag.String("ch_addrs", "", "Comma-separated list of ClickHouse host:port addresses.")
	chSecure = flag.Bool("ch_secure", false, "Whether to connect to Clickhouse using TLS.")
	chDebug  = flag.Bool("ch_debug", false, "Enables debug prints for ClickHouse client.")

	wasmExtProcPort = flag.Int("wasm_ext_proc_port", 2020, "Port for the WASM extension processor.")
	wasmStorePort   = flag.Int("wasm_store_port", 8081, "Port for the remote WASM store.")

	goPluginDir = flag.String("go_plugin_dir", "/var/lib/apoxy/go", "Directory for Go plugins.")
	esZipDir    = flag.String("eszip_dir", "/var/lib/apoxy/js", "Directory for JavaScript bundles.")

	useEnvoyContrib = flag.Bool("use_envoy_contrib", false, "Use Envoy contrib filters.")

	overloadMaxHeapSizeBytes     = flag.Uint64("overload-max-heap-size-bytes", 0, "Maximum heap size in bytes for Envoy overload manager.")
	overloadMaxActiveConnections = flag.Uint64("overload-max-active-connections", 0, "Maximum number of active downstream connections for Envoy overload manager.")

	k8sKVNamespace    = flag.String("k8s_kv_namespace", os.Getenv("POD_NAMESPACE"), "Namespace for the K/V store.")
	k8sKVPeerSelector = flag.String("k8s_kv_peer_selector", "app.kubernetes.io/component=backplane", "Label selector for K/V store peers.")

	wsRouterPort = flag.Int("ws_router_port", 8082, "Port for the WebSocket router.")

	dnsPort  = flag.Int("dns_port", 8053, "Port for the DNS server.")
	extIface = flag.String("ext_iface", "eth0", "External interface name.")

	useEdgeController    = flag.Bool("use_edge_controller", false, "Use new per-namespace EdgeController instead of legacy per-function runtime.")
	edgeControllerNS     = flag.String("edge_controller_namespace", "default", "Default namespace for EdgeController.")
)

func main() {
	flag.Parse()
	// TODO(dilyevsky): This should be part of log.Init.
	if *logLevel == "" {
		*logLevel = log.InfoLevel.String()
	}
	lOpts := []log.Option{
		log.WithAlsoLogToStderr(),
		log.WithLevelString(*logLevel),
	}
	if *devMode {
		lOpts = append(lOpts, log.WithDevMode())
	}
	log.Init(lOpts...)
	ctx := context.Background()

	if *apiServerAddr == "" {
		log.Fatalf("--apiserver_addr must be set")
	}
	rC := apiserver.NewClientConfig(apiserver.WithClientHost(*apiServerAddr))

	if *proxyName == "" || *replicaName == "" {
		log.Fatalf("--proxy and --replica must be set")
	}

	var chConn chdriver.Conn
	var chOpts *clickhouse.Options
	if *chAddrs != "" {
		projUUID, err := uuid.Parse(*projectID)
		if err != nil {
			log.Fatalf("invalid project UUID: %v", err)
		}
		log.Infof("Connecting to ClickHouse at %v", *chAddrs)
		chOpts = &clickhouse.Options{
			Addr: strings.Split(*chAddrs, ","),
			Auth: clickhouse.Auth{
				Database: strings.ReplaceAll(projUUID.String(), "-", ""),
				//Username: strings.ReplaceAll(*projectID, "-", ""),
				//Password: os.Getenv("CH_PASSWORD"),
			},
			DialTimeout: 5 * time.Second,
			Settings: clickhouse.Settings{
				"max_execution_time": 60,
			},
			Debug: *chDebug,
		}
		if *chSecure { // Secure mode requires setting at least empty tls.Config.
			chOpts.TLS = &tls.Config{}
		}
		// TODO(dsky): Wrap this for lazy initialization to avoid blocking startup.
		chConn, err = clickhouse.Open(chOpts)
		if err != nil {
			log.Fatalf("Failed to connect to ClickHouse: %v", err)
		}
		if err := chConn.Ping(ctx); err != nil {
			log.Fatalf("Failed to ping ClickHouse: %v", err)
		}
	}

	log.Infof("Setting up K/V store")
	kv := kvstore.New(*k8sKVNamespace, *k8sKVPeerSelector)
	if *devMode {
		kv = kvstore.NewDev()
	}
	kvStarted := make(chan struct{})
	go func() {
		if err := kv.Start(kvStarted); err != nil {
			log.Fatalf("Failed to start K/V store: %v", err)
		}
	}()
	select {
	case <-kvStarted:
	case <-ctx.Done():
		log.Fatalf("Failed to start K/V store: %v", ctx.Err())
	}

	log.Infof("Setting up WASM runtime")

	ls, err := net.Listen("tcp", fmt.Sprintf(":%d", *wasmExtProcPort))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer ls.Close()
	srv := grpc.NewServer()
	ms := manifest.NewMemory()
	wasmSrv := ext_proc.NewServer(ms)
	wasmSrv.Register(srv)
	go func() {
		<-ctx.Done()
		log.Infof("Shutting down WASM runtime server")
		srv.GracefulStop()
	}()
	go func() {
		log.Infof("Starting WASM runtime server on %v", ls.Addr())
		if err := srv.Serve(ls); err != nil {
			log.Fatalf("Failed to start WASM runtime server: %v", err)
		}
	}()

	log.Infof("Looking up external IP addresses")

	var (
		extIPv4Prefix netip.Prefix
	)
	extAddrs, err := tunnet.GetGlobalUnicastAddresses(*extIface, false)
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
	}

	log.Infof("Setting up managers")

	ctrl.SetLogger(zap.New(zap.UseDevMode(true))) // TODO(dilyevsky): Use default golang logger.
	mgr, err := ctrl.NewManager(rC, ctrl.Options{
		Cache: cache.Options{
			SyncPeriod: ptr.To(30 * time.Second),
		},
		Scheme:         scheme,
		LeaderElection: false,
		Metrics: metricsserver.Options{
			BindAddress: fmt.Sprintf(":%d", *controllerMetricsPort),
		},
		HealthProbeBindAddress: fmt.Sprintf(":%d", *healthProbePort),
	})
	if err != nil {
		log.Fatalf("unable to start manager: %v", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Fatalf("Failed to add healthz check: %v", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Fatalf("Failed to add readyz check: %v", err)
	}

	log.Infof("Setting up controllers...")
	proxyOpts := []bpctrl.Option{
		bpctrl.WithGoPluginDir(*goPluginDir),
	}
	if chConn != nil {
		proxyOpts = append(proxyOpts, bpctrl.WithClickHouseConn(chConn), bpctrl.WithClickHouseOptions(chOpts))
	}
	if *envoyReleaseURL != "" {
		proxyOpts = append(proxyOpts, bpctrl.WithURLRelease(*envoyReleaseURL))
	}
	if *useEnvoyContrib {
		proxyOpts = append(proxyOpts, bpctrl.WithEnvoyContrib())
	}
	if *overloadMaxHeapSizeBytes > 0 {
		proxyOpts = append(proxyOpts, bpctrl.WithOverloadMaxHeapSizeBytes(*overloadMaxHeapSizeBytes))
	}
	if *overloadMaxActiveConnections > 0 {
		proxyOpts = append(proxyOpts, bpctrl.WithOverloadMaxActiveConnections(*overloadMaxActiveConnections))
	}
	var hc *healthchecker.AggregatedHealthChecker
	if *readyProbePort != 0 {
		hc = healthchecker.NewAggregatedHealthChecker()
		go hc.Start(ctx, *readyProbePort)
	}

	// Is there a port specified in the API server address?
	apiServerHost, _, err := net.SplitHostPort(*apiServerAddr)
	if err != nil {
		apiServerHost = *apiServerAddr
	}

	log.Infof("Starting Backplane controller")

	pctrl := bpctrl.NewProxyReconciler(
		mgr.GetClient(),
		*proxyName,
		*replicaName,
		extIPv4Prefix.Addr(),
		apiServerHost,
		proxyOpts...,
	)
	if *downloadEnvoy {
		if err := pctrl.DownloadEnvoy(ctx); err != nil {
			log.Fatalf("Failed to download Envoy: %v", err)
		}
		os.Exit(0)
	}
	if err := pctrl.SetupWithManager(ctx, mgr); err != nil {
		log.Fatalf("failed to set up Backplane controller: %v", err)
	}

	log.Infof("Starting Gateway controller")

	gwctrl := bpctrl.NewGatewayReconciler(
		mgr.GetClient(),
		*proxyName,
		hc,
	)
	if err := gwctrl.SetupWithManager(mgr); err != nil {
		log.Fatalf("failed to set up Gateway controller: %v", err)
	}

	log.Infof("Starting EdgeFunction controller")

	edgeRuntime, err := runc.NewRuntime(ctx)
	if err != nil {
		log.Fatalf("failed to set up EdgeFunction controller: %v", err)
	}

	var edgeController *edgefuncctrl.EdgeController
	if *useEdgeController {
		log.Infof("Using new per-namespace EdgeController (namespace=%s)", *edgeControllerNS)
		edgeController = edgefuncctrl.NewEdgeControllerFromRuntime(
			edgeRuntime,
			*esZipDir,
			edgefuncctrl.Namespace(*edgeControllerNS),
		)
	} else {
		log.Infof("Using legacy per-function EdgeRuntime")
	}

	edgeFuncReconciler := bpctrl.NewEdgeFunctionRevisionReconciler(bpctrl.EdgeFunctionRevisionReconcilerArgs{
		Client:           mgr.GetClient(),
		ReplicaName:      *replicaName,
		ApiserverHost:    net.JoinHostPort(apiServerHost, strconv.Itoa(*wasmStorePort)),
		WasmStore:        ms,
		GoStoreDir:       *goPluginDir,
		JsStoreDir:       *esZipDir,
		EdgeRuntime:      edgeRuntime,
		EdgeController:   edgeController,
		DefaultNamespace: edgefuncctrl.Namespace(*edgeControllerNS),
	})
	if err := edgeFuncReconciler.SetupWithManager(ctx, mgr, *proxyName); err != nil {
		log.Fatalf("failed to set up EdgeFunction controller: %v", err)
	}

	if err := bpctrl.NewTunnelNodeReconciler(
		mgr.GetClient(),
		*proxyName,
		*replicaName,
		extIPv4Prefix.Addr(),
	).SetupWithManager(ctx, mgr); err != nil {
		log.Fatalf("failed to set up TunnelNode controller: %v", err)
	}

	tunnelResolver := tundns.NewTunnelNodeDNSReconciler(mgr.GetClient())
	if err := tunnelResolver.SetupWithManager(mgr); err != nil {
		log.Fatalf("failed to set up TunnelNodeDNS controller: %v", err)
	}

	go func() {
		// Use EdgeController's resolver if available, otherwise use legacy runtime's resolver.
		var edgeFuncResolver func(next plugin.Handler) plugin.Handler
		if edgeController != nil {
			edgeFuncResolver = edgeController.Resolver
		} else {
			edgeFuncResolver = edgeRuntime.Resolver
		}

		if err := dns.ListenAndServe(
			fmt.Sprintf(":%d", *dnsPort),
			dns.WithPlugins(edgeFuncResolver, tunnelResolver.Resolver),
			dns.WithBlockNonGlobalIPs(),
		); err != nil {
			log.Fatalf("failed to start DNS server: %v", err)
		}
	}()

	// Setup metrics proxy handler
	log.Infof("Setting up metrics proxy handler")
	upstreams := map[string]string{
		"/controller/metrics": "127.0.0.1:" + strconv.Itoa(*controllerMetricsPort) + "/metrics",
		"/envoy/metrics":      "127.0.0.1:19000/stats/prometheus",
	}
	metricsHandler := metrics.NewProxyHandler(upstreams)
	metricsCtx, metricsCancel := context.WithCancel(ctx)
	defer metricsCancel()
	if err := metrics.StartServer(metricsCtx, *metricsPort, metricsHandler); err != nil {
		log.Fatalf("Failed to start metrics proxy server: %v", err)
	}
	log.Infof("Metrics proxy server started on port %d", *metricsPort)

	// Setup SIGTERM handler.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	go func() {
		<-sig
		log.Infof("Received SIGTERM, shutting down")
		pctrl.Shutdown(ctx) // Blocks until all resources are released.
		metricsCancel()     // Cancel metrics server context
		os.Exit(0)
	}()

	log.Infof("Starting manager")
	if err := mgr.Start(ctx); err != nil {
		log.Fatalf("unable to start manager: %v", err)
	}
	kv.Stop(context.Background())
}
