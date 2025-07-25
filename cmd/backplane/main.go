package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/apoxy-dev/apoxy/client/versioned"
	"github.com/apoxy-dev/apoxy/pkg/apiserver"
	bpctrl "github.com/apoxy-dev/apoxy/pkg/backplane/controllers"
	"github.com/apoxy-dev/apoxy/pkg/backplane/healthchecker"
	"github.com/apoxy-dev/apoxy/pkg/backplane/kvstore"
	"github.com/apoxy-dev/apoxy/pkg/backplane/metrics"
	"github.com/apoxy-dev/apoxy/pkg/backplane/wasm/ext_proc"
	"github.com/apoxy-dev/apoxy/pkg/backplane/wasm/manifest"
	"github.com/apoxy-dev/apoxy/pkg/cmd/utils"
	"github.com/apoxy-dev/apoxy/pkg/edgefunc/runc"
	"github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/apoxy-dev/apoxy/pkg/net/dns"
	tundns "github.com/apoxy-dev/apoxy/pkg/tunnel/dns"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy/api/controllers/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	extensionv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(ctrlv1alpha1.AddToScheme(scheme))
	utilruntime.Must(extensionv1alpha2.AddToScheme(scheme))
	utilruntime.Must(corev1alpha.AddToScheme(scheme))
}

var (
	projectID = flag.String("project_id", "", "Apoxy project UUID.")

	proxyPath       = flag.String("proxy_path", "", "Path to the Proxy to create in the API.")
	proxyName       = flag.String("proxy", "", "Name of the Proxy to manage. Must not be used with --proxy_path.")
	replicaName     = flag.String("replica", os.Getenv("HOSTNAME"), "Name of the replica to manage.")
	envoyReleaseURL = flag.String("envoy_release_url", "", "URL to the Envoy release tarball.")
	downloadEnvoy   = flag.Bool("download_envoy_only", false, "Whether to just download Envoy from the release URL and exit.")

	devMode  = flag.Bool("dev", false, "Enable development mode.")
	logLevel = flag.String("log_level", "info", "Log level.")

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

	dnsPort       = flag.Int("dns_port", 8053, "Port for the DNS server.")
	tunnelDNSAddr = flag.String("tunnel_dns_addr", "127.0.0.1:8053", "Address for the DNS server run by tunnel agents.")
)

func upsertProxyFromPath(ctx context.Context, rC *rest.Config, path string) (string, error) {
	proxyConfig, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}
	proxy := &ctrlv1alpha1.Proxy{}
	proxyJSON, err := utils.YAMLToJSON(string(proxyConfig))
	if err != nil {
		// Try assuming that the config is a JSON string?
		proxyJSON = string(proxyConfig)
	}
	err = json.Unmarshal([]byte(proxyJSON), proxy)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal Proxy config: %w", err)
	}

	c := versioned.NewForConfigOrDie(rC)
	_, err = c.ControllersV1alpha1().Proxies().Create(ctx, proxy, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		e, err := c.ControllersV1alpha1().Proxies().Get(ctx, proxy.Name, metav1.GetOptions{})
		if err != nil {
			return "", fmt.Errorf("failed to get existing Proxy: %w", err)
		}

		proxy.ResourceVersion = e.ResourceVersion

		_, err = c.ControllersV1alpha1().Proxies().Update(ctx, proxy, metav1.UpdateOptions{})
		if err != nil {
			return "", fmt.Errorf("failed to update existing Proxy: %w", err)
		}

		log.Infof("Proxy %s updated", proxy.Name)

		return proxy.Name, nil
	} else if err != nil {
		return "", fmt.Errorf("failed to create Proxy: %w", err)
	}

	log.Infof("Proxy %s created", proxy.Name)

	return proxy.Name, nil
}

func main() {
	flag.Parse()
	var lOpts []log.Option
	if *devMode {
		lOpts = append(lOpts, log.WithDevMode(), log.WithAlsoLogToStderr())
	} else if *logLevel != "" {
		lOpts = append(lOpts, log.WithLevelString(*logLevel))
	}
	log.Init(lOpts...)
	ctx := context.Background()

	if *apiServerAddr == "" {
		log.Fatalf("--apiserver_addr must be set")
	}
	rC := apiserver.NewClientConfig(apiserver.WithClientHost(*apiServerAddr))

	if *proxyPath == "" && *proxyName == "" {
		log.Fatalf("either --proxy_path or --proxy must be set")
	}
	if *proxyPath != "" {
		var err error
		*proxyName, err = upsertProxyFromPath(ctx, rC, *proxyPath)
		if err != nil {
			log.Fatalf("Failed to update proxy from path: %v", err)
		}
	} else if *proxyName != "" {
		if *replicaName == "" {
			log.Fatalf("--replica must be set when --proxy is set")
		}
	} else {
		log.Fatalf("only one of --proxy_path or --proxy must be set")
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
	if *readyProbePort != 0 {
		hc := healthchecker.NewAggregatedHealthChecker()
		go hc.Start(ctx, *readyProbePort)
		proxyOpts = append(proxyOpts, bpctrl.WithAggregatedHealthChecker(hc))
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

	log.Infof("Starting EdgeFunction controller")

	edgeRuntime, err := runc.NewRuntime(ctx)
	if err != nil {
		log.Fatalf("failed to set up EdgeFunction controller: %v", err)
	}
	if err := bpctrl.NewEdgeFunctionRevisionReconciler(
		mgr.GetClient(),
		*replicaName,
		net.JoinHostPort(apiServerHost, strconv.Itoa(*wasmStorePort)),
		ms,
		*goPluginDir,
		*esZipDir,
		edgeRuntime,
	).SetupWithManager(ctx, mgr, *proxyName); err != nil {
		log.Fatalf("failed to set up EdgeFunction controller: %v", err)
	}

	if err := bpctrl.NewTunnelNodeReconciler(
		mgr.GetClient(),
		*proxyName,
		*replicaName,
	).SetupWithManager(ctx, mgr); err != nil {
		log.Fatalf("failed to set up TunnelNode controller: %v", err)
	}

	tunnelResolver := tundns.NewTunnelNodeDNSReconciler(mgr.GetClient(), *tunnelDNSAddr)
	if err := tunnelResolver.SetupWithManager(mgr); err != nil {
		log.Fatalf("failed to set up TunnelNodeDNS controller: %v", err)
	}

	go func() {
		if err := dns.ListenAndServe(fmt.Sprintf(":%d", *dnsPort), dns.WithPlugins(edgeRuntime.Resolver, tunnelResolver.Resolver), dns.WithBlockNonGlobalIPs()); err != nil {
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
		pctrl.Shutdown(ctx, "received SIGTERM") // Blocks until all resources are released.
		metricsCancel()                         // Cancel metrics server context
		os.Exit(0)
	}()

	log.Infof("Starting manager")
	if err := mgr.Start(ctx); err != nil {
		log.Fatalf("unable to start manager: %v", err)
	}
	kv.Stop(context.Background())
}
