// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
)

// Run is the workerd-manager entry point, invoked after sandbox.DispatchRunsc().
// It brings up the single resident workerd, serves the dispatcher control
// channel, and runs the resident reconciler against the project apiserver. It
// blocks until signalled.
//
// This is the data-plane half of APO-796 (the minting reconciler runs in the
// apiserver via apiserver.WithAdditionalController). It only runs meaningfully
// on linux — host.NewResidentHost needs the gVisor core — but compiles
// everywhere so the package is unit-testable with fakes on darwin.
func Run() error {
	// A dedicated FlagSet, not the global flag.CommandLine: controller-runtime's
	// client/config init() already registers a global --kubeconfig, so defining
	// the manager's own flags on the default set panics with "flag redefined".
	fs := flag.NewFlagSet("workerd-manager", flag.ExitOnError)
	var (
		stateDir      = fs.String("state_dir", "/run/workerd-manager/state", "runsc --root state dir")
		rootDir       = fs.String("root_dir", "/run/workerd-manager/root", "host staging dir for the dispatcher config")
		imageBaseDir  = fs.String("image_base_dir", "/run/workerd-manager/images", "OCI image extraction dir")
		workerdImage  = fs.String("workerd_image", "", "stock workerd OCI image the resident runs (required)")
		listenAddr    = fs.String("listen_addr", "*:8080", "dispatcher http socket bind address")
		controlAddr   = fs.String("control_addr", "127.0.0.1:2024", "host loopback TCP address the control channel listens on (the Sentry control forwarder dials it; TCP because the plugin seccomp blocks host AF_UNIX)")
		controlFwd    = fs.String("control_forward_addr", "", "in-sandbox TCP address the dispatcher dials for the control channel (default 127.0.0.2:80)")
		kubeconfig    = fs.String("kubeconfig", "", "path to the project apiserver kubeconfig (in-cluster config if empty)")
		devMode       = fs.Bool("dev", false, "dev mode: build an insecure apiserver client to --apiserver_host instead of using kubeconfig/in-cluster config")
		apiserverHost = fs.String("apiserver_host", "localhost:8443", "apiserver host:port for --dev mode (reached over the docker network by name when co-located with the backplane)")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	// Route controller-runtime's logr through slog so cache-sync/reconcile errors
	// surface instead of being silently discarded ("log.SetLogger never called").
	ctrl.SetLogger(logr.FromSlogHandler(slog.Default().Handler()))

	if *workerdImage == "" {
		return fmt.Errorf("workerd-manager: --workerd_image is required")
	}

	// The resident's runsc state/staging/image-extraction dirs live under the
	// shared volume (/run/workerd-manager); only the mount point exists, so create
	// the subdirs the sandbox core and image store expect before first use.
	for _, d := range []string{*stateDir, *rootDir, *imageBaseDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("creating manager dir %s: %w", d, err)
		}
	}

	// PID-1 reaper for the Sentry/gofer orphans (no-op off linux).
	host.StartChildReaper()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	resident, err := host.NewResidentHost(host.ResidentConfig{
		StateDir:           *stateDir,
		RootDir:            *rootDir,
		ImageBaseDir:       *imageBaseDir,
		WorkerdImage:       *workerdImage,
		ListenAddr:         *listenAddr,
		ControlHostAddr:    *controlAddr,
		ControlForwardAddr: *controlFwd,
	})
	if err != nil {
		return fmt.Errorf("constructing resident host: %w", err)
	}
	if err := resident.Cleanup(ctx); err != nil {
		slog.Warn("Sandbox cleanup reported an error", "error", err)
	}
	residentInst, err := resident.EnsureResident(ctx)
	if err != nil {
		return fmt.Errorf("starting resident workerd: %w", err)
	}
	slog.Info("Resident workerd serving", "listen", *listenAddr, "inboundSocket", residentInst.InboundSocket)

	cfg, err := restConfig(*devMode, *apiserverHost, *kubeconfig)
	if err != nil {
		return fmt.Errorf("building apiserver client config: %w", err)
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(computev1alpha1.Install(scheme))

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false,
		// The manager runs one-per-pod next to its resident; controller-runtime's
		// default :8080 metrics listener would collide, so disable it.
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		return fmt.Errorf("creating controller manager: %w", err)
	}

	store := NewStore(NewResolver(mgr.GetClient()))
	control := NewControlServer(store)
	go func() {
		if err := control.ServeTCP(ctx, *controlAddr); err != nil {
			slog.Error("Control channel server exited", "error", err)
			stop()
		}
	}()

	// The resident reconciler is read-only on the API: it keeps the resident up,
	// warms each revision, and records THIS node's serveable revision per service
	// on the store for the dispatcher's /resolve. Nothing is pushed off-node — the
	// xDS demux is stateless and the resident owns revision resolution.
	if err := NewResidentReconciler(mgr.GetClient(), resident, store).SetupWithManager(ctx, mgr); err != nil {
		return fmt.Errorf("setting up resident reconciler: %w", err)
	}

	slog.Info("Starting workerd-manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("running controller manager: %w", err)
	}

	slog.Info("Draining resident workerd")
	if err := resident.Stop(context.Background()); err != nil {
		slog.Warn("Resident drain reported an error", "error", err)
	}
	return nil
}

// restConfig builds a client config for the project apiserver. In dev mode it
// returns an insecure client to apiserverHost (the `apoxy dev` apiserver, reached
// over the shared loopback when the manager joins the apiserver's netns);
// otherwise it uses the kubeconfig path, falling back to in-cluster config.
func restConfig(dev bool, apiserverHost, kubeconfig string) (*rest.Config, error) {
	if dev {
		return &rest.Config{
			Host:            "https://" + apiserverHost,
			TLSClientConfig: rest.TLSClientConfig{Insecure: true},
			QPS:             -1,
		}, nil
	}
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}
