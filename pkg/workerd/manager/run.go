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
	var (
		stateDir      = flag.String("state_dir", "/run/workerd-manager/state", "runsc --root state dir")
		rootDir       = flag.String("root_dir", "/run/workerd-manager/root", "host staging dir for the dispatcher config")
		imageBaseDir  = flag.String("image_base_dir", "/run/workerd-manager/images", "OCI image extraction dir")
		workerdImage  = flag.String("workerd_image", "", "stock workerd OCI image the resident runs (required)")
		listenAddr    = flag.String("listen_addr", "*:8080", "dispatcher http socket bind address")
		controlSocket = flag.String("control_socket", "/run/workerd-manager/control.sock", "host AF_UNIX socket the control channel listens on")
		controlFwd    = flag.String("control_forward_addr", "", "in-sandbox TCP address the dispatcher dials for the control channel (default 127.0.0.2:80)")
		kubeconfig    = flag.String("kubeconfig", "", "path to the project apiserver kubeconfig (in-cluster config if empty)")
		backplaneAddr = flag.String("backplane_publish_addr", "", "loopback host:port of the co-located backplane's private workerd publish channel (empty disables publishing)")
		projectID     = flag.String("project_id", "", "the project this manager serves; scopes the demux id so the shared resident never collides two projects' services (required)")
		devMode       = flag.Bool("dev", false, "dev mode: build an insecure apiserver client to --apiserver_host instead of using kubeconfig/in-cluster config")
		apiserverHost = flag.String("apiserver_host", "localhost:8443", "apiserver host:port for --dev mode (reached over the shared loopback when co-located with the apiserver)")
	)
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if *workerdImage == "" {
		return fmt.Errorf("workerd-manager: --workerd_image is required")
	}
	if *projectID == "" {
		return fmt.Errorf("workerd-manager: --project_id is required")
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
		ControlSocketPath:  *controlSocket,
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

	store := NewStore(NewResolver(mgr.GetClient(), *projectID))
	control := NewControlServer(store)
	go func() {
		if err := control.ServeUnix(ctx, *controlSocket); err != nil {
			slog.Error("Control channel server exited", "error", err)
			stop()
		}
	}()

	if err := NewResidentReconciler(mgr.GetClient(), resident, store, *projectID).SetupWithManager(ctx, mgr); err != nil {
		return fmt.Errorf("setting up resident reconciler: %w", err)
	}

	// Publish the resident socket + live-revision map to the co-located backplane
	// over the private node-local channel (the backplane never reads the customer
	// compute API for this).
	if *backplaneAddr != "" {
		pub := NewPublishReconciler(mgr.GetClient(), NewHTTPPublisher(*backplaneAddr), residentInst.InboundSocket, *projectID)
		if err := pub.SetupWithManager(ctx, mgr); err != nil {
			return fmt.Errorf("setting up publish reconciler: %w", err)
		}
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
