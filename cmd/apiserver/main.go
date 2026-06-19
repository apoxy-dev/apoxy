package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	goruntime "runtime"
	"strings"

	"github.com/google/uuid"
	"github.com/temporalio/cli/temporalcli/devserver"
	tclient "go.temporal.io/sdk/client"
	tworker "go.temporal.io/sdk/worker"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"

	a3yversionedclient "github.com/apoxy-dev/apoxy/client/versioned"
	"github.com/apoxy-dev/apoxy/pkg/apiserver"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/ingest"
	"github.com/apoxy-dev/apoxy/pkg/gateway"
	"github.com/apoxy-dev/apoxy/pkg/gateway/message"
	gatewayworkerd "github.com/apoxy-dev/apoxy/pkg/gateway/workerd"
	xdstranslator "github.com/apoxy-dev/apoxy/pkg/gateway/xds/translator"
	"github.com/apoxy-dev/apoxy/pkg/log"
	workerdmanager "github.com/apoxy-dev/apoxy/pkg/workerd/manager"
)

var (
	devMode  = flag.Bool("dev", false, "Enable development mode.")
	logLevel = flag.String("log_level", "info", "Log level.")

	dbFilePath       = flag.String("db", "apoxy.db", "Path to the database file.")
	tmprlDBFilePath  = flag.String("temporal-db", "temporal.db", "Path to the Temporal database file.")
	inCluster        = flag.Bool("in-cluster", false, "Enable in-cluster authentication.")
	insecure         = flag.Bool("insecure", true, "Enable insecure mode.")
	ingestStoreDir   = flag.String("ingest-store-dir", os.TempDir(), "Path to the ingest store directory.")
	ingestStorePort  = flag.Int("ingest-store-port", 8081, "Port for the ingest store.")
	controllerNames  = flag.String("controller-names", "", "Comma-separated list of GatewayClass controller names to watch. Defaults to both standalone and legacy controller names.")
	// APO-796: each backplane node's workerd-manager POSTs its per-node routing
	// snapshot (resident socket + the revision it serves per service) here; the
	// Gateway→xDS translator injects the resident cluster and x-apoxy-service demux
	// header from it. Empty disables the receiver (workerd routing stays inert).
	// Loopback by default; in --dev it binds the docker network (the manager runs
	// in the backplane's netns and reaches it by name).
	workerdPublishAddr = flag.String("workerd_publish_addr", "127.0.0.1:2021", "host:port for the private workerd-manager routing publish channel (empty disables).")
)

func stopCh(ctx context.Context) <-chan interface{} {
	ch := make(chan interface{})
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch
}

type startErr struct {
	Err error
}

func (r *startErr) Error() string {
	return r.Err.Error()
}

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
	ctx, ctxCancel := context.WithCancelCause(ctrl.SetupSignalHandler())

	tOpts := devserver.StartOptions{
		FrontendIP:             "127.0.0.1",
		FrontendPort:           7223,
		Namespaces:             []string{"default"},
		Logger:                 log.DefaultLogger,
		LogLevel:               slog.LevelError, // Too noisy otherwise.
		ClusterID:              uuid.NewString(),
		MasterClusterName:      "active",
		CurrentClusterName:     "active",
		InitialFailoverVersion: 1,
		DatabaseFile:           *tmprlDBFilePath,
	}
	tSrv, err := devserver.Start(tOpts)
	if err != nil {
		log.Fatalf("failed starting Temporal server: %w", err)
	}
	defer tSrv.Stop()
	tc, err := tclient.NewLazyClient(tclient.Options{
		HostPort:  "localhost:7223",
		Namespace: "default",
		Logger:    nil, // No logging.
	})
	if err != nil {
		log.Fatalf("Failed creating Temporal client: %v", err)
	}

	// APO-796 workerd data plane: install the registry the Gateway→xDS translator
	// reads to inject the resident workerd cluster + x-apoxy-service demux header,
	// and serve the private publish channel the co-located workerd-manager pushes
	// its routing snapshot to. The translator hook is inert until a snapshot lands.
	if *workerdPublishAddr != "" {
		workerdRegistry := gatewayworkerd.NewRegistry()
		xdstranslator.SetWorkerdRegistry(workerdRegistry)
		srv := gatewayworkerd.NewServer(workerdRegistry)
		publishAddr := *workerdPublishAddr
		if *devMode {
			// Dev reflects the 1:1 backplane↔resident coupling: the workerd-manager
			// runs in the BACKPLANE's netns, so it reaches this apiserver-hosted
			// channel over the docker network by name, not loopback. Bind all
			// interfaces and allow the non-loopback bind (private docker bridge).
			srv.AllowNonLoopback = true
			if host, port, err := net.SplitHostPort(publishAddr); err == nil {
				switch host {
				case "127.0.0.1", "localhost", "::1", "":
					publishAddr = ":" + port
				}
			}
		}
		go func() {
			if err := srv.Serve(ctx, publishAddr); err != nil {
				log.Errorf("workerd publish channel exited: %v", err)
				ctxCancel(&startErr{Err: err})
			}
		}()
	}

	gwResources := new(message.ProviderResources)
	go func() {
		if err := gateway.RunServer(ctx, gwResources); err != nil {
			log.Errorf("failed to serve Gateway APIs: %v", err)
			ctxCancel(&startErr{Err: err})
		}
	}()

	var kc *rest.Config
	rC := apiserver.NewClientConfig()
	if *inCluster {
		rC, err = rest.InClusterConfig()
		if err != nil {
			log.Errorf("failed to create in-cluster k8s config: %v", err)
			ctxCancel(&startErr{Err: err})
		}
		kc = rC
	}
	m := apiserver.New()
	go func() {
		sOpts := []apiserver.Option{
			apiserver.WithSQLitePath(*dbFilePath),
			// APO-796: mint/promote/GC compute.apoxy.dev ServiceRevisions. The
			// data-plane resident reconciler runs separately in cmd/workerd-manager.
			apiserver.WithAdditionalController(func(c client.Client) apiserver.Controller {
				return workerdmanager.NewServiceReconciler(c)
			}),
		}
		if *inCluster {
			if !*insecure {
				sOpts = append(sOpts, apiserver.WithInClusterAuth())
			}
			sOpts = append(sOpts, apiserver.WithClientConfig(rC))
			sOpts = append(sOpts, apiserver.WithKubeAPI())
		}
		if *controllerNames != "" {
			names := strings.Split(*controllerNames, ",")
			sOpts = append(sOpts, apiserver.WithControllerNames(names...))
		}
		if err := m.Start(ctx, gwResources, tc, sOpts...); err != nil {
			log.Errorf("failed to start API server manager: %v", err)
			ctxCancel(&startErr{Err: err})
		}
	}()
	select {
	case err, ok := <-m.ReadyCh:
		if !ok || err == nil {
			log.Infof("API server is ready")
		} else {
			log.Fatalf("API server failed to start: %v", err)
		}
	case <-ctx.Done():
		log.Fatalf("context canceled: %v", context.Cause(ctx))
	}

	a3y, err := a3yversionedclient.NewForConfig(rC)
	if err != nil {
		log.Fatalf("failed creating A3Y client: %v", err)
		ctxCancel(&startErr{Err: err})
	}

	wOpts := tworker.Options{
		MaxConcurrentActivityExecutionSize:     goruntime.NumCPU(),
		MaxConcurrentWorkflowTaskExecutionSize: goruntime.NumCPU(),
		EnableSessionWorker:                    true,
	}
	w := tworker.New(tc, ingest.EdgeFunctionIngestQueue, wOpts)
	ingest.RegisterWorkflows(w)
	ww := ingest.NewWorker(kc, a3y, *ingestStoreDir)
	ww.RegisterActivities(w)
	go func() {
		if err = ww.ListenAndServeEdgeFuncs("" /* host */, *ingestStorePort); err != nil {
			log.Errorf("failed to start Wasm server: %v", err)
			ctxCancel(&startErr{Err: err})
		}
	}()
	go func() {
		err = w.Run(stopCh(ctx))
		if err != nil {
			log.Errorf("failed running Temporal worker: %v", err)
			ctxCancel(&startErr{Err: err})
		}
	}()

	<-ctx.Done()
	sErr := &startErr{}
	if err := context.Cause(ctx); errors.As(err, &sErr) {
		log.Errorf("failed to start: %v", sErr.Err)
	} else {
		log.Infof("shutting down")
	}
}
