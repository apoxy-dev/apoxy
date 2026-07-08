package gateway

import (
	"context"

	"google.golang.org/grpc/credentials"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gatewayapirunner "github.com/apoxy-dev/apoxy/pkg/gateway/gatewayapi/runner"
	"github.com/apoxy-dev/apoxy/pkg/gateway/message"
	statusrunner "github.com/apoxy-dev/apoxy/pkg/gateway/status/runner"
	xdsserverrunner "github.com/apoxy-dev/apoxy/pkg/gateway/xds/server/runner"
	xdstranslator "github.com/apoxy-dev/apoxy/pkg/gateway/xds/translator"
	xdstranslatorrunner "github.com/apoxy-dev/apoxy/pkg/gateway/xds/translator/runner"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

// ServerOption is an xDS server option.
type ServerOption func(*serverOptions)

type serverOptions struct {
	extensionEnabled         bool
	extensionServerAddr      string
	extensionServerCreds     credentials.TransportCredentials
	extensionFailOpen        bool
	client                   client.Client
	workerdProjectNamespaces bool
}

// WithClient sets the Kubernetes client for status updates.
// If provided, a status runner will be started to write Gateway API
// resource statuses back to the API server.
func WithClient(c client.Client) ServerOption {
	return func(o *serverOptions) {
		o.client = c
	}
}

// WithWorkerdProjectNamespaces marks route namespaces as project UUIDs for the
// workerd xDS hook. It is the opt-in for multi-project translation owners —
// the shared backplane, whose DefaultGatewayReconciler rewrites route
// namespaces to multicluster cluster names (project UUIDs). With it, the hook
// emits one per-project resident cluster per project instead of the single
// legacy cluster. Never set it in dedicated/dev single-project topologies,
// where namespaces are user namespaces. (APO-796)
func WithWorkerdProjectNamespaces() ServerOption {
	return func(o *serverOptions) {
		o.workerdProjectNamespaces = true
	}
}

// WithExtensionServer sets the extension server for the server options. If failOpen is true,
// the server will still translate xDS (unmodified) if the extension server is not available.
func WithExtensionServer(addr string, creds credentials.TransportCredentials, failOpen bool) ServerOption {
	return func(o *serverOptions) {
		o.extensionEnabled = true
		o.extensionServerAddr = addr
		o.extensionServerCreds = creds
		o.extensionFailOpen = failOpen
	}
}

// RunServer runs the Gateway API xDS server. Uses resources to subscribe to
// Gateway-API resource updates, translates it to xDS IR and infra IR resources,
// and publishes them via xDS snapshotter service.
// The call will block until the ctx is canceled.
func RunServer(ctx context.Context, resources *message.ProviderResources, opts ...ServerOption) error {
	logger := log.DefaultLogger

	options := &serverOptions{}
	for _, opt := range opts {
		opt(options)
	}

	// Start the Status Runner if a client is provided.
	// It subscribes to Gateway API resource status updates and writes them
	// back to Kubernetes.
	if options.client != nil {
		statusRunner := statusrunner.New(&statusrunner.Config{
			Client:            options.client,
			ProviderResources: resources,
		})
		if err := statusRunner.Start(ctx); err != nil {
			return err
		}
	}

	xdsIR := new(message.XdsIR)
	// Start the GatewayAPI Translator Runner.
	// It subscribes to the provider resources, translates it to xDS IR
	// and infra IR resources and publishes them.
	gwRunner := gatewayapirunner.New(&gatewayapirunner.Config{
		ProviderResources:           resources,
		XdsIR:                       xdsIR,
		WorkerdProjectFromNamespace: options.workerdProjectNamespaces,
	})
	if err := gwRunner.Start(ctx); err != nil {
		return err
	}

	xds := new(message.Xds)
	defer xds.Close()
	// Start the Xds Translator Service
	// It subscribes to the xdsIR, translates it into xds Resources and publishes it.
	// It also computes the EnvoyPatchPolicy statuses and publishes it.
	xdsTranslatorRunner := xdstranslatorrunner.New(&xdstranslatorrunner.Config{
		XdsIR:             xdsIR,
		Xds:               xds,
		ProviderResources: resources,
	})

	if options.extensionEnabled {
		logger.Info("Initializing extension server")
		var err error
		xdsTranslatorRunner.ExtensionServer, err = xdstranslator.NewExtensionServer(
			options.extensionServerAddr,
			xdstranslator.WithExtensionFailOpen(options.extensionFailOpen),
			xdstranslator.WithExtensionCreds(options.extensionServerCreds),
		)
		if err != nil {
			return err
		}
	}

	if err := xdsTranslatorRunner.Start(ctx); err != nil {
		return err
	}

	xdsServerRunner := xdsserverrunner.New(&xdsserverrunner.Config{
		Xds:       xds,
		Resources: resources,
	})
	if err := xdsServerRunner.Start(ctx); err != nil {
		return err
	}

	<-ctx.Done()

	return nil
}
