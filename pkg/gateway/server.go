package gateway

import (
	"context"

	gatewayapirunner "github.com/apoxy-dev/apoxy/pkg/gateway/gatewayapi/runner"
	"github.com/apoxy-dev/apoxy/pkg/gateway/message"
	xdsserverrunner "github.com/apoxy-dev/apoxy/pkg/gateway/xds/server/runner"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/translator"
	xdstranslatorrunner "github.com/apoxy-dev/apoxy/pkg/gateway/xds/translator/runner"
	"github.com/envoyproxy/gateway/proto/extension"
)

// ServerOption is an xDS server option.
type ServerOption func(*serverOptions)

type serverOptions struct {
	extensionClient   extension.EnvoyGatewayExtensionClient
	extensionFailOpen bool
}

// WithExtensionServer sets the extension server for the server options. If failOpen is true,
// the server will still translate xDS (unmodified) if the extension server is not available.
func WithExtensionServer(c extension.EnvoyGatewayExtensionClient, failOpen bool) ServerOption {
	return func(o *serverOptions) {
		o.extensionClient = c
		o.extensionFailOpen = failOpen
	}
}

// RunServer runs the Gateway API xDS server. Uses resources to subscribe to
// Gateway-API resource updates, translates it to xDS IR and infra IR resources,
// and publishes them via xDS snapshotter service.
// The call will block until the ctx is canceled.
func RunServer(ctx context.Context, resources *message.ProviderResources, opts ...ServerOption) error {
	options := &serverOptions{}
	for _, opt := range opts {
		opt(options)
	}

	xdsIR := new(message.XdsIR)
	// Start the GatewayAPI Translator Runner.
	// It subscribes to the provider resources, translates it to xDS IR
	// and infra IR resources and publishes them.
	gwRunner := gatewayapirunner.New(&gatewayapirunner.Config{
		ProviderResources: resources,
		XdsIR:             xdsIR,
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
		ExtensionServer: &translator.ExtensionServer{
			EnvoyGatewayExtensionClient: options.extensionClient,
			FailOpen:                    options.extensionFailOpen,
		},
	})
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
