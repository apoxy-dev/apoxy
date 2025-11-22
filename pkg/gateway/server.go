package gateway

import (
	"context"

	gatewayapirunner "github.com/apoxy-dev/apoxy/pkg/gateway/gatewayapi/runner"
	"github.com/apoxy-dev/apoxy/pkg/gateway/message"
	xdsserverrunner "github.com/apoxy-dev/apoxy/pkg/gateway/xds/server/runner"
	xdstranslatorrunner "github.com/apoxy-dev/apoxy/pkg/gateway/xds/translator/runner"
)

type Server struct {
	Resources *message.ProviderResources
}

// NewServer creates a new Gateway API server.
func NewServer() *Server {
	return &Server{
		Resources: new(message.ProviderResources),
	}
}

func (s *Server) Run(ctx context.Context) error {
	xdsIR := new(message.XdsIR)
	// Start the GatewayAPI Translator Runner
	// It subscribes to the provider resources, translates it to xDS IR
	// and infra IR resources and publishes them.
	gwRunner := gatewayapirunner.New(&gatewayapirunner.Config{
		ProviderResources: s.Resources,
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
		ProviderResources: s.Resources,
		XdsIR:             xdsIR,
		Xds:               xds,
	})
	if err := xdsTranslatorRunner.Start(ctx); err != nil {
		return err
	}

	xdsServerRunner := xdsserverrunner.New(&xdsserverrunner.Config{
		Xds:       xds,
		Resources: s.Resources,
	})
	if err := xdsServerRunner.Start(ctx); err != nil {
		return err
	}

	<-ctx.Done()

	return nil
}
