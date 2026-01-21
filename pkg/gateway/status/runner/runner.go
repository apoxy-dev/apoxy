package runner

import (
	"context"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	gatewayv1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
	gatewayv1alpha2 "github.com/apoxy-dev/apoxy/api/gateway/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/gateway/gatewayapi/status"
	"github.com/apoxy-dev/apoxy/pkg/gateway/message"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

// Config is the status runner configuration.
type Config struct {
	Client            client.Client
	ProviderResources *message.ProviderResources
}

// Runner subscribes to Gateway API resource status updates and writes them
// back to Kubernetes using the UpdateHandler.
type Runner struct {
	Config
	statusUpdater status.Updater
}

// New creates a new status runner.
func New(cfg *Config) *Runner {
	return &Runner{Config: *cfg}
}

// Start starts the status runner.
func (r *Runner) Start(ctx context.Context) error {
	// Convert slog.Logger to logr.Logger for the UpdateHandler
	logger := logr.FromSlogHandler(log.DefaultLogger.Handler())

	// Create and start the UpdateHandler
	updateHandler := status.NewUpdateHandler(logger, r.Client)
	go updateHandler.Start(ctx)
	r.statusUpdater = updateHandler.Writer()

	// Subscribe to Gateway status updates
	go r.subscribeToGatewayStatuses(ctx)
	// Subscribe to HTTPRoute status updates
	go r.subscribeToHTTPRouteStatuses(ctx)
	// Subscribe to GRPCRoute status updates
	go r.subscribeToGRPCRouteStatuses(ctx)
	// Subscribe to TLSRoute status updates
	go r.subscribeToTLSRouteStatuses(ctx)
	// Subscribe to TCPRoute status updates
	go r.subscribeToTCPRouteStatuses(ctx)
	// Subscribe to UDPRoute status updates
	go r.subscribeToUDPRouteStatuses(ctx)

	log.Infof("Started status runner")
	return nil
}

func (r *Runner) subscribeToGatewayStatuses(ctx context.Context) {
	message.HandleSubscription(
		message.Metadata{Runner: "status", Message: "gateway-statuses"},
		r.ProviderResources.GatewayStatuses.Subscribe(ctx),
		func(update message.Update[types.NamespacedName, *gwapiv1.GatewayStatus], errChan chan error) {
			if update.Delete {
				return
			}

			log.Infof("Received gateway status update: %s", update.Key)

			// Send status update to the handler
			r.statusUpdater.Send(status.Update{
				NamespacedName: update.Key,
				Resource:       &gatewayv1.Gateway{},
				Mutator: status.MutatorFunc(func(obj client.Object) client.Object {
					gw := obj.(*gatewayv1.Gateway)
					gw.Status.GatewayStatus = *update.Value
					return gw
				}),
			})
		},
	)
}

func (r *Runner) subscribeToHTTPRouteStatuses(ctx context.Context) {
	message.HandleSubscription(
		message.Metadata{Runner: "status", Message: "httproute-statuses"},
		r.ProviderResources.HTTPRouteStatuses.Subscribe(ctx),
		func(update message.Update[types.NamespacedName, *gwapiv1.HTTPRouteStatus], errChan chan error) {
			if update.Delete {
				return
			}

			log.Infof("Received HTTPRoute status update: %s", update.Key)

			r.statusUpdater.Send(status.Update{
				NamespacedName: update.Key,
				Resource:       &gatewayv1.HTTPRoute{},
				Mutator: status.MutatorFunc(func(obj client.Object) client.Object {
					route := obj.(*gatewayv1.HTTPRoute)
					route.Status.HTTPRouteStatus = *update.Value
					return route
				}),
			})
		},
	)
}

func (r *Runner) subscribeToGRPCRouteStatuses(ctx context.Context) {
	message.HandleSubscription(
		message.Metadata{Runner: "status", Message: "grpcroute-statuses"},
		r.ProviderResources.GRPCRouteStatuses.Subscribe(ctx),
		func(update message.Update[types.NamespacedName, *gwapiv1.GRPCRouteStatus], errChan chan error) {
			if update.Delete {
				return
			}

			log.Infof("Received GRPCRoute status update: %s", update.Key)

			r.statusUpdater.Send(status.Update{
				NamespacedName: update.Key,
				Resource:       &gatewayv1.GRPCRoute{},
				Mutator: status.MutatorFunc(func(obj client.Object) client.Object {
					route := obj.(*gatewayv1.GRPCRoute)
					route.Status.GRPCRouteStatus = *update.Value
					return route
				}),
			})
		},
	)
}

func (r *Runner) subscribeToTLSRouteStatuses(ctx context.Context) {
	message.HandleSubscription(
		message.Metadata{Runner: "status", Message: "tlsroute-statuses"},
		r.ProviderResources.TLSRouteStatuses.Subscribe(ctx),
		func(update message.Update[types.NamespacedName, *gwapiv1a2.TLSRouteStatus], errChan chan error) {
			if update.Delete {
				return
			}

			log.Infof("Received TLSRoute status update: %s", update.Key)

			r.statusUpdater.Send(status.Update{
				NamespacedName: update.Key,
				Resource:       &gatewayv1alpha2.TLSRoute{},
				Mutator: status.MutatorFunc(func(obj client.Object) client.Object {
					route := obj.(*gatewayv1alpha2.TLSRoute)
					route.Status.TLSRouteStatus = *update.Value
					return route
				}),
			})
		},
	)
}

func (r *Runner) subscribeToTCPRouteStatuses(ctx context.Context) {
	message.HandleSubscription(
		message.Metadata{Runner: "status", Message: "tcproute-statuses"},
		r.ProviderResources.TCPRouteStatuses.Subscribe(ctx),
		func(update message.Update[types.NamespacedName, *gwapiv1a2.TCPRouteStatus], errChan chan error) {
			if update.Delete {
				return
			}

			log.Infof("Received TCPRoute status update: %s", update.Key)

			r.statusUpdater.Send(status.Update{
				NamespacedName: update.Key,
				Resource:       &gatewayv1alpha2.TCPRoute{},
				Mutator: status.MutatorFunc(func(obj client.Object) client.Object {
					route := obj.(*gatewayv1alpha2.TCPRoute)
					route.Status.TCPRouteStatus = *update.Value
					return route
				}),
			})
		},
	)
}

func (r *Runner) subscribeToUDPRouteStatuses(ctx context.Context) {
	message.HandleSubscription(
		message.Metadata{Runner: "status", Message: "udproute-statuses"},
		r.ProviderResources.UDPRouteStatuses.Subscribe(ctx),
		func(update message.Update[types.NamespacedName, *gwapiv1a2.UDPRouteStatus], errChan chan error) {
			if update.Delete {
				return
			}

			log.Infof("Received UDPRoute status update: %s", update.Key)

			r.statusUpdater.Send(status.Update{
				NamespacedName: update.Key,
				Resource:       &gatewayv1alpha2.UDPRoute{},
				Mutator: status.MutatorFunc(func(obj client.Object) client.Object {
					route := obj.(*gatewayv1alpha2.UDPRoute)
					route.Status.UDPRouteStatus = *update.Value
					return route
				}),
			})
		},
	)
}
