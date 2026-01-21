package runner

import (
	"context"
	"fmt"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/apoxy-dev/apoxy/pkg/gateway/gatewayapi"
	"github.com/apoxy-dev/apoxy/pkg/gateway/message"
	"github.com/apoxy-dev/apoxy/pkg/gateway/utils"
	"github.com/apoxy-dev/apoxy/pkg/log"

	extensions "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
)

var (
	extensionsGroupKinds = []schema.GroupKind{
		{Group: extensions.GroupVersion.Group, Kind: "EdgeFunction"},
	}
)

// Config is the gateway-api translator runner configuration.
type Config struct {
	ProviderResources *message.ProviderResources
	XdsIR             *message.XdsIR
}

// Runner is the gateway-api translator runner.
type Runner struct {
	Config
}

// New creates a new gateway-api translator runner.
func New(cfg *Config) *Runner {
	return &Runner{
		Config: *cfg,
	}
}

// Start starts the gateway-api translator runner
func (r *Runner) Start(ctx context.Context) (err error) {
	log := log.DefaultLogger.With("runner", "gateway-api")

	go r.subscribeAndTranslate(ctx)
	log.Info("Started translator runner")
	return
}

func (r *Runner) subscribeAndTranslate(ctx context.Context) {
	log := log.DefaultLogger.With("runner", "gateway-api")
	message.HandleSubscription(
		message.Metadata{
			Runner:  string(egv1a1.LogComponentGatewayAPIRunner),
			Message: "provider-resources",
		},
		r.ProviderResources.GatewayAPIResources.Subscribe(ctx),
		func(update message.Update[string, *gatewayapi.ControllerResources], errChan chan error) {
			log.Info("Received an update", "key", update.Key)
			val := update.Value
			// There is only 1 key which is the controller name
			// so when a delete is triggered, delete all IR keys
			if update.Delete || val == nil {
				log.Info("deleting all IR keys")
				r.deleteAllIRKeys()
				r.deleteAllStatusKeys()
				return
			}

			// IR keys for watchable
			var curIRKeys, newIRKeys []string

			// Get current IR keys
			for key := range r.XdsIR.LoadAll() {
				curIRKeys = append(curIRKeys, key)
			}

			// Iterating through the controller resources, any valid keys will be removed from statusesToDelete.
			// Remaining keys will be deleted from watchable before we exit this function.
			statusesToDelete := r.getAllStatuses()

			for _, resources := range *val {
				log.Debug("Initiating translation for GWC", "GatewayClass", resources.GatewayClass.Name)
				// Translate and publish IRs.
				t := &gatewayapi.Translator{
					GatewayControllerName: string(resources.GatewayClass.Spec.ControllerName),
					GatewayClassName:      gwapiv1.ObjectName(resources.GatewayClass.Name),
					ExtensionGroupKinds:   extensionsGroupKinds,
					// TODO(dilyevsky): Re-enable support for Endpoint slices.
					// https://linear.app/apoxy/issue/APO-257/enable-support-for-endpoint-slices
					EndpointRoutingDisabled: true,
				}

				log.Info("Translating resources", "resources", resources)

				// Translate to IR
				result := t.Translate(resources)
				for key, val := range result.XdsIR {
					log.Info("Translated resources", "key", key, "value", val.YAMLString())
					if err := val.Validate(); err != nil {
						log.Error("unable to validate xds ir, skipped sending it", "error", err)
						errChan <- err

						// Update Gateway status to reflect validation error
						for _, gateway := range result.Gateways {
							gwKey := utils.NamespacedName(gateway)
							meta.SetStatusCondition(&gateway.Status.Conditions, metav1.Condition{
								Type:               string(gwapiv1.GatewayConditionProgrammed),
								Status:             metav1.ConditionFalse,
								ObservedGeneration: gateway.Generation,
								LastTransitionTime: metav1.Now(),
								Reason:             string(gwapiv1.GatewayReasonInvalid),
								Message:            fmt.Sprintf("IR validation failed: %v", err),
							})
							r.ProviderResources.GatewayStatuses.Store(gwKey, &gateway.Status)
							delete(statusesToDelete.GatewayStatusKeys, gwKey)
						}

						continue
					}

					log.Info("Storing xds ir", "key", key)
					r.XdsIR.Store(key, val)
					newIRKeys = append(newIRKeys, key)
				}

				// Update Status
				for _, gateway := range result.Gateways {
					key := utils.NamespacedName(gateway)
					r.ProviderResources.GatewayStatuses.Store(key, &gateway.Status)
					delete(statusesToDelete.GatewayStatusKeys, key)
				}
				for _, httpRoute := range result.HTTPRoutes {
					key := utils.NamespacedName(httpRoute)
					r.ProviderResources.HTTPRouteStatuses.Store(key, &httpRoute.Status)
					delete(statusesToDelete.HTTPRouteStatusKeys, key)
				}
				for _, grpcRoute := range result.GRPCRoutes {
					key := utils.NamespacedName(grpcRoute)
					r.ProviderResources.GRPCRouteStatuses.Store(key, &grpcRoute.Status)
					delete(statusesToDelete.GRPCRouteStatusKeys, key)
				}
				for _, tlsRoute := range result.TLSRoutes {
					key := utils.NamespacedName(tlsRoute)
					r.ProviderResources.TLSRouteStatuses.Store(key, &tlsRoute.Status)
					delete(statusesToDelete.TLSRouteStatusKeys, key)
				}
				for _, tcpRoute := range result.TCPRoutes {
					key := utils.NamespacedName(tcpRoute)
					r.ProviderResources.TCPRouteStatuses.Store(key, &tcpRoute.Status)
					delete(statusesToDelete.TCPRouteStatusKeys, key)
				}
				for _, udpRoute := range result.UDPRoutes {
					key := utils.NamespacedName(udpRoute)
					r.ProviderResources.UDPRouteStatuses.Store(key, &udpRoute.Status)
					delete(statusesToDelete.UDPRouteStatusKeys, key)
				}

				// Skip updating status for policies with empty status
				// They may have been skipped in this translation because
				// their target is not found (not relevant)
				/*
					for _, backendTLSPolicy := range result.BackendTLSPolicies {
						backendTLSPolicy := backendTLSPolicy
						key := utils.NamespacedName(backendTLSPolicy)
						if !(reflect.ValueOf(backendTLSPolicy.Status).IsZero()) {
							r.ProviderResources.BackendTLSPolicyStatuses.Store(key, &backendTLSPolicy.Status)
						}
						delete(statusesToDelete.BackendTLSPolicyStatusKeys, key)
					}
				*/
			}

			// Delete IR keys
			// There is a 1:1 mapping between infra and xds IR keys
			delKeys := getIRKeysToDelete(curIRKeys, newIRKeys)
			for _, key := range delKeys {
				r.XdsIR.Delete(key)
			}

			// Delete status keys
			r.deleteStatusKeys(statusesToDelete)
		},
	)
	log.Info("Shutting down")
}

// deleteAllIRKeys deletes all XdsIR and InfraIR
func (r *Runner) deleteAllIRKeys() {
	for key := range r.XdsIR.LoadAll() {
		r.XdsIR.Delete(key)
	}
}

type StatusesToDelete struct {
	GatewayStatusKeys          map[types.NamespacedName]bool
	HTTPRouteStatusKeys        map[types.NamespacedName]bool
	GRPCRouteStatusKeys        map[types.NamespacedName]bool
	TLSRouteStatusKeys         map[types.NamespacedName]bool
	TCPRouteStatusKeys         map[types.NamespacedName]bool
	UDPRouteStatusKeys         map[types.NamespacedName]bool
	BackendTLSPolicyStatusKeys map[types.NamespacedName]bool
}

func (r *Runner) getAllStatuses() *StatusesToDelete {
	// Maps storing status keys to be deleted
	ds := &StatusesToDelete{
		GatewayStatusKeys:          make(map[types.NamespacedName]bool),
		HTTPRouteStatusKeys:        make(map[types.NamespacedName]bool),
		GRPCRouteStatusKeys:        make(map[types.NamespacedName]bool),
		TLSRouteStatusKeys:         make(map[types.NamespacedName]bool),
		TCPRouteStatusKeys:         make(map[types.NamespacedName]bool),
		UDPRouteStatusKeys:         make(map[types.NamespacedName]bool),
		BackendTLSPolicyStatusKeys: make(map[types.NamespacedName]bool),
	}

	// Get current status keys
	for key := range r.ProviderResources.GatewayStatuses.LoadAll() {
		ds.GatewayStatusKeys[key] = true
	}
	for key := range r.ProviderResources.HTTPRouteStatuses.LoadAll() {
		ds.HTTPRouteStatusKeys[key] = true
	}
	for key := range r.ProviderResources.GRPCRouteStatuses.LoadAll() {
		ds.GRPCRouteStatusKeys[key] = true
	}
	for key := range r.ProviderResources.TLSRouteStatuses.LoadAll() {
		ds.TLSRouteStatusKeys[key] = true
	}
	for key := range r.ProviderResources.TCPRouteStatuses.LoadAll() {
		ds.TCPRouteStatusKeys[key] = true
	}
	for key := range r.ProviderResources.UDPRouteStatuses.LoadAll() {
		ds.UDPRouteStatusKeys[key] = true
	}
	for key := range r.ProviderResources.BackendTLSPolicyStatuses.LoadAll() {
		ds.BackendTLSPolicyStatusKeys[key] = true
	}

	return ds
}

func (r *Runner) deleteStatusKeys(ds *StatusesToDelete) {
	for key := range ds.GatewayStatusKeys {
		r.ProviderResources.GatewayStatuses.Delete(key)
		delete(ds.GatewayStatusKeys, key)
	}
	for key := range ds.HTTPRouteStatusKeys {
		r.ProviderResources.HTTPRouteStatuses.Delete(key)
		delete(ds.HTTPRouteStatusKeys, key)
	}
	for key := range ds.GRPCRouteStatusKeys {
		r.ProviderResources.GRPCRouteStatuses.Delete(key)
		delete(ds.GRPCRouteStatusKeys, key)
	}
	for key := range ds.TLSRouteStatusKeys {
		r.ProviderResources.TLSRouteStatuses.Delete(key)
		delete(ds.TLSRouteStatusKeys, key)
	}
	for key := range ds.TCPRouteStatusKeys {
		r.ProviderResources.TCPRouteStatuses.Delete(key)
		delete(ds.TCPRouteStatusKeys, key)
	}
	for key := range ds.UDPRouteStatusKeys {
		r.ProviderResources.UDPRouteStatuses.Delete(key)
		delete(ds.UDPRouteStatusKeys, key)
	}
	for key := range ds.BackendTLSPolicyStatusKeys {
		r.ProviderResources.BackendTLSPolicyStatuses.Delete(key)
		delete(ds.BackendTLSPolicyStatusKeys, key)
	}
}

// deleteAllStatusKeys deletes all status keys stored by the subscriber.
func (r *Runner) deleteAllStatusKeys() {
	// Fields of GatewayAPIStatuses
	for key := range r.ProviderResources.GatewayStatuses.LoadAll() {
		r.ProviderResources.GatewayStatuses.Delete(key)
	}
	for key := range r.ProviderResources.HTTPRouteStatuses.LoadAll() {
		r.ProviderResources.HTTPRouteStatuses.Delete(key)
	}
	for key := range r.ProviderResources.GRPCRouteStatuses.LoadAll() {
		r.ProviderResources.GRPCRouteStatuses.Delete(key)
	}
	for key := range r.ProviderResources.TLSRouteStatuses.LoadAll() {
		r.ProviderResources.TLSRouteStatuses.Delete(key)
	}
	for key := range r.ProviderResources.TCPRouteStatuses.LoadAll() {
		r.ProviderResources.TCPRouteStatuses.Delete(key)
	}
	for key := range r.ProviderResources.UDPRouteStatuses.LoadAll() {
		r.ProviderResources.UDPRouteStatuses.Delete(key)
	}
	for key := range r.ProviderResources.BackendTLSPolicyStatuses.LoadAll() {
		r.ProviderResources.BackendTLSPolicyStatuses.Delete(key)
	}
}

// getIRKeysToDelete returns the list of IR keys to delete
// based on the difference between the current keys and the
// new keys parameters passed to the function.
func getIRKeysToDelete(curKeys, newKeys []string) []string {
	curSet := sets.NewString(curKeys...)
	newSet := sets.NewString(newKeys...)

	log.Infof("Diffing IR keys, current: %v, new: %v", curSet.List(), newSet.List())

	delSet := curSet.Difference(newSet)

	return delSet.List()
}
