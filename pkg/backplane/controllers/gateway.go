package controllers

import (
	"context"
	"fmt"
	"strconv"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/apoxy-dev/apoxy/pkg/backplane/envoy"
	"github.com/apoxy-dev/apoxy/pkg/backplane/healthchecker"
	"github.com/apoxy-dev/apoxy/pkg/gateway/gatewayapi"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/bootstrap"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	gatewayv1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
)

var _ reconcile.Reconciler = &GatewayReconciler{}

// GatewayReconciler reconciles Gateway objects and validates their listeners
// against the associated Proxy's Envoy configuration.
type GatewayReconciler struct {
	client.Client

	// proxyName is the name of the Proxy resource managed by this Backplane.
	proxyName string

	// healthChecker is used to register health checks for Gateway listeners.
	healthChecker *healthchecker.AggregatedHealthChecker
}

// NewGatewayReconciler creates a new GatewayReconciler.
func NewGatewayReconciler(client client.Client, proxyName string, hc *healthchecker.AggregatedHealthChecker) *GatewayReconciler {
	return &GatewayReconciler{
		Client:        client,
		proxyName:     proxyName,
		healthChecker: hc,
	}
}

// Reconcile implements the reconcile.Reconciler interface.
func (r *GatewayReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	log := log.FromContext(ctx)

	gw := &gatewayv1.Gateway{}
	err := r.Get(ctx, request.NamespacedName, gw)
	if errors.IsNotFound(err) {
		// Gateway has been deleted, deregister health checks.
		if r.healthChecker != nil {
			hcName := fmt.Sprintf("gateway-%s-listeners", request.Name)
			r.healthChecker.Unregister(hcName)
		}
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get Gateway: %w", err)
	}

	if !r.isGatewayForProxy(gw) {
		log.Info("Gateway not associated with this proxy", "gateway", gw.Name, "proxy", r.proxyName)
		return reconcile.Result{}, nil
	}

	log.Info("Reconciling Gateway", "gateway", gw.Name)

	// Fetch the associated Proxy to get admin endpoint information.
	proxy := &corev1alpha2.Proxy{}
	err = r.Get(ctx, types.NamespacedName{Name: r.proxyName}, proxy)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Associated Proxy not found", "proxy", r.proxyName)
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("failed to get Proxy: %w", err)
	}

	// Extract listeners from Gateway spec and register health checks.
	if r.healthChecker != nil {
		listeners := r.extractEnvoyListeners(gw)
		if len(listeners) > 0 {
			hcName := fmt.Sprintf("gateway-%s-listeners", gw.Name)
			adminHost := bootstrap.EnvoyAdminAddress + ":" + strconv.Itoa(bootstrap.EnvoyAdminPort)
			r.healthChecker.Register(
				hcName,
				envoy.NewReadyChecker(adminHost, listeners...),
			)
			log.Info("Registered listener health checks", "gateway", gw.Name, "listeners", len(listeners))
		}
	}

	err = r.updateGatewayStatus(ctx, gw, proxy)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to update Gateway status: %w", err)
	}

	return reconcile.Result{}, nil
}

// isGatewayForProxy checks if the Gateway is associated with the Proxy managed by this Backplane.
func (r *GatewayReconciler) isGatewayForProxy(gw *gatewayv1.Gateway) bool {
	if gw.Spec.Infrastructure == nil {
		return false
	}

	ref := gw.Spec.Infrastructure.ParametersRef
	if ref == nil {
		return false
	}

	return ref.Kind == "Proxy" && ref.Name == r.proxyName
}

// extractEnvoyListeners converts Gateway listeners to Envoy listener format for health checking.
func (r *GatewayReconciler) extractEnvoyListeners(gw *gatewayv1.Gateway) []*envoy.Listener {
	listeners := make([]*envoy.Listener, 0, len(gw.Spec.Listeners))

	for _, l := range gw.Spec.Listeners {
		var protocol corev3.SocketAddress_Protocol
		switch l.Protocol {
		case gwapiv1.HTTPProtocolType, gwapiv1.HTTPSProtocolType, gwapiv1.TLSProtocolType, gwapiv1.TCPProtocolType:
			protocol = corev3.SocketAddress_TCP
		case gwapiv1.UDPProtocolType:
			protocol = corev3.SocketAddress_UDP
		default: // Skip unknown protocols.
			continue
		}

		listeners = append(listeners, &envoy.Listener{
			Name: gatewayapi.HTTPListenerName(gw.Namespace, gw.Name, l.Name),
			Address: corev3.Address{
				Address: &corev3.Address_SocketAddress{
					SocketAddress: &corev3.SocketAddress{
						Protocol: protocol,
						PortSpecifier: &corev3.SocketAddress_PortValue{
							PortValue: uint32(l.Port),
						},
					},
				},
			},
		})
	}

	return listeners
}

// updateGatewayStatus updates the Gateway status with conditions based on the Proxy state.
func (r *GatewayReconciler) updateGatewayStatus(ctx context.Context, gw *gatewayv1.Gateway, proxy *corev1alpha2.Proxy) error {
	acceptedCondition := metav1.Condition{
		Type:               string(gwapiv1.GatewayConditionAccepted),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: gw.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             string(gwapiv1.GatewayReasonAccepted),
		Message:            "Gateway accepted and associated with Proxy",
	}

	programmedCondition := metav1.Condition{
		Type:               string(gwapiv1.GatewayConditionProgrammed),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: gw.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             string(gwapiv1.GatewayReasonProgrammed),
		Message:            "Gateway listeners are configured in Envoy",
	}

	meta.SetStatusCondition(&gw.Status.Conditions, acceptedCondition)
	meta.SetStatusCondition(&gw.Status.Conditions, programmedCondition)

	for i, l := range gw.Spec.Listeners {
		if i < len(gw.Status.Listeners) {
			gw.Status.Listeners[i].Name = l.Name
			gw.Status.Listeners[i].AttachedRoutes = 0 // This would need route counting logic

			// Set listener conditions
			listenerAccepted := metav1.Condition{
				Type:               string(gwapiv1.ListenerConditionAccepted),
				Status:             metav1.ConditionTrue,
				ObservedGeneration: gw.Generation,
				LastTransitionTime: metav1.Now(),
				Reason:             string(gwapiv1.ListenerReasonAccepted),
				Message:            "Listener accepted",
			}
			meta.SetStatusCondition(&gw.Status.Listeners[i].Conditions, listenerAccepted)
		}
	}

	return r.Status().Update(ctx, gw)
}

// SetupWithManager sets up the controller with the Manager.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}
