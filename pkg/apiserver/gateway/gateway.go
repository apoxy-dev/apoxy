// Package gateway implements Gateway API controllers.
package gateway

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/apoxy-dev/apoxy/pkg/gateway/gatewayapi"
	gatewayapirunner "github.com/apoxy-dev/apoxy/pkg/gateway/gatewayapi/runner"
	"github.com/apoxy-dev/apoxy/pkg/gateway/message"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	gatewayv1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
	gatewayv1alpha2 "github.com/apoxy-dev/apoxy/api/gateway/v1alpha2"
)

func Install(scheme *runtime.Scheme) {
	utilruntime.Must(corev1.AddToScheme(scheme))
}

const (
	classGatewayIndex     = "classGatewayIndex"
	gatewayHTTPRouteIndex = "gatewayHTTPRouteIndex"
	backendHTTPRouteIndex = "backendHTTPRouteIndex"
	serviceHTTPRouteIndex = "serviceHTTPRouteIndex"
	gatewayTCPRouteIndex  = "gatewayTCPRouteIndex"
	backendTCPRouteIndex  = "backendTCPRouteIndex"
	serviceTCPRouteIndex  = "serviceTCPRouteIndex"
	gatewayUDPRouteIndex  = "gatewayUDPRouteIndex"
	backendUDPRouteIndex  = "backendUDPRouteIndex"
	serviceUDPRouteIndex  = "serviceUDPRouteIndex"
	gatewayTLSRouteIndex  = "gatewayTLSRouteIndex"
	backendTLSRouteIndex  = "backendTLSRouteIndex"
	serviceTLSRouteIndex  = "serviceTLSRouteIndex"
	gatewayInfraRefIndex  = "gatewayInfraRefIndex"
	edgeFunctionLiveIndex = "edgeFunctionLiveIndex"
)

var (
	conv = runtime.DefaultUnstructuredConverter

	_ reconcile.Reconciler = &GatewayReconciler{}
)

// GatewayReconciler reconciles a Proxy object.
type GatewayReconciler struct {
	client.Client

	resources *message.ProviderResources
	watchK8s  bool
}

type Option func(*GatewayReconciler)

// WithKubeAPI enables watching for K8s resources.
func WithKubeAPI() Option {
	return func(r *GatewayReconciler) {
		r.watchK8s = true
	}
}

// NewGatewayReconciler returns a new reconciler for Gateway API resources.
func NewGatewayReconciler(
	c client.Client,
	pr *message.ProviderResources,
	opts ...Option,
) *GatewayReconciler {
	r := &GatewayReconciler{
		Client:    c,
		resources: pr,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Reconcile implements reconcile.Reconciler.
func (r *GatewayReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx, "controller", request.Name)
	log.Info("Reconciling the GatewayClass")

	var gwcsl gatewayv1.GatewayClassList
	if err := r.List(ctx, &gwcsl); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list GatewayClasses: %w", err)
	}
	var gwcs []*gatewayv1.GatewayClass
	for _, gwc := range gwcsl.Items {
		if !gwc.DeletionTimestamp.IsZero() {
			log.V(1).Info("GatewayClass is being deleted", "name", gwc.Name)
			continue
		}
		if gwc.Spec.ControllerName == gatewayapirunner.ControllerName {
			log.Info("Reconciling GatewayClass", "name", gwc.Name)
			gwcs = append(gwcs, &gwc) // No longer requires copy since 1.22. See: https://go.dev/blog/loopvar-preview
		}
	}

	if len(gwcs) == 0 {
		log.Info("No matching GatewayClass objects found for controller")
		return ctrl.Result{}, nil
	}

	res := gatewayapi.NewResources()
	extRefs, err := r.getExtensionRefs(ctx, res)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get extension references: %w", err)
	}

	ress := make(gatewayapi.ControllerResources, 0, len(gwcs))
	for _, gwc := range gwcs {
		res.GatewayClass = &gwapiv1.GatewayClass{
			TypeMeta:   gwc.TypeMeta,
			ObjectMeta: gwc.ObjectMeta,
			Spec:       gwc.Spec,
			Status:     gwc.Status.GatewayClassStatus,
		}

		if err := r.reconcileGateways(clog.IntoContext(ctx, log), gwc, extRefs, res); err != nil {
			log.Error(err, "Failed to reconcile GatewayClass", "name", gwc.Name)
		}
		if err := r.reconcileBackends(clog.IntoContext(ctx, log), res); err != nil {
			log.Error(err, "Failed to reconcile BackendRefs for GatewayClass", "name", gwc.Name)
		}
		if err := r.reconcileServices(clog.IntoContext(ctx, log), res); err != nil {
			log.Error(err, "Failed to reconcile Services for GatewayClass", "name", gwc.Name)
		}
		ress = append(ress, res)
	}

	r.resources.GatewayAPIResources.Store(gatewayapirunner.ControllerName, &ress)

	return ctrl.Result{}, nil
}

type extensionRefKey struct {
	Name      string
	GroupKind schema.GroupKind
}

func (r *GatewayReconciler) getExtensionRefs(
	ctx context.Context,
	res *gatewayapi.Resources,
) (map[extensionRefKey]*unstructured.Unstructured, error) {
	log := clog.FromContext(ctx)

	var (
		extRefs   = make(map[extensionRefKey]*unstructured.Unstructured)
		edgeFuncs = make(map[string]bool)
	)

	funls := extensionsv1alpha2.EdgeFunctionList{}
	if err := r.List(ctx, &funls, client.MatchingFields{edgeFunctionLiveIndex: "true"}); err != nil {
		return nil, fmt.Errorf("failed to list EdgeFunctions: %w", err)
	}
	for _, fun := range funls.Items {
		if fun.Status.LiveRevision == "" {
			log.V(1).Info("EdgeFunction is not ready", "name", fun.Name)
			continue
		}

		un, err := conv.ToUnstructured(&fun)
		if err != nil {
			return nil, fmt.Errorf("failed to convert EdgeFunction to Unstructured: %w", err)
		}

		// Collect live revisions.
		rev := &extensionsv1alpha2.EdgeFunctionRevision{}
		if err := r.Get(ctx, types.NamespacedName{Name: fun.Status.LiveRevision}, rev); err != nil {
			return nil, fmt.Errorf("failed to get EdgeFunctionRevision: %w", err)
		}
		if !edgeFuncs[fun.Name] {
			edgeFuncs[fun.Name] = true
			res.EdgeFunctionRevisions = append(res.EdgeFunctionRevisions, rev)
		}

		extRefs[extensionRefKey{
			Name:      fun.Name,
			GroupKind: schema.GroupKind{Group: fun.GroupVersionKind().Group, Kind: "EdgeFunction"},
		}] = &unstructured.Unstructured{Object: un}
	}

	// TODO(dilyevsky): Process other extensions.

	return extRefs, nil
}

func (r *GatewayReconciler) reconcileGateways(
	ctx context.Context,
	gwc *gatewayv1.GatewayClass,
	extRefs map[extensionRefKey]*unstructured.Unstructured,
	res *gatewayapi.Resources,
) error {
	log := clog.FromContext(ctx, "GatewayClass", gwc.Name)

	var gwsl gatewayv1.GatewayList
	if err := r.List(ctx, &gwsl, client.MatchingFields{classGatewayIndex: string(gwc.Name)}); err != nil {
		return fmt.Errorf("failed to list Gateways: %w", err)
	}
	var gws []*gatewayv1.Gateway
	for _, gw := range gwsl.Items {
		if !gw.DeletionTimestamp.IsZero() {
			log.V(1).Info("Gateway is being deleted", "name", gw.Name)
			continue
		}
		log.Info("Reconciling Gateway", "name", gw.Name)
		gws = append(gws, &gw) // No longer requires copy since 1.22. See: https://go.dev/blog/loopvar-preview
	}

	if len(gws) == 0 {
		log.Info("No matching Gateway objects found for GatewayClass")
		return nil
	}

	for _, gw := range gws {
		if gw.Spec.Infrastructure == nil || gw.Spec.Infrastructure.ParametersRef.Kind != "Proxy" {
			log.Info("Gateway does not have a Proxy reference", "name", gw.Name)
			continue
		}

		// Check if the Proxy object actually exists.
		var proxy corev1alpha2.Proxy
		pn := types.NamespacedName{Name: gw.Spec.Infrastructure.ParametersRef.Name}
		if err := r.Get(ctx, pn, &proxy); err != nil {
			return fmt.Errorf("failed to get Proxy %s: %w", pn, err)
		}
		// Add the Proxy object to the resources if it doesn't already exist.
		if _, ok := res.GetProxy(proxy.Name); !ok {
			res.Proxies = append(res.Proxies, &proxy)
		}

		for _, listener := range gw.Spec.Listeners {
			log.V(1).Info("Processing Gateway Listener", "listener", listener)
			if terminatesTLS(&listener) {
				log.V(1).Info("Processing TLS Secret reference", "listener", listener.Name)
				for _, certRef := range listener.TLS.CertificateRefs {
					log.V(1).Info("Processing TLS Secret reference", "secretRef", certRef)
					if refsSecret(&certRef) {
						log.Info("Processing TLS Secret reference", "secretRef", certRef)
						if err := r.processSecretRef(clog.IntoContext(ctx, log), certRef, res); err != nil {
							log.Error(err,
								"failed to process TLS SecretRef for gateway",
								"gateway", gw, "secretRef", certRef)
						}
					}
				}
			}
		}

		if err := r.reconcileHTTPRoutes(clog.IntoContext(ctx, log), gw, extRefs, res); err != nil {
			log.Error(err, "Failed to reconcile HTTPRoutes for Gateway", "name", gw.Name)
		}
		if err := r.reconcileTCPRoutes(clog.IntoContext(ctx, log), gw, res); err != nil {
			log.Error(err, "Failed to reconcile TCPRoutes for Gateway", "name", gw.Name)
		}
		if err := r.reconcileUDPRoutes(clog.IntoContext(ctx, log), gw, res); err != nil {
			log.Error(err, "Failed to reconcile UDPRoutes for Gateway", "name", gw.Name)
		}
		if err := r.reconcileTLSRoutes(clog.IntoContext(ctx, log), gw, res); err != nil {
			log.Error(err, "Failed to reconcile TLSRoutes for Gateway", "name", gw.Name)
		}
		res.Gateways = append(res.Gateways, &gwapiv1.Gateway{
			TypeMeta:   gw.TypeMeta,
			ObjectMeta: gw.ObjectMeta,
			Spec:       gw.Spec,
			Status:     gw.Status.GatewayStatus,
		})
	}

	return nil
}

func (r *GatewayReconciler) processSecretRef(
	ctx context.Context,
	secretRef gwapiv1.SecretObjectReference,
	res *gatewayapi.Resources,
) error {
	log := clog.FromContext(ctx, "Secret", secretRef.Name)

	secret := &corev1.Secret{}
	secretNs := ptr.Deref(secretRef.Namespace, metav1.NamespaceDefault)
	if err := r.Get(ctx,
		types.NamespacedName{Namespace: string(secretNs), Name: string(secretRef.Name)},
		secret,
	); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("unable to find the Secret %s/%s: %v", secretNs, secretRef.Name, err)
	}

	res.Secrets = append(res.Secrets, secret)

	log.Info("Secret added to resources", "name", secret.Name, "namespace", secret.Namespace)

	return nil
}

func (r *GatewayReconciler) reconcileHTTPRoutes(
	ctx context.Context,
	gw *gatewayv1.Gateway,
	extRefs map[extensionRefKey]*unstructured.Unstructured,
	res *gatewayapi.Resources,
) error {
	log := clog.FromContext(ctx, "Gateway", gw.Name)

	var hrsl gatewayv1.HTTPRouteList
	if err := r.List(ctx, &hrsl, client.MatchingFields{gatewayHTTPRouteIndex: string(gw.Name)}); err != nil {
		return fmt.Errorf("failed to list HTTPRoutes: %w", err)
	}

	for _, hr := range hrsl.Items {
		if !hr.DeletionTimestamp.IsZero() {
			log.V(1).Info("HTTPRoute is being deleted", "name", hr.Name)
			continue
		}

		log.Info("Reconciling HTTPRoute", "name", hr.Name)

		for _, rule := range hr.Spec.Rules {
			for _, filter := range rule.Filters {
				if filter.ExtensionRef != nil {
					if filter.ExtensionRef.Group == "" {
						filter.ExtensionRef.Group = "extensions.apoxy.dev"
					}
					key := extensionRefKey{
						Name: string(filter.ExtensionRef.Name),
						GroupKind: schema.GroupKind{
							Group: string(filter.ExtensionRef.Group),
							Kind:  string(filter.ExtensionRef.Kind),
						},
					}
					if ref, ok := extRefs[key]; ok {
						log.Info("Found extension reference",
							"name", ref.GetName(), "gvk", ref.GroupVersionKind())
						res.ExtensionRefFilters = append(res.ExtensionRefFilters, *ref)
					} else {
						log.Info("Unable to find extension reference", "name", key.Name, "group", key.GroupKind.Group, "kind", key.GroupKind.Kind)
					}
				}
			}
			for _, backend := range rule.BackendRefs {
				if backend.Group != nil && backend.Kind != nil {
					key := extensionRefKey{
						Name: string(backend.Name),
						GroupKind: schema.GroupKind{
							Group: string(*backend.Group),
							Kind:  string(*backend.Kind),
						},
					}
					if ref, ok := extRefs[key]; ok {
						log.Info("Found extension backend reference",
							"name", ref.GetName(), "gvk", ref.GroupVersionKind())
						var fun extensionsv1alpha2.EdgeFunction
						if err := conv.FromUnstructured(ref.UnstructuredContent(), &fun); err != nil {
							log.Error(err, "Failed to convert extension reference to EdgeFunction", "name", ref.GetName())
						}
						res.EdgeFunctionBackends = append(res.EdgeFunctionBackends, &fun)
					} else {
						log.Info("Unable to find extension backend reference", "name", key.Name, "group", key.GroupKind.Group, "kind", key.GroupKind.Kind)
					}
				}
			}
		}

		res.HTTPRoutes = append(res.HTTPRoutes, &gwapiv1.HTTPRoute{
			TypeMeta:   hr.TypeMeta,
			ObjectMeta: hr.ObjectMeta,
			Spec:       hr.Spec,
			Status:     hr.Status.HTTPRouteStatus,
		})
	}

	return nil
}

func (r *GatewayReconciler) reconcileTCPRoutes(
	ctx context.Context,
	gw *gatewayv1.Gateway,
	res *gatewayapi.Resources,
) error {
	log := clog.FromContext(ctx, "Gateway", gw.Name)

	var trsl gatewayv1alpha2.TCPRouteList
	if err := r.List(ctx, &trsl, client.MatchingFields{gatewayTCPRouteIndex: string(gw.Name)}); err != nil {
		return fmt.Errorf("failed to list TCPRoutes: %w", err)
	}

	for _, tr := range trsl.Items {
		if !tr.DeletionTimestamp.IsZero() {
			log.V(1).Info("TCPRoute is being deleted", "name", tr.Name)
			continue
		}

		log.Info("Reconciling TCPRoute", "name", tr.Name)

		res.TCPRoutes = append(res.TCPRoutes, &gwapiv1a2.TCPRoute{
			TypeMeta:   tr.TypeMeta,
			ObjectMeta: tr.ObjectMeta,
			Spec:       tr.Spec,
			Status:     tr.Status.TCPRouteStatus,
		})
	}

	return nil
}

func (r *GatewayReconciler) reconcileUDPRoutes(
	ctx context.Context,
	gw *gatewayv1.Gateway,
	res *gatewayapi.Resources,
) error {
	log := clog.FromContext(ctx, "Gateway", gw.Name)

	var ursl gatewayv1alpha2.UDPRouteList
	if err := r.List(ctx, &ursl, client.MatchingFields{gatewayUDPRouteIndex: string(gw.Name)}); err != nil {
		return fmt.Errorf("failed to list UDPRoutes: %w", err)
	}

	for _, ur := range ursl.Items {
		if !ur.DeletionTimestamp.IsZero() {
			log.V(1).Info("UDPRoute is being deleted", "name", ur.Name)
			continue
		}

		log.Info("Reconciling UDPRoute", "name", ur.Name)

		res.UDPRoutes = append(res.UDPRoutes, &gwapiv1a2.UDPRoute{
			TypeMeta:   ur.TypeMeta,
			ObjectMeta: ur.ObjectMeta,
			Spec:       ur.Spec,
			Status:     ur.Status.UDPRouteStatus,
		})
	}

	return nil
}

func (r *GatewayReconciler) reconcileTLSRoutes(
	ctx context.Context,
	gw *gatewayv1.Gateway,
	res *gatewayapi.Resources,
) error {
	log := clog.FromContext(ctx, "Gateway", gw.Name)

	var tlsrsl gatewayv1alpha2.TLSRouteList
	if err := r.List(ctx, &tlsrsl, client.MatchingFields{gatewayTLSRouteIndex: string(gw.Name)}); err != nil {
		return fmt.Errorf("failed to list TLSRoutes: %w", err)
	}

	for _, tlsr := range tlsrsl.Items {
		if !tlsr.DeletionTimestamp.IsZero() {
			log.V(1).Info("TLSRoute is being deleted", "name", tlsr.Name)
			continue
		}

		log.Info("Reconciling TLSRoute", "name", tlsr.Name)

		res.TLSRoutes = append(res.TLSRoutes, &gwapiv1a2.TLSRoute{
			TypeMeta:   tlsr.TypeMeta,
			ObjectMeta: tlsr.ObjectMeta,
			Spec:       tlsr.Spec,
			Status:     tlsr.Status.TLSRouteStatus,
		})
	}

	return nil
}

func (r *GatewayReconciler) reconcileBackends(
	ctx context.Context,
	res *gatewayapi.Resources,
) error {
	log := clog.FromContext(ctx)

	var bl corev1alpha2.BackendList
	if err := r.List(ctx, &bl); err != nil {
		return fmt.Errorf("failed to list Backends: %w", err)
	}

	for _, b := range bl.Items {
		if !b.DeletionTimestamp.IsZero() {
			log.V(1).Info("Backend is being deleted", "name", b.Name)
			continue
		}

		// Check if Backend is referenced by any route type
		var hasRouteRef bool

		var hrsl gatewayv1.HTTPRouteList
		if err := r.List(ctx, &hrsl, client.MatchingFields{backendHTTPRouteIndex: string(b.Name)}); err != nil {
			return fmt.Errorf("failed to list HTTPRoutes for Backend %s: %w", b.Name, err)
		}
		hasRouteRef = hasRouteRef || len(hrsl.Items) > 0

		var trsl gatewayv1alpha2.TCPRouteList
		if err := r.List(ctx, &trsl, client.MatchingFields{backendTCPRouteIndex: string(b.Name)}); err != nil {
			return fmt.Errorf("failed to list TCPRoutes for Backend %s: %w", b.Name, err)
		}
		hasRouteRef = hasRouteRef || len(trsl.Items) > 0

		var ursl gatewayv1alpha2.UDPRouteList
		if err := r.List(ctx, &ursl, client.MatchingFields{backendUDPRouteIndex: string(b.Name)}); err != nil {
			return fmt.Errorf("failed to list UDPRoutes for Backend %s: %w", b.Name, err)
		}
		hasRouteRef = hasRouteRef || len(ursl.Items) > 0

		var tlsrsl gatewayv1alpha2.TLSRouteList
		if err := r.List(ctx, &tlsrsl, client.MatchingFields{backendTLSRouteIndex: string(b.Name)}); err != nil {
			return fmt.Errorf("failed to list TLSRoutes for Backend %s: %w", b.Name, err)
		}
		hasRouteRef = hasRouteRef || len(tlsrsl.Items) > 0

		if !hasRouteRef {
			log.Info("No matching Route objects found for Backend", "name", b.Name)
			continue
		}

		log.Info("Reconciling Backend", "name", b.Name)

		res.Backends = append(res.Backends, &b) // No longer requires copy since 1.22. See: https://go.dev/blog/loopvar-preview
	}

	return nil
}

func (r *GatewayReconciler) reconcileServices(
	ctx context.Context,
	res *gatewayapi.Resources,
) error {
	log := clog.FromContext(ctx)

	var svcl corev1.ServiceList
	if err := r.List(ctx, &svcl); err != nil {
		return fmt.Errorf("failed to list Services: %w", err)
	}

	for _, svc := range svcl.Items {
		if !svc.DeletionTimestamp.IsZero() {
			log.V(1).Info("Service is being deleted", "name", svc.Name)
			continue
		}

		log.Info("Reconciling Service", "name", svc.Name)

		var hrsl gatewayv1.HTTPRouteList
		if err := r.List(ctx, &hrsl, client.MatchingFields{serviceHTTPRouteIndex: string(svc.Name)}); err != nil {
			return fmt.Errorf("failed to list HTTPRoutes for Service %s: %w", svc.Name, err)
		} else if len(hrsl.Items) == 0 {
			log.Info("No matching HTTPRoute objects found for Service", "name", svc.Name)
			continue
		}

		res.Services = append(res.Services, &svc) // No longer requires copy since 1.22. See: https://go.dev/blog/loopvar-preview
	}

	return nil
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *GatewayReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	// Indexes Gateway objects by the name of the referenced GatewayClass object.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1.Gateway{}, classGatewayIndex, func(obj client.Object) []string {
		return []string{string(obj.(*gatewayv1.Gateway).Spec.GatewayClassName)}
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}
	// Indexes Gateway objects by the name of the referenced Proxy object.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1.Gateway{}, gatewayInfraRefIndex, func(obj client.Object) []string {
		var ref *gwapiv1.LocalParametersReference
		if obj.(*gatewayv1.Gateway).Spec.Infrastructure != nil {
			ref = obj.(*gatewayv1.Gateway).Spec.Infrastructure.ParametersRef
		}
		if ref != nil && ref.Kind == "Proxy" && ref.Name != "" {
			return []string{string(ref.Name)}
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}
	// Indexes HTTPRoute objects by the name of the referenced Gateway object.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1.HTTPRoute{}, gatewayHTTPRouteIndex, func(obj client.Object) []string {
		route := obj.(*gatewayv1.HTTPRoute)
		var gateways []string
		for _, ref := range route.Spec.ParentRefs {
			if ref.Kind == nil || *ref.Kind == "Gateway" {
				gateways = append(gateways, string(ref.Name))
			}
		}
		return gateways
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}
	// Indexes HTTPRoute objects by the name of the referenced Backend object.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1.HTTPRoute{}, backendHTTPRouteIndex, func(obj client.Object) []string {
		route := obj.(*gatewayv1.HTTPRoute)
		var backends []string
		for _, ref := range route.Spec.Rules {
			for _, backend := range ref.BackendRefs {
				if backend.Kind != nil && *backend.Kind == "Backend" {
					backends = append(backends, string(backend.Name))
				}
			}
		}
		return backends
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}
	// Indexes TCPRoute objects by the name of the referenced Gateway object.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1alpha2.TCPRoute{}, gatewayTCPRouteIndex, func(obj client.Object) []string {
		route := obj.(*gatewayv1alpha2.TCPRoute)
		var gateways []string
		for _, ref := range route.Spec.ParentRefs {
			if ref.Kind == nil || *ref.Kind == "Gateway" {
				gateways = append(gateways, string(ref.Name))
			}
		}
		return gateways
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}
	// Indexes TCPRoute objects by the name of the referenced Backend object.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1alpha2.TCPRoute{}, backendTCPRouteIndex, func(obj client.Object) []string {
		route := obj.(*gatewayv1alpha2.TCPRoute)
		var backends []string
		for _, rule := range route.Spec.Rules {
			for _, backend := range rule.BackendRefs {
				if backend.Kind != nil && *backend.Kind == "Backend" {
					backends = append(backends, string(backend.Name))
				}
			}
		}
		return backends
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}
	// Indexes UDPRoute objects by the name of the referenced Gateway object.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1alpha2.UDPRoute{}, gatewayUDPRouteIndex, func(obj client.Object) []string {
		route := obj.(*gatewayv1alpha2.UDPRoute)
		var gateways []string
		for _, ref := range route.Spec.ParentRefs {
			if ref.Kind == nil || *ref.Kind == "Gateway" {
				gateways = append(gateways, string(ref.Name))
			}
		}
		return gateways
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}
	// Indexes UDPRoute objects by the name of the referenced Backend object.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1alpha2.UDPRoute{}, backendUDPRouteIndex, func(obj client.Object) []string {
		route := obj.(*gatewayv1alpha2.UDPRoute)
		var backends []string
		for _, rule := range route.Spec.Rules {
			for _, backend := range rule.BackendRefs {
				if backend.Kind != nil && *backend.Kind == "Backend" {
					backends = append(backends, string(backend.Name))
				}
			}
		}
		return backends
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}
	// Indexes TLSRoute objects by the name of the referenced Gateway object.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1alpha2.TLSRoute{}, gatewayTLSRouteIndex, func(obj client.Object) []string {
		route := obj.(*gatewayv1alpha2.TLSRoute)
		var gateways []string
		for _, ref := range route.Spec.ParentRefs {
			if ref.Kind == nil || *ref.Kind == "Gateway" {
				gateways = append(gateways, string(ref.Name))
			}
		}
		return gateways
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}
	// Indexes TLSRoute objects by the name of the referenced Backend object.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1alpha2.TLSRoute{}, backendTLSRouteIndex, func(obj client.Object) []string {
		route := obj.(*gatewayv1alpha2.TLSRoute)
		var backends []string
		for _, rule := range route.Spec.Rules {
			for _, backend := range rule.BackendRefs {
				if backend.Kind != nil && *backend.Kind == "Backend" {
					backends = append(backends, string(backend.Name))
				}
			}
		}
		return backends
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}
	if r.watchK8s {
		// Indexes HTTPRoute objects by the name of the referenced Service object.
		if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1.HTTPRoute{}, serviceHTTPRouteIndex, func(obj client.Object) []string {
			route := obj.(*gatewayv1.HTTPRoute)
			var services []string
			for _, rule := range route.Spec.Rules {
				for _, backend := range rule.BackendRefs {
					if backend.Kind != nil && *backend.Kind == "Service" {
						services = append(services, string(backend.Name))
					}
				}
			}
			return services
		}); err != nil {
			return fmt.Errorf("failed to setup field indexer: %w", err)
		}
		// Indexes TCPRoute objects by the name of the referenced Service object.
		if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1alpha2.TCPRoute{}, serviceTCPRouteIndex, func(obj client.Object) []string {
			route := obj.(*gatewayv1alpha2.TCPRoute)
			var services []string
			for _, rule := range route.Spec.Rules {
				for _, backend := range rule.BackendRefs {
					if backend.Kind != nil && *backend.Kind == "Service" {
						services = append(services, string(backend.Name))
					}
				}
			}
			return services
		}); err != nil {
			return fmt.Errorf("failed to setup field indexer: %w", err)
		}
		// Indexes UDPRoute objects by the name of the referenced Service object.
		if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1alpha2.UDPRoute{}, serviceUDPRouteIndex, func(obj client.Object) []string {
			route := obj.(*gatewayv1alpha2.UDPRoute)
			var services []string
			for _, rule := range route.Spec.Rules {
				for _, backend := range rule.BackendRefs {
					if backend.Kind != nil && *backend.Kind == "Service" {
						services = append(services, string(backend.Name))
					}
				}
			}
			return services
		}); err != nil {
			return fmt.Errorf("failed to setup field indexer: %w", err)
		}
		// Indexes TLSRoute objects by the name of the referenced Service object.
		if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1alpha2.TLSRoute{}, serviceTLSRouteIndex, func(obj client.Object) []string {
			route := obj.(*gatewayv1alpha2.TLSRoute)
			var services []string
			for _, rule := range route.Spec.Rules {
				for _, backend := range rule.BackendRefs {
					if backend.Kind != nil && *backend.Kind == "Service" {
						services = append(services, string(backend.Name))
					}
				}
			}
			return services
		}); err != nil {
			return fmt.Errorf("failed to setup field indexer: %w", err)
		}
	}
	// Index EdgeFunction objects that are ready.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &extensionsv1alpha2.EdgeFunction{}, edgeFunctionLiveIndex, func(obj client.Object) []string {
		if obj.(*extensionsv1alpha2.EdgeFunction).Status.LiveRevision != "" {
			return []string{"true"}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}

	b := ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.GatewayClass{}).
		Watches(
			&gatewayv1.GatewayClass{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueClass),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Watches(
			&gatewayv1.Gateway{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueClass),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Watches(
			&gatewayv1.HTTPRoute{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueClass),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Watches(
			&gatewayv1alpha2.TCPRoute{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueClass),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Watches(
			&gatewayv1alpha2.UDPRoute{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueClass),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Watches(
			&gatewayv1alpha2.TLSRoute{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueClass),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Watches(
			&corev1alpha2.Backend{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueClass),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Watches(
			&extensionsv1alpha2.EdgeFunction{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueClass),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		)

	if r.watchK8s {
		b = b.
			Watches(
				&corev1.Service{},
				handler.EnqueueRequestsFromMapFunc(r.enqueueClass),
				builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
			).
			Watches(
				&corev1.Secret{},
				handler.EnqueueRequestsFromMapFunc(r.enqueueClass),
				builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
			)
	}

	return b.Complete(r)
}

func (r *GatewayReconciler) enqueueClass(_ context.Context, _ client.Object) []reconcile.Request {
	return []reconcile.Request{{NamespacedName: types.NamespacedName{
		Name: gatewayapirunner.ControllerName,
	}}}
}
