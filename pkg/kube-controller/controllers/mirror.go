package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	coordinationclient "k8s.io/client-go/kubernetes/typed/coordination/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	apoxygatewayv1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
	apoxygatewayv1alpha2 "github.com/apoxy-dev/apoxy/api/gateway/v1alpha2"
	"github.com/apoxy-dev/apoxy/client/versioned"
	"github.com/apoxy-dev/apoxy/pkg/gateway/gatewayapi"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

const (
	labelCluster   = "mirror.apoxy.dev/cluster"
	labelNamespace = "mirror.apoxy.dev/namespace"
	labelName      = "mirror.apoxy.dev/name"

	annotationHeartbeat = "mirror.apoxy.dev/heartbeat"

	heartbeatInterval      = 10 * time.Second
	heartbeatLeaseDuration = 30 * time.Second
)

// MirrorReconciler watches local Gateway API resources and mirrors them to Apoxy.
type MirrorReconciler struct {
	localClient       client.Client
	apoxyClient       versioned.Interface
	coordinationClient coordinationclient.CoordinationV1Interface
	clusterName       string
	mirrorMode        configv1alpha1.MirrorMode
}

// NewMirrorReconciler creates a new MirrorReconciler.
func NewMirrorReconciler(
	localClient client.Client,
	apoxyClient versioned.Interface,
	coordinationClient coordinationclient.CoordinationV1Interface,
	cfg *configv1alpha1.KubeMirrorConfig,
) *MirrorReconciler {
	return &MirrorReconciler{
		localClient:        localClient,
		apoxyClient:        apoxyClient,
		coordinationClient: coordinationClient,
		clusterName:        cfg.ClusterName,
		mirrorMode:         cfg.Mirror,
	}
}

// mirrorName returns a deconflicted name for an Apoxy resource.
// Format: {name}-{first 8 hex chars of SHA-256(clusterName/namespace)}.
func (r *MirrorReconciler) mirrorName(namespace, name string) string {
	h := sha256.Sum256([]byte(r.clusterName + "/" + namespace))
	return fmt.Sprintf("%s-%s", name, hex.EncodeToString(h[:4]))
}

// originLabels returns labels that identify the source of a mirrored resource.
func (r *MirrorReconciler) originLabels(namespace, name string) map[string]string {
	return map[string]string{
		labelCluster:   r.clusterName,
		labelNamespace: namespace,
		labelName:      name,
	}
}

// heartbeatAnnotations returns annotations with the current heartbeat timestamp.
func (r *MirrorReconciler) heartbeatAnnotations() map[string]string {
	return map[string]string{
		annotationHeartbeat: time.Now().UTC().Format(time.RFC3339),
	}
}

// matchesControllerName returns true if the given controller name is an Apoxy controller.
func (r *MirrorReconciler) matchesControllerName(name gwapiv1.GatewayController) bool {
	return string(name) == gatewayapi.StandaloneControllerName
}

// isApoxyGateway checks whether the Gateway's GatewayClass has an Apoxy controller name.
func (r *MirrorReconciler) isApoxyGateway(ctx context.Context, gw *gwapiv1.Gateway) (bool, error) {
	gwc := &gwapiv1.GatewayClass{}
	if err := r.localClient.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, gwc); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return r.matchesControllerName(gwc.Spec.ControllerName), nil
}

// isRouteForApoxyGateway checks whether any v1 ParentReference points to a Gateway
// whose GatewayClass has an Apoxy controller name.
func (r *MirrorReconciler) isRouteForApoxyGateway(ctx context.Context, namespace string, refs []gwapiv1.ParentReference) (bool, error) {
	for _, ref := range refs {
		if ref.Group != nil && string(*ref.Group) != gwapiv1.GroupName {
			continue
		}
		if ref.Kind != nil && string(*ref.Kind) != "Gateway" {
			continue
		}
		ns := namespace
		if ref.Namespace != nil {
			ns = string(*ref.Namespace)
		}
		gw := &gwapiv1.Gateway{}
		if err := r.localClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: string(ref.Name)}, gw); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return false, err
		}
		if match, err := r.isApoxyGateway(ctx, gw); err != nil {
			return false, err
		} else if match {
			return true, nil
		}
	}
	return false, nil
}

// isRouteForApoxyGatewayV1Alpha2 is the v1alpha2 variant of isRouteForApoxyGateway.
func (r *MirrorReconciler) isRouteForApoxyGatewayV1Alpha2(ctx context.Context, namespace string, refs []gwapiv1alpha2.ParentReference) (bool, error) {
	for _, ref := range refs {
		if ref.Group != nil && string(*ref.Group) != gwapiv1.GroupName {
			continue
		}
		if ref.Kind != nil && string(*ref.Kind) != "Gateway" {
			continue
		}
		ns := namespace
		if ref.Namespace != nil {
			ns = string(*ref.Namespace)
		}
		gw := &gwapiv1.Gateway{}
		if err := r.localClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: string(ref.Name)}, gw); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return false, err
		}
		if match, err := r.isApoxyGateway(ctx, gw); err != nil {
			return false, err
		} else if match {
			return true, nil
		}
	}
	return false, nil
}

func resourceIsAvailable(scheme *runtime.Scheme, mapper meta.RESTMapper, obj client.Object) (bool, string, error) {
	gvk, err := apiutil.GVKForObject(obj, scheme)
	if err != nil {
		return false, "", err
	}
	if _, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version); err != nil {
		if meta.IsNoMatchError(err) {
			return false, gvk.String(), nil
		}
		return false, gvk.String(), err
	}
	return true, gvk.String(), nil
}

func setupControllerIfAvailable(mgr ctrl.Manager, name string, obj client.Object, fn reconcile.Func) error {
	ok, gvk, err := resourceIsAvailable(mgr.GetScheme(), mgr.GetRESTMapper(), obj)
	if err != nil {
		return fmt.Errorf("checking %s availability: %w", name, err)
	}
	if !ok {
		log.Infof("Mirror: skipping %s controller; resource %s is not installed", name, gvk)
		return nil
	}
	if err := ctrl.NewControllerManagedBy(mgr).
		For(obj).
		Complete(fn); err != nil {
		return fmt.Errorf("setting up %s controller: %w", name, err)
	}
	return nil
}

// SetupWithManager registers controllers for each Gateway API resource type.
func (r *MirrorReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := setupControllerIfAvailable(mgr, "Gateway", &gwapiv1.Gateway{}, reconcile.Func(r.reconcileGateway)); err != nil {
		return err
	}

	if err := setupControllerIfAvailable(mgr, "HTTPRoute", &gwapiv1.HTTPRoute{}, reconcile.Func(r.reconcileHTTPRoute)); err != nil {
		return err
	}

	if err := setupControllerIfAvailable(mgr, "GRPCRoute", &gwapiv1.GRPCRoute{}, reconcile.Func(r.reconcileGRPCRoute)); err != nil {
		return err
	}

	if err := setupControllerIfAvailable(mgr, "TCPRoute", &gwapiv1alpha2.TCPRoute{}, reconcile.Func(r.reconcileTCPRoute)); err != nil {
		return err
	}

	if err := setupControllerIfAvailable(mgr, "TLSRoute", &gwapiv1alpha2.TLSRoute{}, reconcile.Func(r.reconcileTLSRoute)); err != nil {
		return err
	}

	if err := setupControllerIfAvailable(mgr, "UDPRoute", &gwapiv1alpha2.UDPRoute{}, reconcile.Func(r.reconcileUDPRoute)); err != nil {
		return err
	}

	return nil
}

// rewriteV1ParentRefs rewrites upstream gwapiv1 ParentRefs to use deconflicted names.
func (r *MirrorReconciler) rewriteV1ParentRefs(namespace string, refs []gwapiv1.ParentReference) []gwapiv1.ParentReference {
	out := make([]gwapiv1.ParentReference, len(refs))
	for i, ref := range refs {
		out[i] = ref
		refNS := namespace
		if ref.Namespace != nil {
			refNS = string(*ref.Namespace)
		}
		mirroredName := gwapiv1.ObjectName(r.mirrorName(refNS, string(ref.Name)))
		out[i].Name = mirroredName
		out[i].Namespace = nil
	}
	return out
}

// rewriteV1Alpha2ParentRefs rewrites upstream gwapiv1alpha2 ParentRefs to use deconflicted names.
func (r *MirrorReconciler) rewriteV1Alpha2ParentRefs(namespace string, refs []gwapiv1alpha2.ParentReference) []gwapiv1alpha2.ParentReference {
	out := make([]gwapiv1alpha2.ParentReference, len(refs))
	for i, ref := range refs {
		out[i] = ref
		refNS := namespace
		if ref.Namespace != nil {
			refNS = string(*ref.Namespace)
		}
		mirroredName := gwapiv1alpha2.ObjectName(r.mirrorName(refNS, string(ref.Name)))
		out[i].Name = mirroredName
		out[i].Namespace = nil
	}
	return out
}

// --- Gateway ---

func (r *MirrorReconciler) reconcileGateway(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	gw := &gwapiv1.Gateway{}
	if err := r.localClient.Get(ctx, req.NamespacedName, gw); err != nil {
		if apierrors.IsNotFound(err) {
			return r.deleteApoxyGateway(ctx, r.mirrorName(req.Namespace, req.Name))
		}
		return reconcile.Result{}, err
	}
	if match, err := r.isApoxyGateway(ctx, gw); err != nil {
		return reconcile.Result{}, err
	} else if !match {
		return reconcile.Result{}, nil
	}
	return r.syncGateway(ctx, gw)
}

func (r *MirrorReconciler) syncGateway(ctx context.Context, gw *gwapiv1.Gateway) (reconcile.Result, error) {
	apoxyName := r.mirrorName(gw.Namespace, gw.Name)
	apoxy := &apoxygatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:        apoxyName,
			Labels:      r.originLabels(gw.Namespace, gw.Name),
			Annotations: r.heartbeatAnnotations(),
		},
		Spec: *gw.Spec.DeepCopy(),
	}

	existing, err := r.apoxyClient.GatewayV1().Gateways().Get(ctx, apoxyName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		log.Infof("Mirror: creating Gateway %s (from %s/%s)", apoxyName, gw.Namespace, gw.Name)
		if _, err := r.apoxyClient.GatewayV1().Gateways().Create(ctx, apoxy, metav1.CreateOptions{}); err != nil {
			return reconcile.Result{}, fmt.Errorf("creating Apoxy Gateway %s: %w", apoxyName, err)
		}
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("getting Apoxy Gateway %s: %w", apoxyName, err)
	}

	apoxy.ResourceVersion = existing.ResourceVersion
	log.Infof("Mirror: updating Gateway %s (from %s/%s)", apoxyName, gw.Namespace, gw.Name)
	if _, err := r.apoxyClient.GatewayV1().Gateways().Update(ctx, apoxy, metav1.UpdateOptions{}); err != nil {
		return reconcile.Result{}, fmt.Errorf("updating Apoxy Gateway %s: %w", apoxyName, err)
	}
	return reconcile.Result{}, nil
}

func (r *MirrorReconciler) deleteApoxyGateway(ctx context.Context, name string) (reconcile.Result, error) {
	log.Infof("Mirror: deleting Gateway %s", name)
	if err := r.apoxyClient.GatewayV1().Gateways().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("deleting Apoxy Gateway %s: %w", name, err)
	}
	return reconcile.Result{}, nil
}

// --- HTTPRoute ---

func (r *MirrorReconciler) reconcileHTTPRoute(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	route := &gwapiv1.HTTPRoute{}
	if err := r.localClient.Get(ctx, req.NamespacedName, route); err != nil {
		if apierrors.IsNotFound(err) {
			return r.deleteApoxyHTTPRoute(ctx, r.mirrorName(req.Namespace, req.Name))
		}
		return reconcile.Result{}, err
	}
	if match, err := r.isRouteForApoxyGateway(ctx, route.Namespace, route.Spec.ParentRefs); err != nil {
		return reconcile.Result{}, err
	} else if !match {
		return reconcile.Result{}, nil
	}
	return r.syncHTTPRoute(ctx, route)
}

func (r *MirrorReconciler) syncHTTPRoute(ctx context.Context, route *gwapiv1.HTTPRoute) (reconcile.Result, error) {
	apoxyName := r.mirrorName(route.Namespace, route.Name)
	spec := *route.Spec.DeepCopy()
	spec.ParentRefs = r.rewriteV1ParentRefs(route.Namespace, spec.ParentRefs)

	apoxy := &apoxygatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:        apoxyName,
			Labels:      r.originLabels(route.Namespace, route.Name),
			Annotations: r.heartbeatAnnotations(),
		},
		Spec: spec,
	}

	existing, err := r.apoxyClient.GatewayV1().HTTPRoutes().Get(ctx, apoxyName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		log.Infof("Mirror: creating HTTPRoute %s (from %s/%s)", apoxyName, route.Namespace, route.Name)
		if _, err := r.apoxyClient.GatewayV1().HTTPRoutes().Create(ctx, apoxy, metav1.CreateOptions{}); err != nil {
			return reconcile.Result{}, fmt.Errorf("creating Apoxy HTTPRoute %s: %w", apoxyName, err)
		}
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("getting Apoxy HTTPRoute %s: %w", apoxyName, err)
	}

	apoxy.ResourceVersion = existing.ResourceVersion
	log.Infof("Mirror: updating HTTPRoute %s (from %s/%s)", apoxyName, route.Namespace, route.Name)
	if _, err := r.apoxyClient.GatewayV1().HTTPRoutes().Update(ctx, apoxy, metav1.UpdateOptions{}); err != nil {
		return reconcile.Result{}, fmt.Errorf("updating Apoxy HTTPRoute %s: %w", apoxyName, err)
	}
	return reconcile.Result{}, nil
}

func (r *MirrorReconciler) deleteApoxyHTTPRoute(ctx context.Context, name string) (reconcile.Result, error) {
	log.Infof("Mirror: deleting HTTPRoute %s", name)
	if err := r.apoxyClient.GatewayV1().HTTPRoutes().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("deleting Apoxy HTTPRoute %s: %w", name, err)
	}
	return reconcile.Result{}, nil
}

// --- GRPCRoute ---

func (r *MirrorReconciler) reconcileGRPCRoute(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	route := &gwapiv1.GRPCRoute{}
	if err := r.localClient.Get(ctx, req.NamespacedName, route); err != nil {
		if apierrors.IsNotFound(err) {
			return r.deleteApoxyGRPCRoute(ctx, r.mirrorName(req.Namespace, req.Name))
		}
		return reconcile.Result{}, err
	}
	if match, err := r.isRouteForApoxyGateway(ctx, route.Namespace, route.Spec.ParentRefs); err != nil {
		return reconcile.Result{}, err
	} else if !match {
		return reconcile.Result{}, nil
	}
	return r.syncGRPCRoute(ctx, route)
}

func (r *MirrorReconciler) syncGRPCRoute(ctx context.Context, route *gwapiv1.GRPCRoute) (reconcile.Result, error) {
	apoxyName := r.mirrorName(route.Namespace, route.Name)
	spec := *route.Spec.DeepCopy()
	spec.ParentRefs = r.rewriteV1ParentRefs(route.Namespace, spec.ParentRefs)

	apoxy := &apoxygatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:        apoxyName,
			Labels:      r.originLabels(route.Namespace, route.Name),
			Annotations: r.heartbeatAnnotations(),
		},
		Spec: spec,
	}

	existing, err := r.apoxyClient.GatewayV1().GRPCRoutes().Get(ctx, apoxyName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		log.Infof("Mirror: creating GRPCRoute %s (from %s/%s)", apoxyName, route.Namespace, route.Name)
		if _, err := r.apoxyClient.GatewayV1().GRPCRoutes().Create(ctx, apoxy, metav1.CreateOptions{}); err != nil {
			return reconcile.Result{}, fmt.Errorf("creating Apoxy GRPCRoute %s: %w", apoxyName, err)
		}
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("getting Apoxy GRPCRoute %s: %w", apoxyName, err)
	}

	apoxy.ResourceVersion = existing.ResourceVersion
	log.Infof("Mirror: updating GRPCRoute %s (from %s/%s)", apoxyName, route.Namespace, route.Name)
	if _, err := r.apoxyClient.GatewayV1().GRPCRoutes().Update(ctx, apoxy, metav1.UpdateOptions{}); err != nil {
		return reconcile.Result{}, fmt.Errorf("updating Apoxy GRPCRoute %s: %w", apoxyName, err)
	}
	return reconcile.Result{}, nil
}

func (r *MirrorReconciler) deleteApoxyGRPCRoute(ctx context.Context, name string) (reconcile.Result, error) {
	log.Infof("Mirror: deleting GRPCRoute %s", name)
	if err := r.apoxyClient.GatewayV1().GRPCRoutes().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("deleting Apoxy GRPCRoute %s: %w", name, err)
	}
	return reconcile.Result{}, nil
}

// --- TCPRoute ---

func (r *MirrorReconciler) reconcileTCPRoute(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	route := &gwapiv1alpha2.TCPRoute{}
	if err := r.localClient.Get(ctx, req.NamespacedName, route); err != nil {
		if apierrors.IsNotFound(err) {
			return r.deleteApoxyTCPRoute(ctx, r.mirrorName(req.Namespace, req.Name))
		}
		return reconcile.Result{}, err
	}
	if match, err := r.isRouteForApoxyGatewayV1Alpha2(ctx, route.Namespace, route.Spec.ParentRefs); err != nil {
		return reconcile.Result{}, err
	} else if !match {
		return reconcile.Result{}, nil
	}
	return r.syncTCPRoute(ctx, route)
}

func (r *MirrorReconciler) syncTCPRoute(ctx context.Context, route *gwapiv1alpha2.TCPRoute) (reconcile.Result, error) {
	apoxyName := r.mirrorName(route.Namespace, route.Name)
	spec := *route.Spec.DeepCopy()
	spec.ParentRefs = r.rewriteV1Alpha2ParentRefs(route.Namespace, spec.ParentRefs)

	apoxy := &apoxygatewayv1alpha2.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:        apoxyName,
			Labels:      r.originLabels(route.Namespace, route.Name),
			Annotations: r.heartbeatAnnotations(),
		},
		Spec: spec,
	}

	existing, err := r.apoxyClient.GatewayV1alpha2().TCPRoutes().Get(ctx, apoxyName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		log.Infof("Mirror: creating TCPRoute %s (from %s/%s)", apoxyName, route.Namespace, route.Name)
		if _, err := r.apoxyClient.GatewayV1alpha2().TCPRoutes().Create(ctx, apoxy, metav1.CreateOptions{}); err != nil {
			return reconcile.Result{}, fmt.Errorf("creating Apoxy TCPRoute %s: %w", apoxyName, err)
		}
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("getting Apoxy TCPRoute %s: %w", apoxyName, err)
	}

	apoxy.ResourceVersion = existing.ResourceVersion
	log.Infof("Mirror: updating TCPRoute %s (from %s/%s)", apoxyName, route.Namespace, route.Name)
	if _, err := r.apoxyClient.GatewayV1alpha2().TCPRoutes().Update(ctx, apoxy, metav1.UpdateOptions{}); err != nil {
		return reconcile.Result{}, fmt.Errorf("updating Apoxy TCPRoute %s: %w", apoxyName, err)
	}
	return reconcile.Result{}, nil
}

func (r *MirrorReconciler) deleteApoxyTCPRoute(ctx context.Context, name string) (reconcile.Result, error) {
	log.Infof("Mirror: deleting TCPRoute %s", name)
	if err := r.apoxyClient.GatewayV1alpha2().TCPRoutes().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("deleting Apoxy TCPRoute %s: %w", name, err)
	}
	return reconcile.Result{}, nil
}

// --- TLSRoute ---

func (r *MirrorReconciler) reconcileTLSRoute(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	route := &gwapiv1alpha2.TLSRoute{}
	if err := r.localClient.Get(ctx, req.NamespacedName, route); err != nil {
		if apierrors.IsNotFound(err) {
			return r.deleteApoxyTLSRoute(ctx, r.mirrorName(req.Namespace, req.Name))
		}
		return reconcile.Result{}, err
	}
	if match, err := r.isRouteForApoxyGatewayV1Alpha2(ctx, route.Namespace, route.Spec.ParentRefs); err != nil {
		return reconcile.Result{}, err
	} else if !match {
		return reconcile.Result{}, nil
	}
	return r.syncTLSRoute(ctx, route)
}

func (r *MirrorReconciler) syncTLSRoute(ctx context.Context, route *gwapiv1alpha2.TLSRoute) (reconcile.Result, error) {
	apoxyName := r.mirrorName(route.Namespace, route.Name)
	spec := *route.Spec.DeepCopy()
	spec.ParentRefs = r.rewriteV1Alpha2ParentRefs(route.Namespace, spec.ParentRefs)

	apoxy := &apoxygatewayv1alpha2.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:        apoxyName,
			Labels:      r.originLabels(route.Namespace, route.Name),
			Annotations: r.heartbeatAnnotations(),
		},
		Spec: spec,
	}

	existing, err := r.apoxyClient.GatewayV1alpha2().TLSRoutes().Get(ctx, apoxyName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		log.Infof("Mirror: creating TLSRoute %s (from %s/%s)", apoxyName, route.Namespace, route.Name)
		if _, err := r.apoxyClient.GatewayV1alpha2().TLSRoutes().Create(ctx, apoxy, metav1.CreateOptions{}); err != nil {
			return reconcile.Result{}, fmt.Errorf("creating Apoxy TLSRoute %s: %w", apoxyName, err)
		}
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("getting Apoxy TLSRoute %s: %w", apoxyName, err)
	}

	apoxy.ResourceVersion = existing.ResourceVersion
	log.Infof("Mirror: updating TLSRoute %s (from %s/%s)", apoxyName, route.Namespace, route.Name)
	if _, err := r.apoxyClient.GatewayV1alpha2().TLSRoutes().Update(ctx, apoxy, metav1.UpdateOptions{}); err != nil {
		return reconcile.Result{}, fmt.Errorf("updating Apoxy TLSRoute %s: %w", apoxyName, err)
	}
	return reconcile.Result{}, nil
}

func (r *MirrorReconciler) deleteApoxyTLSRoute(ctx context.Context, name string) (reconcile.Result, error) {
	log.Infof("Mirror: deleting TLSRoute %s", name)
	if err := r.apoxyClient.GatewayV1alpha2().TLSRoutes().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("deleting Apoxy TLSRoute %s: %w", name, err)
	}
	return reconcile.Result{}, nil
}

// --- UDPRoute ---

func (r *MirrorReconciler) reconcileUDPRoute(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	route := &gwapiv1alpha2.UDPRoute{}
	if err := r.localClient.Get(ctx, req.NamespacedName, route); err != nil {
		if apierrors.IsNotFound(err) {
			return r.deleteApoxyUDPRoute(ctx, r.mirrorName(req.Namespace, req.Name))
		}
		return reconcile.Result{}, err
	}
	if match, err := r.isRouteForApoxyGatewayV1Alpha2(ctx, route.Namespace, route.Spec.ParentRefs); err != nil {
		return reconcile.Result{}, err
	} else if !match {
		return reconcile.Result{}, nil
	}
	return r.syncUDPRoute(ctx, route)
}

func (r *MirrorReconciler) syncUDPRoute(ctx context.Context, route *gwapiv1alpha2.UDPRoute) (reconcile.Result, error) {
	apoxyName := r.mirrorName(route.Namespace, route.Name)
	spec := *route.Spec.DeepCopy()
	spec.ParentRefs = r.rewriteV1Alpha2ParentRefs(route.Namespace, spec.ParentRefs)

	apoxy := &apoxygatewayv1alpha2.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:        apoxyName,
			Labels:      r.originLabels(route.Namespace, route.Name),
			Annotations: r.heartbeatAnnotations(),
		},
		Spec: spec,
	}

	existing, err := r.apoxyClient.GatewayV1alpha2().UDPRoutes().Get(ctx, apoxyName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		log.Infof("Mirror: creating UDPRoute %s (from %s/%s)", apoxyName, route.Namespace, route.Name)
		if _, err := r.apoxyClient.GatewayV1alpha2().UDPRoutes().Create(ctx, apoxy, metav1.CreateOptions{}); err != nil {
			return reconcile.Result{}, fmt.Errorf("creating Apoxy UDPRoute %s: %w", apoxyName, err)
		}
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("getting Apoxy UDPRoute %s: %w", apoxyName, err)
	}

	apoxy.ResourceVersion = existing.ResourceVersion
	log.Infof("Mirror: updating UDPRoute %s (from %s/%s)", apoxyName, route.Namespace, route.Name)
	if _, err := r.apoxyClient.GatewayV1alpha2().UDPRoutes().Update(ctx, apoxy, metav1.UpdateOptions{}); err != nil {
		return reconcile.Result{}, fmt.Errorf("updating Apoxy UDPRoute %s: %w", apoxyName, err)
	}
	return reconcile.Result{}, nil
}

func (r *MirrorReconciler) deleteApoxyUDPRoute(ctx context.Context, name string) (reconcile.Result, error) {
	log.Infof("Mirror: deleting UDPRoute %s", name)
	if err := r.apoxyClient.GatewayV1alpha2().UDPRoutes().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("deleting Apoxy UDPRoute %s: %w", name, err)
	}
	return reconcile.Result{}, nil
}

// RunHeartbeat periodically creates or renews a coordination Lease to signal
// that this mirror controller is alive. The GC controller on the cloud side
// uses lease expiry to clean up orphaned mirrored objects.
func (r *MirrorReconciler) RunHeartbeat(ctx context.Context, namespace string) error {
	leaseName := "mirror-" + r.clusterName
	durationSecs := int32(heartbeatLeaseDuration / time.Second)

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	// Renew immediately on start, then every tick.
	for {
		if err := r.renewLease(ctx, namespace, leaseName, durationSecs); err != nil {
			log.Errorf("Mirror heartbeat: failed to renew lease %s: %v", leaseName, err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (r *MirrorReconciler) renewLease(ctx context.Context, namespace, leaseName string, durationSecs int32) error {
	now := metav1.NewMicroTime(time.Now())
	leases := r.coordinationClient.Leases(namespace)

	existing, err := leases.Get(ctx, leaseName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		lease := &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{
				Name:      leaseName,
				Namespace: namespace,
			},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       ptr.To(r.clusterName),
				LeaseDurationSeconds: ptr.To(durationSecs),
				AcquireTime:          &now,
				RenewTime:            &now,
			},
		}
		if _, err := leases.Create(ctx, lease, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("creating lease: %w", err)
		}
		log.Infof("Mirror heartbeat: created lease %s", leaseName)
		return nil
	}
	if err != nil {
		return fmt.Errorf("getting lease: %w", err)
	}

	existing.Spec.RenewTime = &now
	existing.Spec.HolderIdentity = ptr.To(r.clusterName)
	existing.Spec.LeaseDurationSeconds = ptr.To(durationSecs)
	if _, err := leases.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("updating lease: %w", err)
	}
	return nil
}
