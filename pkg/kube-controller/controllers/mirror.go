package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	apoxygatewayv1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
	apoxygatewayv1alpha2 "github.com/apoxy-dev/apoxy/api/gateway/v1alpha2"
	"github.com/apoxy-dev/apoxy/client/versioned"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

const (
	labelCluster   = "mirror.apoxy.dev/cluster"
	labelNamespace = "mirror.apoxy.dev/namespace"
	labelName      = "mirror.apoxy.dev/name"
)

// MirrorReconciler watches local Gateway API resources and mirrors them to Apoxy.
type MirrorReconciler struct {
	localClient client.Client
	apoxyClient versioned.Interface
	clusterName string
	mirrorMode  configv1alpha1.MirrorMode
}

// NewMirrorReconciler creates a new MirrorReconciler.
func NewMirrorReconciler(
	localClient client.Client,
	apoxyClient versioned.Interface,
	cfg *configv1alpha1.KubeMirrorConfig,
) *MirrorReconciler {
	return &MirrorReconciler{
		localClient: localClient,
		apoxyClient: apoxyClient,
		clusterName: cfg.ClusterName,
		mirrorMode:  cfg.Mirror,
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

// SetupWithManager registers controllers for each Gateway API resource type.
func (r *MirrorReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&gwapiv1.Gateway{}).
		Complete(reconcile.Func(r.reconcileGateway)); err != nil {
		return fmt.Errorf("setting up Gateway controller: %w", err)
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&gwapiv1.HTTPRoute{}).
		Complete(reconcile.Func(r.reconcileHTTPRoute)); err != nil {
		return fmt.Errorf("setting up HTTPRoute controller: %w", err)
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&gwapiv1.GRPCRoute{}).
		Complete(reconcile.Func(r.reconcileGRPCRoute)); err != nil {
		return fmt.Errorf("setting up GRPCRoute controller: %w", err)
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&gwapiv1alpha2.TCPRoute{}).
		Complete(reconcile.Func(r.reconcileTCPRoute)); err != nil {
		return fmt.Errorf("setting up TCPRoute controller: %w", err)
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&gwapiv1alpha2.TLSRoute{}).
		Complete(reconcile.Func(r.reconcileTLSRoute)); err != nil {
		return fmt.Errorf("setting up TLSRoute controller: %w", err)
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&gwapiv1alpha2.UDPRoute{}).
		Complete(reconcile.Func(r.reconcileUDPRoute)); err != nil {
		return fmt.Errorf("setting up UDPRoute controller: %w", err)
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
	return r.syncGateway(ctx, gw)
}

func (r *MirrorReconciler) syncGateway(ctx context.Context, gw *gwapiv1.Gateway) (reconcile.Result, error) {
	apoxyName := r.mirrorName(gw.Namespace, gw.Name)
	apoxy := &apoxygatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:   apoxyName,
			Labels: r.originLabels(gw.Namespace, gw.Name),
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
	return r.syncHTTPRoute(ctx, route)
}

func (r *MirrorReconciler) syncHTTPRoute(ctx context.Context, route *gwapiv1.HTTPRoute) (reconcile.Result, error) {
	apoxyName := r.mirrorName(route.Namespace, route.Name)
	spec := *route.Spec.DeepCopy()
	spec.ParentRefs = r.rewriteV1ParentRefs(route.Namespace, spec.ParentRefs)

	apoxy := &apoxygatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:   apoxyName,
			Labels: r.originLabels(route.Namespace, route.Name),
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
	return r.syncGRPCRoute(ctx, route)
}

func (r *MirrorReconciler) syncGRPCRoute(ctx context.Context, route *gwapiv1.GRPCRoute) (reconcile.Result, error) {
	apoxyName := r.mirrorName(route.Namespace, route.Name)
	spec := *route.Spec.DeepCopy()
	spec.ParentRefs = r.rewriteV1ParentRefs(route.Namespace, spec.ParentRefs)

	apoxy := &apoxygatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:   apoxyName,
			Labels: r.originLabels(route.Namespace, route.Name),
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
	return r.syncTCPRoute(ctx, route)
}

func (r *MirrorReconciler) syncTCPRoute(ctx context.Context, route *gwapiv1alpha2.TCPRoute) (reconcile.Result, error) {
	apoxyName := r.mirrorName(route.Namespace, route.Name)
	spec := *route.Spec.DeepCopy()
	spec.ParentRefs = r.rewriteV1Alpha2ParentRefs(route.Namespace, spec.ParentRefs)

	apoxy := &apoxygatewayv1alpha2.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:   apoxyName,
			Labels: r.originLabels(route.Namespace, route.Name),
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
	return r.syncTLSRoute(ctx, route)
}

func (r *MirrorReconciler) syncTLSRoute(ctx context.Context, route *gwapiv1alpha2.TLSRoute) (reconcile.Result, error) {
	apoxyName := r.mirrorName(route.Namespace, route.Name)
	spec := *route.Spec.DeepCopy()
	spec.ParentRefs = r.rewriteV1Alpha2ParentRefs(route.Namespace, spec.ParentRefs)

	apoxy := &apoxygatewayv1alpha2.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:   apoxyName,
			Labels: r.originLabels(route.Namespace, route.Name),
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
	return r.syncUDPRoute(ctx, route)
}

func (r *MirrorReconciler) syncUDPRoute(ctx context.Context, route *gwapiv1alpha2.UDPRoute) (reconcile.Result, error) {
	apoxyName := r.mirrorName(route.Namespace, route.Name)
	spec := *route.Spec.DeepCopy()
	spec.ParentRefs = r.rewriteV1Alpha2ParentRefs(route.Namespace, spec.ParentRefs)

	apoxy := &apoxygatewayv1alpha2.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:   apoxyName,
			Labels: r.originLabels(route.Namespace, route.Name),
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
