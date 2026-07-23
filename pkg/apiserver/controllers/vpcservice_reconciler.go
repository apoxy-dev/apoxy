package controllers

import (
	"context"
	"sort"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
)

var _ reconcile.Reconciler = &VPCServiceReconciler{}

// VPCServiceReconciler maintains a VPCService's endpoints view: the live member
// Tunnels selected by the service's label selector, scoped to its network. It
// is the k8s Endpoints controller analog. Tunnels are created complete and
// deleted on disconnect (never patched), so every Tunnel watch event is a real
// membership transition and no heartbeat-filtering predicate is needed (§2.4).
type VPCServiceReconciler struct {
	client.Client
}

// NewVPCServiceReconciler creates a VPCService endpoints reconciler.
func NewVPCServiceReconciler(c client.Client) *VPCServiceReconciler {
	return &VPCServiceReconciler{Client: c}
}

// Reconcile recomputes a VPCService's endpoints from its selected Tunnels.
func (r *VPCServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := controllerlog.FromContext(ctx, "service", req.Name)

	var svc vpcv1alpha1.VPCService
	if err := r.Get(ctx, req.NamespacedName, &svc); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	sel, err := metav1.LabelSelectorAsSelector(svc.Spec.Selector)
	if err != nil {
		log.Error(err, "Invalid VPCService selector")
		return reconcile.Result{}, nil // a bad selector is not retryable
	}

	// Scope membership to the service's network server-side: relays stamp
	// LabelNetwork on every Tunnel, and a selector could otherwise span networks.
	var tunnels vpcv1alpha1.TunnelList
	if err := r.List(ctx, &tunnels,
		client.MatchingLabelsSelector{Selector: sel},
		client.MatchingLabels{vpcv1alpha1.LabelNetwork: svc.Spec.NetworkRef.Name},
	); err != nil {
		return reconcile.Result{}, err
	}

	endpoints := make([]vpcv1alpha1.VPCServiceEndpoint, 0, len(tunnels.Items))
	for i := range tunnels.Items {
		t := &tunnels.Items[i]
		endpoints = append(endpoints, vpcv1alpha1.VPCServiceEndpoint{
			TunnelRef: vpcv1alpha1.TunnelRef{Name: t.Name},
			Addresses: t.Status.Addresses,
		})
	}
	// Deterministic order so no-op reconciles don't churn the status.
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].TunnelRef.Name < endpoints[j].TunnelRef.Name
	})

	changed := false
	if !apiequality.Semantic.DeepEqual(svc.Status.Endpoints, endpoints) {
		svc.Status.Endpoints = endpoints
		changed = true
	}
	if meta.SetStatusCondition(&svc.Status.Conditions, metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionTrue,
		Reason:  "EndpointsComputed",
		Message: "Endpoints reflect current members",
	}) {
		changed = true
	}
	if changed {
		if err := r.Status().Update(ctx, &svc); err != nil {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

// SetupWithManager wires the reconciler to VPCServices and to the Tunnels that
// feed their membership.
func (r *VPCServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("vpcservice").
		For(&vpcv1alpha1.VPCService{}).
		Watches(&vpcv1alpha1.Tunnel{}, handler.EnqueueRequestsFromMapFunc(r.tunnelToServices)).
		Complete(r)
}

// tunnelToServices maps a Tunnel (created or deleted) to the VPCServices whose
// selector, scoped to the Tunnel's network, selects it.
func (r *VPCServiceReconciler) tunnelToServices(ctx context.Context, obj client.Object) []reconcile.Request {
	t, ok := obj.(*vpcv1alpha1.Tunnel)
	if !ok {
		return nil
	}
	network := t.Labels[vpcv1alpha1.LabelNetwork]

	var services vpcv1alpha1.VPCServiceList
	if err := r.List(ctx, &services); err != nil {
		return nil
	}

	var reqs []reconcile.Request
	for i := range services.Items {
		svc := &services.Items[i]
		if svc.Spec.NetworkRef.Name != network {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(svc.Spec.Selector)
		if err != nil {
			continue
		}
		if sel.Matches(labels.Set(t.Labels)) {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKey{Name: svc.Name}})
		}
	}
	return reqs
}
