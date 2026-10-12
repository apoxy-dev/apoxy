package controllers

import (
	"context"
	"fmt"
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

// VPCServiceReconciler maintains a VPCService's endpoints view: the usable
// member Tunnels selected by the service's label selector, scoped to its
// network. It is the k8s Endpoints controller analog.
//
// Tunnels are written by their owning relay at connect and deleted at
// disconnect; the only steady-state write is the status update that follows
// the create with the allocated overlay addresses. Every Tunnel watch event is
// therefore either a membership transition or that one address write, and both
// have to be acted on — a member is not an endpoint until it has an address
// (§2.4) — so no heartbeat-filtering predicate is needed.
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

	// A service pointing at a network that isn't there has no membership scope.
	// Admission rejects this at create, so the reachable case is a network
	// deleted out from under a live service, which must show up in the
	// conditions rather than being passed off as healthy.
	//
	// The endpoints view is deliberately left as it was. Deleting the network
	// object does not disconnect its Tunnels or tear down the overlay, so the
	// recorded members are still carrying traffic; clearing them here would
	// pull a working service's DNS records (backplane zone and worker name
	// plane both publish straight off this list) out from under live requests
	// in response to a control-plane bookkeeping change. Real membership loss
	// still arrives the normal way, as Tunnel deletes.
	var network vpcv1alpha1.VPCNetwork
	if err := r.Get(ctx, client.ObjectKey{Name: svc.Spec.NetworkRef.Name}, &network); err != nil {
		if !apierrors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
		log.Info("VPCService references a network that does not exist", "network", svc.Spec.NetworkRef.Name)
		return r.writeStatus(ctx, &svc, svc.Status.Endpoints,
			vpcv1alpha1.VPCServiceReasonNetworkNotFound,
			fmt.Sprintf("VPCNetwork %q does not exist", svc.Spec.NetworkRef.Name))
	}

	// Membership is only computed from a selector that means what it says.
	// MembershipSelector rejects the shapes LabelSelectorAsSelector would turn
	// into a surprise — nil into "nothing", empty into "every Tunnel in the
	// network" — which admission also rejects, but ratcheted update validation
	// keeps objects stored before that rule writable, so they still arrive
	// here. Endpoints are cleared: whatever the previous list held was derived
	// from a rule that cannot be trusted to have meant it.
	sel, err := svc.Spec.MembershipSelector()
	if err != nil {
		log.Error(err, "Unusable VPCService selector")
		// Not retryable: report it and wait for a spec edit.
		return r.writeStatus(ctx, &svc, nil,
			vpcv1alpha1.VPCServiceReasonInvalidSelector,
			fmt.Sprintf("spec.selector cannot be used to select members: %v", err))
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
	pending := 0
	for i := range tunnels.Items {
		t := &tunnels.Items[i]
		ep := vpcv1alpha1.VPCServiceEndpoint{
			TunnelRef: vpcv1alpha1.TunnelRef{Name: t.Name},
			Addresses: t.Status.Addresses,
		}
		// Selection alone does not make a Tunnel an endpoint. Two members are
		// skipped: one with no usable overlay address (the relay creates the
		// object and writes addresses in a second call, and a hand-authored
		// Tunnel never gets them at all), and one with no terminating relay,
		// which is not a live connection. Relay *liveness* deliberately isn't
		// checked here — a relay object flapping would pull every one of its
		// tunnels out of DNS at once; the lease watcher deletes those Tunnels
		// instead, which is a real membership transition.
		if !ep.HasUsableAddress() || t.Spec.RelayRef.Name == "" {
			pending++
			continue
		}
		endpoints = append(endpoints, ep)
	}
	// Deterministic order so no-op reconciles don't churn the status.
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].TunnelRef.Name < endpoints[j].TunnelRef.Name
	})

	if len(endpoints) == 0 {
		msg := "No Tunnel matches the selector in this network"
		if pending > 0 {
			msg = fmt.Sprintf("%d selected member(s) have no overlay address or no terminating relay yet", pending)
		}
		return r.writeStatus(ctx, &svc, endpoints, vpcv1alpha1.VPCServiceReasonNoEndpoints, msg)
	}
	return r.writeStatus(ctx, &svc, endpoints, vpcv1alpha1.VPCServiceReasonEndpointsAvailable,
		fmt.Sprintf("%d endpoint(s) available", len(endpoints)))
}

// writeStatus records the recomputed endpoints view and the pair of conditions
// derived from it, updating the object only when something actually changed.
//
// Reconciled and Ready are separate on purpose: computing an empty endpoint
// list is the controller succeeding, not the service working. Ready
// is the one that answers "can traffic to this name land anywhere", so it is
// True only for readyReason == EndpointsAvailable; every other reason is a
// service that resolves to nothing.
func (r *VPCServiceReconciler) writeStatus(
	ctx context.Context,
	svc *vpcv1alpha1.VPCService,
	endpoints []vpcv1alpha1.VPCServiceEndpoint,
	readyReason, readyMessage string,
) (reconcile.Result, error) {
	changed := false
	if !apiequality.Semantic.DeepEqual(svc.Status.Endpoints, endpoints) {
		svc.Status.Endpoints = endpoints
		changed = true
	}

	// Reconciled is False only when the spec itself prevents membership from
	// being computed; an empty-but-correct result is still a completed pass.
	reconciled := metav1.Condition{
		Type:               vpcv1alpha1.VPCServiceConditionReconciled,
		Status:             metav1.ConditionTrue,
		Reason:             vpcv1alpha1.VPCServiceReasonEndpointsComputed,
		Message:            "Endpoints reflect current members",
		ObservedGeneration: svc.Generation,
	}
	switch readyReason {
	case vpcv1alpha1.VPCServiceReasonNetworkNotFound, vpcv1alpha1.VPCServiceReasonInvalidSelector:
		reconciled.Status = metav1.ConditionFalse
		reconciled.Reason = readyReason
		reconciled.Message = readyMessage
	}
	if meta.SetStatusCondition(&svc.Status.Conditions, reconciled) {
		changed = true
	}

	readyStatus := metav1.ConditionFalse
	if readyReason == vpcv1alpha1.VPCServiceReasonEndpointsAvailable {
		readyStatus = metav1.ConditionTrue
	}
	if meta.SetStatusCondition(&svc.Status.Conditions, metav1.Condition{
		Type:               vpcv1alpha1.VPCServiceConditionReady,
		Status:             readyStatus,
		Reason:             readyReason,
		Message:            readyMessage,
		ObservedGeneration: svc.Generation,
	}) {
		changed = true
	}

	if changed {
		if err := r.Status().Update(ctx, svc); err != nil {
			return reconcile.Result{}, err
		}
	}
	return reconcile.Result{}, nil
}

// IndexServiceNetwork is the cache index over spec.networkRef.name. Both watch
// mappings fan in through it, and every Tunnel event carries one — on a busy
// network that is one indexed lookup per connect/disconnect instead of a full
// scan of the project's VPCServices.
const IndexServiceNetwork = "spec.networkRef.name"

// SetupWithManager wires the reconciler to VPCServices, to the Tunnels that
// feed their membership, and to the VPCNetworks that scope them.
func (r *VPCServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(), &vpcv1alpha1.VPCService{}, IndexServiceNetwork,
		func(obj client.Object) []string {
			svc, ok := obj.(*vpcv1alpha1.VPCService)
			if !ok || svc.Spec.NetworkRef.Name == "" {
				return nil
			}
			return []string{svc.Spec.NetworkRef.Name}
		},
	); err != nil {
		return fmt.Errorf("indexing VPCService by network: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named("vpcservice").
		For(&vpcv1alpha1.VPCService{}).
		Watches(&vpcv1alpha1.Tunnel{}, handler.EnqueueRequestsFromMapFunc(r.tunnelToServices)).
		Watches(&vpcv1alpha1.VPCNetwork{}, handler.EnqueueRequestsFromMapFunc(r.networkToServices)).
		Complete(r)
}

// networkToServices maps a VPCNetwork event to the VPCServices scoped to it.
// Deletion is the one that matters: without it a service outlives its network
// still reporting Ready off a membership list nothing will ever update again.
func (r *VPCServiceReconciler) networkToServices(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.servicesInNetwork(ctx, obj.GetName(), nil)
}

// tunnelToServices maps a Tunnel (created or deleted) to the VPCServices whose
// selector, scoped to the Tunnel's network, selects it.
func (r *VPCServiceReconciler) tunnelToServices(ctx context.Context, obj client.Object) []reconcile.Request {
	t, ok := obj.(*vpcv1alpha1.Tunnel)
	if !ok {
		return nil
	}
	return r.servicesInNetwork(ctx, t.Labels[vpcv1alpha1.LabelNetwork], func(svc *vpcv1alpha1.VPCService) bool {
		sel, err := svc.Spec.MembershipSelector()
		if err != nil {
			// An unusable selector selects nothing; the service's own
			// reconcile is what reports it.
			return false
		}
		return sel.Matches(labels.Set(t.Labels))
	})
}

// servicesInNetwork returns reconcile requests for the VPCServices scoped to
// network, optionally narrowed by match. Both watch mappings share it so the
// network scoping stays defined once and both get the indexed lookup.
func (r *VPCServiceReconciler) servicesInNetwork(
	ctx context.Context,
	network string,
	match func(*vpcv1alpha1.VPCService) bool,
) []reconcile.Request {
	if network == "" {
		return nil
	}

	var services vpcv1alpha1.VPCServiceList
	if err := r.List(ctx, &services, client.MatchingFields{IndexServiceNetwork: network}); err != nil {
		return nil
	}

	var reqs []reconcile.Request
	for i := range services.Items {
		svc := &services.Items[i]
		if match != nil && !match(svc) {
			continue
		}
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKey{Name: svc.Name}})
	}
	return reqs
}
