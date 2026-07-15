// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

// EgressStatusReconciler is the control-plane half of the egress reconciler
// (APO-726): it resolves each Service's egress selection against the
// project's EgressGateways/EgressRoutes and writes the resulting status —
// EgressReady on Services, Ready + per-listener attachment counts on
// EgressGateways, parents on EgressRoutes. It registers into the project
// apiserver via apiserver.WithAdditionalController, next to the minting
// ServiceReconciler, so status has exactly one writer (the data-plane pusher
// in workerd-manager stays read-only on the API, per the conditions.go
// contract).
//
// Every reconcile is a full tenant pass over the (small) egress object set:
// the inputs are all-to-all — one gateway edit changes every attached
// Service's condition — so per-object requests would recompute the same plan
// anyway. No-op writes are suppressed.
type EgressStatusReconciler struct {
	client.Client
}

// NewEgressStatusReconciler returns an EgressStatusReconciler.
func NewEgressStatusReconciler(c client.Client) *EgressStatusReconciler {
	return &EgressStatusReconciler{Client: c}
}

// Reconcile recomputes the tenant's egress plan and writes every object's
// status. The request is ignored: any egress-relevant event triggers a full
// pass.
func (r *EgressStatusReconciler) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	plan, err := compileFromClient(ctx, r.Client, false)
	if err != nil {
		return ctrl.Result{}, err
	}

	if err := errors.Join(
		r.writeServiceConditions(ctx, plan),
		r.writeGatewayStatuses(ctx, plan),
		r.writeRouteStatuses(ctx, plan),
	); err != nil {
		return ctrl.Result{}, fmt.Errorf("writing egress statuses: %w", err)
	}
	return ctrl.Result{}, nil
}

// compileFromClient lists the tenant's egress inputs and compiles them.
// liveOnly restricts Services to those with a serving revision (the pusher's
// view: only serving Services have a worker to configure); the status
// reconciler includes every Service so a pre-first-mint Service still gets an
// EgressReady condition.
func compileFromClient(ctx context.Context, c client.Client, liveOnly bool) (*EgressPlan, error) {
	var svcs computev1alpha1.ServiceList
	if err := c.List(ctx, &svcs); err != nil {
		return nil, fmt.Errorf("listing Services: %w", err)
	}
	var gws computev1alpha1.EgressGatewayList
	if err := c.List(ctx, &gws); err != nil {
		return nil, fmt.Errorf("listing EgressGateways: %w", err)
	}
	var routes computev1alpha1.EgressRouteList
	if err := c.List(ctx, &routes); err != nil {
		return nil, fmt.Errorf("listing EgressRoutes: %w", err)
	}

	var inputs []ServiceEgressInput
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		if !svc.DeletionTimestamp.IsZero() {
			continue
		}
		if liveOnly && svc.Status.LiveRevision == "" {
			continue
		}
		inputs = append(inputs, ServiceEgressInput{
			Name:   svc.Name,
			Egress: resolveServiceEgress(ctx, c, svc),
		})
	}
	return CompileEgress(inputs, gws.Items, routes.Items), nil
}

// resolveServiceEgress returns the egress selection that governs the Service:
// the live ServiceRevision's (enforcement must match what serves), falling
// back to the Service template when nothing serves yet or the revision is
// unreadable.
func resolveServiceEgress(ctx context.Context, c client.Client, svc *computev1alpha1.Service) *computev1alpha1.ServiceEgress {
	if live := svc.Status.LiveRevision; live != "" {
		var rev computev1alpha1.ServiceRevision
		if err := c.Get(ctx, types.NamespacedName{Name: live}, &rev); err == nil {
			return rev.Spec.Egress
		}
	}
	return svc.Spec.Template.Spec.Egress
}

// updateStatus fetches the named object into obj, runs mutate, and writes the
// status subresource only when mutate reports a change. It owns the
// conflict-retry and not-found handling every egress status writer shares: a
// concurrent minting write must be retried, and a just-deleted object skipped
// rather than failing the pass.
func (r *EgressStatusReconciler) updateStatus(ctx context.Context, name string, obj client.Object, mutate func() (changed bool)) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := r.Get(ctx, types.NamespacedName{Name: name}, obj); err != nil {
			return client.IgnoreNotFound(err)
		}
		if !mutate() {
			return nil
		}
		return r.Status().Update(ctx, obj)
	})
}

// conditionEqual reports whether an existing condition already carries the
// desired Status/Reason/Message. ObservedGeneration and LastTransitionTime are
// deliberately not compared: a text-identical condition is left untouched so
// its transition time stays stable.
func conditionEqual(existing *metav1.Condition, desired metav1.Condition) bool {
	return existing != nil &&
		existing.Status == desired.Status &&
		existing.Reason == desired.Reason &&
		existing.Message == desired.Message
}

// writeServiceConditions writes each Service's EgressReady condition.
func (r *EgressStatusReconciler) writeServiceConditions(ctx context.Context, plan *EgressPlan) error {
	var errs []error
	for _, sp := range plan.Services {
		var svc computev1alpha1.Service
		err := r.updateStatus(ctx, sp.Name, &svc, func() bool {
			cond := metav1.Condition{
				Type:               computev1alpha1.ConditionEgressReady,
				Status:             conditionStatus(sp.Ready),
				Reason:             sp.Reason,
				Message:            sp.Message,
				ObservedGeneration: svc.Generation,
			}
			if conditionEqual(meta.FindStatusCondition(svc.Status.Conditions, cond.Type), cond) {
				return false
			}
			meta.SetStatusCondition(&svc.Status.Conditions, cond)
			return true
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("service %s: %w", sp.Name, err))
		}
	}
	return errors.Join(errs...)
}

// writeGatewayStatuses writes each EgressGateway's Ready condition and
// listener attachment counts, preserving the data-plane-owned listener fields
// (port, backendAddress, listener conditions).
func (r *EgressStatusReconciler) writeGatewayStatuses(ctx context.Context, plan *EgressPlan) error {
	var errs []error
	for _, gp := range plan.Gateways {
		var gw computev1alpha1.EgressGateway
		err := r.updateStatus(ctx, gp.Name, &gw, func() bool {
			existingByName := make(map[string]computev1alpha1.EgressListenerStatus, len(gw.Status.Listeners))
			for _, ls := range gw.Status.Listeners {
				existingByName[ls.Name] = ls
			}
			listeners := make([]computev1alpha1.EgressListenerStatus, 0, len(gw.Spec.Listeners))
			for _, l := range gw.Spec.Listeners {
				ls := existingByName[l.Name]
				ls.Name = l.Name
				ls.AttachedRoutes = gp.AttachedRoutes[l.Name]
				listeners = append(listeners, ls)
			}
			cond := metav1.Condition{
				Type:               computev1alpha1.EgressGatewayConditionReady,
				Status:             conditionStatus(gp.Ready),
				Reason:             gp.Reason,
				Message:            gp.Message,
				ObservedGeneration: gw.Generation,
			}
			if conditionEqual(meta.FindStatusCondition(gw.Status.Conditions, cond.Type), cond) &&
				listenerStatusesEqual(gw.Status.Listeners, listeners) {
				return false
			}
			gw.Status.Listeners = listeners
			meta.SetStatusCondition(&gw.Status.Conditions, cond)
			return true
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("egressgateway %s: %w", gp.Name, err))
		}
	}
	return errors.Join(errs...)
}

// writeRouteStatuses writes each EgressRoute's status.parents.
func (r *EgressStatusReconciler) writeRouteStatuses(ctx context.Context, plan *EgressPlan) error {
	var errs []error
	for _, rp := range plan.Routes {
		var route computev1alpha1.EgressRoute
		err := r.updateStatus(ctx, rp.Name, &route, func() bool {
			if routeParentsEqual(route.Status.Parents, rp.Parents) {
				return false
			}
			// Preserve LastTransitionTime for conditions that did not change
			// state, then stamp the rest.
			now := metav1.Now()
			parents := make([]gwapiv1.RouteParentStatus, len(rp.Parents))
			copy(parents, rp.Parents)
			for i := range parents {
				for j := range parents[i].Conditions {
					c := &parents[i].Conditions[j]
					c.LastTransitionTime = now
					if i < len(route.Status.Parents) {
						if old := meta.FindStatusCondition(route.Status.Parents[i].Conditions, c.Type); old != nil && old.Status == c.Status {
							c.LastTransitionTime = old.LastTransitionTime
						}
					}
				}
			}
			route.Status.Parents = parents
			return true
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("egressroute %s: %w", rp.Name, err))
		}
	}
	return errors.Join(errs...)
}

// listenerStatusesEqual compares listener statuses.
func listenerStatusesEqual(a, b []computev1alpha1.EgressListenerStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Port != b[i].Port ||
			a[i].BackendAddress != b[i].BackendAddress || a[i].AttachedRoutes != b[i].AttachedRoutes {
			return false
		}
	}
	return true
}

// routeParentsEqual compares parent statuses ignoring LastTransitionTime.
func routeParentsEqual(a, b []gwapiv1.RouteParentStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ControllerName != b[i].ControllerName ||
			string(a[i].ParentRef.Name) != string(b[i].ParentRef.Name) ||
			!sectionNamesEqual(a[i].ParentRef.SectionName, b[i].ParentRef.SectionName) ||
			len(a[i].Conditions) != len(b[i].Conditions) {
			return false
		}
		for j := range a[i].Conditions {
			ca, cb := a[i].Conditions[j], b[i].Conditions[j]
			if ca.Type != cb.Type || ca.Status != cb.Status || ca.Reason != cb.Reason || ca.Message != cb.Message {
				return false
			}
		}
	}
	return true
}

func sectionNamesEqual(a, b *gwapiv1.SectionName) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

// EgressFullPassRequestName is the name of the synthetic singleton request
// every egress-relevant event coalesces into. The reconcilers ignore it and
// recompute the whole tenant, so bursts of events collapse into one pass; the
// apoxy-cloud multicluster pusher reuses this name for the same purpose.
const EgressFullPassRequestName = "egress-config"

// egressFullPassRequest is the synthetic singleton request every
// egress-relevant event maps to, so bursts of events coalesce into one pass.
var egressFullPassRequest = reconcile.Request{NamespacedName: types.NamespacedName{Name: EgressFullPassRequestName}}

// enqueueEgressFullPass maps any watched object to the singleton full-pass
// request.
func enqueueEgressFullPass() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{egressFullPassRequest}
	})
}

// SetupWithManager registers the reconciler. Everything egress-relevant funnels
// into the singleton full-pass request.
func (r *EgressStatusReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("compute-egress-status").
		For(&computev1alpha1.EgressGateway{}).
		Watches(&computev1alpha1.EgressRoute{}, enqueueEgressFullPass()).
		Watches(&computev1alpha1.Service{}, enqueueEgressFullPass()).
		Watches(&computev1alpha1.ServiceRevision{}, enqueueEgressFullPass()).
		Complete(r)
}
