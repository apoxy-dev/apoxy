package controllers

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

const (
	indexByTunnelRef = "spec.tunnelRef.name"
)

// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnelagents,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnelagents/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnelagents/finalizers,verbs=update
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnels,verbs=get;list;watch

type TunnelAgentReconciler struct {
	client    client.Client
	agentIPAM tunnet.IPAM
}

func NewTunnelAgentReconciler(c client.Client, agentIPAM tunnet.IPAM) *TunnelAgentReconciler {
	return &TunnelAgentReconciler{
		client:    c,
		agentIPAM: agentIPAM,
	}
}

func (r *TunnelAgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := controllerlog.FromContext(ctx, "name", req.Name)

	var agent corev1alpha2.TunnelAgent
	if err := r.client.Get(ctx, req.NamespacedName, &agent); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	// handle deletion
	if !agent.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&agent, ApiServerFinalizer) {
			if err := r.releasePrefixIfPresent(&agent, log); err != nil {
				log.Error(err, "failed to release prefix; will retry")
				return ctrl.Result{}, fmt.Errorf("failed to release prefix: %w", err)
			}

			// Remove finalizer
			if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				var cur corev1alpha2.TunnelAgent
				if getErr := r.client.Get(ctx, req.NamespacedName, &cur); getErr != nil {
					return getErr
				}
				controllerutil.RemoveFinalizer(&cur, ApiServerFinalizer)
				return r.client.Update(ctx, &cur)
			}); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// ensure finalizer
	if !controllerutil.ContainsFinalizer(&agent, ApiServerFinalizer) {
		if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			var cur corev1alpha2.TunnelAgent
			if getErr := r.client.Get(ctx, req.NamespacedName, &cur); getErr != nil {
				return getErr
			}
			controllerutil.AddFinalizer(&cur, ApiServerFinalizer)
			return r.client.Update(ctx, &cur)
		}); err != nil {
			return ctrl.Result{}, err
		}
	}

	// fetch owner Tunnel
	tunnelName := agent.Spec.TunnelRef.Name
	if tunnelName == "" {
		log.Info("tunnelRef.name is empty; skipping")
		return ctrl.Result{}, nil
	}

	var tunnel corev1alpha2.Tunnel
	if err := r.client.Get(ctx, client.ObjectKey{Name: tunnelName}, &tunnel); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Referenced Tunnel not found; will retry", "tunnel", tunnelName)
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}

		return ctrl.Result{}, err
	}

	// ensure controller ownerRef agent -> tunnel (retry on conflict)
	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var cur corev1alpha2.TunnelAgent
		if getErr := r.client.Get(ctx, req.NamespacedName, &cur); getErr != nil {
			return getErr
		}
		changed, ensureErr := r.ensureControllerOwner(&cur, &tunnel)
		if ensureErr != nil {
			return ensureErr
		}
		if !changed {
			return nil
		}
		return r.client.Update(ctx, &cur)
	}); err != nil {
		return ctrl.Result{}, err
	}

	needsPrefix := agent.Status.Prefix == ""
	if needsPrefix {
		if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			var cur corev1alpha2.TunnelAgent
			if getErr := r.client.Get(ctx, req.NamespacedName, &cur); getErr != nil {
				return getErr
			}
			if cur.Status.Prefix != "" { // someone else already set it
				return nil
			}

			// allocate on-demand within the retry to avoid leaks
			pfx, ipErr := r.agentIPAM.Allocate()
			if ipErr != nil {
				return fmt.Errorf("failed to allocate prefix: %w", ipErr)
			}
			cur.Status.Prefix = pfx.String()
			if updErr := r.client.Status().Update(ctx, &cur); updErr != nil {
				// release on failed update (including conflicts)
				_ = r.agentIPAM.Release(pfx)
				return updErr
			}
			return nil
		}); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *TunnelAgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// field index
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1alpha2.TunnelAgent{}, indexByTunnelRef,
		func(obj client.Object) []string {
			ta := obj.(*corev1alpha2.TunnelAgent)
			if ta.Spec.TunnelRef.Name == "" {
				return nil
			}
			return []string{ta.Spec.TunnelRef.Name}
		}); err != nil {
		return fmt.Errorf("index TunnelAgents by TunnelRef: %w", err)
	}

	// map Tunnel -> its agents
	mapTunnelToAgents := handler.TypedEnqueueRequestsFromMapFunc[*corev1alpha2.Tunnel](func(ctx context.Context, t *corev1alpha2.Tunnel) []reconcile.Request {
		var list corev1alpha2.TunnelAgentList
		if err := mgr.GetClient().List(ctx, &list, client.MatchingFields{indexByTunnelRef: t.Name}); err != nil {
			return nil
		}
		reqs := make([]reconcile.Request, 0, len(list.Items))
		for _, ta := range list.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKey{Name: ta.Name}})
		}
		return reqs
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.TunnelAgent{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WatchesRawSource(
			source.Kind(mgr.GetCache(), &corev1alpha2.Tunnel{}, mapTunnelToAgents),
		).
		Complete(r)
}

func (r *TunnelAgentReconciler) ensureControllerOwner(child client.Object, owner client.Object) (bool, error) {
	for _, or := range child.GetOwnerReferences() {
		if or.UID == owner.GetUID() && or.Controller != nil && *or.Controller {
			return false, nil
		}
	}

	// Set controller reference (overwrites any existing controller owner)
	if err := controllerutil.SetControllerReference(
		owner,
		child,
		r.client.Scheme(),
	); err != nil {
		return false, err
	}

	return true, nil
}

func (r *TunnelAgentReconciler) releasePrefixIfPresent(agent *corev1alpha2.TunnelAgent, log logr.Logger) error {
	if agent.Status.Prefix == "" {
		return nil
	}

	pfx, err := netip.ParsePrefix(agent.Status.Prefix)
	if err != nil {
		log.Error(err, "invalid prefix in status; skipping release", "prefix", agent.Status.Prefix)
		return nil
	}

	return r.agentIPAM.Release(pfx)
}
