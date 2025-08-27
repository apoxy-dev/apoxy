package controllers

import (
	"context"

	"github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnels,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnels/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnels/finalizers,verbs=update

type TunnelReconciler struct {
	client client.Client
}

func NewTunnelReconciler(c client.Client) *TunnelReconciler {
	return &TunnelReconciler{client: c}
}

func (r *TunnelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := controllerlog.FromContext(ctx, "name", req.Name)

	var tunnel v1alpha2.Tunnel
	if err := r.client.Get(ctx, req.NamespacedName, &tunnel); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// handle deletion
	if !tunnel.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&tunnel, ApiServerFinalizer) {
			// TODO: Add any cleanup logic here as required.

			log.Info("handling Tunnel deletion")

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
	if !controllerutil.ContainsFinalizer(&tunnel, ApiServerFinalizer) {
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

	// TODO: Add reconciliation logic as required.

	log.Info("Tunnel reconciled successfully")

	return ctrl.Result{}, nil
}

func (r *TunnelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha2.Tunnel{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
