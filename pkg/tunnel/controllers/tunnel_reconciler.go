package controllers

import (
	"context"
	"fmt"
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

type TunnelReconciler struct {
	client        client.Client
	relay         Relay
	labelSelector string
}

func NewTunnelReconciler(c client.Client, relay Relay, labelSelector string) *TunnelReconciler {
	return &TunnelReconciler{
		client:        c,
		relay:         relay,
		labelSelector: labelSelector,
	}
}

func (r *TunnelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var tunnel corev1alpha2.Tunnel
	if err := r.client.Get(ctx, req.NamespacedName, &tunnel); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	// Update relay credentials if they have changed.
	if tunnel.Status.Credentials != nil {
		r.relay.SetCredentials(tunnel.Name, tunnel.Status.Credentials.Token)
	}

	// Update relay addresses if they have changed.
	r.relay.SetRelayAddresses(tunnel.Name, tunnel.Status.Addresses)

	// Add our relay address to the list of addresses if missing.
	if !slices.Contains(tunnel.Status.Addresses, r.relay.Address().String()) {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var latest corev1alpha2.Tunnel
			if err := r.client.Get(ctx, req.NamespacedName, &latest); err != nil {
				return err
			}

			// Append our address if still missing
			if !slices.Contains(latest.Status.Addresses, r.relay.Address().String()) {
				latest.Status.Addresses = append(latest.Status.Addresses, r.relay.Address().String())
			}

			return r.client.Status().Update(ctx, &latest)
		})
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update Tunnel status: %w", err)
		}
	}

	return ctrl.Result{}, nil
}

func (r *TunnelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	lss, err := metav1.ParseToLabelSelector(r.labelSelector)
	if err != nil {
		return fmt.Errorf("failed to parse label selector: %w", err)
	}

	ls, err := predicate.LabelSelectorPredicate(*lss)
	if err != nil {
		return fmt.Errorf("failed to create label selector predicate: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.Tunnel{}, builder.WithPredicates(predicate.GenerationChangedPredicate{}, ls)).
		Complete(r)
}
