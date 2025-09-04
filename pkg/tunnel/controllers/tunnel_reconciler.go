package controllers

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

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
