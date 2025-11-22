package controllers

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
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
	r := &TunnelReconciler{
		client:        c,
		relay:         relay,
		labelSelector: labelSelector,
	}
	relay.SetOnShutdown(r.RemoveRelayAddress)
	return r
}

func (r *TunnelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := controllerlog.FromContext(ctx, "name", req.Name)

	log.Info("Reconciling Tunnel")

	var tunnel corev1alpha2.Tunnel
	if err := r.client.Get(ctx, req.NamespacedName, &tunnel); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	// Update relay credentials if they have changed.
	if tunnel.Status.Credentials != nil {
		log.Info("Updating credentials for tunnel")

		r.relay.SetCredentials(tunnel.Name, tunnel.Status.Credentials.Token)
	}

	// Update relay addresses if they have changed.
	log.Info("Updating relay addresses for tunnel")
	r.relay.SetRelayAddresses(tunnel.Name, tunnel.Status.Addresses)

	// Update egress gateway setting
	var egressGatewayEnabled bool
	if tunnel.Spec.EgressGateway != nil {
		egressGatewayEnabled = tunnel.Spec.EgressGateway.Enabled
	}
	r.relay.SetEgressGateway(egressGatewayEnabled)

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
		For(&corev1alpha2.Tunnel{}, builder.WithPredicates(&predicate.ResourceVersionChangedPredicate{}, ls)).
		Complete(r)
}

func (r *TunnelReconciler) RemoveRelayAddress(ctx context.Context) {
	// Build the same label selector we filter on during watch.
	lss, err := metav1.ParseToLabelSelector(r.labelSelector)
	if err != nil {
		slog.Error("Failed to parse label selector during shutdown cleanup", slog.Any("error", err))
		return
	}
	sel, err := metav1.LabelSelectorAsSelector(lss)
	if err != nil {
		slog.Error("Failed to build label selector during shutdown cleanup", slog.Any("error", err))
		return
	}

	var list corev1alpha2.TunnelList
	if err := r.client.List(ctx, &list, &client.ListOptions{LabelSelector: sel}); err != nil {
		slog.Error("Failed to list tunnels during shutdown cleanup", slog.Any("error", err))
		return
	}

	relayAddr := r.relay.Address().String()
	for _, t := range list.Items {
		// Skip if there's nothing to remove.
		if !slices.Contains(t.Status.Addresses, relayAddr) {
			continue
		}

		key := types.NamespacedName{Namespace: t.Namespace, Name: t.Name}
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var latest corev1alpha2.Tunnel
			if err := r.client.Get(ctx, key, &latest); err != nil {
				return err
			}

			// Filter out this relay's address.
			filtered := latest.Status.Addresses[:0]
			for _, a := range latest.Status.Addresses {
				if a != relayAddr {
					filtered = append(filtered, a)
				}
			}
			latest.Status.Addresses = filtered

			return r.client.Status().Update(ctx, &latest)
		})
		if err != nil {
			slog.Error("Failed to remove relay address from tunnel during shutdown cleanup", slog.Any("error", err), slog.String("tunnel", key.String()))
		}
	}
}
