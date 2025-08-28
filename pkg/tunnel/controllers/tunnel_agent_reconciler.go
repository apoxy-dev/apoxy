package controllers

import (
	"context"
	"fmt"

	"github.com/alphadose/haxmap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

const tunnelRelayFinalizerTmpl = "tunnelrelay.apoxy.dev/%s/finalizer"

type TunnelAgentReconciler struct {
	client        client.Client
	relay         Relay
	labelSelector string
	finalizer     string
	conns         *haxmap.Map[string, Connection]
}

func NewTunnelAgentReconciler(c client.Client, relay Relay, labelSelector string) *TunnelAgentReconciler {
	finalizer := fmt.Sprintf(tunnelRelayFinalizerTmpl, relay.Name())
	return &TunnelAgentReconciler{
		client:    c,
		relay:     relay,
		finalizer: finalizer,
		conns:     haxmap.New[string, Connection](),
	}
}

func (r *TunnelAgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var agent corev1alpha2.TunnelAgent
	if err := r.client.Get(ctx, req.NamespacedName, &agent); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// handle deletion
	if !agent.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&agent, r.finalizer) {
			// Close all connections associated with this relay.
			for _, c := range agent.Status.Connections {
				if conn, ok := r.conns.Get(c.ID); ok {
					_ = conn.Close()
					r.conns.Del(c.ID)
				}
			}

			// Remove our finalizer
			if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				var cur corev1alpha2.TunnelAgent
				if getErr := r.client.Get(ctx, req.NamespacedName, &cur); getErr != nil {
					return getErr
				}
				controllerutil.RemoveFinalizer(&cur, r.finalizer)
				return r.client.Update(ctx, &cur)
			}); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func (r *TunnelAgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	lss, err := metav1.ParseToLabelSelector(r.labelSelector)
	if err != nil {
		return fmt.Errorf("failed to parse label selector: %w", err)
	}

	ls, err := predicate.LabelSelectorPredicate(*lss)
	if err != nil {
		return fmt.Errorf("failed to create label selector predicate: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.TunnelAgent{}, builder.WithPredicates(predicate.GenerationChangedPredicate{}, ls)).
		Complete(r)
}

// AddConnection registers a new active connection for the given agent.
func (r *TunnelAgentReconciler) AddConnection(ctx context.Context, agentName string, conn Connection) error {
	// Track the connection in-memory.
	r.conns.Set(conn.ID(), conn)

	// Upsert connection in status (first), so we truly have a connection before adding the finalizer.
	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var cur corev1alpha2.TunnelAgent
		if err := r.client.Get(ctx, types.NamespacedName{Name: agentName}, &cur); err != nil {
			return err
		}

		now := metav1.Now()
		entry := corev1alpha2.TunnelAgentConnection{
			ID:           conn.ID(),
			ConnectedAt:  &now,
			Address:      conn.Address().String(),
			RelayAddress: r.relay.Address().String(),
			VNI:          conn.VNI(),
		}

		found := false
		for i := range cur.Status.Connections {
			if cur.Status.Connections[i].ID == entry.ID {
				cur.Status.Connections[i] = entry
				found = true
				break
			}
		}
		if !found {
			cur.Status.Connections = append(cur.Status.Connections, entry)
		}

		return r.client.Status().Update(ctx, &cur)
	}); err != nil {
		return err
	}

	// Add the finalizer ONLY IF we have at least one connection for this relay.
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var cur corev1alpha2.TunnelAgent
		if err := r.client.Get(ctx, types.NamespacedName{Name: agentName}, &cur); err != nil {
			return err
		}

		if controllerutil.ContainsFinalizer(&cur, r.finalizer) {
			return nil
		}

		hasRelayConn := false
		for _, c := range cur.Status.Connections {
			if _, ok := r.conns.Get(c.ID); ok {
				hasRelayConn = true
				break
			}
		}

		if hasRelayConn {
			controllerutil.AddFinalizer(&cur, r.finalizer)
			return r.client.Update(ctx, &cur)
		}

		return nil
	})
}

// RemoveConnection deregisters a connection from the given agent by its ID.
func (r *TunnelAgentReconciler) RemoveConnection(ctx context.Context, agentName, id string) error {
	// Drop from in-memory map.
	r.conns.Del(id)

	// Remove from status.connections (by ID)
	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var cur corev1alpha2.TunnelAgent
		if err := r.client.Get(ctx, types.NamespacedName{Name: agentName}, &cur); err != nil {
			return err
		}

		newConns := make([]corev1alpha2.TunnelAgentConnection, 0, len(cur.Status.Connections))
		for _, c := range cur.Status.Connections {
			if c.ID != id {
				newConns = append(newConns, c)
			}
		}
		cur.Status.Connections = newConns

		return r.client.Status().Update(ctx, &cur)
	}); err != nil {
		return err
	}

	// If no connections remain for THIS relay, remove our relay-scoped finalizer.
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var cur corev1alpha2.TunnelAgent
		if err := r.client.Get(ctx, types.NamespacedName{Name: agentName}, &cur); err != nil {
			return err
		}

		hasRelayConn := false
		for _, c := range cur.Status.Connections {
			if _, ok := r.conns.Get(c.ID); ok {
				hasRelayConn = true
				break
			}
		}

		if !hasRelayConn && controllerutil.ContainsFinalizer(&cur, r.finalizer) {
			controllerutil.RemoveFinalizer(&cur, r.finalizer)
			return r.client.Update(ctx, &cur)
		}
		return nil
	})
}
