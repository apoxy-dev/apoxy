package controllers

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/alphadose/haxmap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

// How often to push connection stats to the TunnelAgent status.
// This is throttled to avoid overwhelming the API server.
const statsUpdateInterval = 30 * time.Second

// Each relay gets its own finalizer on the TunnelAgent object.
const tunnelRelayFinalizerTmpl = "tunnelrelay.apoxy.dev/%s-finalizer"

type TunnelAgentReconciler struct {
	client        client.Client
	relay         Relay
	labelSelector string
	finalizer     string
	conns         *haxmap.Map[string, Connection] // id -> connection
	connAgent     *haxmap.Map[string, string]     // id -> agent name
}

func NewTunnelAgentReconciler(c client.Client, relay Relay, labelSelector string) *TunnelAgentReconciler {
	finalizer := fmt.Sprintf(tunnelRelayFinalizerTmpl, relay.Name())
	r := &TunnelAgentReconciler{
		client:    c,
		relay:     relay,
		finalizer: finalizer,
		conns:     haxmap.New[string, Connection](),
		connAgent: haxmap.New[string, string](),
	}
	relay.SetOnConnect(r.AddConnection)
	relay.SetOnDisconnect(r.RemoveConnection)
	return r
}

func (r *TunnelAgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := controllerlog.FromContext(ctx, "name", req.Name)

	log.Info("Reconciling TunnelAgent")

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

			// Remove finalizer
			controllerutil.RemoveFinalizer(&agent, r.finalizer)
			if err := r.client.Update(ctx, &agent); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Propagate status → live connection: set overlay address and VNI when populated by the other reconciler.
	for _, sc := range agent.Status.Connections {
		if conn, ok := r.conns.Get(sc.ID); ok {
			if sc.Address != "" {
				if err := conn.SetOverlayAddress(sc.Address); err != nil {
					return ctrl.Result{}, fmt.Errorf("failed to set overlay address for connection %q: %w", sc.ID, err)
				}
			}

			if sc.VNI != nil {
				if err := conn.SetVNI(ctx, uint(*sc.VNI)); err != nil {
					return ctrl.Result{}, fmt.Errorf("failed to set VNI for connection %q: %w", sc.ID, err)
				}
			}
		}
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

	// Periodically push connection stats to the API server.
	err = mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		ticker := time.NewTicker(statsUpdateInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				r.PushStatsOnce(ctx)
			}
		}
	}))
	if err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.TunnelAgent{}, builder.WithPredicates(&predicate.ResourceVersionChangedPredicate{}, ls)).
		Complete(r)
}

// AddConnection registers a new active connection for the given agent.
func (r *TunnelAgentReconciler) AddConnection(ctx context.Context, tunnelName, agentName string, conn Connection) error {
	// Track the connection in-memory.
	r.conns.Set(conn.ID(), conn)
	r.connAgent.Set(conn.ID(), agentName)

	// Get the parent Tunnel object.
	var tunnel corev1alpha2.Tunnel
	if err := r.client.Get(ctx, types.NamespacedName{Name: tunnelName}, &tunnel); err != nil {
		return fmt.Errorf("failed to get parent Tunnel %q for TunnelAgent %q: %w", tunnelName, agentName, err)
	}

	// Upsert connection in status (first), so we truly have a connection before adding the finalizer.
	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		cur := corev1alpha2.TunnelAgent{
			ObjectMeta: metav1.ObjectMeta{
				Name:   agentName,
				Labels: tunnel.ObjectMeta.Labels,
			},
			Spec: corev1alpha2.TunnelAgentSpec{
				TunnelRef: corev1alpha2.TunnelRef{
					Name: tunnelName,
				},
			},
		}

		if err := r.client.Get(ctx, types.NamespacedName{Name: agentName}, &cur); err != nil {
			if apierrors.IsNotFound(err) {
				// Create minimal object if missing.
				slog.Info("Creating TunnelAgent object", slog.String("agent", agentName))

				if err := r.client.Create(ctx, &cur); err != nil {
					return fmt.Errorf("failed to create TunnelAgent %q: %w", agentName, err)
				}
			} else {
				return fmt.Errorf("failed to get TunnelAgent %q: %w", agentName, err)
			}
		}

		now := metav1.Now()
		entry := corev1alpha2.TunnelAgentConnection{
			ID:           conn.ID(),
			ConnectedAt:  &now,
			RelayAddress: r.relay.Address().String(),
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
	if conn, ok := r.conns.GetAndDel(id); ok {
		if err := conn.Close(); err != nil {
			slog.Warn("Failed to close connection", slog.String("id", id), slog.Any("error", err))
		}
	}
	r.connAgent.Del(id)

	// Remove from status.connections (by ID)
	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var cur corev1alpha2.TunnelAgent
		if err := r.client.Get(ctx, types.NamespacedName{Name: agentName}, &cur); err != nil {
			if apierrors.IsNotFound(err) {
				return nil // already gone
			}
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
	// Additionally, if there are NO connections remaining at all, delete the TunnelAgent.
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var cur corev1alpha2.TunnelAgent
		if err := r.client.Get(ctx, types.NamespacedName{Name: agentName}, &cur); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}

		// Check if any connections remain at all.
		if len(cur.Status.Connections) == 0 {
			// Ensure our finalizer (if present) is removed to avoid blocking deletion.
			if controllerutil.ContainsFinalizer(&cur, r.finalizer) {
				controllerutil.RemoveFinalizer(&cur, r.finalizer)
				if err := r.client.Update(ctx, &cur); err != nil {
					return err
				}
			}
			// Delete the TunnelAgent object (ignore if it disappears between calls).
			return client.IgnoreNotFound(r.client.Delete(ctx, &cur))
		}

		// Otherwise, only consider removing our finalizer if *this relay* no longer has any live connections.
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

// pushStatsOnce performs a single stats sweep.
// This is exposed for testing purposes.
func (r *TunnelAgentReconciler) PushStatsOnce(ctx context.Context) {
	// Snapshot live connection stats.
	updatesByAgent := make(map[string][]corev1alpha2.TunnelAgentConnection)
	r.conns.ForEach(func(id string, conn Connection) bool {
		agentName, ok := r.connAgent.Get(id)
		if !ok {
			slog.Warn("Connection has no associated agent", slog.String("id", id))
			return true // shouldn't happen, but skip safely
		}

		if s, ok := conn.Stats(); ok {
			u := corev1alpha2.TunnelAgentConnection{
				ID: id,
			}
			if !s.LastRX.IsZero() {
				t := metav1.NewTime(s.LastRX)
				u.LastRX = &t
			}
			// Intentionally swap the order so transfer stats are from the agent's perspective.
			if s.TXBytes != 0 {
				u.RXBytes = &s.TXBytes
			}
			if s.RXBytes != 0 {
				u.TXBytes = &s.RXBytes
			}
			updatesByAgent[agentName] = append(updatesByAgent[agentName], u)
		}
		return true
	})

	// Apply updates per agent with conflict retries.
	for agentName, updates := range updatesByAgent {
		err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			var cur corev1alpha2.TunnelAgent
			if err := r.client.Get(ctx, types.NamespacedName{Name: agentName}, &cur); err != nil {
				// If the object is gone, skip.
				return client.IgnoreNotFound(err)
			}

			// Build a quick lookup: connection ID -> status entry.
			connByID := make(map[string]*corev1alpha2.TunnelAgentConnection, len(cur.Status.Connections))
			for i := range cur.Status.Connections {
				c := &cur.Status.Connections[i]
				connByID[c.ID] = c
			}

			// Apply stats only for known connections.
			for _, u := range updates {
				if c := connByID[u.ID]; c != nil {
					c.RXBytes = u.RXBytes
					c.TXBytes = u.TXBytes
					if u.LastRX != nil {
						c.LastRX = u.LastRX
					}
				}
			}

			return r.client.Status().Update(ctx, &cur)
		})
		if err != nil {
			slog.Warn("Failed to update TunnelAgent stats", slog.String("agent", agentName), slog.Any("error", err))
		}
	}
}
