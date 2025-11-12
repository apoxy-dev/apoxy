package controllers

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/vni"
)

// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnelagents,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnelagents/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnelagents/finalizers,verbs=update
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnels,verbs=get;list;watch

const (
	// must be longer than the relays own gc max silence
	gcMaxSilence            = 5 * time.Minute
	gcCheckInterval         = time.Minute
	indexControllerOwnerUID = ".metadata.controllerOwnerUID"
)

type TunnelAgentReconciler struct {
	client    client.Client
	agentIPAM tunnet.IPAM
	vniPool   *vni.VNIPool
}

func NewTunnelAgentReconciler(c client.Client, agentIPAM tunnet.IPAM, vniPool *vni.VNIPool) *TunnelAgentReconciler {
	return &TunnelAgentReconciler{
		client:    c,
		agentIPAM: agentIPAM,
		vniPool:   vniPool,
	}
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

	// Handle deletion
	if !agent.DeletionTimestamp.IsZero() {
		log.Info("Handling deletion of TunnelAgent")

		if controllerutil.ContainsFinalizer(&agent, ApiServerFinalizer) {
			log.Info("Releasing resources for TunnelAgent")

			changed, err := r.releaseResourcesIfPresent(ctx, log, req.NamespacedName)
			if err != nil {
				log.Error(err, "Failed to release resources for TunnelAgent")
				// not retryable, just log and continue so we don't block deletion.
			}

			// Refetch to avoid conflicts if we modified the object
			if changed {
				if err := r.client.Get(ctx, req.NamespacedName, &agent); err != nil {
					if apierrors.IsNotFound(err) {
						return ctrl.Result{}, nil
					}
					return ctrl.Result{}, err
				}
			}

			log.Info("Removing finalizer from TunnelAgent")

			// Remove finalizer
			controllerutil.RemoveFinalizer(&agent, ApiServerFinalizer)
			if err := r.client.Update(ctx, &agent); err != nil {
				return ctrl.Result{}, err
			}
		}

		return ctrl.Result{}, nil
	}

	// Ensure finalizer
	if !controllerutil.ContainsFinalizer(&agent, ApiServerFinalizer) {
		controllerutil.AddFinalizer(&agent, ApiServerFinalizer)
		if err := r.client.Update(ctx, &agent); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Fetch owner Tunnel
	tunnelName := agent.Spec.TunnelRef.Name
	if tunnelName == "" {
		// TODO: why would this happen? Should we mark the agent as failed.
		log.Info("tunnelRef.name is empty; skipping")
		return ctrl.Result{}, nil
	}

	log.Info("Fetching owner Tunnel", "tunnelName", tunnelName)

	var tunnel corev1alpha2.Tunnel
	if err := r.client.Get(ctx, client.ObjectKey{Name: tunnelName}, &tunnel); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Referenced Tunnel not found; skipping", "tunnelName", tunnelName)
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		return ctrl.Result{}, err
	}

	// Ensure controller ownerRef agent -> tunnel
	changed, err := r.ensureControllerOwner(&agent, &tunnel)
	if err != nil {
		return ctrl.Result{}, err
	}
	if changed {
		if err := r.client.Update(ctx, &agent); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Assign overlay addresses and VNIs for any connections missing them
	if err := r.ensureConnectionAllocations(ctx, log, req.NamespacedName); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *TunnelAgentReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	// Cache index to quickly look up TunnelAgents by their controller owner UID.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&corev1alpha2.TunnelAgent{},
		indexControllerOwnerUID,
		func(obj client.Object) []string {
			ta := obj.(*corev1alpha2.TunnelAgent)
			for _, or := range ta.GetOwnerReferences() {
				if or.Controller != nil && *or.Controller {
					return []string{string(or.UID)}
				}
			}
			return nil
		},
	); err != nil {
		return err
	}

	// Run periodic orphaned connection cleanup
	err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		ticker := time.NewTicker(gcCheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil

			case <-ticker.C:
				if err := r.PruneOrphanedConnections(ctx); err != nil {
					slog.Warn("Failed to run orphaned connection cleanup", slog.Any("error", err))
				}
			}
		}
	}))
	if err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.TunnelAgent{}, builder.WithPredicates(&predicate.ResourceVersionChangedPredicate{})).
		Complete(r)
}

func (r *TunnelAgentReconciler) ensureConnectionAllocations(
	ctx context.Context,
	log logr.Logger,
	key client.ObjectKey,
) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var cur corev1alpha2.TunnelAgent
		if err := r.client.Get(ctx, key, &cur); err != nil {
			return err
		}

		// Track newly made allocations so we can roll them back if Status().Update fails.
		var newlyAllocatedPrefixes []netip.Prefix
		var newlyAllocatedVNIs []uint

		for i := range cur.Status.Connections {
			conn := &cur.Status.Connections[i]

			// Allocate overlay address if missing
			if conn.Address == "" {
				pfx, err := r.agentIPAM.Allocate()
				if err != nil {
					// rollback anything we grabbed this pass
					for _, p := range newlyAllocatedPrefixes {
						_ = r.agentIPAM.Release(p)
					}
					for _, vni := range newlyAllocatedVNIs {
						r.vniPool.Release(vni)
					}
					return fmt.Errorf("failed to allocate address: %w", err)
				}
				conn.Address = pfx.String()
				newlyAllocatedPrefixes = append(newlyAllocatedPrefixes, pfx)
				log.Info("Allocated overlay address", "connectionID", conn.ID, "address", conn.Address)
			}

			// Allocate VNI if missing
			if conn.VNI == nil {
				vni, err := r.vniPool.Allocate()
				if err != nil {
					// rollback anything we grabbed this pass
					for _, p := range newlyAllocatedPrefixes {
						_ = r.agentIPAM.Release(p)
					}
					for _, vni := range newlyAllocatedVNIs {
						r.vniPool.Release(vni)
					}
					return fmt.Errorf("failed to allocate VNI: %w", err)
				}
				conn.VNI = &vni
				newlyAllocatedVNIs = append(newlyAllocatedVNIs, vni)
				log.Info("Allocated VNI", "connectionID", conn.ID, "vni", *conn.VNI)
			}
		}

		if len(newlyAllocatedPrefixes) == 0 && len(newlyAllocatedVNIs) == 0 {
			return nil
		}

		// Commit to status; if it fails, release fresh allocations from this attempt.
		if err := r.client.Status().Update(ctx, &cur); err != nil {
			// rollback anything we grabbed this pass
			for _, p := range newlyAllocatedPrefixes {
				_ = r.agentIPAM.Release(p)
			}
			for _, vni := range newlyAllocatedVNIs {
				r.vniPool.Release(vni)
			}
			return err
		}

		return nil
	})
}

// releaseConnectionResources releases any resources held by a single connection.
// It attempts to release both the IP prefix and the VNI; it returns the first
// error encountered but will attempt both releases regardless.
func (r *TunnelAgentReconciler) releaseConnectionResources(addr string, vniPtr *uint) error {
	var firstErr error

	// Release overlay address/prefix (if set)
	if addr != "" {
		pfx, err := netip.ParsePrefix(addr)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to parse address %q for release: %w", addr, err)
			}
		} else {
			if err := r.agentIPAM.Release(pfx); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("failed to release address %q: %w", addr, err)
			}
		}
	}

	// Release VNI (if set)
	if vniPtr != nil {
		r.vniPool.Release(*vniPtr)
	}

	return firstErr
}

func (r *TunnelAgentReconciler) releaseResourcesIfPresent(
	ctx context.Context,
	log logr.Logger,
	key client.ObjectKey,
) (bool, error) {
	var changed bool
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var cur corev1alpha2.TunnelAgent
		if err := r.client.Get(ctx, key, &cur); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}

		// If there are no connections, we’re done.
		if len(cur.Status.Connections) == 0 {
			return nil
		}

		for i := range cur.Status.Connections {
			conn := &cur.Status.Connections[i]

			if conn.Address == "" && conn.VNI == nil {
				continue
			}

			// Release any resources the connection holds.
			if err := r.releaseConnectionResources(conn.Address, conn.VNI); err != nil {
				return err
			}
			log.Info("Released resources for connection", "connectionID", conn.ID, "address", conn.Address, "vni", conn.VNI)

			conn.Address = ""
			conn.VNI = nil
			changed = true
		}

		if changed {
			if err := r.client.Status().Update(ctx, &cur); err != nil {
				return err
			}
		}
		return nil
	})

	return changed, err
}

func (r *TunnelAgentReconciler) ensureControllerOwner(child client.Object, owner client.Object) (bool, error) {
	for _, or := range child.GetOwnerReferences() {
		if or.UID == owner.GetUID() && or.Controller != nil && *or.Controller {
			return false, nil
		}
	}

	if err := controllerutil.SetControllerReference(owner, child, r.client.Scheme()); err != nil {
		return false, err
	}
	return true, nil
}

// PruneOrphanedConnections prunes orphaned connections from TunnelAgent status
// (due to a relay unexpectedly shutting down). This is exposed for testing purposes.
func (r *TunnelAgentReconciler) PruneOrphanedConnections(ctx context.Context) error {
	var agents corev1alpha2.TunnelAgentList
	if err := r.client.List(ctx, &agents); err != nil {
		return err
	}

	var firstErr error
	for i := range agents.Items {
		agent := &agents.Items[i]
		key := client.ObjectKeyFromObject(agent)

		err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			var cur corev1alpha2.TunnelAgent
			if err := r.client.Get(ctx, key, &cur); err != nil {
				if apierrors.IsNotFound(err) {
					return nil
				}
				return err
			}

			// No connections to prune
			if len(cur.Status.Connections) == 0 {
				return nil
			}

			now := time.Now().UTC()
			conns := make([]corev1alpha2.TunnelAgentConnection, 0, len(cur.Status.Connections))
			updated := false

			for j := range cur.Status.Connections {
				conn := &cur.Status.Connections[j]

				// Determine orphaned-ness
				isOrphaned := false
				switch {
				case conn.LastRX != nil:
					isOrphaned = conn.LastRX.Add(gcMaxSilence).Before(now)
				case conn.ConnectedAt != nil:
					isOrphaned = conn.ConnectedAt.Add(gcMaxSilence).Before(now)
				default:
					isOrphaned = false
				}
				if !isOrphaned {
					conns = append(conns, *conn)
					continue
				}

				slog.Info("Pruning orphaned connection from TunnelAgent",
					slog.String("agent", agent.Name),
					slog.String("connectionID", conn.ID),
					slog.String("address", conn.Address))

				// Release any resources the orphaned connection holds.
				if err := r.releaseConnectionResources(conn.Address, conn.VNI); err != nil {
					slog.Warn("Failed to release resources for orphaned connection",
						slog.String("agent", agent.Name),
						slog.String("connectionID", conn.ID),
						slog.String("address", conn.Address),
						slog.Any("error", err))
				}

				// Do not append to the new list: this prunes the connection.
				updated = true
			}
			if !updated {
				return nil
			}

			cur.Status.Connections = conns
			if err := r.client.Status().Update(ctx, &cur); err != nil {
				return err
			}
			return nil
		})

		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			slog.Warn("Failed pruning orphaned connections for agent",
				slog.String("agent", agent.Name), slog.Any("error", err))
		}
	}

	return firstErr
}
