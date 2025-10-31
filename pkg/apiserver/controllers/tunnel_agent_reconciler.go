package controllers

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/vni"
)

// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnelagents,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnelagents/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnelagents/finalizers,verbs=update
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnels,verbs=get;list;watch

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
				return ctrl.Result{}, fmt.Errorf("failed to release resources: %w", err)
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
	// So that the Tunnel reconciler can list controller-owned TunnelAgents.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&corev1alpha2.TunnelAgent{},
		".metadata.controllerOwnerUID",
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

	// Reconcile when spec generation changes OR when status (e.g., Connections) changes.
	statusOrGenChanged := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool { return true },
		DeleteFunc: func(e event.DeleteEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldObj, ok1 := e.ObjectOld.(*corev1alpha2.TunnelAgent)
			newObj, ok2 := e.ObjectNew.(*corev1alpha2.TunnelAgent)
			if !ok1 || !ok2 {
				return false
			}
			genChanged := oldObj.GetGeneration() != newObj.GetGeneration()
			statusDiff := !equality.Semantic.DeepEqual(oldObj.Status, newObj.Status)
			deletionBegan := oldObj.GetDeletionTimestamp().IsZero() && !newObj.GetDeletionTimestamp().IsZero()
			return genChanged || statusDiff || deletionBegan
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.TunnelAgent{}, builder.WithPredicates(statusOrGenChanged)).
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

			// Release overlay address/prefix (if set)
			if conn.Address != "" {
				pfx, err := netip.ParsePrefix(conn.Address)
				if err != nil {
					return fmt.Errorf("failed to parse address %q for release: %w", conn.Address, err)
				}
				if err := r.agentIPAM.Release(pfx); err != nil {
					return fmt.Errorf("failed to release address %q: %w", conn.Address, err)
				}
				log.Info("Released overlay address", "connectionID", conn.ID, "address", conn.Address)
				conn.Address = ""
				changed = true
			}

			// Release VNI (if set)
			if conn.VNI != nil {
				vni := *conn.VNI
				r.vniPool.Release(vni)
				log.Info("Released VNI", "connectionID", conn.ID, "vni", vni)
				conn.VNI = nil
				changed = true
			}
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
