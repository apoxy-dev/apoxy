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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/vni"
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
			if err := r.releaseResourcesIfPresent(log, &agent); err != nil {
				log.Error(err, "failed to release resources; will retry")
				return ctrl.Result{}, fmt.Errorf("failed to release resources: %w", err)
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

	// Assign overlay addresses and VNIs for any connections missing them
	if err := r.ensureConnectionAllocations(ctx, log, req.NamespacedName); err != nil {
		return ctrl.Result{}, err
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

	// Reconcile when spec generation changes OR when status (e.g., Connections) changes.
	statusChanged := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldObj, ok1 := e.ObjectOld.(*corev1alpha2.TunnelAgent)
			newObj, ok2 := e.ObjectNew.(*corev1alpha2.TunnelAgent)
			if !ok1 || !ok2 {
				return false
			}
			genChanged := oldObj.GetGeneration() != newObj.GetGeneration()
			statusDiff := !equality.Semantic.DeepEqual(oldObj.Status, newObj.Status)
			return genChanged || statusDiff
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.TunnelAgent{}, builder.WithPredicates(statusChanged)).
		WatchesRawSource(
			source.Kind(mgr.GetCache(), &corev1alpha2.Tunnel{}, mapTunnelToAgents),
		).
		Complete(r)
}

func (r *TunnelAgentReconciler) ensureConnectionAllocations(
	ctx context.Context,
	log logr.Logger,
	key client.ObjectKey,
) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var cur corev1alpha2.TunnelAgent
		if getErr := r.client.Get(ctx, key, &cur); getErr != nil {
			return getErr
		}

		// Track newly made allocations so we can roll them back if Status().Update fails.
		var newlyAllocatedPrefixes []netip.Prefix
		var newlyAllocatedVNIs []uint32

		needsUpdate := false
		addrAssigned := 0
		vniAssigned := 0

		for i := range cur.Status.Connections {
			conn := &cur.Status.Connections[i]

			// Allocate overlay address if missing
			if conn.Address == "" {
				pfx, ipErr := r.agentIPAM.Allocate()
				if ipErr != nil {
					// rollback anything we grabbed this pass
					for _, p := range newlyAllocatedPrefixes {
						_ = r.agentIPAM.Release(p)
					}
					for _, v := range newlyAllocatedVNIs {
						r.vniPool.Free(v)
					}
					log.Error(ipErr, "failed to allocate address")
					return fmt.Errorf("failed to allocate address: %w", ipErr)
				}
				conn.Address = pfx.String()
				newlyAllocatedPrefixes = append(newlyAllocatedPrefixes, pfx)
				addrAssigned++
				needsUpdate = true
			}

			// Allocate VNI if missing (nil means "unset"; zero can be valid but your pool won't return 0)
			if conn.VNI == nil {
				v, vErr := r.vniPool.Allocate()
				if vErr != nil {
					// rollback anything we grabbed this pass
					for _, p := range newlyAllocatedPrefixes {
						_ = r.agentIPAM.Release(p)
					}
					for _, nv := range newlyAllocatedVNIs {
						r.vniPool.Free(nv)
					}
					log.Error(vErr, "failed to allocate VNI")
					return fmt.Errorf("failed to allocate VNI: %w", vErr)
				}
				vInt := int(v) // status uses *int; vniPool returns uint32
				conn.VNI = &vInt
				newlyAllocatedVNIs = append(newlyAllocatedVNIs, v)
				vniAssigned++
				needsUpdate = true
			}
		}

		if !needsUpdate {
			log.Info("no connections missing address or VNI")
			return nil
		}

		// Commit to status; if it fails, release fresh allocations from this attempt.
		if updErr := r.client.Status().Update(ctx, &cur); updErr != nil {
			for _, p := range newlyAllocatedPrefixes {
				_ = r.agentIPAM.Release(p)
			}
			for _, v := range newlyAllocatedVNIs {
				r.vniPool.Free(v)
			}
			log.Error(updErr, "status update failed; released newly allocated resources",
				"addresses", addrAssigned, "vnis", vniAssigned)
			return updErr
		}

		log.Info("assigned resources to connections",
			"addresses", addrAssigned, "vnis", vniAssigned)
		return nil
	})
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

func (r *TunnelAgentReconciler) releaseResourcesIfPresent(log logr.Logger, agent *corev1alpha2.TunnelAgent) error {
	for _, conn := range agent.Status.Connections {
		// Release overlay address/prefix
		if conn.Address != "" {
			if pfx, err := netip.ParsePrefix(conn.Address); err == nil {
				if relErr := r.agentIPAM.Release(pfx); relErr != nil {
					log.Error(relErr, "failed to release prefix", "address", conn.Address)
					return relErr
				}
			} else {
				log.Error(fmt.Errorf("unrecognized address format"), "skipping address release", "address", conn.Address)
			}
		}

		// Release VNI
		if conn.VNI != nil {
			r.vniPool.Free(uint32(*conn.VNI))
		}
	}
	return nil
}
