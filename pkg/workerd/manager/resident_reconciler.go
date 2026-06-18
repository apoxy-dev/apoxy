// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
)

// residentFinalizer drains a revision's cached definition before the
// ServiceRevision is deleted, so a delete races neither the dispatcher's pull
// nor the cache.
const residentFinalizer = "compute.apoxy.dev/resident"

var _ reconcile.Reconciler = &ResidentReconciler{}

// ResidentReconciler is the data-plane half of the APO-796 ServiceManager. It
// runs inside cmd/workerd-manager next to the runsc host, watches
// ServiceRevisions, keeps the single resident workerd up, warms each revision's
// WorkerDefinition (validating the bundle is pullable and the modules build),
// and reports ResidentReady so the minting reconciler can promote LiveRevision.
//
// Request routing is PULL-only in M1: the dispatcher fetches a definition on its
// first request for a revision; this reconciler does not push loads. Readiness
// therefore means "the resident is up AND this revision resolves", which is the
// honest gate that breaks the promote/route chicken-and-egg (the backplane only
// sends a revision's demux header once it is the live revision).
type ResidentReconciler struct {
	client.Client
	resident  host.ResidentRuntime
	store     *Store
	projectID string
}

// NewResidentReconciler returns a resident reconciler driving resident + store,
// scoped to the project the manager serves.
func NewResidentReconciler(c client.Client, resident host.ResidentRuntime, store *Store, projectID string) *ResidentReconciler {
	return &ResidentReconciler{Client: c, resident: resident, store: store, projectID: projectID}
}

// Reconcile keeps the resident up and the revision's ResidentReady condition
// current.
func (r *ResidentReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx, "revision", req.Name)

	rev := &computev1alpha1.ServiceRevision{}
	if err := r.Get(ctx, req.NamespacedName, rev); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	id, idErr := serviceRevisionID(r.projectID, rev)

	// Deletion: drop the cached definition and release the finalizer.
	if !rev.DeletionTimestamp.IsZero() {
		if idErr == nil {
			r.store.Invalidate(id)
		}
		if controllerutil.RemoveFinalizer(rev, residentFinalizer) {
			if err := r.Update(ctx, rev); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// A revision with no service label can't be routed; surface it rather than
	// silently treating it as not-ready forever.
	if idErr != nil {
		r.setResidentReady(rev, metav1.ConditionFalse, "Unroutable", idErr.Error())
		return ctrl.Result{}, r.Status().Update(ctx, rev)
	}

	if controllerutil.AddFinalizer(rev, residentFinalizer) {
		// Persist the finalizer before doing work, then reconcile the freshly
		// updated object on the next pass.
		if err := r.Update(ctx, rev); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Keep the single resident up (idempotent; self-heals if it died).
	if _, err := r.resident.EnsureResident(ctx); err != nil {
		log.Error(err, "Resident not ready")
		r.setResidentReady(rev, metav1.ConditionFalse, "ResidentDown", err.Error())
		// Surface the error so controller-runtime backs off and retries.
		if uerr := r.Status().Update(ctx, rev); uerr != nil {
			return ctrl.Result{}, uerr
		}
		return ctrl.Result{}, fmt.Errorf("ensuring resident: %w", err)
	}

	// Validate the revision resolves (bundle pullable, modules build). On success
	// the definition is cached so the dispatcher's first pull is served warm.
	if _, err := r.store.Warm(ctx, id); err != nil {
		log.Error(err, "Worker definition not resolvable")
		r.setResidentReady(rev, metav1.ConditionFalse, "DefinitionUnavailable", err.Error())
		return ctrl.Result{RequeueAfter: requeueAwaitBuild}, r.Status().Update(ctx, rev)
	}

	r.setResidentReady(rev, metav1.ConditionTrue, "Loadable", "resident is up and the worker definition resolved")
	return ctrl.Result{}, r.Status().Update(ctx, rev)
}

// setResidentReady writes the ResidentReady condition on the revision status.
func (r *ResidentReconciler) setResidentReady(rev *computev1alpha1.ServiceRevision, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&rev.Status.Conditions, metav1.Condition{
		Type:               computev1alpha1.ConditionResidentReady,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: rev.Generation,
	})
}

// SetupWithManager registers the reconciler with the manager.
func (r *ResidentReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("compute-resident").
		For(&computev1alpha1.ServiceRevision{}).
		Complete(r)
}
