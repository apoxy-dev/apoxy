// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"fmt"
	"sort"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
)

var _ reconcile.Reconciler = &ResidentReconciler{}

// ResidentReconciler is the data-plane half of the APO-796 ServiceManager for
// ONE tenant: it reconciles that tenant's ServiceRevisions against its
// resident and store using a project-scoped client. It is constructed per
// ReconcileWithClient call by ResidentManager (which owns the long-lived
// per-tenant state), mirroring how tunnelproxy's shard wrapper drives
// TunnelServer.ReconcileWithClient with the per-cluster client. It keeps the
// tenant's resident workerd up, warms each revision's WorkerDefinition
// (validating the bundle is pullable and the modules build), and records THIS
// node's serveable revision per service so the resident's dispatcher can
// resolve it via /resolve.
//
// It is strictly READ-ONLY on the Service/ServiceRevision API objects: with
// dozens-to-hundreds of revisions across N nodes, a data-plane writer on a shared,
// cluster-scoped object is a last-writer-wins race and write amplification. So
// readiness is NOT recorded on the Revision; the resident resolves what it can
// serve from this node's local warm state.
//
// Request routing is PULL-only in M1: the dispatcher fetches a definition on its
// first request for a revision. "Readiness" therefore means "the resident is up
// AND this node has warmed this revision", and the node serves the newest
// revision it has warmed per service — so it keeps serving the PREVIOUS revision
// until it has pulled a new one (make-before-break, the interim promotion model).
type ResidentReconciler struct {
	client.Client
	resident host.ResidentRuntime
	store    *Store
}

// NewResidentReconciler returns a resident reconciler driving resident + store.
// The demux it computes per reconcile is recorded on the store for the control
// server's /resolve handler; nothing is pushed off-node.
func NewResidentReconciler(c client.Client, resident host.ResidentRuntime, store *Store) *ResidentReconciler {
	return &ResidentReconciler{
		Client:   c,
		resident: resident,
		store:    store,
	}
}

// Reconcile keeps the resident up, warms the revision into the store, and
// republishes this node's serveable routing state. It never writes the API object.
func (r *ResidentReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx, "revision", req.Name)

	rev := &computev1alpha1.ServiceRevision{}
	if err := r.Get(ctx, req.NamespacedName, rev); err != nil {
		if apierrors.IsNotFound(err) {
			// The revision is gone (GC or cascade delete). Republish so this node
			// stops advertising it; the store is pruned to the surviving set inside
			// republish (no finalizer needed — the cache is non-authoritative and
			// the workerd isolate idles out on its own).
			return ctrl.Result{}, r.refreshDemux(ctx)
		}
		return ctrl.Result{}, err
	}

	id, idErr := serviceRevisionID(rev)

	// Terminating or unroutable (no service label): nothing to warm; just refresh
	// the published view (which drops the revision from this node's serveable set).
	if !rev.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.refreshDemux(ctx)
	}
	if idErr != nil {
		log.Info("Skipping unroutable revision (no service label)", "error", idErr.Error())
		return ctrl.Result{}, r.refreshDemux(ctx)
	}

	// Keep the tenant's resident up (idempotent; self-heals if it died).
	if _, err := r.resident.EnsureResident(ctx); err != nil {
		// No API write: surface the error so controller-runtime backs off and retries.
		return ctrl.Result{}, fmt.Errorf("ensuring resident: %w", err)
	}

	// Validate the revision resolves (bundle pullable, modules build) and cache it
	// so the dispatcher's first pull is served warm. On failure the node keeps
	// advertising whatever it has already warmed (the previous revision) and retries.
	if _, err := r.store.Warm(ctx, id); err != nil {
		log.Error(err, "Worker definition not resolvable; keeping previous revision live")
		if perr := r.refreshDemux(ctx); perr != nil {
			return ctrl.Result{}, perr
		}
		return ctrl.Result{RequeueAfter: requeueAwaitBuild}, nil
	}

	// Warmed: advertise this node's now-current serveable set.
	return ctrl.Result{}, r.refreshDemux(ctx)
}

// refreshDemux computes this node's serveable demux from local warm state and
// records it for the control server's /resolve handler. For each service it
// selects an explicit spec.liveRevision pin once warmed, else the NEWEST revision
// this node has warmed — so a node serves the previous revision until it pulls the
// new one. It also prunes the store to the surviving revision set. No API object
// is written and nothing leaves the node.
func (r *ResidentReconciler) refreshDemux(ctx context.Context) error {
	revs := &computev1alpha1.ServiceRevisionList{}
	if err := r.List(ctx, revs); err != nil {
		return fmt.Errorf("listing revisions: %w", err)
	}
	svcs := &computev1alpha1.ServiceList{}
	if err := r.List(ctx, svcs); err != nil {
		return fmt.Errorf("listing services: %w", err)
	}

	// Pinned revision per service (spec.liveRevision), if any.
	pin := make(map[string]string, len(svcs.Items))
	for i := range svcs.Items {
		s := &svcs.Items[i]
		if s.Spec.LiveRevision != "" {
			pin[s.Name] = s.Spec.LiveRevision
		}
	}

	// Group revisions by service (newest first) and collect the valid id set.
	type rinfo struct {
		name    string
		created int64
	}
	byService := make(map[string][]rinfo)
	valid := make(map[string]bool, len(revs.Items))
	for i := range revs.Items {
		rev := &revs.Items[i]
		svc := rev.Labels[serviceLabel]
		if svc == "" {
			continue
		}
		valid[demuxID(svc, rev.Name)] = true
		byService[svc] = append(byService[svc], rinfo{name: rev.Name, created: rev.CreationTimestamp.UnixNano()})
	}
	r.store.retain(valid)

	demux := make(map[string]string)
	for svc, list := range byService {
		sort.SliceStable(list, func(i, j int) bool { return list[i].created > list[j].created })
		if p, ok := pin[svc]; ok && r.store.cached(demuxID(svc, p)) {
			demux[svc] = p
			continue
		}
		for _, ri := range list {
			if r.store.cached(demuxID(svc, ri.name)) {
				demux[svc] = ri.name
				break
			}
		}
	}

	// Record the selection so the control server's /resolve handler can map a
	// service to its live revision id for the dispatcher.
	r.store.setDemux(demux)
	return nil
}
