// SPDX-License-Identifier: AGPL-3.0-only

// Package manager implements the APO-796 ServiceManager: the control-plane
// Service->ServiceRevision minting reconciler (platform-neutral, this file) and
// the data-plane resident reconciler (resident_reconciler.go) that drives the
// workerd resident and publishes this node's serveable routing. The minting
// reconciler runs inside the apiserver via apiserver.WithAdditionalController; the
// resident reconciler runs inside cmd/workerd-manager next to the runsc host and
// is strictly read-only on the API.
package manager

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

// serviceLabel links a minted ServiceRevision (and a Build) back to its Service.
const serviceLabel = "compute.apoxy.dev/service"

// defaultRevisionHistoryLimit is used when Service.spec.revisionHistoryLimit is
// unset.
const defaultRevisionHistoryLimit = 10

var _ reconcile.Reconciler = &ServiceReconciler{}

// ServiceReconciler mints immutable ServiceRevisions from a Service's
// spec.template + spec.source, tracks LatestRevision/LiveRevision, and GCs old
// revisions. It is platform-neutral (no runsc, no workerd) and registers into
// the apiserver's manager via apiserver.WithAdditionalController.
type ServiceReconciler struct {
	client.Client
	scheme *runtime.Scheme
}

// NewServiceReconciler returns a ServiceReconciler. The scheme is captured from
// the manager in SetupWithManager.
func NewServiceReconciler(c client.Client) *ServiceReconciler {
	return &ServiceReconciler{Client: c}
}

// Reconcile mints/promotes/GCs revisions for one Service.
func (r *ServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	svc := &computev1alpha1.Service{}
	if err := r.Get(ctx, req.NamespacedName, svc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !svc.DeletionTimestamp.IsZero() {
		// Minted revisions are owned (controllerRef) and cascade-delete; nothing
		// to do on Service deletion.
		return ctrl.Result{}, nil
	}

	log := clog.FromContext(ctx, "service", svc.Name)

	bundle, ready, err := r.resolveBundle(ctx, svc)
	if err != nil {
		// Invalid spec: surface as Accepted=False, do not hot-requeue.
		meta.SetStatusCondition(&svc.Status.Conditions, metav1.Condition{
			Type: computev1alpha1.ConditionAccepted, Status: metav1.ConditionFalse,
			Reason: "InvalidSource", Message: err.Error(), ObservedGeneration: svc.Generation,
		})
		svc.Status.ObservedGeneration = svc.Generation
		return ctrl.Result{}, r.Status().Update(ctx, svc)
	}
	if !ready {
		// Waiting on a build to produce a bundle.
		meta.SetStatusCondition(&svc.Status.Conditions, metav1.Condition{
			Type: computev1alpha1.ConditionAccepted, Status: metav1.ConditionFalse,
			Reason: "AwaitingBuild", Message: "no successful build has produced a bundle yet",
			ObservedGeneration: svc.Generation,
		})
		svc.Status.ObservedGeneration = svc.Generation
		return ctrl.Result{RequeueAfter: requeueAwaitBuild}, r.Status().Update(ctx, svc)
	}

	rev, err := r.ensureRevision(ctx, svc, bundle)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("ensuring ServiceRevision: %w", err)
	}
	log.Info("Reconciled ServiceRevision", "revision", rev.Name)

	svc.Status.LatestRevision = rev.Name
	svc.Status.ObservedGeneration = svc.Generation
	meta.SetStatusCondition(&svc.Status.Conditions, metav1.Condition{
		Type: computev1alpha1.ConditionAccepted, Status: metav1.ConditionTrue,
		Reason: "Minted", Message: "ServiceRevision minted from spec.template",
		ObservedGeneration: svc.Generation,
	})

	// LiveRevision records the INTENDED revision (an explicit spec.liveRevision pin,
	// else the latest minted). It is NOT readiness-gated here: which revision each
	// backplane actually serves is a per-node decision the workerd-manager reports
	// over the private publish channel — it keeps serving the previous revision
	// until it has pulled the new bundle (make-before-break). The control plane no
	// longer waits on a data-plane readiness signal, because the data plane never
	// writes the API (it cannot: the revision is cluster-scoped and shared by N
	// nodes). Per-node "serve previous until this backplane pulled it" lives in
	// pkg/workerd/manager; full promotion policy is a design follow-up.
	target := svc.Spec.LiveRevision
	if target == "" {
		target = rev.Name
	}
	svc.Status.LiveRevision = target

	if err := r.Status().Update(ctx, svc); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.gcRevisions(ctx, svc); err != nil {
		log.Error(err, "Revision GC failed (non-fatal)")
	}

	return ctrl.Result{}, nil
}

// resolveBundle resolves spec.source to the digest-pinned BundleRef the revision
// will run. ready=false means a build is still pending (git source).
func (r *ServiceReconciler) resolveBundle(ctx context.Context, svc *computev1alpha1.Service) (computev1alpha1.BundleRef, bool, error) {
	src := svc.Spec.Source
	switch {
	case src.OCI != nil:
		b := *src.OCI
		if b.Repo == "" {
			return computev1alpha1.BundleRef{}, false, fmt.Errorf("spec.source.oci.repo is required")
		}
		if b.Digest == "" && b.Tag == "" {
			return computev1alpha1.BundleRef{}, false, fmt.Errorf("spec.source.oci needs a digest or tag")
		}
		return b, true, nil
	case src.Git != nil:
		builds := &computev1alpha1.BuildList{}
		if err := r.List(ctx, builds); err != nil {
			return computev1alpha1.BundleRef{}, false, fmt.Errorf("listing builds: %w", err)
		}
		var best *computev1alpha1.Build
		for i := range builds.Items {
			b := &builds.Items[i]
			if string(b.Spec.ServiceRef) != svc.Name {
				continue
			}
			if b.Status.Phase != computev1alpha1.BuildSucceeded || b.Status.Bundle == nil {
				continue
			}
			if best == nil || b.CreationTimestamp.After(best.CreationTimestamp.Time) {
				best = b
			}
		}
		if best == nil {
			return computev1alpha1.BundleRef{}, false, nil
		}
		return *best.Status.Bundle, true, nil
	default:
		return computev1alpha1.BundleRef{}, false, fmt.Errorf("spec.source has neither oci nor git set")
	}
}

// ensureRevision get-or-creates the deterministically-named immutable
// ServiceRevision for the current template + bundle.
func (r *ServiceReconciler) ensureRevision(ctx context.Context, svc *computev1alpha1.Service, bundle computev1alpha1.BundleRef) (*computev1alpha1.ServiceRevision, error) {
	name := revisionName(svc, bundle)

	rev := &computev1alpha1.ServiceRevision{}
	err := r.Get(ctx, client.ObjectKey{Name: name}, rev)
	if err == nil {
		return rev, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}

	rev = &computev1alpha1.ServiceRevision{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      map[string]string{serviceLabel: svc.Name},
			Annotations: map[string]string{},
		},
		Spec: computev1alpha1.ServiceRevisionSpec{
			ServiceConfigSpec: *svc.Spec.Template.Spec.DeepCopy(),
			Bundle:            bundle,
		},
	}
	// Propagate template metadata (labels/annotations) onto the minted revision.
	for k, v := range svc.Spec.Template.Labels {
		rev.Labels[k] = v
	}
	for k, v := range svc.Spec.Template.Annotations {
		rev.Annotations[k] = v
	}
	if err := controllerutil.SetControllerReference(svc, rev, r.scheme); err != nil {
		return nil, fmt.Errorf("setting controller reference: %w", err)
	}
	if err := r.Create(ctx, rev); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Raced with another reconcile; re-read.
			if gErr := r.Get(ctx, client.ObjectKey{Name: name}, rev); gErr != nil {
				return nil, gErr
			}
			return rev, nil
		}
		return nil, err
	}
	return rev, nil
}

// gcRevisions deletes revisions beyond RevisionHistoryLimit, oldest first, never
// removing the latest or the live revision.
func (r *ServiceReconciler) gcRevisions(ctx context.Context, svc *computev1alpha1.Service) error {
	limit := defaultRevisionHistoryLimit
	if svc.Spec.RevisionHistoryLimit != nil {
		limit = int(*svc.Spec.RevisionHistoryLimit)
	}

	revs := &computev1alpha1.ServiceRevisionList{}
	if err := r.List(ctx, revs, client.MatchingLabels{serviceLabel: svc.Name}); err != nil {
		return fmt.Errorf("listing revisions: %w", err)
	}
	items := revs.Items
	if len(items) <= limit {
		return nil
	}
	// Oldest first.
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreationTimestamp.Before(&items[j].CreationTimestamp)
	})

	keep := map[string]bool{
		svc.Status.LatestRevision: true,
		svc.Status.LiveRevision:   true,
	}
	// Keep the newest `limit` regardless.
	for i := len(items) - limit; i < len(items); i++ {
		if i >= 0 {
			keep[items[i].Name] = true
		}
	}

	for i := range items {
		rev := &items[i]
		if keep[rev.Name] {
			continue
		}
		if err := r.Delete(ctx, rev); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("deleting revision %s: %w", rev.Name, err)
		}
	}
	return nil
}

// revisionName is the deterministic immutable name for a revision: the service
// name plus a short hash of the template config and the resolved bundle. A
// template or bundle change yields a new name (a new revision).
func revisionName(svc *computev1alpha1.Service, bundle computev1alpha1.BundleRef) string {
	h := sha256.New()
	enc := json.NewEncoder(h)
	_ = enc.Encode(svc.Spec.Template.Spec)
	_ = enc.Encode(struct{ Repo, Digest, Tag string }{bundle.Repo, bundle.Digest, bundle.Tag})
	return fmt.Sprintf("%s-%x", svc.Name, h.Sum(nil)[:5])
}

// SetupWithManager registers the reconciler with the manager.
func (r *ServiceReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	r.scheme = mgr.GetScheme()
	return ctrl.NewControllerManagedBy(mgr).
		Named("compute-service-minting").
		For(&computev1alpha1.Service{}).
		Owns(&computev1alpha1.ServiceRevision{}).
		Complete(r)
}
