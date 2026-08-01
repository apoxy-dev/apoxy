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
	"errors"
	"fmt"
	"log/slog"
	"sort"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
)

// serviceLabel links a minted ServiceRevision (and a Build) back to its Service.
const serviceLabel = "compute.apoxy.dev/service"

// defaultRevisionHistoryLimit is used when Service.spec.revisionHistoryLimit is
// unset.
const defaultRevisionHistoryLimit = 10

// mintingConcurrency is how many Services this reconciler mints in parallel.
// Minting a tag-sourced Service does a registry round trip bounded by
// registryResolveTimeout, and controller-runtime defaults to a single worker,
// so one project pointing at a slow or unreachable registry would otherwise
// stall every other Service's rollout behind it for 30 seconds at a time.
// Keyed per Service, so a given Service is still never minted concurrently
// with itself.
const mintingConcurrency = 4

var _ reconcile.Reconciler = &ServiceReconciler{}

// ServiceReconciler mints immutable ServiceRevisions from a Service's
// spec.template + spec.source, tracks LatestRevision/LiveRevision, and GCs old
// revisions. It is platform-neutral (no runsc, no workerd) and registers into
// the apiserver's manager via apiserver.WithAdditionalController.
type ServiceReconciler struct {
	client.Client
	scheme     *runtime.Scheme
	resolveTag TagResolver
}

// TagResolver turns a tag-bearing BundleRef into the digest the tag names.
type TagResolver func(context.Context, computev1alpha1.BundleRef) (string, error)

// ServiceReconcilerOption configures a ServiceReconciler.
type ServiceReconcilerOption func(*ServiceReconciler)

// WithTagResolver replaces the default direct-to-registry tag resolution.
//
// The default reaches the registry over the network with whatever credentials
// the BundleRef carries, which is right for a customer's own registry and
// wrong for the platform registry: a hosted control plane authenticates to its
// own registry out of band, not with a credential stored on the object. That
// wiring is deployment-specific, so it is injected rather than assumed here.
func WithTagResolver(resolve TagResolver) ServiceReconcilerOption {
	return func(r *ServiceReconciler) {
		if resolve != nil {
			r.resolveTag = resolve
		}
	}
}

// NewServiceReconciler returns a ServiceReconciler. The scheme is captured from
// the manager in SetupWithManager.
func NewServiceReconciler(c client.Client, opts ...ServiceReconcilerOption) *ServiceReconciler {
	r := &ServiceReconciler{Client: c, resolveTag: ResolveRegistryTag}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// invalidSourceError separates a malformed stored source, which cannot heal
// without a Service update, from a registry failure, which should be retried.
type invalidSourceError struct {
	message string
}

func (e *invalidSourceError) Error() string { return e.message }

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
	bundle, ready, err := r.resolveBundle(ctx, svc)
	if err != nil {
		var invalid *invalidSourceError
		terminal := errors.As(err, &invalid)
		reason := "BundleResolutionFailed"
		if terminal {
			reason = "InvalidSource"
		} else {
			slog.WarnContext(ctx, "Failed to resolve service bundle", "service", svc.Name, "error", err)
		}
		meta.SetStatusCondition(&svc.Status.Conditions, metav1.Condition{
			Type: computev1alpha1.ConditionAccepted, Status: metav1.ConditionFalse,
			Reason: reason, Message: err.Error(), ObservedGeneration: svc.Generation,
		})
		svc.Status.ObservedGeneration = svc.Generation
		if updateErr := r.Status().Update(ctx, svc); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		if terminal {
			// A malformed source cannot heal on its own. Fixing it is a spec
			// edit, which bumps generation and re-enqueues.
			return ctrl.Result{}, nil
		}
		// Registry failures take the workqueue's exponential backoff instead
		// of a flat requeue. A typo'd tag or a revoked credential otherwise
		// re-hits the registry every 15s for the life of the process — enough
		// to trip a shared registry's rate limits and break pulls for healthy
		// services on the same host — while backoff still recovers on its own
		// once the registry is fixed.
		return ctrl.Result{}, err
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
	slog.InfoContext(ctx, "Reconciled service revision", "service", svc.Name, "revision", rev.Name)

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
		slog.ErrorContext(ctx, "Failed to garbage collect service revisions", "service", svc.Name, "error", err)
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
			return computev1alpha1.BundleRef{}, false, &invalidSourceError{message: "spec.source.oci.repo is required"}
		}
		if b.Digest == "" && b.Tag == "" {
			return computev1alpha1.BundleRef{}, false, &invalidSourceError{message: "spec.source.oci needs a digest or tag"}
		}
		if b.Digest == "" {
			resolveTag := r.resolveTag
			if resolveTag == nil {
				resolveTag = ResolveRegistryTag
			}
			digest, err := resolveTag(ctx, b)
			if err != nil {
				return computev1alpha1.BundleRef{}, false, fmt.Errorf("resolving bundle tag %s:%s: %w", b.Repo, b.Tag, err)
			}
			b.Digest = digest
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
		return computev1alpha1.BundleRef{}, false, &invalidSourceError{message: "spec.source has neither oci nor git set"}
	}
}

// ResolveRegistryTag asks the registry which immutable digest a tag currently
// names. Resolution happens in the control plane, not per node, so that every
// node running the minted revision pulls the identical digest — a tag resolved
// per-node would let two backplanes serve different code under one revision.
//
// The repository comes from host.BundleRepositoryFor rather than being built
// here, so it picks up the BundleRef's own credentials and whatever platform
// TLS the process installed (host.SetPlatformPullTLS) — an open-coded
// bundle.NewRepository silently drops the latter and 401s on exactly the
// platform-registry bundles. A control plane that holds no registry identity
// of its own resolves those through its own path instead; see WithTagResolver.
func ResolveRegistryTag(ctx context.Context, ref computev1alpha1.BundleRef) (string, error) {
	repository, err := host.BundleRepositoryFor(ref)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, registryResolveTimeout)
	defer cancel()

	descriptor, err := repository.Resolve(ctx, ref.Tag)
	if err != nil {
		return "", fmt.Errorf("resolving registry reference: %w", err)
	}
	if err := descriptor.Digest.Validate(); err != nil {
		return "", fmt.Errorf("registry returned an invalid digest: %w", err)
	}
	return descriptor.Digest.String(), nil
}

// ensureRevision get-or-creates the deterministically-named immutable
// ServiceRevision for the current template + bundle.
func (r *ServiceReconciler) ensureRevision(ctx context.Context, svc *computev1alpha1.Service, bundle computev1alpha1.BundleRef) (*computev1alpha1.ServiceRevision, error) {
	legacyName := revisionNameFor(svc.Name, svc.Spec.Template.Spec, bundle)
	bundle = digestPinnedRevisionBundle(bundle)
	name := revisionName(svc, bundle)

	rev := &computev1alpha1.ServiceRevision{}
	err := r.Get(ctx, client.ObjectKey{Name: name}, rev)
	if err == nil {
		return rev, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}

	// Older revisions could retain a tag alongside their digest. Reuse one when
	// it points at the same artifact instead of creating a duplicate solely
	// because new revisions are stored without that tag.
	existing, err := r.findEquivalentRevision(ctx, svc, name, legacyName)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return existing, nil
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

type equivalentRevisionSet struct {
	byName      map[string]*computev1alpha1.ServiceRevision
	newestFirst []*computev1alpha1.ServiceRevision
}

func newEquivalentRevisionSet(
	serviceName string,
	canonicalName string,
	revisions []computev1alpha1.ServiceRevision,
) equivalentRevisionSet {
	set := equivalentRevisionSet{byName: make(map[string]*computev1alpha1.ServiceRevision)}
	for i := range revisions {
		revision := &revisions[i]
		name := revisionNameFor(
			serviceName,
			revision.Spec.ServiceConfigSpec,
			digestPinnedRevisionBundle(revision.Spec.Bundle),
		)
		if name != canonicalName {
			continue
		}
		set.byName[revision.Name] = revision
		set.newestFirst = append(set.newestFirst, revision)
	}

	sort.Slice(set.newestFirst, func(i, j int) bool {
		left, right := set.newestFirst[i], set.newestFirst[j]
		if left.CreationTimestamp.Equal(&right.CreationTimestamp) {
			return left.Name > right.Name
		}
		return left.CreationTimestamp.After(right.CreationTimestamp.Time)
	})
	return set
}

func (set equivalentRevisionSet) selectRevision(preferredNames ...string) *computev1alpha1.ServiceRevision {
	for _, name := range preferredNames {
		if revision := set.byName[name]; revision != nil {
			return revision
		}
	}
	if len(set.newestFirst) == 0 {
		return nil
	}
	return set.newestFirst[0]
}

// findEquivalentRevision finds an existing revision with the same template and digest.
func (r *ServiceReconciler) findEquivalentRevision(
	ctx context.Context,
	svc *computev1alpha1.Service,
	canonicalName string,
	legacyName string,
) (*computev1alpha1.ServiceRevision, error) {
	revs := &computev1alpha1.ServiceRevisionList{}
	if err := r.List(ctx, revs, client.MatchingLabels{serviceLabel: svc.Name}); err != nil {
		return nil, fmt.Errorf("listing equivalent revisions: %w", err)
	}

	set := newEquivalentRevisionSet(svc.Name, canonicalName, revs.Items)
	return set.selectRevision(
		svc.Status.LatestRevision,
		svc.Spec.LiveRevision,
		svc.Status.LiveRevision,
		legacyName,
	), nil
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

// digestPinnedRevisionBundle converts a resolved Service source into the
// immutable reference stored on a ServiceRevision. The source may retain its
// human-facing tag, but edge nodes receive only the resolved digest.
func digestPinnedRevisionBundle(bundle computev1alpha1.BundleRef) computev1alpha1.BundleRef {
	pinned := *bundle.DeepCopy()
	if pinned.Digest != "" {
		pinned.Tag = ""
	}
	return pinned
}

// revisionName is the deterministic immutable name for a revision: the service
// name plus a short hash of the template config and the resolved bundle. A
// template or bundle change yields a new name (a new revision).
func revisionName(svc *computev1alpha1.Service, bundle computev1alpha1.BundleRef) string {
	bundle = digestPinnedRevisionBundle(bundle)
	return revisionNameFor(svc.Name, svc.Spec.Template.Spec, bundle)
}

// revisionNameFor hashes exactly the supplied inputs. Keeping digest-only
// conversion in revisionName lets migration code also reconstruct an older
// name that included both digest and tag.
func revisionNameFor(service string, spec computev1alpha1.ServiceConfigSpec, bundle computev1alpha1.BundleRef) string {
	h := sha256.New()
	enc := json.NewEncoder(h)
	_ = enc.Encode(spec)
	_ = enc.Encode(struct{ Repo, Digest, Tag string }{bundle.Repo, bundle.Digest, bundle.Tag})
	return fmt.Sprintf("%s-%x", service, h.Sum(nil)[:5])
}

// SetupWithManager registers the reconciler with the manager.
func (r *ServiceReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	r.scheme = mgr.GetScheme()
	return ctrl.NewControllerManagedBy(mgr).
		Named("compute-service-minting").
		WithOptions(controller.Options{MaxConcurrentReconciles: mintingConcurrency}).
		For(&computev1alpha1.Service{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// Minted revisions are immutable, so an update to one tells the minter
		// nothing — and reconciling on it would re-resolve the Service's tag,
		// minting a new revision because a tag moved in the registry rather
		// than because anyone changed the spec. Creates and deletes still
		// matter: a deleted revision has to be re-minted.
		Owns(&computev1alpha1.ServiceRevision{}, builder.WithPredicates(predicate.Funcs{
			UpdateFunc: func(event.UpdateEvent) bool { return false },
		})).
		// A git-sourced Service runs the newest succeeded Build. Without this
		// watch the only thing noticing a build finish was the requeueAwaitBuild
		// poll, which stops once a revision exists — so the first build rolled
		// out and every later one sat there until the Service was edited.
		Watches(&computev1alpha1.Build{}, handler.EnqueueRequestsFromMapFunc(enqueueBuildService)).
		Complete(r)
}

// enqueueBuildService maps a Build to the Service that owns it.
func enqueueBuildService(_ context.Context, obj client.Object) []reconcile.Request {
	build, ok := obj.(*computev1alpha1.Build)
	if !ok || build.Spec.ServiceRef == "" {
		return nil
	}
	return []reconcile.Request{{
		NamespacedName: client.ObjectKey{Name: string(build.Spec.ServiceRef)},
	}}
}
