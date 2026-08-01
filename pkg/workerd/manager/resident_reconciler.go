// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
)

const (
	// warmConcurrency bounds simultaneous bundle pulls in one reconcile pass.
	// The whole catalog is refreshed under a single queue key, so without a
	// bound a project with a large service count would open one registry
	// connection per service on every cold start.
	warmConcurrency = 4

	// warmRetryLimit is how many consecutive fast retries a failing warm gets
	// before it falls back to the periodic resync. The early attempts cover
	// make-before-break — a freshly minted revision whose bundle is still
	// propagating. Past that the failure is not transient, and re-pulling every
	// requeueAwaitBuild only adds registry load for a revision that is not
	// going to appear, so it degrades to demuxResyncInterval.
	warmRetryLimit = 4
)

var _ reconcile.Reconciler = &ResidentReconciler{}

// ResidentReconciler maintains one tenant's local routes and warmed definitions.
type ResidentReconciler struct {
	client.Client
	resident host.ResidentRuntime
	store    *Store

	// warmFailures counts consecutive warm failures per definition id. A
	// revision whose bundle never becomes pullable would otherwise hold the
	// tenant on the short retry interval for the life of the process.
	warmMu       sync.Mutex
	warmFailures map[string]int
}

type revisionCandidate struct {
	name      string
	createdAt int64
	// terminating marks a revision with a deletionTimestamp. It stays in the
	// catalog so its definition is not pruned and this node can keep serving
	// it through the deletion grace window, but it is never newly selected.
	terminating bool
}

type serviceRevisionCandidates struct {
	serviceName    string
	pinnedRevision string
	// latestRevision is the Service's status.latestRevision — the revision the
	// control plane minted most recently. Used only to break creation-time
	// ties; see ordered().
	latestRevision string
	revisions      []revisionCandidate
}

func (c serviceRevisionCandidates) definitionID(revisionName string) string {
	return demuxID(c.serviceName, revisionName)
}

// pinnedCandidate returns the candidate named by spec.liveRevision, if that
// revision still exists and is not being deleted.
func (c serviceRevisionCandidates) pinnedCandidate() (revisionCandidate, bool) {
	if c.pinnedRevision == "" {
		return revisionCandidate{}, false
	}
	for _, revision := range c.revisions {
		if revision.name == c.pinnedRevision && !revision.terminating {
			return revision, true
		}
	}
	return revisionCandidate{}, false
}

// ordered returns the selectable candidates, newest first.
//
// metav1.Time serializes at second granularity on both the JSON and protobuf
// paths, so two revisions minted in the same second decode to identical
// timestamps — common when a pipeline pushes twice or an edit is immediately
// corrected. Ties therefore have to be broken on something meaningful:
// status.latestRevision is what the control plane most recently minted, so it
// wins. Revision names are a truncated SHA of the template and bundle and
// carry no ordering at all, so they are only a last resort to keep the sort
// total and deterministic.
func (c serviceRevisionCandidates) ordered() []revisionCandidate {
	ordered := make([]revisionCandidate, 0, len(c.revisions))
	for _, revision := range c.revisions {
		if revision.terminating {
			continue
		}
		ordered = append(ordered, revision)
	}

	sort.Slice(ordered, func(i, j int) bool {
		left, right := ordered[i], ordered[j]
		if left.createdAt != right.createdAt {
			return left.createdAt > right.createdAt
		}
		if c.latestRevision != "" && (left.name == c.latestRevision) != (right.name == c.latestRevision) {
			return left.name == c.latestRevision
		}
		return left.name > right.name
	})

	if c.pinnedRevision == "" {
		return ordered
	}
	for i, revision := range ordered {
		if revision.name == c.pinnedRevision {
			copy(ordered[1:i+1], ordered[:i])
			ordered[0] = revision
			break
		}
	}
	return ordered
}

type revisionCatalog struct {
	services          []serviceRevisionCandidates
	activeDefinitions map[string]struct{}
}

func newRevisionCatalog(services []computev1alpha1.Service, revisions []computev1alpha1.ServiceRevision) revisionCatalog {
	type servicePolicy struct {
		pinned string
		latest string
	}
	policies := make(map[string]servicePolicy, len(services))
	for i := range services {
		policies[services[i].Name] = servicePolicy{
			pinned: services[i].Spec.LiveRevision,
			latest: services[i].Status.LatestRevision,
		}
	}

	grouped := make(map[string][]revisionCandidate)
	definitions := make(map[string]struct{}, len(revisions))
	for i := range revisions {
		revision := &revisions[i]
		serviceName := revision.Labels[serviceLabel]
		if serviceName == "" {
			continue
		}

		grouped[serviceName] = append(grouped[serviceName], revisionCandidate{
			name:        revision.Name,
			createdAt:   revision.CreationTimestamp.UnixNano(),
			terminating: !revision.DeletionTimestamp.IsZero(),
		})
		// Terminating revisions are kept here too: their definitions must
		// survive retain() so a node already serving one is not cut off
		// mid-grace-window.
		definitions[demuxID(serviceName, revision.Name)] = struct{}{}
	}

	serviceNames := make([]string, 0, len(grouped))
	for serviceName := range grouped {
		serviceNames = append(serviceNames, serviceName)
	}
	sort.Strings(serviceNames)

	catalog := revisionCatalog{activeDefinitions: definitions}
	for _, serviceName := range serviceNames {
		policy := policies[serviceName]
		catalog.services = append(catalog.services, serviceRevisionCandidates{
			serviceName:    serviceName,
			pinnedRevision: policy.pinned,
			latestRevision: policy.latest,
			revisions:      grouped[serviceName],
		})
	}
	return catalog
}

type revisionSelection struct {
	revisionName string
	needsRetry   bool
}

// NewResidentReconciler returns a resident reconciler driving resident + store.
func NewResidentReconciler(c client.Client, resident host.ResidentRuntime, store *Store) *ResidentReconciler {
	return &ResidentReconciler{
		Client:       c,
		resident:     resident,
		store:        store,
		warmFailures: make(map[string]int),
	}
}

// Reconcile refreshes local routing and schedules a periodic resync. It runs
// under a single queue key covering the whole tenant, so it refreshes every
// service rather than the one named in the request.
func (r *ResidentReconciler) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	catalog, err := r.loadRevisionCatalog(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}

	if len(catalog.services) > 0 {
		if _, err := r.resident.EnsureResident(ctx); err != nil {
			return ctrl.Result{}, fmt.Errorf("ensuring resident: %w", err)
		}
	}

	previousRoutes := r.store.demuxSnapshot()

	retained := make(map[string]struct{}, len(catalog.activeDefinitions)+len(catalog.services))
	for id := range catalog.activeDefinitions {
		retained[id] = struct{}{}
	}
	routed := make(map[string]struct{}, len(catalog.services))

	var (
		mu         sync.Mutex
		needsRetry bool
		wg         sync.WaitGroup
	)
	slots := make(chan struct{}, warmConcurrency)
	for _, service := range catalog.services {
		wg.Add(1)
		go func(service serviceRevisionCandidates) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()

			selection := r.selectRevision(ctx, service, previousRoutes[service.serviceName])

			mu.Lock()
			defer mu.Unlock()
			needsRetry = needsRetry || selection.needsRetry
			if selection.revisionName == "" {
				return
			}
			routed[service.serviceName] = struct{}{}
			// The selected revision may be one the control plane has already
			// garbage-collected (holding the previous route through a warm
			// gap), so it is not necessarily in activeDefinitions.
			retained[service.definitionID(selection.revisionName)] = struct{}{}
			r.store.publishRoute(service.serviceName, selection.revisionName)
		}(service)
	}
	wg.Wait()

	r.store.retain(retained)
	r.store.pruneRoutes(routed)

	if needsRetry {
		return ctrl.Result{RequeueAfter: requeueAwaitBuild}, nil
	}
	return ctrl.Result{RequeueAfter: demuxResyncInterval}, nil
}

func (r *ResidentReconciler) loadRevisionCatalog(ctx context.Context) (revisionCatalog, error) {
	revisions := &computev1alpha1.ServiceRevisionList{}
	if err := r.List(ctx, revisions); err != nil {
		return revisionCatalog{}, fmt.Errorf("listing revisions: %w", err)
	}
	services := &computev1alpha1.ServiceList{}
	if err := r.List(ctx, services); err != nil {
		return revisionCatalog{}, fmt.Errorf("listing services: %w", err)
	}
	return newRevisionCatalog(services.Items, revisions.Items), nil
}

func (r *ResidentReconciler) selectRevision(ctx context.Context, service serviceRevisionCandidates, previousRevision string) revisionSelection {
	selection := revisionSelection{}

	// An explicit spec.liveRevision is a directive, not a preference: it is how
	// an operator rolls back off a bad revision. Falling through to the next
	// candidate would serve the newest revision — exactly the one being rolled
	// away from — so a pin that will not warm holds whatever this node already
	// serves and retries, rather than promoting something the operator
	// deselected.
	if pinned, ok := service.pinnedCandidate(); ok {
		if err := r.warmRevision(ctx, service, pinned, true); err != nil {
			selection.needsRetry = r.shouldRetryWarm(service.definitionID(pinned.name))
			return r.holdPrevious(selection, service, previousRevision)
		}
		selection.revisionName = pinned.name
		return selection
	}

	for priority, revision := range service.ordered() {
		if err := r.warmRevision(ctx, service, revision, priority == 0); err != nil {
			// Only the preferred candidate is worth retrying for. An older
			// fallback that cannot warm is not what this node is trying to
			// serve, and counting it would hold the whole tenant on the short
			// retry interval because of a revision nobody is waiting on.
			if priority == 0 {
				selection.needsRetry = r.shouldRetryWarm(service.definitionID(revision.name))
			}
			continue
		}
		selection.revisionName = revision.name
		return selection
	}

	return r.holdPrevious(selection, service, previousRevision)
}

// holdPrevious keeps this node on the revision it already serves when nothing
// selectable would warm, so a registry blip degrades to "no rollout yet"
// instead of dropping the service's route entirely.
func (r *ResidentReconciler) holdPrevious(
	selection revisionSelection,
	service serviceRevisionCandidates,
	previousRevision string,
) revisionSelection {
	if previousRevision != "" && r.store.cached(service.definitionID(previousRevision)) {
		selection.revisionName = previousRevision
	}
	return selection
}

func (r *ResidentReconciler) warmRevision(ctx context.Context, service serviceRevisionCandidates, revision revisionCandidate, preferred bool) error {
	id := service.definitionID(revision.name)
	if r.store.cached(id) {
		r.recordWarmResult(id, nil)
		return nil
	}

	if _, err := r.store.Warm(ctx, id); err != nil {
		r.recordWarmResult(id, err)
		if preferred {
			slog.WarnContext(ctx, "Failed to warm selected service revision",
				"service", service.serviceName, "revision", revision.name, "error", err)
		} else {
			slog.DebugContext(ctx, "Failed to warm fallback service revision",
				"service", service.serviceName, "revision", revision.name, "error", err)
		}
		return err
	}
	r.recordWarmResult(id, nil)
	return nil
}

// recordWarmResult tracks consecutive failures per definition so a permanently
// unpullable bundle stops driving the short retry interval.
func (r *ResidentReconciler) recordWarmResult(id string, err error) {
	r.warmMu.Lock()
	defer r.warmMu.Unlock()
	if r.warmFailures == nil {
		r.warmFailures = make(map[string]int)
	}
	if err == nil {
		delete(r.warmFailures, id)
		return
	}
	r.warmFailures[id]++
}

// shouldRetryWarm reports whether id has failed few enough times in a row to
// still be worth the short retry interval. Past the limit the periodic resync
// keeps retrying, just without hammering the registry.
func (r *ResidentReconciler) shouldRetryWarm(id string) bool {
	r.warmMu.Lock()
	defer r.warmMu.Unlock()
	return r.warmFailures[id] <= warmRetryLimit
}
