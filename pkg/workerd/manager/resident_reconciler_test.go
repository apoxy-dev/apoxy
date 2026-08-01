// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
)

// fakeResident is an in-memory host.ResidentRuntime. Locked: the manager's
// done-watcher drives residents from its own goroutine, concurrently with
// test-goroutine assertions.
type fakeResident struct {
	mu          sync.Mutex
	ensureErr   error
	stopErr     error
	ensureCalls int
	stopCalls   int
}

func (f *fakeResident) EnsureResident(_ context.Context) (*host.ResidentInstance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureCalls++
	if f.ensureErr != nil {
		return nil, f.ensureErr
	}
	return &host.ResidentInstance{SandboxID: "apoxy-workerd-resident", InboundSocket: "/run/in.sock"}, nil
}

func (f *fakeResident) Stop(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalls++
	return f.stopErr
}

func (f *fakeResident) ensured() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ensureCalls
}

func (f *fakeResident) stopped() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopCalls
}

func (f *fakeResident) setStopErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopErr = err
}

func newResidentReconciler(t *testing.T, resident host.ResidentRuntime, f BundleFetcher, objs ...client.Object) (*ResidentReconciler, client.Client) {
	t.Helper()
	c := newFakeClient(t, objs...)
	store := NewStore(newResolverWithFetcher(c, f))
	return NewResidentReconciler(c, resident, store), c
}

// liveRevision is the demux selection the dispatcher's /resolve reads back from
// the store. The reconciler records it per reconcile; nothing is pushed off-node.
func liveRevision(t *testing.T, r *ResidentReconciler, key string) string {
	t.Helper()
	rev, _ := r.store.liveRevision(key)
	return rev
}

func reconcileRevision(t *testing.T, r *ResidentReconciler, name string) (reconcile.Result, error) {
	t.Helper()
	return r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
}

func getRevision(t *testing.T, c client.Client, name string) *computev1alpha1.ServiceRevision {
	t.Helper()
	rev := &computev1alpha1.ServiceRevision{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: name}, rev); err != nil {
		t.Fatalf("get revision %s: %v", name, err)
	}
	return rev
}

// revisionAt is revision() stamped with a creation time so newest-first ordering
// is deterministic in make-before-break tests.
func revisionAt(name, service, digest string, unixTs int64) *computev1alpha1.ServiceRevision {
	rev := revision(name, service, digest)
	rev.CreationTimestamp = metav1.Unix(unixTs, 0)
	return rev
}

func okFetcher() *fakeFetcher {
	return &fakeFetcher{manifest: esManifest(), modules: map[string][]byte{"index.js": []byte("export default {}")}}
}

func TestServiceRevisionCandidatesOrdered(t *testing.T) {
	defaultRevisions := []revisionCandidate{
		{name: "api-v1", createdAt: 100},
		{name: "api-v2", createdAt: 200},
		{name: "api-v3", createdAt: 200},
	}
	cases := []struct {
		name            string
		revisions       []revisionCandidate
		pinnedRevision  string
		latestRevision  string
		wantRevisionIDs []string
	}{
		{
			name:            "newest revision first",
			wantRevisionIDs: []string{"api-v3", "api-v2", "api-v1"},
		},
		{
			name:            "pinned revision first",
			pinnedRevision:  "api-v1",
			wantRevisionIDs: []string{"api-v1", "api-v3", "api-v2"},
		},
		{
			name:            "missing pin ignored",
			pinnedRevision:  "api-missing",
			wantRevisionIDs: []string{"api-v3", "api-v2", "api-v1"},
		},
		{
			// metav1.Time is second-granular, so two revisions minted in the
			// same second are indistinguishable by creation time. The control
			// plane's most recent mint breaks the tie; revision names are a
			// truncated SHA and carry no ordering.
			name:            "latest revision breaks a creation-time tie",
			latestRevision:  "api-v2",
			wantRevisionIDs: []string{"api-v2", "api-v3", "api-v1"},
		},
		{
			name:            "latest revision does not outrank a newer revision",
			latestRevision:  "api-v1",
			wantRevisionIDs: []string{"api-v3", "api-v2", "api-v1"},
		},
		{
			name: "terminating revisions are not selectable",
			revisions: []revisionCandidate{
				{name: "api-v1", createdAt: 100},
				{name: "api-v2", createdAt: 200, terminating: true},
			},
			wantRevisionIDs: []string{"api-v1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			revisions := tc.revisions
			if revisions == nil {
				revisions = defaultRevisions
			}
			candidates := serviceRevisionCandidates{
				serviceName:    "api",
				pinnedRevision: tc.pinnedRevision,
				latestRevision: tc.latestRevision,
				revisions:      revisions,
			}
			ordered := candidates.ordered()
			got := make([]string, 0, len(ordered))
			for _, revision := range ordered {
				got = append(got, revision.name)
			}
			if !reflect.DeepEqual(got, tc.wantRevisionIDs) {
				t.Errorf("ordered revisions = %v, want %v", got, tc.wantRevisionIDs)
			}
		})
	}
}

// TestResidentReconciler_WarmsAndRecordsReadOnly is the core invariant: a
// successful reconcile warms the store and records THIS node's serveable demux
// for /resolve, and writes NOTHING on the API object (no conditions, no
// finalizers).
func TestResidentReconciler_WarmsAndRecordsReadOnly(t *testing.T) {
	r, c := newResidentReconciler(t, &fakeResident{}, okFetcher(), revision("api-abc", "api", "sha256:d"))

	if _, err := reconcileRevision(t, r, "api-abc"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if !r.store.cached("api:api-abc") {
		t.Fatal("definition should be cached after a successful reconcile")
	}
	if got := liveRevision(t, r, "api"); got != "api-abc" {
		t.Errorf("liveRevision(api) = %q, want api-abc", got)
	}

	rev := getRevision(t, c, "api-abc")
	if len(rev.Status.Conditions) != 0 {
		t.Errorf("resident must not write status conditions: %+v", rev.Status.Conditions)
	}
	if len(rev.Finalizers) != 0 {
		t.Errorf("resident must not set finalizers: %+v", rev.Finalizers)
	}
}

// TestResidentReconciler_ResidentDownErrorsNoWrite: an un-ensurable resident is
// surfaced as an error (for backoff) and still never writes the API object.
func TestResidentReconciler_ResidentDownErrorsNoWrite(t *testing.T) {
	r, c := newResidentReconciler(t, &fakeResident{ensureErr: fmt.Errorf("runsc create failed")}, okFetcher(), revision("api-abc", "api", "sha256:d"))

	if _, err := reconcileRevision(t, r, "api-abc"); err == nil {
		t.Fatal("want an error when the resident cannot be ensured")
	}
	rev := getRevision(t, c, "api-abc")
	if len(rev.Status.Conditions) != 0 || len(rev.Finalizers) != 0 {
		t.Errorf("resident-down must not write the API object: conds=%+v finalizers=%+v", rev.Status.Conditions, rev.Finalizers)
	}
}

// TestResidentReconciler_KeepsPreviousUntilNewWarms is the interim fallback: a
// newly minted revision whose bundle won't pull yet must NOT displace the
// previous revision this node already serves.
func TestResidentReconciler_KeepsPreviousUntilNewWarms(t *testing.T) {
	f := okFetcher()
	r, c := newResidentReconciler(t, &fakeResident{}, f, revisionAt("api-v1", "api", "sha256:1", 100))

	if _, err := reconcileRevision(t, r, "api-v1"); err != nil {
		t.Fatalf("v1 reconcile: %v", err)
	}
	if got := liveRevision(t, r, "api"); got != "api-v1" {
		t.Fatalf("v1 should be live, liveRevision = %q", got)
	}

	// A newer revision is minted but its bundle won't pull.
	if err := c.Create(context.Background(), revisionAt("api-v2", "api", "sha256:2", 200)); err != nil {
		t.Fatalf("create v2: %v", err)
	}
	f.setManifestErr(fmt.Errorf("registry down"))

	res, err := reconcileRevision(t, r, "api-v2")
	if err != nil {
		t.Fatalf("v2 reconcile should not hard-error (transient): %v", err)
	}
	if res.RequeueAfter != requeueAwaitBuild {
		t.Errorf("RequeueAfter = %v, want %v", res.RequeueAfter, requeueAwaitBuild)
	}
	if got := liveRevision(t, r, "api"); got != "api-v1" {
		t.Errorf("must keep serving the previous revision; liveRevision = %q, want api-v1", got)
	}
}

func TestResidentReconciler_GCAcrossWarmGapNeverEmptiesDemux(t *testing.T) {
	cases := []struct {
		name              string
		failFirstWarm     bool
		wantFirstRevision string
	}{
		{
			name:              "replacement warms before old cache is pruned",
			wantFirstRevision: "api-v2",
		},
		{
			name:              "failed replacement retains garbage-collected previous revision",
			failFirstWarm:     true,
			wantFirstRevision: "api-v1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := okFetcher()
			r, c := newResidentReconciler(t, &fakeResident{}, f, revisionAt("api-v1", "api", "sha256:1", 100))

			if _, err := reconcileRevision(t, r, "api-v1"); err != nil {
				t.Fatalf("warming v1: %v", err)
			}
			if err := c.Create(context.Background(), revisionAt("api-v2", "api", "sha256:2", 200)); err != nil {
				t.Fatalf("creating v2: %v", err)
			}
			if err := c.Delete(context.Background(), getRevision(t, c, "api-v1")); err != nil {
				t.Fatalf("garbage-collecting v1: %v", err)
			}
			if tc.failFirstWarm {
				f.setManifestErr(fmt.Errorf("registry unavailable"))
			}

			result, err := reconcileRevision(t, r, "api-v2")
			if err != nil {
				t.Fatalf("reconciling v2: %v", err)
			}
			if got := liveRevision(t, r, "api"); got != tc.wantFirstRevision {
				t.Fatalf("demux went through the wrong first state: got %q, want %q", got, tc.wantFirstRevision)
			}
			if tc.failFirstWarm {
				if result.RequeueAfter != requeueAwaitBuild {
					t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, requeueAwaitBuild)
				}
				if !r.store.cached("api:api-v1") {
					t.Fatal("previous definition was pruned before its replacement warmed")
				}

				f.setManifestErr(nil)
				if _, err := reconcileRevision(t, r, "api-v2"); err != nil {
					t.Fatalf("reconciling recovered v2: %v", err)
				}
				if got := liveRevision(t, r, "api"); got != "api-v2" {
					t.Fatalf("demux after recovery = %q, want api-v2", got)
				}
			}
			if got := liveRevision(t, r, "api"); got == "" {
				t.Fatal("service disappeared from demux during revision GC and warming")
			}
		})
	}
}

// TestResidentReconciler_FlipsToNewRevisionOnceWarmed: once the new revision
// warms, the node serves it (make-before-break completes).
func TestResidentReconciler_FlipsToNewRevisionOnceWarmed(t *testing.T) {
	r, c := newResidentReconciler(t, &fakeResident{}, okFetcher(), revisionAt("api-v1", "api", "sha256:1", 100))

	if _, err := reconcileRevision(t, r, "api-v1"); err != nil {
		t.Fatalf("v1 reconcile: %v", err)
	}
	if err := c.Create(context.Background(), revisionAt("api-v2", "api", "sha256:2", 200)); err != nil {
		t.Fatalf("create v2: %v", err)
	}
	if _, err := reconcileRevision(t, r, "api-v2"); err != nil {
		t.Fatalf("v2 reconcile: %v", err)
	}
	if got := liveRevision(t, r, "api"); got != "api-v2" {
		t.Errorf("after warming v2, liveRevision = %q, want api-v2 (newest warmed)", got)
	}
}

// TestResidentReconciler_HonorsPin: an explicit spec.liveRevision pin is served
// once warmed, even if a newer revision exists.
func TestResidentReconciler_HonorsPin(t *testing.T) {
	svc := &computev1alpha1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api"},
		Spec:       computev1alpha1.ServiceSpec{LiveRevision: "api-v1"},
	}
	r, _ := newResidentReconciler(t, &fakeResident{}, okFetcher(),
		svc, revisionAt("api-v1", "api", "sha256:1", 100), revisionAt("api-v2", "api", "sha256:2", 200))

	// Warm both revisions.
	if _, err := reconcileRevision(t, r, "api-v1"); err != nil {
		t.Fatalf("v1: %v", err)
	}
	if _, err := reconcileRevision(t, r, "api-v2"); err != nil {
		t.Fatalf("v2: %v", err)
	}
	if got := liveRevision(t, r, "api"); got != "api-v1" {
		t.Errorf("pinned liveRevision should win; liveRevision = %q, want api-v1", got)
	}
}

// TestResidentReconciler_DeletePrunesCacheNoFinalizer: deletion drains the node's
// cache via the watch event, without a finalizer, and stops serving it.
func TestResidentReconciler_DeletePrunesCacheNoFinalizer(t *testing.T) {
	r, c := newResidentReconciler(t, &fakeResident{}, okFetcher(), revision("api-abc", "api", "sha256:d"))

	if _, err := reconcileRevision(t, r, "api-abc"); err != nil {
		t.Fatalf("warm reconcile: %v", err)
	}
	if !r.store.cached("api:api-abc") {
		t.Fatal("want cached after warm")
	}

	rev := getRevision(t, c, "api-abc")
	if len(rev.Finalizers) != 0 {
		t.Fatalf("resident must not set a finalizer: %+v", rev.Finalizers)
	}
	// No finalizer -> Delete removes the object immediately.
	if err := c.Delete(context.Background(), rev); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := reconcileRevision(t, r, "api-abc"); err != nil {
		t.Fatalf("delete reconcile: %v", err)
	}

	if r.store.cached("api:api-abc") {
		t.Error("deleted revision's definition should be pruned from the cache")
	}
	if rev, ok := r.store.liveRevision("api"); ok {
		t.Errorf("deleted service must not be served; liveRevision = %q", rev)
	}
}

// TestResidentReconciler_PinnedRevisionNeverFallsThrough: spec.liveRevision is a
// directive, not a preference. A pin is how an operator rolls back off a bad
// revision, so a pin that will not warm must never fall through to the next
// candidate — the next candidate is the revision being rolled away from.
func TestResidentReconciler_PinnedRevisionNeverFallsThrough(t *testing.T) {
	pinnedService := func(revisionName string) *computev1alpha1.Service {
		return &computev1alpha1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "api"},
			Spec:       computev1alpha1.ServiceSpec{LiveRevision: revisionName},
		}
	}

	t.Run("cold node stays unrouted", func(t *testing.T) {
		f := okFetcher()
		f.failDigest("sha256:1", fmt.Errorf("bundle not found"))
		r, _ := newResidentReconciler(t, &fakeResident{}, f,
			pinnedService("api-v1"),
			revisionAt("api-v1", "api", "sha256:1", 100),
			revisionAt("api-v2", "api", "sha256:2", 200))

		result, err := reconcileRevision(t, r, "api-v1")
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if got, ok := r.store.liveRevision("api"); ok {
			t.Errorf("unwarmable pin fell through to %q; the service must stay unrouted", got)
		}
		if r.store.cached("api:api-v2") {
			t.Error("a pinned service must not warm the revision it was pinned away from")
		}
		if result.RequeueAfter != requeueAwaitBuild {
			t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, requeueAwaitBuild)
		}

		// Once the pinned bundle is pullable the node serves exactly it.
		f.failDigest("sha256:1", nil)
		if _, err := reconcileRevision(t, r, "api-v1"); err != nil {
			t.Fatalf("recovered reconcile: %v", err)
		}
		if got := liveRevision(t, r, "api"); got != "api-v1" {
			t.Errorf("liveRevision = %q, want api-v1", got)
		}
	})

	t.Run("warm node holds its previous revision", func(t *testing.T) {
		f := okFetcher()
		r, c := newResidentReconciler(t, &fakeResident{}, f,
			revisionAt("api-v1", "api", "sha256:1", 100),
			revisionAt("api-v2", "api", "sha256:2", 200))

		if _, err := reconcileRevision(t, r, "api-v2"); err != nil {
			t.Fatalf("initial reconcile: %v", err)
		}
		if got := liveRevision(t, r, "api"); got != "api-v2" {
			t.Fatalf("liveRevision = %q, want api-v2 before the pin moves", got)
		}

		// The operator pins forward to a revision whose bundle never appears.
		f.failDigest("sha256:3", fmt.Errorf("bundle not found"))
		if err := c.Create(context.Background(), revisionAt("api-v3", "api", "sha256:3", 300)); err != nil {
			t.Fatalf("create v3: %v", err)
		}
		if err := c.Create(context.Background(), pinnedService("api-v3")); err != nil {
			t.Fatalf("create service: %v", err)
		}

		if _, err := reconcileRevision(t, r, "api-v3"); err != nil {
			t.Fatalf("pinned reconcile: %v", err)
		}
		if got := liveRevision(t, r, "api"); got != "api-v2" {
			t.Errorf("liveRevision = %q, want api-v2 held while the pin cannot warm", got)
		}
	})
}

// TestResidentReconciler_FailedServiceKeepsOtherRoutes: routing is published per
// service as each one warms. One unpullable service must not cost the rest of
// the tenant its routes — the failure mode the whole-catalog swap had, where a
// cold node held every service unroutable until the slowest pull finished.
func TestResidentReconciler_FailedServiceKeepsOtherRoutes(t *testing.T) {
	f := okFetcher()
	f.failDigest("sha256:w", fmt.Errorf("registry down"))
	r, _ := newResidentReconciler(t, &fakeResident{}, f,
		revisionAt("api-v1", "api", "sha256:a", 100),
		revisionAt("web-v1", "web", "sha256:w", 100))

	// Twice: the first pass publishes, the second proves the prune pass does
	// not drop a healthy service on behalf of its failing neighbor.
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := reconcileRevision(t, r, "api-v1"); err != nil {
			t.Fatalf("reconcile %d: %v", attempt, err)
		}
		if got := liveRevision(t, r, "api"); got != "api-v1" {
			t.Fatalf("reconcile %d: liveRevision(api) = %q, want api-v1", attempt, got)
		}
		if got, ok := r.store.liveRevision("web"); ok {
			t.Fatalf("reconcile %d: unwarmable service must not be routed, got %q", attempt, got)
		}
	}
}

// TestResidentReconciler_TerminatingRevisionNotPromoted: a revision with a
// deletionTimestamp is never newly selected, but its definition survives the
// cache prune so a node already serving it can drain its grace window.
func TestResidentReconciler_TerminatingRevisionNotPromoted(t *testing.T) {
	v2 := revisionAt("api-v2", "api", "sha256:2", 200)
	// The fake client only keeps a deleted object around (with a
	// deletionTimestamp) if something holds a finalizer on it.
	v2.Finalizers = []string{"apoxy.dev/test-hold"}
	r, c := newResidentReconciler(t, &fakeResident{}, okFetcher(),
		revisionAt("api-v1", "api", "sha256:1", 100), v2)

	if _, err := reconcileRevision(t, r, "api-v2"); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	if got := liveRevision(t, r, "api"); got != "api-v2" {
		t.Fatalf("liveRevision = %q, want api-v2 before deletion", got)
	}

	if err := c.Delete(context.Background(), getRevision(t, c, "api-v2")); err != nil {
		t.Fatalf("delete v2: %v", err)
	}
	if _, err := reconcileRevision(t, r, "api-v2"); err != nil {
		t.Fatalf("post-delete reconcile: %v", err)
	}
	if got := liveRevision(t, r, "api"); got != "api-v1" {
		t.Errorf("liveRevision = %q, want api-v1 once the newest revision is terminating", got)
	}
	if !r.store.cached("api:api-v2") {
		t.Error("terminating revision's definition was pruned inside its grace window")
	}
}

// TestResidentReconciler_StopsFastRetryAfterRepeatedWarmFailures: the short
// retry interval exists to cover make-before-break, where a freshly minted
// bundle is still propagating. A bundle that is never going to appear must
// degrade to the periodic resync instead of re-pulling every few seconds for
// the life of the process.
func TestResidentReconciler_StopsFastRetryAfterRepeatedWarmFailures(t *testing.T) {
	f := okFetcher()
	f.failDigest("sha256:1", fmt.Errorf("bundle not found"))
	r, _ := newResidentReconciler(t, &fakeResident{}, f, revisionAt("api-v1", "api", "sha256:1", 100))

	for attempt := 1; attempt <= warmRetryLimit; attempt++ {
		result, err := reconcileRevision(t, r, "api-v1")
		if err != nil {
			t.Fatalf("reconcile %d: %v", attempt, err)
		}
		if result.RequeueAfter != requeueAwaitBuild {
			t.Fatalf("reconcile %d: RequeueAfter = %v, want %v", attempt, result.RequeueAfter, requeueAwaitBuild)
		}
	}

	result, err := reconcileRevision(t, r, "api-v1")
	if err != nil {
		t.Fatalf("reconcile past the retry limit: %v", err)
	}
	if result.RequeueAfter != demuxResyncInterval {
		t.Errorf("RequeueAfter = %v, want %v once the warm has failed %d times",
			result.RequeueAfter, demuxResyncInterval, warmRetryLimit+1)
	}

	// A recovered bundle clears the counter, so the next transient failure gets
	// the fast retries again rather than inheriting a poisoned count.
	f.failDigest("sha256:1", nil)
	if _, err := reconcileRevision(t, r, "api-v1"); err != nil {
		t.Fatalf("recovered reconcile: %v", err)
	}
	if !r.shouldRetryWarm("api:api-v1") {
		t.Error("a successful warm must reset the consecutive-failure count")
	}
}

// TestResidentReconciler_UnroutableSkipped: a revision with no service label is
// not warmed and the API object is untouched.
func TestResidentReconciler_UnroutableSkipped(t *testing.T) {
	rev := revision("api-abc", "api", "sha256:d")
	rev.Labels = nil
	r, c := newResidentReconciler(t, &fakeResident{}, okFetcher(), rev)

	if _, err := reconcileRevision(t, r, "api-abc"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := getRevision(t, c, "api-abc")
	if len(got.Status.Conditions) != 0 || len(got.Finalizers) != 0 {
		t.Errorf("unroutable revision must be untouched: conds=%+v finalizers=%+v", got.Status.Conditions, got.Finalizers)
	}
	if r.store.cached("api:api-abc") {
		t.Error("unroutable revision must not be warmed")
	}
}
