// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
)

// fakeResident is an in-memory host.ResidentRuntime.
type fakeResident struct {
	ensureErr   error
	ensureCalls int
}

func (f *fakeResident) EnsureResident(_ context.Context) (*host.ResidentInstance, error) {
	f.ensureCalls++
	if f.ensureErr != nil {
		return nil, f.ensureErr
	}
	return &host.ResidentInstance{SandboxID: "apoxy-workerd-resident", InboundSocket: "/run/in.sock"}, nil
}

func (f *fakeResident) Stop(_ context.Context) error    { return nil }
func (f *fakeResident) Cleanup(_ context.Context) error { return nil }

func newResidentReconciler(t *testing.T, resident host.ResidentRuntime, f *fakeFetcher, objs ...client.Object) (*ResidentReconciler, client.Client) {
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
	f.manifestErr = fmt.Errorf("registry down")

	res, err := reconcileRevision(t, r, "api-v2")
	if err != nil {
		t.Fatalf("v2 reconcile should not hard-error (transient): %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Errorf("want a requeue-after for the transient bundle failure, got %+v", res)
	}
	if got := liveRevision(t, r, "api"); got != "api-v1" {
		t.Errorf("must keep serving the previous revision; liveRevision = %q, want api-v1", got)
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
