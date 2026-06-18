// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"fmt"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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
	store := NewStore(newResolverWithFetcher(c, "proj", f))
	return NewResidentReconciler(c, resident, store, "proj"), c
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

// drive runs reconcile until it stops requesting an immediate requeue (the first
// pass only adds the finalizer), returning the final result.
func drive(t *testing.T, r *ResidentReconciler, name string) reconcile.Result {
	t.Helper()
	for i := 0; i < 5; i++ {
		res, err := reconcileRevision(t, r, name)
		if err != nil {
			t.Fatalf("Reconcile(%s): %v", name, err)
		}
		if !res.Requeue {
			return res
		}
	}
	t.Fatalf("Reconcile(%s) never settled", name)
	return reconcile.Result{}
}

func TestResidentReconciler_MarksReadyWhenResolvable(t *testing.T) {
	f := &fakeFetcher{manifest: esManifest(), modules: map[string][]byte{"index.js": []byte("export default {}")}}
	r, c := newResidentReconciler(t, &fakeResident{}, f, revision("api-abc", "api", "sha256:d"))

	drive(t, r, "api-abc")

	rev := getRevision(t, c, "api-abc")
	cond := meta.FindStatusCondition(rev.Status.Conditions, computev1alpha1.ConditionResidentReady)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("ResidentReady = %+v, want True", cond)
	}
	if cond.Reason != "Loadable" {
		t.Errorf("reason = %q, want Loadable", cond.Reason)
	}
	// The finalizer is held so a delete can drain the cached definition.
	if !hasFinalizer(rev, residentFinalizer) {
		t.Errorf("resident finalizer not set: %+v", rev.Finalizers)
	}
}

func TestResidentReconciler_ResidentDown(t *testing.T) {
	f := &fakeFetcher{manifest: esManifest(), modules: map[string][]byte{"index.js": []byte("x")}}
	r, c := newResidentReconciler(t, &fakeResident{ensureErr: fmt.Errorf("runsc create failed")}, f, revision("api-abc", "api", "sha256:d"))

	// First pass adds the finalizer (no error); the next surfaces the resident
	// failure as an error so controller-runtime backs off.
	if _, err := reconcileRevision(t, r, "api-abc"); err != nil {
		t.Fatalf("finalizer pass should not error: %v", err)
	}
	if _, err := reconcileRevision(t, r, "api-abc"); err == nil {
		t.Fatal("want error when the resident cannot be ensured")
	}
	rev := getRevision(t, c, "api-abc")
	cond := meta.FindStatusCondition(rev.Status.Conditions, computev1alpha1.ConditionResidentReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "ResidentDown" {
		t.Errorf("ResidentReady = %+v, want False/ResidentDown", cond)
	}
}

func TestResidentReconciler_DefinitionUnavailable(t *testing.T) {
	// Resident is up, but the bundle won't pull.
	f := &fakeFetcher{manifestErr: fmt.Errorf("registry down")}
	r, c := newResidentReconciler(t, &fakeResident{}, f, revision("api-abc", "api", "sha256:d"))

	res := drive(t, r, "api-abc")
	if res.RequeueAfter == 0 {
		t.Errorf("want a requeue-after for a transient bundle failure, got %+v", res)
	}
	rev := getRevision(t, c, "api-abc")
	cond := meta.FindStatusCondition(rev.Status.Conditions, computev1alpha1.ConditionResidentReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "DefinitionUnavailable" {
		t.Errorf("ResidentReady = %+v, want False/DefinitionUnavailable", cond)
	}
}

func TestResidentReconciler_Unroutable(t *testing.T) {
	// A revision with no service label can't be turned into a demux id.
	rev := revision("api-abc", "api", "sha256:d")
	rev.Labels = nil
	f := &fakeFetcher{manifest: esManifest(), modules: map[string][]byte{"index.js": []byte("x")}}
	r, c := newResidentReconciler(t, &fakeResident{}, f, rev)

	if _, err := reconcileRevision(t, r, "api-abc"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := getRevision(t, c, "api-abc")
	cond := meta.FindStatusCondition(got.Status.Conditions, computev1alpha1.ConditionResidentReady)
	if cond == nil || cond.Reason != "Unroutable" {
		t.Errorf("ResidentReady = %+v, want Unroutable", cond)
	}
}

func TestResidentReconciler_DeleteInvalidatesAndReleases(t *testing.T) {
	f := &fakeFetcher{manifest: esManifest(), modules: map[string][]byte{"index.js": []byte("export default {}")}}
	r, c := newResidentReconciler(t, &fakeResident{}, f, revision("api-abc", "api", "sha256:d"))

	// Bring it to ready (also warms the cache and adds the finalizer).
	drive(t, r, "api-abc")
	if !r.store.cached("proj:api:api-abc") {
		t.Fatal("expected the definition to be cached after readiness")
	}

	// Delete: the finalizer keeps the object until the reconciler releases it.
	rev := getRevision(t, c, "api-abc")
	if err := c.Delete(context.Background(), rev); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := reconcileRevision(t, r, "api-abc"); err != nil {
		t.Fatalf("delete reconcile: %v", err)
	}

	if r.store.cached("proj:api:api-abc") {
		t.Error("delete should invalidate the cached definition")
	}
	// Finalizer released -> the object is actually gone.
	err := c.Get(context.Background(), client.ObjectKey{Name: "api-abc"}, &computev1alpha1.ServiceRevision{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("revision should be deleted after finalizer release, got %v", err)
	}
}

func hasFinalizer(o client.Object, f string) bool {
	for _, x := range o.GetFinalizers() {
		if x == f {
			return true
		}
	}
	return false
}
