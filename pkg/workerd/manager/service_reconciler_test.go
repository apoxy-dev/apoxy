// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := computev1alpha1.Install(s); err != nil {
		t.Fatalf("install compute scheme: %v", err)
	}
	return s
}

func newReconciler(t *testing.T, objs ...client.Object) (*ServiceReconciler, client.Client) {
	t.Helper()
	s := testScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&computev1alpha1.Service{}, &computev1alpha1.ServiceRevision{}).
		WithObjects(objs...).
		Build()
	return &ServiceReconciler{Client: c, scheme: s}, c
}

func ociService(name, repo, digest string) *computev1alpha1.Service {
	return &computev1alpha1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name + "-uid")},
		Spec: computev1alpha1.ServiceSpec{
			Template: computev1alpha1.ServiceTemplateSpec{Spec: computev1alpha1.ServiceConfigSpec{}},
			Source:   computev1alpha1.ServiceSource{OCI: &computev1alpha1.BundleRef{Repo: repo, Digest: digest}},
		},
	}
}

func reconcileOnce(t *testing.T, r *ServiceReconciler, name string) reconcile.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
	if err != nil {
		t.Fatalf("Reconcile(%s): %v", name, err)
	}
	return res
}

func getService(t *testing.T, c client.Client, name string) *computev1alpha1.Service {
	t.Helper()
	svc := &computev1alpha1.Service{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: name}, svc); err != nil {
		t.Fatalf("get service %s: %v", name, err)
	}
	return svc
}

func listRevisions(t *testing.T, c client.Client) []computev1alpha1.ServiceRevision {
	t.Helper()
	revs := &computev1alpha1.ServiceRevisionList{}
	if err := c.List(context.Background(), revs); err != nil {
		t.Fatalf("list revisions: %v", err)
	}
	return revs.Items
}

func TestServiceReconciler_MintsAndTracksLatest(t *testing.T) {
	svc := ociService("api", "reg/acme/api", "sha256:abc")
	r, c := newReconciler(t, svc)

	reconcileOnce(t, r, "api")

	revs := listRevisions(t, c)
	if len(revs) != 1 {
		t.Fatalf("want 1 revision, got %d", len(revs))
	}
	rev := revs[0]
	if rev.Spec.Bundle.Digest != "sha256:abc" {
		t.Errorf("revision bundle = %+v", rev.Spec.Bundle)
	}
	if len(rev.OwnerReferences) != 1 || rev.OwnerReferences[0].Name != "api" {
		t.Errorf("revision ownerRefs = %+v", rev.OwnerReferences)
	}
	got := getService(t, c, "api")
	if got.Status.LatestRevision != rev.Name {
		t.Errorf("LatestRevision = %q, want %q", got.Status.LatestRevision, rev.Name)
	}
	if got.Status.LiveRevision != "" {
		t.Errorf("LiveRevision = %q, want empty (revision not resident-ready yet)", got.Status.LiveRevision)
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, computev1alpha1.ConditionAccepted) {
		t.Errorf("Accepted should be true: %+v", got.Status.Conditions)
	}
	if meta.IsStatusConditionTrue(got.Status.Conditions, computev1alpha1.ConditionReady) {
		t.Errorf("Ready should be false before resident-ready")
	}
}

func TestServiceReconciler_Idempotent(t *testing.T) {
	svc := ociService("api", "reg/acme/api", "sha256:abc")
	r, c := newReconciler(t, svc)
	reconcileOnce(t, r, "api")
	reconcileOnce(t, r, "api")
	reconcileOnce(t, r, "api")
	if n := len(listRevisions(t, c)); n != 1 {
		t.Fatalf("want 1 revision after repeated reconciles, got %d", n)
	}
}

func TestServiceReconciler_PromotesWhenResidentReady(t *testing.T) {
	svc := ociService("api", "reg/acme/api", "sha256:abc")
	r, c := newReconciler(t, svc)
	reconcileOnce(t, r, "api")

	rev := listRevisions(t, c)[0]
	// The resident reconciler marks the revision ResidentReady.
	meta.SetStatusCondition(&rev.Status.Conditions, metav1.Condition{
		Type: computev1alpha1.ConditionResidentReady, Status: metav1.ConditionTrue, Reason: "Serving",
	})
	if err := c.Status().Update(context.Background(), &rev); err != nil {
		t.Fatalf("update revision status: %v", err)
	}

	reconcileOnce(t, r, "api")
	got := getService(t, c, "api")
	if got.Status.LiveRevision != rev.Name {
		t.Errorf("LiveRevision = %q, want %q after resident-ready", got.Status.LiveRevision, rev.Name)
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, computev1alpha1.ConditionReady) {
		t.Errorf("Ready should be true once live")
	}
}

func TestServiceReconciler_PinnedLiveRevision(t *testing.T) {
	svc := ociService("api", "reg/acme/api", "sha256:abc")
	r, c := newReconciler(t, svc)
	reconcileOnce(t, r, "api")
	rev := listRevisions(t, c)[0]

	// Pin liveRevision to the (not-yet-ready) revision: must NOT go live.
	svc2 := getService(t, c, "api")
	svc2.Spec.LiveRevision = rev.Name
	if err := c.Update(context.Background(), svc2); err != nil {
		t.Fatalf("update service: %v", err)
	}
	reconcileOnce(t, r, "api")
	if lr := getService(t, c, "api").Status.LiveRevision; lr != "" {
		t.Errorf("pinned-but-not-ready LiveRevision = %q, want empty", lr)
	}

	// Now mark it ready -> promotes.
	meta.SetStatusCondition(&rev.Status.Conditions, metav1.Condition{
		Type: computev1alpha1.ConditionResidentReady, Status: metav1.ConditionTrue, Reason: "Serving",
	})
	if err := c.Status().Update(context.Background(), &rev); err != nil {
		t.Fatalf("update revision status: %v", err)
	}
	reconcileOnce(t, r, "api")
	if lr := getService(t, c, "api").Status.LiveRevision; lr != rev.Name {
		t.Errorf("LiveRevision = %q, want %q", lr, rev.Name)
	}
}

func TestServiceReconciler_InvalidSource(t *testing.T) {
	svc := &computev1alpha1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", UID: "bad-uid"},
		Spec:       computev1alpha1.ServiceSpec{Template: computev1alpha1.ServiceTemplateSpec{Spec: computev1alpha1.ServiceConfigSpec{}}},
	}
	r, c := newReconciler(t, svc)
	reconcileOnce(t, r, "bad")
	if n := len(listRevisions(t, c)); n != 0 {
		t.Fatalf("want 0 revisions for invalid source, got %d", n)
	}
	got := getService(t, c, "bad")
	cond := meta.FindStatusCondition(got.Status.Conditions, computev1alpha1.ConditionAccepted)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "InvalidSource" {
		t.Errorf("Accepted condition = %+v, want False/InvalidSource", cond)
	}
}

func TestServiceReconciler_GitAwaitsBuild(t *testing.T) {
	svc := &computev1alpha1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "git", UID: "git-uid"},
		Spec: computev1alpha1.ServiceSpec{
			Template: computev1alpha1.ServiceTemplateSpec{Spec: computev1alpha1.ServiceConfigSpec{}},
			Source:   computev1alpha1.ServiceSource{Git: &computev1alpha1.GitSource{}},
		},
	}
	r, c := newReconciler(t, svc)
	reconcileOnce(t, r, "git")
	if n := len(listRevisions(t, c)); n != 0 {
		t.Fatalf("want 0 revisions while awaiting build, got %d", n)
	}
	cond := meta.FindStatusCondition(getService(t, c, "git").Status.Conditions, computev1alpha1.ConditionAccepted)
	if cond == nil || cond.Reason != "AwaitingBuild" {
		t.Errorf("Accepted = %+v, want AwaitingBuild", cond)
	}
}

func TestServiceReconciler_GitMintsFromBuild(t *testing.T) {
	svc := &computev1alpha1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "git", UID: "git-uid"},
		Spec: computev1alpha1.ServiceSpec{
			Template: computev1alpha1.ServiceTemplateSpec{Spec: computev1alpha1.ServiceConfigSpec{}},
			Source:   computev1alpha1.ServiceSource{Git: &computev1alpha1.GitSource{}},
		},
	}
	build := &computev1alpha1.Build{
		ObjectMeta: metav1.ObjectMeta{Name: "git-build-1"},
		Spec:       computev1alpha1.BuildSpec{ServiceRef: "git", Commit: "deadbeef"},
		Status: computev1alpha1.BuildStatus{
			Phase:  computev1alpha1.BuildSucceeded,
			Bundle: &computev1alpha1.BundleRef{Repo: "reg/acme/git", Digest: "sha256:frombuild"},
		},
	}
	r, c := newReconciler(t, svc, build)
	reconcileOnce(t, r, "git")
	revs := listRevisions(t, c)
	if len(revs) != 1 {
		t.Fatalf("want 1 revision minted from build, got %d", len(revs))
	}
	if revs[0].Spec.Bundle.Digest != "sha256:frombuild" {
		t.Errorf("bundle = %+v, want digest from build", revs[0].Spec.Bundle)
	}
}

func TestServiceReconciler_GCsOldRevisions(t *testing.T) {
	svc := ociService("api", "reg/acme/api", "sha256:abc")
	limit := int32(2)
	svc.Spec.RevisionHistoryLimit = &limit
	r, c := newReconciler(t, svc)

	// Seed 5 stale revisions owned by the service, then reconcile (which mints
	// the current one and GCs down to the limit, keeping latest+live).
	for i, ts := range []int64{100, 200, 300, 400, 500} {
		rev := &computev1alpha1.ServiceRevision{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "api-old-" + string(rune('a'+i)),
				Labels:            map[string]string{serviceLabel: "api"},
				CreationTimestamp: metav1.Unix(ts, 0),
			},
			Spec: computev1alpha1.ServiceRevisionSpec{Bundle: computev1alpha1.BundleRef{Repo: "r", Digest: "d"}},
		}
		if err := c.Create(context.Background(), rev); err != nil {
			t.Fatalf("seed revision: %v", err)
		}
	}

	reconcileOnce(t, r, "api")

	revs := listRevisions(t, c)
	// limit=2 but latest (the just-minted) is always kept; the 2 newest seeds may
	// also be retained. Assert we GC'd at least down toward the limit and never
	// deleted the latest.
	got := getService(t, c, "api")
	foundLatest := false
	for _, rv := range revs {
		if rv.Name == got.Status.LatestRevision {
			foundLatest = true
		}
	}
	if !foundLatest {
		t.Errorf("latest revision %q was GC'd", got.Status.LatestRevision)
	}
	if len(revs) > 3 {
		t.Errorf("expected GC to trim revisions, still have %d: %v", len(revs), revNames(revs))
	}
}

func revNames(revs []computev1alpha1.ServiceRevision) []string {
	out := make([]string, len(revs))
	for i, r := range revs {
		out[i] = r.Name
	}
	return out
}
