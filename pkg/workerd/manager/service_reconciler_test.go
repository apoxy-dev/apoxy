// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	workerdbundle "github.com/apoxy-dev/apoxy/pkg/workerd/bundle"
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
	if got.Status.LiveRevision != rev.Name {
		t.Errorf("LiveRevision = %q, want %q (auto-promoted intent; readiness is per-node)", got.Status.LiveRevision, rev.Name)
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, computev1alpha1.ConditionAccepted) {
		t.Errorf("Accepted should be true: %+v", got.Status.Conditions)
	}
	// Minting does not set Ready: which revision each backplane actually serves is
	// reported per-node over the publish channel, not by the control plane.
	if meta.IsStatusConditionTrue(got.Status.Conditions, computev1alpha1.ConditionReady) {
		t.Errorf("minting must not set Ready")
	}
}

func TestServiceReconciler_ResolvesOCISource(t *testing.T) {
	resolvedDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pinnedDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cases := []struct {
		name          string
		digest        string
		tag           string
		resolveDigest string
		resolveErr    error
		wantCalls     int
		wantRevisions int
		wantDigest    string
		wantReason    string
		wantRequeue   time.Duration
		// wantErr means the reconcile surfaces the failure to the workqueue so
		// it applies rate-limited backoff, instead of asking for a flat requeue.
		wantErr bool
	}{
		{
			name:          "tag is resolved before minting",
			tag:           "latest",
			resolveDigest: resolvedDigest,
			wantCalls:     1,
			wantRevisions: 1,
			wantDigest:    resolvedDigest,
			wantReason:    "Minted",
		},
		{
			name:          "existing digest wins over tag",
			digest:        pinnedDigest,
			tag:           "latest",
			wantRevisions: 1,
			wantDigest:    pinnedDigest,
			wantReason:    "Minted",
		},
		{
			// A registry failure is indistinguishable here from a permanent
			// one (typo'd tag, deleted repo, revoked credential), so it takes
			// the workqueue's exponential backoff rather than a flat 15s
			// requeue that would re-hit the registry forever.
			name:       "registry failure backs off",
			tag:        "latest",
			resolveErr: errors.New("registry unavailable"),
			wantCalls:  1,
			wantReason: "BundleResolutionFailed",
			wantErr:    true,
		},
		{
			// A structurally invalid source cannot heal without a spec edit,
			// which bumps generation and re-enqueues on its own.
			name:       "malformed source is terminal",
			wantReason: "InvalidSource",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := ociService("api", "reg.example/acme/api", tc.digest)
			svc.Spec.Source.OCI.Tag = tc.tag
			r, c := newReconciler(t, svc)
			calls := 0
			r.resolveTag = func(_ context.Context, ref computev1alpha1.BundleRef) (string, error) {
				calls++
				if ref.Repo != svc.Spec.Source.OCI.Repo || ref.Tag != tc.tag || ref.Digest != "" {
					t.Errorf("resolver ref = %+v, want unresolved Service source %+v", ref, *svc.Spec.Source.OCI)
				}
				return tc.resolveDigest, tc.resolveErr
			}

			result, err := r.Reconcile(context.Background(),
				reconcile.Request{NamespacedName: types.NamespacedName{Name: svc.Name}})
			if tc.wantErr != (err != nil) {
				t.Fatalf("Reconcile(%s) error = %v, want error %v", svc.Name, err, tc.wantErr)
			}
			if calls != tc.wantCalls {
				t.Errorf("resolver calls = %d, want %d", calls, tc.wantCalls)
			}
			if result.RequeueAfter != tc.wantRequeue {
				t.Errorf("RequeueAfter = %s, want %s", result.RequeueAfter, tc.wantRequeue)
			}

			revisions := listRevisions(t, c)
			if len(revisions) != tc.wantRevisions {
				t.Fatalf("revisions = %d, want %d", len(revisions), tc.wantRevisions)
			}
			if len(revisions) == 1 {
				if revisions[0].Spec.Bundle.Digest != tc.wantDigest {
					t.Errorf("revision digest = %q, want %q", revisions[0].Spec.Bundle.Digest, tc.wantDigest)
				}
				if revisions[0].Spec.Bundle.Tag != "" {
					t.Errorf("digest-pinned revision retained tag %q", revisions[0].Spec.Bundle.Tag)
				}
			}
			condition := meta.FindStatusCondition(getService(t, c, svc.Name).Status.Conditions, computev1alpha1.ConditionAccepted)
			if condition == nil || condition.Reason != tc.wantReason {
				t.Errorf("Accepted condition = %+v, want reason %q", condition, tc.wantReason)
			}
		})
	}
}

func TestResolveRegistryTag(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2}`)
	wantDigest := digest.FromBytes(manifest)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v2/acme/api/manifests/latest" {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", ocispecv1.MediaTypeImageManifest)
		w.Header().Set("Content-Length", strconv.Itoa(len(manifest)))
		w.Header().Set("Docker-Content-Digest", wantDigest.String())
		if req.Method != http.MethodHead {
			_, _ = w.Write(manifest)
		}
	}))
	t.Cleanup(registry.Close)

	registryHost := strings.TrimPrefix(registry.URL, "http://")
	t.Setenv(workerdbundle.InsecureRegistriesEnv, registryHost)
	got, err := ResolveRegistryTag(t.Context(), computev1alpha1.BundleRef{
		Repo: registryHost + "/acme/api",
		Tag:  "latest",
	})
	if err != nil {
		t.Fatalf("ResolveRegistryTag() error = %v", err)
	}
	if got != wantDigest.String() {
		t.Errorf("ResolveRegistryTag() = %q, want %q", got, wantDigest)
	}
}

func TestServiceReconciler_NoOpDoesNotMint(t *testing.T) {
	cases := []struct {
		name          string
		prepare       func(*computev1alpha1.Service)
		mutate        func(*computev1alpha1.Service)
		resolveDigest string
	}{
		{
			name: "repeated reconcile",
		},
		{
			name: "defaulted tag on digest-pinned source",
			mutate: func(svc *computev1alpha1.Service) {
				// Applying the manifest without its deploy-owned digest lets
				// admission default tag=latest before the digest pin lands.
				// Digest identifies the artifact, so this is a semantic no-op.
				svc.Spec.Source.OCI.Tag = "latest"
			},
		},
		{
			name: "stable tag resolution",
			prepare: func(svc *computev1alpha1.Service) {
				svc.Spec.Source.OCI.Digest = ""
				svc.Spec.Source.OCI.Tag = "latest"
			},
			resolveDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := ociService("api", "reg/acme/api", "sha256:abc")
			if tc.prepare != nil {
				tc.prepare(svc)
			}
			r, c := newReconciler(t, svc)
			if tc.resolveDigest != "" {
				r.resolveTag = func(context.Context, computev1alpha1.BundleRef) (string, error) {
					return tc.resolveDigest, nil
				}
			}

			reconcileOnce(t, r, "api")
			first := listRevisions(t, c)
			if len(first) != 1 {
				t.Fatalf("revisions after first reconcile = %d, want 1", len(first))
			}
			firstName := first[0].Name

			if tc.mutate != nil {
				current := getService(t, c, "api")
				tc.mutate(current)
				if err := c.Update(context.Background(), current); err != nil {
					t.Fatalf("updating service with semantic no-op: %v", err)
				}
			}
			reconcileOnce(t, r, "api")
			reconcileOnce(t, r, "api")

			revs := listRevisions(t, c)
			if len(revs) != 1 {
				t.Fatalf("revisions after no-op reconciles = %d, want 1: %v", len(revs), revNames(revs))
			}
			if revs[0].Name != firstName {
				t.Errorf("revision name = %q, want stable %q", revs[0].Name, firstName)
			}
			if revs[0].Spec.Bundle.Tag != "" {
				t.Errorf("digest-pinned revision retained non-semantic tag %q", revs[0].Spec.Bundle.Tag)
			}
		})
	}
}

func TestServiceReconciler_ReusesLegacyTaggedRevision(t *testing.T) {
	cases := []struct {
		name         string
		sourceTag    string
		recordStatus bool
	}{
		{
			name:         "tag remains on digest-pinned source",
			sourceTag:    "latest",
			recordStatus: true,
		},
		{
			name:         "tag disappeared but status names legacy revision",
			recordStatus: true,
		},
		{
			name: "empty status falls back to equivalent revision",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := ociService("api", "reg/acme/api", "sha256:abc")
			svc.Spec.Source.OCI.Tag = tc.sourceTag

			legacyBundle := *svc.Spec.Source.OCI.DeepCopy()
			legacyBundle.Tag = "latest"
			legacyName := revisionNameFor(svc.Name, svc.Spec.Template.Spec, legacyBundle)
			digestOnlyName := revisionName(svc, *svc.Spec.Source.OCI)
			if legacyName == digestOnlyName {
				t.Fatal("test fixture did not produce distinct tagged and digest-only names")
			}

			legacy := &computev1alpha1.ServiceRevision{
				ObjectMeta: metav1.ObjectMeta{
					Name:              legacyName,
					Labels:            map[string]string{serviceLabel: svc.Name},
					CreationTimestamp: metav1.Unix(100, 0),
				},
				Spec: computev1alpha1.ServiceRevisionSpec{
					ServiceConfigSpec: *svc.Spec.Template.Spec.DeepCopy(),
					Bundle:            legacyBundle,
				},
			}
			if tc.recordStatus {
				svc.Status.LatestRevision = legacyName
				svc.Status.LiveRevision = legacyName
			}

			r, c := newReconciler(t, svc, legacy)
			reconcileOnce(t, r, svc.Name)

			revs := listRevisions(t, c)
			if len(revs) != 1 {
				t.Fatalf("revisions after digest-only upgrade = %d, want 1: %v", len(revs), revNames(revs))
			}
			if revs[0].Name != legacyName {
				t.Errorf("revision name = %q, want reused legacy %q", revs[0].Name, legacyName)
			}
			if revs[0].Name == digestOnlyName {
				t.Errorf("minted duplicate digest-only revision %q", digestOnlyName)
			}
			got := getService(t, c, svc.Name)
			if got.Status.LatestRevision != legacyName || got.Status.LiveRevision != legacyName {
				t.Errorf("service status = latest %q live %q, want legacy %q",
					got.Status.LatestRevision, got.Status.LiveRevision, legacyName)
			}
		})
	}
}

func TestEquivalentRevisionSetSelectsPreferredOrNewest(t *testing.T) {
	svc := ociService("api", "reg/acme/api", "sha256:abc")
	bundle := digestPinnedRevisionBundle(*svc.Spec.Source.OCI)
	matchingSpec := computev1alpha1.ServiceRevisionSpec{
		ServiceConfigSpec: *svc.Spec.Template.Spec.DeepCopy(),
		Bundle:            bundle,
	}
	revisions := []computev1alpha1.ServiceRevision{
		{ObjectMeta: metav1.ObjectMeta{Name: "old", CreationTimestamp: metav1.Unix(100, 0)}, Spec: matchingSpec},
		{ObjectMeta: metav1.ObjectMeta{Name: "new", CreationTimestamp: metav1.Unix(200, 0)}, Spec: matchingSpec},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "unrelated", CreationTimestamp: metav1.Unix(300, 0)},
			Spec: computev1alpha1.ServiceRevisionSpec{
				ServiceConfigSpec: *svc.Spec.Template.Spec.DeepCopy(),
				Bundle:            computev1alpha1.BundleRef{Repo: bundle.Repo, Digest: "sha256:different"},
			},
		},
	}
	set := newEquivalentRevisionSet(svc.Name, revisionName(svc, bundle), revisions)
	cases := []struct {
		name           string
		preferredNames []string
		want           string
	}{
		{name: "preferred equivalent", preferredNames: []string{"old"}, want: "old"},
		{name: "first matching preference", preferredNames: []string{"missing", "old"}, want: "old"},
		{name: "non-equivalent preference ignored", preferredNames: []string{"unrelated"}, want: "new"},
		{name: "newest equivalent fallback", want: "new"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := set.selectRevision(tc.preferredNames...)
			if got == nil || got.Name != tc.want {
				t.Errorf("selected revision = %v, want %q", got, tc.want)
			}
		})
	}
}

func TestServiceReconciler_LiveTracksLatest(t *testing.T) {
	svc := ociService("api", "reg/acme/api", "sha256:abc")
	r, c := newReconciler(t, svc)
	reconcileOnce(t, r, "api")
	rev := listRevisions(t, c)[0]
	// Auto: LiveRevision records the latest minted revision (intent). Per-node
	// readiness and previous-revision fallback are the workerd-manager's job,
	// reported over the publish channel — not gated here.
	if lr := getService(t, c, "api").Status.LiveRevision; lr != rev.Name {
		t.Errorf("LiveRevision = %q, want %q (latest)", lr, rev.Name)
	}
}

func TestServiceReconciler_PinnedLiveRevision(t *testing.T) {
	svc := ociService("api", "reg/acme/api", "sha256:abc")
	r, c := newReconciler(t, svc)
	reconcileOnce(t, r, "api")
	rev := listRevisions(t, c)[0]

	// Pin liveRevision: the control plane records the pin as the intended revision
	// immediately. There is no control-plane readiness gate — readiness is per-node
	// and reported via the publish channel, so the manager won't actually serve the
	// pinned revision on a node until that node has warmed it.
	svc2 := getService(t, c, "api")
	svc2.Spec.LiveRevision = rev.Name
	if err := c.Update(context.Background(), svc2); err != nil {
		t.Fatalf("update service: %v", err)
	}
	reconcileOnce(t, r, "api")
	if lr := getService(t, c, "api").Status.LiveRevision; lr != rev.Name {
		t.Errorf("pinned LiveRevision = %q, want %q", lr, rev.Name)
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

// TestEnqueueBuildService: a git-sourced Service runs the newest succeeded
// Build, so a Build finishing has to re-enqueue its Service. Nothing else
// notices — the Service's own watch filters on generation, and the
// await-a-build poll stops once a revision exists.
func TestEnqueueBuildService(t *testing.T) {
	cases := []struct {
		name     string
		obj      client.Object
		wantName string
	}{
		{
			name:     "build enqueues its service",
			obj:      &computev1alpha1.Build{Spec: computev1alpha1.BuildSpec{ServiceRef: "api"}},
			wantName: "api",
		},
		{
			name: "build without a service ref enqueues nothing",
			obj:  &computev1alpha1.Build{},
		},
		{
			name: "non-build object enqueues nothing",
			obj:  &computev1alpha1.ServiceRevision{ObjectMeta: metav1.ObjectMeta{Name: "api-abc"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := enqueueBuildService(context.Background(), tc.obj)
			if tc.wantName == "" {
				if len(got) != 0 {
					t.Fatalf("requests = %v, want none", got)
				}
				return
			}
			if len(got) != 1 || got[0].Name != tc.wantName {
				t.Fatalf("requests = %v, want one request for %q", got, tc.wantName)
			}
		})
	}
}

func revNames(revs []computev1alpha1.ServiceRevision) []string {
	out := make([]string, len(revs))
	for i, r := range revs {
		out[i] = r.Name
	}
	return out
}
