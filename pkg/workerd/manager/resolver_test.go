// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

// fakeFetcher is an in-memory BundleFetcher. It counts Bundle calls so cache
// behavior is assertable. Locked: the resident manager's done-watcher rewarms
// stores from its own goroutine, concurrently with test-goroutine reconciles.
type fakeFetcher struct {
	mu          sync.Mutex
	manifest    computev1alpha1.BundleManifest
	modules     map[string][]byte
	manifestErr error
	modulesErr  error
	calls       int
}

func (f *fakeFetcher) Bundle(_ context.Context, _ computev1alpha1.BundleRef) (computev1alpha1.BundleManifest, map[string][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.manifestErr != nil {
		return computev1alpha1.BundleManifest{}, nil, f.manifestErr
	}
	if f.modulesErr != nil {
		return computev1alpha1.BundleManifest{}, nil, f.modulesErr
	}
	return f.manifest, f.modules, nil
}

func (f *fakeFetcher) manifestCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeFetcher) setManifestErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.manifestErr = err
}

// esManifest is a single-esModule manifest fixture.
func esManifest() computev1alpha1.BundleManifest {
	return computev1alpha1.BundleManifest{
		Modules:           []computev1alpha1.Module{{Name: "index.js", Type: computev1alpha1.ESModule, Path: "index.js"}},
		CompatibilityDate: "2024-01-01",
	}
}

func revision(name, service, digest string) *computev1alpha1.ServiceRevision {
	return &computev1alpha1.ServiceRevision{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{serviceLabel: service}},
		Spec: computev1alpha1.ServiceRevisionSpec{
			Bundle: computev1alpha1.BundleRef{Repo: "reg/acme/api", Digest: digest},
		},
	}
}

func newFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithStatusSubresource(&computev1alpha1.Service{}, &computev1alpha1.ServiceRevision{}).
		WithObjects(objs...).
		Build()
}

func TestResolver_Resolve(t *testing.T) {
	t.Run("happy path maps path to name", func(t *testing.T) {
		c := newFakeClient(t, revision("api-abc", "api", "sha256:d"))
		f := &fakeFetcher{manifest: esManifest(), modules: map[string][]byte{"index.js": []byte("export default {}")}}
		r := newResolverWithFetcher(c, f)

		def, err := r.Resolve(context.Background(), "api:api-abc")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if def.MainModule != "index.js" {
			t.Errorf("MainModule = %q", def.MainModule)
		}
		if _, ok := def.Modules["index.js"]; !ok {
			t.Errorf("module index.js missing from definition: %+v", def.Modules)
		}
	})

	t.Run("invalid id", func(t *testing.T) {
		r := newResolverWithFetcher(newFakeClient(t), &fakeFetcher{})
		if _, err := r.Resolve(context.Background(), "noseparator"); err == nil {
			t.Fatal("want error for id without ':'")
		}
	})

	t.Run("revision not found", func(t *testing.T) {
		r := newResolverWithFetcher(newFakeClient(t), &fakeFetcher{manifest: esManifest()})
		_, err := r.Resolve(context.Background(), "api:missing")
		if !errors.Is(err, errRevisionNotFound) {
			t.Fatalf("err = %v, want errRevisionNotFound", err)
		}
	})

	t.Run("service label mismatch is not a 404", func(t *testing.T) {
		c := newFakeClient(t, revision("api-abc", "other", "sha256:d"))
		r := newResolverWithFetcher(c, &fakeFetcher{manifest: esManifest()})
		_, err := r.Resolve(context.Background(), "api:api-abc")
		if err == nil || errors.Is(err, errRevisionNotFound) {
			t.Fatalf("want a non-404 mismatch error, got %v", err)
		}
	})

	t.Run("fetcher manifest error propagates", func(t *testing.T) {
		c := newFakeClient(t, revision("api-abc", "api", "sha256:d"))
		r := newResolverWithFetcher(c, &fakeFetcher{manifestErr: fmt.Errorf("registry down")})
		if _, err := r.Resolve(context.Background(), "api:api-abc"); err == nil {
			t.Fatal("want error when the registry fetch fails")
		}
	})

	t.Run("missing module bytes surfaces precisely", func(t *testing.T) {
		c := newFakeClient(t, revision("api-abc", "api", "sha256:d"))
		// Manifest references index.js but Modules returns nothing for it.
		f := &fakeFetcher{manifest: esManifest(), modules: map[string][]byte{}}
		r := newResolverWithFetcher(c, f)
		_, err := r.Resolve(context.Background(), "api:api-abc")
		if err == nil {
			t.Fatal("want error when a manifest module has no bytes")
		}
	})
}

func TestSplitServiceID(t *testing.T) {
	cases := []struct {
		in      string
		wantSvc string
		wantRev string
		wantErr bool
	}{
		{"api:api-abc", "api", "api-abc", false},
		{"api:api-abc-def", "api", "api-abc-def", false},
		{"noseparator", "", "", true},
		{"api", "", "", true},
		{":rev", "", "", true},
		{"api:", "", "", true},
		{"", "", "", true},
		// A stale three-part "<project>:<service>:<revision>" id (old dispatcher,
		// new manager mid-rollout) must be rejected, not loose-parsed.
		{"proj:api:api-abc", "", "", true},
		{"svc::rev", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			svc, rev, err := splitServiceID(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if svc != tc.wantSvc || rev != tc.wantRev {
				t.Errorf("split(%q) = (%q,%q), want (%q,%q)",
					tc.in, svc, rev, tc.wantSvc, tc.wantRev)
			}
		})
	}
}
