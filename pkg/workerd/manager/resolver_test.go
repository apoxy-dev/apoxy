// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"errors"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

// fakeFetcher is an in-memory BundleFetcher. It counts Manifest calls so cache
// behavior is assertable.
type fakeFetcher struct {
	manifest    computev1alpha1.BundleManifest
	modules     map[string][]byte
	manifestErr error
	modulesErr  error
	calls       int
}

func (f *fakeFetcher) Manifest(_ context.Context, _ string) (computev1alpha1.BundleManifest, error) {
	f.calls++
	if f.manifestErr != nil {
		return computev1alpha1.BundleManifest{}, f.manifestErr
	}
	return f.manifest, nil
}

func (f *fakeFetcher) Modules(_ context.Context, _ string) (map[string][]byte, error) {
	if f.modulesErr != nil {
		return nil, f.modulesErr
	}
	return f.modules, nil
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
		r := newResolverWithFetcher(c, "proj", f)

		def, err := r.Resolve(context.Background(), "proj:api:api-abc")
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
		r := newResolverWithFetcher(newFakeClient(t), "proj", &fakeFetcher{})
		if _, err := r.Resolve(context.Background(), "noseparator"); err == nil {
			t.Fatal("want error for id without ':'")
		}
	})

	t.Run("revision not found", func(t *testing.T) {
		r := newResolverWithFetcher(newFakeClient(t), "proj", &fakeFetcher{manifest: esManifest()})
		_, err := r.Resolve(context.Background(), "proj:api:missing")
		if !errors.Is(err, errRevisionNotFound) {
			t.Fatalf("err = %v, want errRevisionNotFound", err)
		}
	})

	t.Run("wrong project never resolves", func(t *testing.T) {
		// Defense in depth: the shared resident must never serve another project's
		// id even if a revision of that bare name happens to exist locally.
		c := newFakeClient(t, revision("api-abc", "api", "sha256:d"))
		r := newResolverWithFetcher(c, "proj", &fakeFetcher{manifest: esManifest()})
		_, err := r.Resolve(context.Background(), "other:api:api-abc")
		if err == nil || errors.Is(err, errRevisionNotFound) {
			t.Fatalf("want a cross-project rejection, got %v", err)
		}
	})

	t.Run("service label mismatch is not a 404", func(t *testing.T) {
		c := newFakeClient(t, revision("api-abc", "other", "sha256:d"))
		r := newResolverWithFetcher(c, "proj", &fakeFetcher{manifest: esManifest()})
		_, err := r.Resolve(context.Background(), "proj:api:api-abc")
		if err == nil || errors.Is(err, errRevisionNotFound) {
			t.Fatalf("want a non-404 mismatch error, got %v", err)
		}
	})

	t.Run("fetcher manifest error propagates", func(t *testing.T) {
		c := newFakeClient(t, revision("api-abc", "api", "sha256:d"))
		r := newResolverWithFetcher(c, "proj", &fakeFetcher{manifestErr: fmt.Errorf("registry down")})
		if _, err := r.Resolve(context.Background(), "proj:api:api-abc"); err == nil {
			t.Fatal("want error when the registry fetch fails")
		}
	})

	t.Run("missing module bytes surfaces precisely", func(t *testing.T) {
		c := newFakeClient(t, revision("api-abc", "api", "sha256:d"))
		// Manifest references index.js but Modules returns nothing for it.
		f := &fakeFetcher{manifest: esManifest(), modules: map[string][]byte{}}
		r := newResolverWithFetcher(c, "proj", f)
		_, err := r.Resolve(context.Background(), "proj:api:api-abc")
		if err == nil {
			t.Fatal("want error when a manifest module has no bytes")
		}
	})
}

func TestSplitServiceID(t *testing.T) {
	cases := []struct {
		in       string
		wantProj string
		wantSvc  string
		wantRev  string
		wantErr  bool
	}{
		{"proj:api:api-abc", "proj", "api", "api-abc", false},
		{"proj:api:api-abc-def", "proj", "api", "api-abc-def", false},
		{"noseparator", "", "", "", true},
		{"proj:api", "", "", "", true},
		{":api:rev", "", "", "", true},
		{"proj::rev", "", "", "", true},
		{"proj:api:", "", "", "", true},
		{"", "", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			proj, svc, rev, err := splitServiceID(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if proj != tc.wantProj || svc != tc.wantSvc || rev != tc.wantRev {
				t.Errorf("split(%q) = (%q,%q,%q), want (%q,%q,%q)",
					tc.in, proj, svc, rev, tc.wantProj, tc.wantSvc, tc.wantRev)
			}
		})
	}
}
