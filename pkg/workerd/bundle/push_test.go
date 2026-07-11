// SPDX-License-Identifier: AGPL-3.0-only

package bundle_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/bundle"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
)

// fakePushRegistry is a minimal in-memory OCI registry supporting the push
// (blob upload session + manifest PUT) and pull endpoints oras uses, so Push
// output can be round-tripped through the real host fetcher.
type fakePushRegistry struct {
	mu        sync.Mutex
	blobs     map[string][]byte // keyed by digest
	manifests map[string][]byte // keyed by digest AND tag
}

func newFakePushRegistry(t *testing.T) (*fakePushRegistry, string) {
	t.Helper()
	r := &fakePushRegistry{
		blobs:     map[string][]byte{},
		manifests: map[string][]byte{},
	}
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// httptest serves plain HTTP; route both push and pull through the
	// insecure list.
	t.Setenv(bundle.InsecureRegistriesEnv, u.Host)
	return r, u.Host
}

func (r *fakePushRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	path := req.URL.Path
	switch {
	case path == "/v2/":
		w.WriteHeader(http.StatusOK)
	case strings.Contains(path, "/blobs/uploads/") && req.Method == http.MethodPost:
		w.Header().Set("Location", strings.TrimSuffix(path, "/")+"/session")
		w.WriteHeader(http.StatusAccepted)
	case strings.Contains(path, "/blobs/uploads/") && req.Method == http.MethodPut:
		dgst := req.URL.Query().Get("digest")
		body := readAll(req)
		r.blobs[dgst] = body
		w.Header().Set("Docker-Content-Digest", dgst)
		w.WriteHeader(http.StatusCreated)
	case strings.Contains(path, "/blobs/"):
		dgst := path[strings.LastIndex(path, "/")+1:]
		body, ok := r.blobs[dgst]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		serveBlob(w, req, "application/octet-stream", dgst, body)
	case strings.Contains(path, "/manifests/") && req.Method == http.MethodPut:
		ref := path[strings.LastIndex(path, "/")+1:]
		body := readAll(req)
		dgst := digest.FromBytes(body).String()
		r.manifests[dgst] = body
		r.manifests[ref] = body
		w.Header().Set("Docker-Content-Digest", dgst)
		w.WriteHeader(http.StatusCreated)
	case strings.Contains(path, "/manifests/"):
		ref := path[strings.LastIndex(path, "/")+1:]
		body, ok := r.manifests[ref]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		serveBlob(w, req, "application/vnd.oci.image.manifest.v1+json", digest.FromBytes(body).String(), body)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func readAll(req *http.Request) []byte {
	body, _ := io.ReadAll(req.Body)
	return body
}

func serveBlob(w http.ResponseWriter, req *http.Request, mediaType, dgst string, body []byte) {
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Docker-Content-Digest", dgst)
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	if req.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func testManifest() (computev1alpha1.BundleManifest, map[string][]byte) {
	manifest := computev1alpha1.BundleManifest{
		Modules: []computev1alpha1.Module{
			{Name: "index.js", Type: computev1alpha1.ESModule, Path: "index.js"},
			{Name: "data.bin", Type: computev1alpha1.DataModule, Path: "assets/data.bin"},
		},
		CompatibilityDate: "2025-01-01",
	}
	modules := map[string][]byte{
		"index.js":        []byte("export default { fetch() { return new Response('ok') } }"),
		"assets/data.bin": {0x00, 0x01, 0x02},
	}
	return manifest, modules
}

// TestPush_RoundTripsThroughHostFetcher pushes a bundle and pulls it back with
// the production fetcher (pkg/workerd/host), proving build and serve agree on
// the artifact shape end to end.
func TestPush_RoundTripsThroughHostFetcher(t *testing.T) {
	_, registryHost := newFakePushRegistry(t)
	manifest, modules := testManifest()
	repoRef := registryHost + "/acme/api"

	repo, err := bundle.NewRepository(repoRef)
	if err != nil {
		t.Fatalf("NewRepository() error = %v", err)
	}
	dig, err := bundle.Push(t.Context(), repo, "", manifest, modules)
	if err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	gotManifest, gotModules, err := host.FetchBundle(t.Context(), computev1alpha1.BundleRef{
		Repo:   repoRef,
		Digest: dig,
	})
	if err != nil {
		t.Fatalf("host.FetchBundle() error = %v", err)
	}
	if gotManifest.CompatibilityDate != manifest.CompatibilityDate ||
		len(gotManifest.Modules) != len(manifest.Modules) {
		t.Fatalf("fetched manifest = %+v, want %+v", gotManifest, manifest)
	}
	for path, want := range modules {
		if string(gotModules[path]) != string(want) {
			t.Fatalf("fetched module %q = %q, want %q", path, gotModules[path], want)
		}
	}
}

// TestPush_DigestIsReproducible pins the OCI created annotation: without it,
// PackManifest stamps time.Now() and byte-identical bundles mint a new digest
// (and thus a spurious ServiceRevision) on every push.
func TestPush_DigestIsReproducible(t *testing.T) {
	_, registryHost := newFakePushRegistry(t)
	manifest, modules := testManifest()

	repo, err := bundle.NewRepository(registryHost + "/acme/api")
	if err != nil {
		t.Fatalf("NewRepository() error = %v", err)
	}
	dig1, err := bundle.Push(t.Context(), repo, "", manifest, modules)
	if err != nil {
		t.Fatalf("Push() error = %v", err)
	}
	// RFC3339 created-timestamps have 1s granularity; cross the boundary so a
	// regression to time.Now() cannot pass by luck.
	time.Sleep(1100 * time.Millisecond)
	dig2, err := bundle.Push(t.Context(), repo, "", manifest, modules)
	if err != nil {
		t.Fatalf("Push() error = %v", err)
	}
	if dig1 != dig2 {
		t.Fatalf("identical content pushed twice minted different digests: %s vs %s", dig1, dig2)
	}
}

func TestPush_TagsWhenRequested(t *testing.T) {
	reg, registryHost := newFakePushRegistry(t)
	manifest, modules := testManifest()

	repo, err := bundle.NewRepository(registryHost + "/acme/api")
	if err != nil {
		t.Fatalf("NewRepository() error = %v", err)
	}
	dig, err := bundle.Push(t.Context(), repo, "v3", manifest, modules)
	if err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	reg.mu.Lock()
	defer reg.mu.Unlock()
	if string(reg.manifests["v3"]) != string(reg.manifests[dig]) {
		t.Fatalf("tag %q not pointing at pushed digest %q", "v3", dig)
	}
}

func TestPush_Validation(t *testing.T) {
	_, registryHost := newFakePushRegistry(t)
	repo, err := bundle.NewRepository(registryHost + "/acme/api")
	if err != nil {
		t.Fatalf("NewRepository() error = %v", err)
	}

	cases := []struct {
		name     string
		manifest computev1alpha1.BundleManifest
		modules  map[string][]byte
		wantErr  string
	}{
		{
			name:    "no modules",
			modules: nil,
			wantErr: "no modules",
		},
		{
			name: "manifest references missing module",
			manifest: computev1alpha1.BundleManifest{
				Modules: []computev1alpha1.Module{{Name: "gone.js", Type: computev1alpha1.ESModule, Path: "gone.js"}},
			},
			modules: map[string][]byte{"other.js": []byte("x")},
			wantErr: `"gone.js" has no content`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bundle.Push(t.Context(), repo, "", tc.manifest, tc.modules)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Push() error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}
