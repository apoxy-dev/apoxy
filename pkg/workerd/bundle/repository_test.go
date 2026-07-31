// SPDX-License-Identifier: AGPL-3.0-only

package bundle_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/apoxy-dev/apoxy/pkg/workerd/bundle"
)

// blobDigest is a well-formed digest for a blob the fake registry claims to
// have; its bytes never matter because only Exists (a HEAD) is exercised.
const blobDigest = "sha256:40195f05579d155d5856fe876d6c2c4166b77a19112d67c4a85120dc5cf53703"

// redirectingRegistry models the platform registry's blob path: the /v2/
// endpoints answer directly, but a blob request is answered with a redirect to
// a separate storage host that authenticates via presigned URL query
// parameters. It records the Authorization header seen at each hop.
type redirectingRegistry struct {
	mu          sync.Mutex
	registryAuz []string
	storageAuz  []string

	storageURL string
}

func newRedirectingRegistry(t *testing.T) (*redirectingRegistry, string) {
	t.Helper()
	r := &redirectingRegistry{}

	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.storageAuz = append(r.storageAuz, req.Header.Get("Authorization"))
		r.mu.Unlock()
		// Real object storage rejects a presigned request that also carries an
		// Authorization header ("Only one auth mechanism allowed"), which is
		// what turned this leak into a hard push failure.
		if req.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Docker-Content-Digest", blobDigest)
		w.Header().Set("Content-Length", "102")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(storage.Close)
	r.storageURL = storage.URL

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.registryAuz = append(r.registryAuz, req.Header.Get("Authorization"))
		r.mu.Unlock()
		if req.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, req, r.storageURL+"/blobs/data?X-Amz-Signature=deadbeef", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(registry.Close)

	u, err := url.Parse(registry.URL)
	if err != nil {
		t.Fatal(err)
	}
	// httptest serves plain HTTP.
	t.Setenv(bundle.InsecureRegistriesEnv, u.Host)
	return r, u.Host
}

func (r *redirectingRegistry) seen() (registry, storage []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.registryAuz...), append([]string(nil), r.storageAuz...)
}

// TestPreemptiveBasicAuth_NotSentToRedirectTarget is the regression test for
// the credential riding along to a redirect target. A RoundTripper runs for
// every hop http.Client follows, so re-adding the credential there undoes the
// stdlib's cross-host Authorization stripping: the API key reaches storage and
// the push fails with a 400.
func TestPreemptiveBasicAuth_NotSentToRedirectTarget(t *testing.T) {
	reg, registryHost := newRedirectingRegistry(t)

	repo, err := bundle.NewRepository(registryHost+"/acme/api",
		bundle.WithCredentialFunc(auth.StaticCredential(registryHost, auth.Credential{
			Username: "apoxy",
			Password: "super-secret-api-key",
		})),
		bundle.WithPreemptiveBasicAuth(),
	)
	if err != nil {
		t.Fatalf("NewRepository() error = %v", err)
	}

	ok, err := repo.Blobs().Exists(context.Background(), ocispec.Descriptor{
		MediaType: "application/octet-stream",
		Digest:    blobDigest,
		Size:      102,
	})
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if !ok {
		t.Fatal("Exists() = false, want true for a blob the registry redirects to")
	}

	registryAuz, storageAuz := reg.seen()
	if len(storageAuz) == 0 {
		t.Fatal("redirect target was never reached; the test no longer exercises the redirect path")
	}
	for _, got := range storageAuz {
		if got != "" {
			t.Errorf("redirect target received Authorization %q, want none: the registry credential must not follow a cross-host redirect", got)
		}
	}

	var authed bool
	for _, got := range registryAuz {
		if got != "" {
			authed = true
		}
	}
	if !authed {
		t.Error("registry received no Authorization header; preemptive basic auth must still credential the registry itself")
	}
}

// TestPreemptiveBasicAuth_CredentialsRegistryHost guards the other direction:
// the host check must not stop the registry itself from being credentialed,
// including when the reference carries the scheme's default port.
func TestPreemptiveBasicAuth_CredentialsRegistryHost(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		seen = append(seen, req.Header.Get("Authorization"))
		mu.Unlock()
		if req.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Docker-Content-Digest", blobDigest)
		w.Header().Set("Content-Length", "102")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(bundle.InsecureRegistriesEnv, u.Host)

	repo, err := bundle.NewRepository(u.Host+"/acme/api",
		bundle.WithCredentialFunc(auth.StaticCredential(u.Host, auth.Credential{
			Username: "apoxy",
			Password: "super-secret-api-key",
		})),
		bundle.WithPreemptiveBasicAuth(),
	)
	if err != nil {
		t.Fatalf("NewRepository() error = %v", err)
	}

	if _, err := repo.Blobs().Exists(context.Background(), ocispec.Descriptor{
		MediaType: "application/octet-stream",
		Digest:    blobDigest,
		Size:      102,
	}); err != nil {
		t.Fatalf("Exists() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("registry was never reached")
	}
	for _, got := range seen {
		if got == "" {
			t.Fatalf("registry request carried no Authorization header, want preemptive basic auth (saw %v)", seen)
		}
	}
}
