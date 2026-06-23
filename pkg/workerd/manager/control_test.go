// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// getWorker GETs /worker?id=<id> and returns status + body.
func getWorker(t *testing.T, base, id string) (int, string) {
	t.Helper()
	u := base + workerPath
	if id != "" {
		u += "?id=" + id
	}
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// storeWith builds a Store over a client holding one revision (api:api-abc) and
// the given fetcher.
func storeWith(t *testing.T, f *fakeFetcher) *Store {
	t.Helper()
	c := newFakeClient(t, revision("api-abc", "api", "sha256:d"))
	return NewStore(newResolverWithFetcher(c, f))
}

func TestControlServer_ServesWorkerCode(t *testing.T) {
	f := &fakeFetcher{manifest: esManifest(), modules: map[string][]byte{"index.js": []byte("export default {fetch(){return new Response('hi')}}")}}
	store := storeWith(t, f)
	srv := httptest.NewServer(NewControlServer(store).Handler())
	defer srv.Close()

	status, body := getWorker(t, srv.URL, "api:api-abc")
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, body)
	}
	// The body is the WorkerCode shape the dispatcher's WorkerLoader callback
	// consumes, with the runtime "js" module key.
	for _, want := range []string{
		`"mainModule":"index.js"`,
		`"modules":{"index.js":{"js":`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %s:\n%s", want, body)
		}
	}
	// It must be valid JSON.
	var probe map[string]any
	if err := json.Unmarshal([]byte(body), &probe); err != nil {
		t.Errorf("body is not valid JSON: %v", err)
	}
}

func TestControlServer_StatusCodes(t *testing.T) {
	cases := []struct {
		name    string
		id      string
		fetcher *fakeFetcher
		want    int
	}{
		{"missing id", "", &fakeFetcher{manifest: esManifest(), modules: map[string][]byte{"index.js": {}}}, http.StatusBadRequest},
		{"unknown revision", "api:missing", &fakeFetcher{manifest: esManifest(), modules: map[string][]byte{"index.js": {}}}, http.StatusNotFound},
		{"registry failure", "api:api-abc", &fakeFetcher{manifestErr: fmt.Errorf("registry down")}, http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := storeWith(t, tc.fetcher)
			srv := httptest.NewServer(NewControlServer(store).Handler())
			defer srv.Close()
			status, body := getWorker(t, srv.URL, tc.id)
			if status != tc.want {
				t.Errorf("status = %d, want %d (body: %s)", status, tc.want, body)
			}
		})
	}
}

// getResolve GETs /resolve?service=<service> and returns status + body.
func getResolve(t *testing.T, base, service string) (int, string) {
	t.Helper()
	u := base + resolvePath
	if service != "" {
		u += "?service=" + service
	}
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestControlServer_Resolve(t *testing.T) {
	f := &fakeFetcher{manifest: esManifest(), modules: map[string][]byte{"index.js": []byte("x")}}
	store := storeWith(t, f)
	// The resident reconciler records the live-revision selection here; the
	// dispatcher resolves against it instead of reading the revision off the
	// Envoy header.
	store.setDemux(map[string]string{"api": "api-abc"})
	srv := httptest.NewServer(NewControlServer(store).Handler())
	defer srv.Close()

	t.Run("resolves the live revision id", func(t *testing.T) {
		status, body := getResolve(t, srv.URL, "api")
		if status != http.StatusOK {
			t.Fatalf("status = %d, body = %s", status, body)
		}
		var got resolveResponse
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatalf("body is not valid JSON: %v (%s)", err, body)
		}
		// The id is the 2-part demux id the dispatcher feeds straight to /worker.
		if got.ID != "api:api-abc" {
			t.Errorf("id = %q, want api:api-abc", got.ID)
		}
		if got.Revision != "api-abc" {
			t.Errorf("revision = %q, want api-abc", got.Revision)
		}
	})

	t.Run("missing service is a 400", func(t *testing.T) {
		if status, _ := getResolve(t, srv.URL, ""); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("unknown service is a 404", func(t *testing.T) {
		if status, _ := getResolve(t, srv.URL, "nope"); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})
}

func TestStore_CachesAfterWarm(t *testing.T) {
	f := &fakeFetcher{manifest: esManifest(), modules: map[string][]byte{"index.js": []byte("x")}}
	store := storeWith(t, f)

	if _, err := store.Warm(context.Background(), "api:api-abc"); err != nil {
		t.Fatalf("Warm: %v", err)
	}
	if !store.cached("api:api-abc") {
		t.Fatal("Warm should cache the definition")
	}
	callsAfterWarm := f.calls
	// A subsequent Get is served from cache: the fetcher is not hit again.
	if _, err := store.Get(context.Background(), "api:api-abc"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if f.calls != callsAfterWarm {
		t.Errorf("Get should serve from cache; fetcher Manifest calls went %d -> %d", callsAfterWarm, f.calls)
	}

	// After Invalidate, the next Get resolves again.
	store.Invalidate("api:api-abc")
	if store.cached("api:api-abc") {
		t.Fatal("Invalidate should drop the cache entry")
	}
	if _, err := store.Get(context.Background(), "api:api-abc"); err != nil {
		t.Fatalf("Get after invalidate: %v", err)
	}
	if f.calls <= callsAfterWarm {
		t.Errorf("Get after invalidate should re-fetch; calls = %d", f.calls)
	}
}
