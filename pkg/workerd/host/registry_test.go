// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

func TestBundlePullCredentials(t *testing.T) {
	cases := []struct {
		name    string
		bundle  computev1alpha1.BundleRef
		want    PullCredentials
		wantErr string
	}{
		{
			name:   "no credentials is anonymous",
			bundle: computev1alpha1.BundleRef{Repo: "reg.example.com/acme/api"},
			want:   PullCredentials{},
		},
		{
			name: "inline password",
			bundle: computev1alpha1.BundleRef{
				Repo:        "reg.example.com/acme/api",
				Credentials: &computev1alpha1.OCICredentials{Username: "bob", Password: "hunter2"},
			},
			want: PullCredentials{Username: "bob", Password: "hunter2"},
		},
		{
			name: "passwordData wins over password",
			bundle: computev1alpha1.BundleRef{
				Repo: "reg.example.com/acme/api",
				Credentials: &computev1alpha1.OCICredentials{
					Username:     "bob",
					Password:     "stale",
					PasswordData: []byte("hunter2"),
				},
			},
			want: PullCredentials{Username: "bob", Password: "hunter2"},
		},
		{
			name: "tokens pass through",
			bundle: computev1alpha1.BundleRef{
				Repo: "reg.example.com/acme/api",
				Credentials: &computev1alpha1.OCICredentials{
					AccessToken:  "tok123",
					RefreshToken: "refresh456",
				},
			},
			want: PullCredentials{AccessToken: "tok123", RefreshToken: "refresh456"},
		},
		{
			name: "credentialsRef fails loudly",
			bundle: computev1alpha1.BundleRef{
				Repo:           "reg.example.com/acme/api",
				CredentialsRef: &computev1alpha1.OCICredentialsRef{Kind: "Secret", Name: "pull-creds"},
			},
			wantErr: "credentialsRef is not supported",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BundlePullCredentials(tc.bundle)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("BundlePullCredentials() error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("BundlePullCredentials() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("BundlePullCredentials() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// registryAuth configures how fakeBundleRegistry authenticates pulls. Zero
// value = anonymous. user/pass demand basic auth. bearer demands that exact
// bearer token on /v2/*, challenging with a token-service realm; refresh, if
// also set, is the OAuth2 refresh token the /token endpoint exchanges for
// bearer (the ACR-style identity-token flow).
type registryAuth struct {
	user, pass string
	bearer     string
	refresh    string
}

// fakeBundleRegistry serves a minimal OCI pull API (manifest by digest +
// blobs) for a single one-module bundle, gated per auth — enough for oras's
// auth.Client to exercise each credential flow for real. tokenRequests counts
// /token hits so tests can assert how many auth exchanges a fetch performed.
func fakeBundleRegistry(t *testing.T, reg registryAuth) (bundle computev1alpha1.BundleRef, wantManifest computev1alpha1.BundleManifest, tokenRequests *atomic.Int32) {
	t.Helper()

	wantManifest = computev1alpha1.BundleManifest{
		Modules:           []computev1alpha1.Module{{Name: "index.js", Type: computev1alpha1.ESModule, Path: "index.js"}},
		CompatibilityDate: "2024-01-01",
	}
	configBlob, err := json.Marshal(wantManifest)
	if err != nil {
		t.Fatal(err)
	}
	configDigest := digest.FromBytes(configBlob)
	modulesBlob := gzipTar(t, map[string][]byte{"index.js": []byte("export default {}")})
	modulesDigest := digest.FromBytes(modulesBlob)

	manifest := ocispecv1.Manifest{
		MediaType: ocispecv1.MediaTypeImageManifest,
		Config: ocispecv1.Descriptor{
			MediaType: computev1alpha1.ServiceBundleConfigMediaType,
			Digest:    configDigest,
			Size:      int64(len(configBlob)),
		},
		Layers: []ocispecv1.Descriptor{{
			MediaType: computev1alpha1.ServiceBundleModuleLayerMediaType,
			Digest:    modulesDigest,
			Size:      int64(len(modulesBlob)),
		}},
	}
	manifest.SchemaVersion = 2
	manifestBlob, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := digest.FromBytes(manifestBlob)

	blobs := map[string][]byte{
		configDigest.String():  configBlob,
		modulesDigest.String(): modulesBlob,
	}

	serve := func(w http.ResponseWriter, r *http.Request, mediaType string, dgst string, body []byte) {
		w.Header().Set("Content-Type", mediaType)
		w.Header().Set("Docker-Content-Digest", dgst)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}
	tokenRequests = &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokenRequests.Add(1)
			// OAuth2 token endpoint: exchanges the configured refresh token
			// for the bearer the /v2/* endpoints demand.
			if reg.refresh != "" && r.Method == http.MethodPost {
				if err := r.ParseForm(); err == nil &&
					r.PostForm.Get("grant_type") == "refresh_token" &&
					r.PostForm.Get("refresh_token") == reg.refresh {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprintf(w, `{"access_token":%q}`, reg.bearer)
					return
				}
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case reg.bearer != "":
			if r.Header.Get("Authorization") != "Bearer "+reg.bearer {
				w.Header().Set("Www-Authenticate",
					fmt.Sprintf(`Bearer realm=%q,service="registry"`, "http://"+r.Host+"/token"))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		case reg.user != "":
			if u, p, ok := r.BasicAuth(); !ok || u != reg.user || p != reg.pass {
				w.Header().Set("Www-Authenticate", `Basic realm="test"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/v2/acme/api/manifests/"):
			serve(w, r, ocispecv1.MediaTypeImageManifest, manifestDigest.String(), manifestBlob)
		case strings.HasPrefix(r.URL.Path, "/v2/acme/api/blobs/"):
			body, ok := blobs[strings.TrimPrefix(r.URL.Path, "/v2/acme/api/blobs/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			serve(w, r, "application/octet-stream", "", body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// httptest serves plain HTTP; route the fetcher through the insecure list.
	t.Setenv(insecureBundleRegistriesEnv, u.Host)

	return computev1alpha1.BundleRef{
		Repo:   u.Host + "/acme/api",
		Digest: manifestDigest.String(),
	}, wantManifest, tokenRequests
}

// gzipTar packs files into the gzip'd tar shape of a bundle modules layer.
func gzipTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestFetchBundleManifest_Auth(t *testing.T) {
	cases := []struct {
		name    string
		reg     registryAuth
		creds   *computev1alpha1.OCICredentials
		wantErr bool
	}{
		{name: "anonymous registry, zero creds", reg: registryAuth{}},
		{name: "basic auth, matching creds", reg: registryAuth{user: "bob", pass: "hunter2"}, creds: &computev1alpha1.OCICredentials{Username: "bob", Password: "hunter2"}},
		{name: "basic auth, zero creds is denied", reg: registryAuth{user: "bob", pass: "hunter2"}, wantErr: true},
		{name: "basic auth, wrong password is denied", reg: registryAuth{user: "bob", pass: "hunter2"}, creds: &computev1alpha1.OCICredentials{Username: "bob", Password: "nope"}, wantErr: true},
		{name: "bearer registry, direct access token", reg: registryAuth{bearer: "tok123"}, creds: &computev1alpha1.OCICredentials{AccessToken: "tok123"}},
		{name: "bearer registry, refresh token exchange", reg: registryAuth{bearer: "tok123", refresh: "refresh456"}, creds: &computev1alpha1.OCICredentials{RefreshToken: "refresh456"}},
		{name: "bearer registry, zero creds is denied", reg: registryAuth{bearer: "tok123"}, wantErr: true},
		{name: "bearer registry, wrong refresh token is denied", reg: registryAuth{bearer: "tok123", refresh: "refresh456"}, creds: &computev1alpha1.OCICredentials{RefreshToken: "nope"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bundle, want, _ := fakeBundleRegistry(t, tc.reg)
			bundle.Credentials = tc.creds
			got, err := FetchBundleManifest(t.Context(), bundle)
			if tc.wantErr {
				if err == nil {
					t.Fatal("FetchBundleManifest() succeeded, want auth error")
				}
				return
			}
			if err != nil {
				t.Fatalf("FetchBundleManifest() error = %v", err)
			}
			if got.CompatibilityDate != want.CompatibilityDate || len(got.Modules) != len(want.Modules) {
				t.Fatalf("FetchBundleManifest() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestFetchBundle_SingleAuthExchange(t *testing.T) {
	bundle, want, tokenRequests := fakeBundleRegistry(t, registryAuth{bearer: "tok123", refresh: "refresh456"})
	bundle.Credentials = &computev1alpha1.OCICredentials{RefreshToken: "refresh456"}

	manifest, modules, err := FetchBundle(t.Context(), bundle)
	if err != nil {
		t.Fatalf("FetchBundle() error = %v", err)
	}
	if manifest.CompatibilityDate != want.CompatibilityDate {
		t.Fatalf("FetchBundle() manifest = %+v, want %+v", manifest, want)
	}
	if _, ok := modules["index.js"]; !ok {
		t.Fatalf("FetchBundle() modules = %v, want index.js", modules)
	}
	// One repository session serves manifest + config + modules: the OAuth2
	// refresh exchange must run exactly once, not once per blob.
	if got := tokenRequests.Load(); got != 1 {
		t.Fatalf("token exchanges = %d, want exactly 1", got)
	}
}
