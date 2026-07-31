// SPDX-License-Identifier: AGPL-3.0-only

// Package bundle packs, pushes, and stages compute service bundles: the OCI
// artifact shape the workerd data plane pulls (pkg/workerd/host). It is the
// single place where build (CLI) and serve agree on the wire format — an OCI
// image manifest whose config blob is the JSON BundleManifest and whose layers
// carry the modules as a gzip'd tar.
package bundle

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	orasretry "oras.land/oras-go/v2/registry/remote/retry"
)

// InsecureRegistriesEnv lists registries (host[:port], comma-separated) that
// bundle pushes and pulls talk to over plain HTTP instead of HTTPS. It exists
// for `apoxy dev`, where bundles flow through a local insecure registry on the
// docker network — mirroring `oras --plain-http` and docker's
// insecure-registries. Unset in production, so every transfer stays HTTPS.
const InsecureRegistriesEnv = "APOXY_INSECURE_BUNDLE_REGISTRIES"

// RepositoryOption configures NewRepository.
type RepositoryOption func(*repositoryOptions)

type repositoryOptions struct {
	credential      auth.Credential
	credentialFunc  auth.CredentialFunc
	clientTLS       *tls.Config
	preemptiveBasic bool
}

// WithCredential authenticates with a fixed credential. The zero credential is
// anonymous.
func WithCredential(cred auth.Credential) RepositoryOption {
	return func(o *repositoryOptions) { o.credential = cred }
}

// WithCredentialFunc authenticates with a dynamic credential source (e.g. the
// docker credential store). Takes precedence over WithCredential.
func WithCredentialFunc(fn auth.CredentialFunc) RepositoryOption {
	return func(o *repositoryOptions) { o.credentialFunc = fn }
}

// WithClientTLS sets the TLS client configuration for the registry transport —
// the transport-level counterpart of the credential options, used when the
// registry authenticates connections with client certificates (e.g. edge
// services pulling from the platform registry with their shard certs).
func WithClientTLS(cfg *tls.Config) RepositoryOption {
	return func(o *repositoryOptions) { o.clientTLS = cfg }
}

// WithPreemptiveBasicAuth sends the resolved credential as a Basic
// Authorization header on every request instead of waiting for a 401
// challenge. The platform registry needs this: its ext_authz maps anonymous
// reads to a shared read-only pull identity (in dev), so the standard
// probe-then-authenticate dance never sees a challenge and the client would
// be stuck with that identity's rights for the whole push.
func WithPreemptiveBasicAuth() RepositoryOption {
	return func(o *repositoryOptions) { o.preemptiveBasic = true }
}

// NewRepository builds the oras remote.Repository both the bundle pusher (CLI)
// and the bundle fetchers (workerd host) share, with PlainHTTP enabled only
// when the target registry is listed in APOXY_INSECURE_BUNDLE_REGISTRIES.
func NewRepository(imageRef string, opts ...RepositoryOption) (*remote.Repository, error) {
	var o repositoryOptions
	for _, opt := range opts {
		opt(&o)
	}
	repo, err := remote.NewRepository(imageRef)
	if err != nil {
		return nil, err
	}
	credFn := o.credentialFunc
	if credFn == nil {
		credFn = auth.StaticCredential(repo.Reference.Registry, o.credential)
	}
	if IsInsecureRegistry(repo.Reference.Registry) {
		repo.PlainHTTP = true
		// Warn lazily, when a credential actually resolves to something
		// non-anonymous: a credential *source* (e.g. the docker credential
		// store) is always present on the push path but usually yields
		// nothing, and a warning that cries wolf on anonymous transfers
		// trains users to ignore the one that matters.
		credFn = warnPlaintextCredentials(credFn, repo.Reference.Registry)
	}
	httpClient := orasretry.DefaultClient
	if o.clientTLS != nil {
		base := http.DefaultTransport.(*http.Transport).Clone()
		base.TLSClientConfig = o.clientTLS
		httpClient = &http.Client{Transport: orasretry.NewTransport(base)}
	}
	if o.preemptiveBasic {
		base := httpClient.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		httpClient = &http.Client{Transport: &preemptiveBasicTransport{
			next: base,
			cred: credFn,
			host: repo.Reference.Registry,
		}}
	}
	repo.Client = &auth.Client{
		Client:     httpClient,
		Cache:      auth.NewCache(),
		Credential: credFn,
	}
	return repo, nil
}

// preemptiveBasicTransport attaches Basic credentials to requests that carry
// no Authorization header yet, so the first request already authenticates.
// The wrapping auth.Client still handles any 401 that comes back.
type preemptiveBasicTransport struct {
	next http.RoundTripper
	cred auth.CredentialFunc
	host string
}

func (t *preemptiveBasicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only ever credential the registry itself. A RoundTripper sits *below*
	// http.Client's redirect handling, so it runs again for every hop the
	// client follows — and net/http deliberately drops Authorization when a
	// redirect crosses hosts. Without this check we would put the credential
	// back on exactly the requests the stdlib just protected: a registry that
	// serves blobs by redirecting to object storage (the platform registry
	// redirects to presigned S3 URLs) would receive the project API key at a
	// third-party host. S3 also rejects a presigned URL that carries an
	// Authorization header with 400 "Only one auth mechanism allowed", so this
	// broke any push whose blobs were already present in the destination repo.
	if req.Header.Get("Authorization") == "" && sameHost(req.URL, t.host) {
		cred, err := t.cred(req.Context(), t.host)
		if err == nil && cred.Username != "" && cred.Password != "" {
			req = req.Clone(req.Context())
			req.SetBasicAuth(cred.Username, cred.Password)
		}
	}
	return t.next.RoundTrip(req)
}

// sameHost reports whether u addresses host (a registry "host[:port]"),
// treating the scheme's default port as equivalent to no port so that a
// reference written as "registry.example.com:443" still authenticates.
func sameHost(u *url.URL, host string) bool {
	if u == nil {
		return false
	}
	return canonicalHost(u.Host, u.Scheme) == canonicalHost(host, u.Scheme)
}

func canonicalHost(hostport, scheme string) string {
	hostport = strings.ToLower(hostport)
	h, port, err := net.SplitHostPort(hostport)
	if err != nil {
		// No port to normalize away.
		return hostport
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return h
	}
	return hostport
}

// warnPlaintextCredentials wraps a credential source so that the first
// non-anonymous credential resolved for a plain-HTTP registry logs a warning.
// Deliberate but dangerous: the insecure list is a dev-only escape hatch, and
// credentials on this path cross the wire unencrypted.
func warnPlaintextCredentials(credFn auth.CredentialFunc, registry string) auth.CredentialFunc {
	var once sync.Once
	return func(ctx context.Context, hostport string) (auth.Credential, error) {
		cred, err := credFn(ctx, hostport)
		if err == nil && cred != auth.EmptyCredential {
			once.Do(func() {
				slog.Warn("Sending registry credentials over plain HTTP; anyone on the network path can read them",
					"registry", registry)
			})
		}
		return cred, err
	}
}

// IsInsecureRegistry reports whether registry (host[:port]) is on the
// plain-HTTP allowlist.
func IsInsecureRegistry(registry string) bool {
	for _, r := range strings.Split(os.Getenv(InsecureRegistriesEnv), ",") {
		if r = strings.TrimSpace(r); r != "" && r == registry {
			return true
		}
	}
	return false
}
