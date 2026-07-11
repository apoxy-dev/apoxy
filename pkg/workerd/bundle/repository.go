// SPDX-License-Identifier: AGPL-3.0-only

// Package bundle packs, pushes, and stages compute service bundles: the OCI
// artifact shape the workerd data plane pulls (pkg/workerd/host). It is the
// single place where build (CLI) and serve agree on the wire format — an OCI
// image manifest whose config blob is the JSON BundleManifest and whose layers
// carry the modules as a gzip'd tar.
package bundle

import (
	"context"
	"log/slog"
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
	credential     auth.Credential
	credentialFunc auth.CredentialFunc
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
	repo.Client = &auth.Client{
		Client:     orasretry.DefaultClient,
		Cache:      auth.NewCache(),
		Credential: credFn,
	}
	return repo, nil
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
