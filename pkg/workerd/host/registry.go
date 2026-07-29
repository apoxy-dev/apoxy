// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"crypto/tls"
	"fmt"
	"strings"
	"sync/atomic"

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/bundle"
)

// insecureBundleRegistriesEnv lists registries (host[:port], comma-separated)
// the bundle fetcher talks to over plain HTTP instead of HTTPS. See
// bundle.InsecureRegistriesEnv (shared with the push side).
const insecureBundleRegistriesEnv = bundle.InsecureRegistriesEnv

// PullCredentials authenticate bundle pulls against a private registry, using
// the docker/oras credential model directly: Username+Password drive basic
// auth and the standard token-service exchange; RefreshToken drives an OAuth2
// exchange (ACR-style identity tokens); AccessToken is sent as a bearer as-is.
// The zero value means anonymous.
type PullCredentials = auth.Credential

// BundlePullCredentials extracts the pull credentials a BundleRef carries.
// Inline credentials are honored (PasswordData, raw bytes, wins over Password
// when both are set). CredentialsRef cannot be resolved here — there is no
// secret store to dereference it against yet — so it fails loudly rather than
// silently degrading to an anonymous pull that 401s at the registry. Admission
// rejects credentialsRef for the same reason (validateBundle); this guard
// covers objects that predate that check.
func BundlePullCredentials(b computev1alpha1.BundleRef) (PullCredentials, error) {
	if b.CredentialsRef != nil {
		return PullCredentials{}, fmt.Errorf(
			"workerd-host: bundle %s: credentialsRef is not supported by the bundle fetcher yet; use inline credentials", b.Repo)
	}
	if b.Credentials == nil {
		return PullCredentials{}, nil
	}
	pwd := b.Credentials.Password
	if len(b.Credentials.PasswordData) > 0 {
		pwd = string(b.Credentials.PasswordData)
	}
	return PullCredentials{
		Username:     b.Credentials.Username,
		Password:     pwd,
		AccessToken:  b.Credentials.AccessToken,
		RefreshToken: b.Credentials.RefreshToken,
	}, nil
}

// PlatformPullTLSFunc returns the TLS client configuration for pulls from
// registryHost, or ok=false when the host is not the platform registry. Set by
// the embedding data plane (SetPlatformPullTLS) so edge services can
// authenticate platform-registry pulls with the client certs they already
// hold. Deliberately keyed on the registry host: platform credentials must
// never be presented to a customer's BYO registry.
type PlatformPullTLSFunc func(registryHost string) (*tls.Config, bool)

var platformPullTLS atomic.Pointer[PlatformPullTLSFunc]

// SetPlatformPullTLS installs the platform-registry TLS source for bundle
// pulls. Call once at process startup; nil clears it.
func SetPlatformPullTLS(fn PlatformPullTLSFunc) {
	if fn == nil {
		platformPullTLS.Store(nil)
		return
	}
	platformPullTLS.Store(&fn)
}

// bundleRepositoryFor derives the image ref and pull credentials from b and
// builds the repository the fetchers pull over. Single derivation point, so a
// ref can never be paired with another bundle's credentials. Bundles that
// carry no credentials of their own additionally get the platform TLS client
// config when their registry host matches the installed platform source.
func bundleRepositoryFor(b computev1alpha1.BundleRef) (*remote.Repository, error) {
	imageRef, err := BundleImageRef(b)
	if err != nil {
		return nil, err
	}
	creds, err := BundlePullCredentials(b)
	if err != nil {
		return nil, err
	}
	opts := []bundle.RepositoryOption{bundle.WithCredential(creds)}
	if fn := platformPullTLS.Load(); fn != nil && b.Credentials == nil && b.CredentialsRef == nil {
		host, _, _ := strings.Cut(b.Repo, "/")
		if tlsCfg, ok := (*fn)(host); ok {
			opts = append(opts, bundle.WithClientTLS(tlsCfg))
		}
	}
	return bundle.NewRepository(imageRef, opts...)
}

