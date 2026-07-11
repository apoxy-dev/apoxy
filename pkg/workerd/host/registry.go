// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"fmt"

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

// bundleRepositoryFor derives the image ref and pull credentials from b and
// builds the repository the fetchers pull over. Single derivation point, so a
// ref can never be paired with another bundle's credentials.
func bundleRepositoryFor(b computev1alpha1.BundleRef) (*remote.Repository, error) {
	imageRef, err := BundleImageRef(b)
	if err != nil {
		return nil, err
	}
	creds, err := BundlePullCredentials(b)
	if err != nil {
		return nil, err
	}
	return newBundleRepository(imageRef, creds)
}

// newBundleRepository builds the oras remote.Repository the bundle fetchers
// share, authenticating with creds (anonymous when zero) and with PlainHTTP
// enabled only when the target registry is listed in
// APOXY_INSECURE_BUNDLE_REGISTRIES. Shared with the CLI's push side via
// pkg/workerd/bundle so build and serve can never disagree on transport.
func newBundleRepository(imageRef string, creds PullCredentials) (*remote.Repository, error) {
	return bundle.NewRepository(imageRef, bundle.WithCredential(creds))
}
