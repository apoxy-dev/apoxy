// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"os"
	"strings"

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	orasretry "oras.land/oras-go/v2/registry/remote/retry"
)

// insecureBundleRegistriesEnv lists registries (host[:port], comma-separated)
// the bundle fetcher talks to over plain HTTP instead of HTTPS. It exists for
// `apoxy dev`, where the workerd-manager pulls bundles from a local insecure
// registry on the docker network — mirroring `oras --plain-http` and docker's
// insecure-registries. Unset in production, so every pull stays HTTPS.
const insecureBundleRegistriesEnv = "APOXY_INSECURE_BUNDLE_REGISTRIES"

// newBundleRepository builds the oras remote.Repository the bundle fetchers
// share: an anonymous auth client, with PlainHTTP enabled only when the target
// registry is listed in APOXY_INSECURE_BUNDLE_REGISTRIES.
func newBundleRepository(imageRef string) (*remote.Repository, error) {
	repo, err := remote.NewRepository(imageRef)
	if err != nil {
		return nil, err
	}
	repo.Client = &auth.Client{
		Client:     orasretry.DefaultClient,
		Cache:      auth.NewCache(),
		Credential: auth.StaticCredential(repo.Reference.Registry, auth.EmptyCredential),
	}
	if isInsecureBundleRegistry(repo.Reference.Registry) {
		repo.PlainHTTP = true
	}
	return repo, nil
}

func isInsecureBundleRegistry(registry string) bool {
	for _, r := range strings.Split(os.Getenv(insecureBundleRegistriesEnv), ",") {
		if r = strings.TrimSpace(r); r != "" && r == registry {
			return true
		}
	}
	return false
}
