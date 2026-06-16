// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"context"
	"encoding/json"
	"fmt"

	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	orasretry "oras.land/oras-go/v2/registry/remote/retry"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

// fetchBundleManifest fetches the OCI config blob — the JSON-encoded
// BundleManifest (media type application/vnd.apoxy.dev.service.config.v1+json)
// — for a bundle image. The sandbox ImageStore extracts the rootfs but does not
// surface this config blob, so the host fetches it directly. (R1.)
func fetchBundleManifest(ctx context.Context, imageRef string) (computev1alpha1.BundleManifest, error) {
	var out computev1alpha1.BundleManifest

	repo, err := remote.NewRepository(imageRef)
	if err != nil {
		return out, fmt.Errorf("creating repository: %w", err)
	}
	repo.Client = &auth.Client{
		Client:     orasretry.DefaultClient,
		Cache:      auth.NewCache(),
		Credential: auth.StaticCredential(repo.Reference.Registry, auth.EmptyCredential),
	}

	manifestDesc, err := repo.Resolve(ctx, repo.Reference.Reference)
	if err != nil {
		return out, fmt.Errorf("resolving %s: %w", imageRef, err)
	}
	manifestBlob, err := content.FetchAll(ctx, repo, manifestDesc)
	if err != nil {
		return out, fmt.Errorf("fetching OCI manifest: %w", err)
	}
	var manifest ocispecv1.Manifest
	if err := json.Unmarshal(manifestBlob, &manifest); err != nil {
		return out, fmt.Errorf("unmarshaling OCI manifest: %w", err)
	}

	configBlob, err := content.FetchAll(ctx, repo, manifest.Config)
	if err != nil {
		return out, fmt.Errorf("fetching bundle config blob: %w", err)
	}
	if err := json.Unmarshal(configBlob, &out); err != nil {
		return out, fmt.Errorf("unmarshaling bundle manifest: %w", err)
	}
	return out, nil
}
