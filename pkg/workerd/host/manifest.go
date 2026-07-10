// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"context"
	"encoding/json"
	"fmt"

	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

// FetchBundleManifest fetches the OCI config blob — the JSON-encoded
// BundleManifest (media type application/vnd.apoxy.dev.service.config.v1+json)
// — for a bundle. The sandbox ImageStore extracts the rootfs but does not
// surface this config blob, so the host fetches it directly. (R1.)
//
// Pull credentials are derived from the BundleRef itself; callers that also
// need the module bytes should use FetchBundle, which shares one registry
// session for both.
func FetchBundleManifest(ctx context.Context, b computev1alpha1.BundleRef) (computev1alpha1.BundleManifest, error) {
	repo, err := bundleRepositoryFor(b)
	if err != nil {
		return computev1alpha1.BundleManifest{}, err
	}
	manifest, err := fetchOCIManifest(ctx, repo)
	if err != nil {
		return computev1alpha1.BundleManifest{}, err
	}
	return bundleManifestFromConfig(ctx, repo, manifest)
}

// FetchBundle pulls a bundle's BundleManifest and module bytes in one pass:
// one repository, one auth exchange, one OCI manifest resolve serving both.
// It is the fetch entry point for the ServiceManager control plane
// (pkg/workerd/manager), which inlines a revision's module bytes into the
// WorkerLoader payload rather than mounting the bundle rootfs.
func FetchBundle(ctx context.Context, b computev1alpha1.BundleRef) (computev1alpha1.BundleManifest, map[string][]byte, error) {
	repo, err := bundleRepositoryFor(b)
	if err != nil {
		return computev1alpha1.BundleManifest{}, nil, err
	}
	manifest, err := fetchOCIManifest(ctx, repo)
	if err != nil {
		return computev1alpha1.BundleManifest{}, nil, err
	}
	bundle, err := bundleManifestFromConfig(ctx, repo, manifest)
	if err != nil {
		return computev1alpha1.BundleManifest{}, nil, err
	}
	modules, err := modulesFromLayers(ctx, repo, manifest, b.Repo)
	if err != nil {
		return computev1alpha1.BundleManifest{}, nil, err
	}
	return bundle, modules, nil
}

// fetchOCIManifest resolves the repository's pinned reference and fetches the
// OCI image manifest it points at.
func fetchOCIManifest(ctx context.Context, repo *remote.Repository) (ocispecv1.Manifest, error) {
	var manifest ocispecv1.Manifest
	manifestDesc, err := repo.Resolve(ctx, repo.Reference.Reference)
	if err != nil {
		return manifest, fmt.Errorf("resolving %s: %w", repo.Reference, err)
	}
	manifestBlob, err := content.FetchAll(ctx, repo, manifestDesc)
	if err != nil {
		return manifest, fmt.Errorf("fetching OCI manifest: %w", err)
	}
	if err := json.Unmarshal(manifestBlob, &manifest); err != nil {
		return manifest, fmt.Errorf("unmarshaling OCI manifest: %w", err)
	}
	return manifest, nil
}

// bundleManifestFromConfig fetches and decodes the manifest's config blob —
// the BundleManifest the builder embedded.
func bundleManifestFromConfig(ctx context.Context, repo *remote.Repository, manifest ocispecv1.Manifest) (computev1alpha1.BundleManifest, error) {
	var out computev1alpha1.BundleManifest
	configBlob, err := content.FetchAll(ctx, repo, manifest.Config)
	if err != nil {
		return out, fmt.Errorf("fetching bundle config blob: %w", err)
	}
	if err := json.Unmarshal(configBlob, &out); err != nil {
		return out, fmt.Errorf("unmarshaling bundle manifest: %w", err)
	}
	return out, nil
}
