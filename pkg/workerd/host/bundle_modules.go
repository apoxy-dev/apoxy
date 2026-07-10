// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

// maxModuleLayerBytes caps the decompressed modules layer to bound memory when
// the manager inlines module bytes into a WorkerLoader payload. Bundles are
// small (a worker's JS/Wasm), so 64 MiB is generous.
const maxModuleLayerBytes = 64 << 20

// FetchBundleModules pulls a bundle's modules layer (media type
// application/vnd.apoxy.dev.service.modules.v1.tar+gzip) and returns each
// regular file's bytes keyed by its cleaned in-layer path (Module.Path).
//
// Unlike the per-revision sandbox path, which extracts the modules layer into
// the jail, the ServiceManager dispatcher model never mounts a customer bundle:
// the manager reads the bytes here and inlines them into the WorkerLoader
// payload the dispatcher pulls. The returned map is keyed to match
// BundleManifest.Modules[i].Path; the caller maps Path -> Module.Name.
//
// Pull credentials are derived from the BundleRef itself; callers that also
// need the BundleManifest should use FetchBundle, which shares one registry
// session for both.
func FetchBundleModules(ctx context.Context, b computev1alpha1.BundleRef) (map[string][]byte, error) {
	repo, err := bundleRepositoryFor(b)
	if err != nil {
		return nil, err
	}
	manifest, err := fetchOCIManifest(ctx, repo)
	if err != nil {
		return nil, err
	}
	return modulesFromLayers(ctx, repo, manifest, b.Repo)
}

// modulesFromLayers fetches and extracts every modules layer of an
// already-resolved OCI manifest. repoName appears in errors only.
func modulesFromLayers(ctx context.Context, repo *remote.Repository, manifest ocispecv1.Manifest, repoName string) (map[string][]byte, error) {
	out := make(map[string][]byte)
	found := false
	for _, layer := range manifest.Layers {
		if layer.MediaType != computev1alpha1.ServiceBundleModuleLayerMediaType {
			continue
		}
		found = true
		blob, err := content.FetchAll(ctx, repo, layer)
		if err != nil {
			return nil, fmt.Errorf("fetching modules layer %s: %w", layer.Digest, err)
		}
		if err := extractModulesFromLayer(blob, out); err != nil {
			return nil, fmt.Errorf("extracting modules layer %s: %w", layer.Digest, err)
		}
	}
	if !found {
		return nil, fmt.Errorf("workerd-host: bundle %s has no modules layer (%s)",
			repoName, computev1alpha1.ServiceBundleModuleLayerMediaType)
	}
	return out, nil
}

// extractModulesFromLayer untars a gzip-compressed modules layer into dst,
// keyed by cleaned path. Split from FetchBundleModules so the tar handling is
// unit-testable without a registry.
func extractModulesFromLayer(blob []byte, dst map[string][]byte) error {
	gz, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return fmt.Errorf("opening gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		total += hdr.Size
		if total > maxModuleLayerBytes {
			return fmt.Errorf("modules layer exceeds %d bytes", maxModuleLayerBytes)
		}
		buf := make([]byte, 0, hdr.Size)
		w := bytes.NewBuffer(buf)
		if _, err := io.CopyN(w, tr, hdr.Size); err != nil {
			return fmt.Errorf("reading %q: %w", hdr.Name, err)
		}
		dst[CleanModulePath(hdr.Name)] = w.Bytes()
	}
	return nil
}

// CleanModulePath normalizes a tar entry name / Module.Path to a stable lookup
// key: a leading "./" is stripped and the path is lexically cleaned, so the
// builder's "./index.js" and a manifest's "index.js" resolve identically. The
// ServiceManager resolver uses it to map BundleManifest.Modules[i].Path to the
// keys FetchBundleModules returns.
func CleanModulePath(p string) string {
	return path.Clean(strings.TrimPrefix(p, "./"))
}
