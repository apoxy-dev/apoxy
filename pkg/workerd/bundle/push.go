// SPDX-License-Identifier: AGPL-3.0-only

package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry/remote"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

// Push packs manifest+modules as an OCI service bundle and pushes it to repo,
// addressed by its own manifest digest so the artifact is immutable end to
// end. If tag is non-empty the pushed manifest is additionally tagged, as a
// convenience for humans; controllers always pin the returned digest. The
// artifact matches what the workerd-manager pulls (pkg/workerd/host): an OCI
// image manifest whose config blob is the JSON-encoded BundleManifest and
// whose single layer is a gzip tar of the modules keyed by Module.Path.
func Push(ctx context.Context, repo *remote.Repository, tag string, manifest computev1alpha1.BundleManifest, modulesByPath map[string][]byte) (string, error) {
	if len(modulesByPath) == 0 {
		return "", fmt.Errorf("bundle has no modules")
	}
	for _, m := range manifest.Modules {
		if _, ok := modulesByPath[m.Path]; !ok {
			return "", fmt.Errorf("manifest module %q has no content", m.Path)
		}
	}

	store := memory.New()

	configBlob, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("marshaling bundle manifest: %w", err)
	}
	configDesc := blobDescriptor(computev1alpha1.ServiceBundleConfigMediaType, configBlob)
	if err := store.Push(ctx, configDesc, bytes.NewReader(configBlob)); err != nil {
		return "", fmt.Errorf("staging config blob: %w", err)
	}

	layerBlob, err := gzipTarModules(modulesByPath)
	if err != nil {
		return "", fmt.Errorf("packing modules layer: %w", err)
	}
	layerDesc := blobDescriptor(computev1alpha1.ServiceBundleModuleLayerMediaType, layerBlob)
	if err := store.Push(ctx, layerDesc, bytes.NewReader(layerBlob)); err != nil {
		return "", fmt.Errorf("staging modules layer: %w", err)
	}

	manifestDesc, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, "", oras.PackManifestOptions{
		ConfigDescriptor: &configDesc,
		Layers:           []ocispec.Descriptor{layerDesc},
		// Pin the created annotation: PackManifest otherwise stamps
		// time.Now() into the manifest, giving byte-identical bundles a new
		// digest on every push (and thus a spurious revision per deploy).
		ManifestAnnotations: map[string]string{
			ocispec.AnnotationCreated: "1970-01-01T00:00:00Z",
		},
	})
	if err != nil {
		return "", fmt.Errorf("packing OCI manifest: %w", err)
	}

	// The in-memory source must have the ref in its tag index for Copy to
	// resolve it, and pushing the remote by digest (rather than a mutable tag)
	// matches exactly what the Service pins in spec.source.oci.digest.
	dig := manifestDesc.Digest.String()
	if err := store.Tag(ctx, manifestDesc, dig); err != nil {
		return "", fmt.Errorf("tagging manifest in store: %w", err)
	}
	if _, err := oras.Copy(ctx, store, dig, repo, dig, oras.DefaultCopyOptions); err != nil {
		return "", fmt.Errorf("pushing bundle: %w", err)
	}
	if tag != "" {
		if err := repo.Tag(ctx, manifestDesc, tag); err != nil {
			return "", fmt.Errorf("tagging pushed bundle %q: %w", tag, err)
		}
	}
	return dig, nil
}

func blobDescriptor(mediaType string, blob []byte) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(blob),
		Size:      int64(len(blob)),
	}
}

// gzipTarModules packs modules into the gzip'd tar shape of a bundle modules
// layer, in sorted order so identical inputs produce identical digests.
func gzipTarModules(modulesByPath map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(modulesByPath))
	for name := range modulesByPath {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		body := modulesByPath[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
