// SPDX-License-Identifier: AGPL-3.0-only

package bundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

const (
	// ManifestFile is the BundleManifest JSON at the root of a staging dir.
	ManifestFile = "manifest.json"
	// ModulesDir holds module files under their Module.Path.
	ModulesDir = "modules"
)

// WriteDir lays manifest+modules out as a staging directory — the on-disk
// handoff between `apoxy build` and `apoxy bundle push`:
//
//	<dir>/manifest.json      JSON BundleManifest
//	<dir>/modules/<path...>  one file per Module.Path
//
// dir is replaced wholesale so stale modules from a previous build cannot
// leak into the next push.
func WriteDir(dir string, manifest computev1alpha1.BundleManifest, modulesByPath map[string][]byte) error {
	for _, m := range manifest.Modules {
		if _, ok := modulesByPath[m.Path]; !ok {
			return fmt.Errorf("manifest module %q has no content", m.Path)
		}
	}
	// Refuse to clobber a directory that isn't a staging dir: dir comes from
	// user flags (--out/--dir), and RemoveAll on a mistyped path (".", a
	// source tree) would be unrecoverable data loss.
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		if _, err := os.Stat(filepath.Join(dir, ManifestFile)); err != nil {
			return fmt.Errorf("refusing to replace %q: it is not empty and has no %s (not a staging dir)", dir, ManifestFile)
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("clearing staging dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ModulesDir), 0o755); err != nil {
		return fmt.Errorf("creating staging dir: %w", err)
	}
	manifestBlob, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling bundle manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), manifestBlob, 0o644); err != nil {
		return fmt.Errorf("writing bundle manifest: %w", err)
	}
	for path, body := range modulesByPath {
		dst, err := moduleFilePath(dir, path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return fmt.Errorf("creating module dir for %q: %w", path, err)
		}
		if err := os.WriteFile(dst, body, 0o644); err != nil {
			return fmt.Errorf("writing module %q: %w", path, err)
		}
	}
	return nil
}

// LoadDir reads a staging directory produced by WriteDir (or authored by
// hand). Every module referenced by the manifest must exist; extra files under
// modules/ are ignored so editors' stray artifacts don't break a push.
func LoadDir(dir string) (computev1alpha1.BundleManifest, map[string][]byte, error) {
	var manifest computev1alpha1.BundleManifest
	manifestBlob, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return manifest, nil, fmt.Errorf("reading bundle manifest: %w", err)
	}
	if err := json.Unmarshal(manifestBlob, &manifest); err != nil {
		return manifest, nil, fmt.Errorf("parsing bundle manifest: %w", err)
	}
	if len(manifest.Modules) == 0 {
		return manifest, nil, fmt.Errorf("bundle manifest lists no modules")
	}
	modulesByPath := make(map[string][]byte, len(manifest.Modules))
	for _, m := range manifest.Modules {
		src, err := moduleFilePath(dir, m.Path)
		if err != nil {
			return manifest, nil, err
		}
		body, err := os.ReadFile(src)
		if err != nil {
			return manifest, nil, fmt.Errorf("reading module %q: %w", m.Path, err)
		}
		modulesByPath[m.Path] = body
	}
	return manifest, modulesByPath, nil
}

// moduleFilePath resolves a Module.Path within the staging dir, rejecting
// paths that would escape it (absolute or ..-traversal).
func moduleFilePath(dir, path string) (string, error) {
	if filepath.IsAbs(path) {
		return "", fmt.Errorf("module path %q must be relative", path)
	}
	dst := filepath.Join(dir, ModulesDir, filepath.FromSlash(path))
	root := filepath.Join(dir, ModulesDir)
	rel, err := filepath.Rel(root, dst)
	if err != nil || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return "", fmt.Errorf("module path %q escapes the bundle", path)
	}
	return dst, nil
}
