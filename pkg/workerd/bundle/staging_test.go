// SPDX-License-Identifier: AGPL-3.0-only

package bundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

func stagingFixture() (computev1alpha1.BundleManifest, map[string][]byte) {
	return computev1alpha1.BundleManifest{
			Modules:           []computev1alpha1.Module{{Name: "index.js", Type: computev1alpha1.ESModule, Path: "index.js"}},
			CompatibilityDate: "2025-01-01",
		}, map[string][]byte{
			"index.js": []byte("export default {}"),
		}
}

func TestWriteDir(t *testing.T) {
	manifest, modules := stagingFixture()

	t.Run("round-trips through LoadDir", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "out")
		if err := WriteDir(dir, manifest, modules); err != nil {
			t.Fatalf("WriteDir() error = %v", err)
		}
		gotManifest, gotModules, err := LoadDir(dir)
		if err != nil {
			t.Fatalf("LoadDir() error = %v", err)
		}
		if gotManifest.CompatibilityDate != manifest.CompatibilityDate {
			t.Fatalf("compatibilityDate = %q, want %q", gotManifest.CompatibilityDate, manifest.CompatibilityDate)
		}
		if string(gotModules["index.js"]) != string(modules["index.js"]) {
			t.Fatalf("module content = %q", gotModules["index.js"])
		}
	})

	t.Run("replaces a previous staging dir", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "out")
		if err := WriteDir(dir, manifest, modules); err != nil {
			t.Fatalf("first WriteDir() error = %v", err)
		}
		// A stale module from the previous build must not survive.
		stale := filepath.Join(dir, ModulesDir, "stale.js")
		if err := os.WriteFile(stale, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := WriteDir(dir, manifest, modules); err != nil {
			t.Fatalf("second WriteDir() error = %v", err)
		}
		if _, err := os.Stat(stale); !os.IsNotExist(err) {
			t.Fatalf("stale module survived the rewrite: %v", err)
		}
	})

	t.Run("refuses to clobber a non-staging directory", func(t *testing.T) {
		dir := t.TempDir()
		precious := filepath.Join(dir, "main.go")
		if err := os.WriteFile(precious, []byte("package main"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := WriteDir(dir, manifest, modules)
		if err == nil || !strings.Contains(err.Error(), "not a staging dir") {
			t.Fatalf("WriteDir() error = %v, want refusal", err)
		}
		if _, statErr := os.Stat(precious); statErr != nil {
			t.Fatalf("WriteDir() deleted user data despite refusing: %v", statErr)
		}
	})

	t.Run("rejects escaping module paths", func(t *testing.T) {
		badManifest := computev1alpha1.BundleManifest{
			Modules: []computev1alpha1.Module{{Name: "x", Type: computev1alpha1.ESModule, Path: "../escape.js"}},
		}
		err := WriteDir(filepath.Join(t.TempDir(), "out"), badManifest, map[string][]byte{"../escape.js": []byte("x")})
		if err == nil || !strings.Contains(err.Error(), "escapes the bundle") {
			t.Fatalf("WriteDir() error = %v, want escape rejection", err)
		}
	})
}
