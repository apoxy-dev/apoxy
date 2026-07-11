// SPDX-License-Identifier: AGPL-3.0-only

package build

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/bundle"
)

// writeProject lays files out under a temp dir and returns it.
func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for path, body := range files {
		dst := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRun(t *testing.T) {
	cases := []struct {
		name        string
		files       map[string]string
		opts        Options
		wantErr     string
		wantModules []string // manifest paths, in order
		wantInlined string   // substring that must appear in the bundled entry
		wantImport  string   // import specifier that must survive in the entry
	}{
		{
			name: "bundles local imports and collects text modules",
			files: map[string]string{
				"src/index.js": `import greet from "./greet.txt"; import { shout } from "./lib.js";
export default { fetch() { return new Response(shout(greet)) } }`,
				"src/greet.txt": "hello",
				"src/lib.js":    `export function shout(s) { return s.toUpperCase() }`,
			},
			wantModules: []string{"index.js", "src/greet.txt"},
			wantInlined: "toUpperCase",
			wantImport:  `"./src/greet.txt"`,
		},
		{
			name: "entry from package.json main",
			files: map[string]string{
				"package.json": `{"main": "app.js"}`,
				"app.js":       `export default { fetch() { return new Response("ok") } }`,
			},
			wantModules: []string{"index.js"},
			wantInlined: `"ok"`,
		},
		{
			name: "typescript entry auto-detected",
			files: map[string]string{
				"src/index.ts": `const n: number = 42;
export default { fetch(): Response { return new Response(String(n)) } }`,
			},
			wantModules: []string{"index.js"},
			wantInlined: "42",
		},
		{
			name: "wasm import becomes a wasm module",
			files: map[string]string{
				"index.js": `import mod from "./add.wasm"; export default { fetch() { return new Response(String(mod)) } }`,
				"add.wasm": "\x00asm\x01\x00\x00\x00",
			},
			wantModules: []string{"index.js", "add.wasm"},
			wantImport:  `"./add.wasm"`,
		},
		{
			name: "bare specifier wasm resolves through node_modules",
			files: map[string]string{
				"index.js":                        `import mod from "mypkg/add.wasm"; export default { fetch() { return new Response(String(mod)) } }`,
				"node_modules/mypkg/package.json": `{"name": "mypkg"}`,
				"node_modules/mypkg/add.wasm":     "\x00asm\x01\x00\x00\x00",
			},
			wantModules: []string{"index.js", "node_modules/mypkg/add.wasm"},
			wantImport:  `"./node_modules/mypkg/add.wasm"`,
		},
		{
			name: "same module imported from several files is collected once",
			files: map[string]string{
				"index.js":  `import a from "./greet.txt"; import { other } from "./other.js"; export default { fetch() { return new Response(a + other) } }`,
				"other.js":  `import b from "./greet.txt"; export const other = b;`,
				"greet.txt": "hi",
			},
			wantModules: []string{"index.js", "greet.txt"},
			wantImport:  `"./greet.txt"`,
		},
		{
			name:    "no entrypoint",
			files:   map[string]string{"README.md": "nothing to build"},
			wantErr: "no entrypoint found",
		},
		{
			name: "broken source fails with esbuild message",
			files: map[string]string{
				"index.js": `import { missing } from "./nope.js"; export default {}`,
			},
			wantErr: "Could not resolve",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeProject(t, tc.files)
			opts := tc.opts
			opts.Dir = dir
			opts.OutDir = filepath.Join(t.TempDir(), "out")
			if opts.CompatibilityDate == "" {
				opts.CompatibilityDate = "2025-01-01"
			}

			manifest, err := Run(opts)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Run() error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}

			var gotPaths []string
			for _, m := range manifest.Modules {
				gotPaths = append(gotPaths, m.Path)
			}
			if strings.Join(gotPaths, ",") != strings.Join(tc.wantModules, ",") {
				t.Fatalf("manifest modules = %v, want %v", gotPaths, tc.wantModules)
			}
			if manifest.Modules[0].Type != computev1alpha1.ESModule {
				t.Fatalf("entry module type = %q, want esModule", manifest.Modules[0].Type)
			}

			// The staging dir must load back cleanly — that is what push consumes.
			loaded, modules, err := bundle.LoadDir(opts.OutDir)
			if err != nil {
				t.Fatalf("LoadDir() error = %v", err)
			}
			if loaded.CompatibilityDate != opts.CompatibilityDate {
				t.Fatalf("staged compatibilityDate = %q, want %q", loaded.CompatibilityDate, opts.CompatibilityDate)
			}
			entry := string(modules[entryModuleName])
			if tc.wantInlined != "" && !strings.Contains(entry, tc.wantInlined) {
				t.Fatalf("bundled entry missing %q:\n%s", tc.wantInlined, entry)
			}
			if tc.wantImport != "" && !strings.Contains(entry, tc.wantImport) {
				t.Fatalf("bundled entry missing external import %q:\n%s", tc.wantImport, entry)
			}
		})
	}
}
