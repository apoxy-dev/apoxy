// SPDX-License-Identifier: AGPL-3.0-only

// Package build turns a JS/TS project into a staged compute service bundle:
// esbuild runs in-process (wrangler-style: ESM output, workerd conditions)
// with a module-collector plugin that turns wasm/text/data imports into
// separate bundle modules instead of inlining them.
package build

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	esbuild "github.com/evanw/esbuild/pkg/api"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/bundle"
)

// entryModuleName is the bundled entrypoint's name in the flat module
// namespace. The data plane treats the first esModule as the entrypoint.
const entryModuleName = "index.js"

// entryCandidates are tried in order when package.json names no module/main.
var entryCandidates = []string{
	"src/index.ts", "src/index.js", "src/worker.ts", "src/worker.js",
	"index.ts", "index.js", "worker.ts", "worker.js",
}

// collectedTypes maps import extensions the collector plugin intercepts to
// their bundle module type. Everything else is inlined by esbuild.
var collectedTypes = map[string]computev1alpha1.ModuleType{
	".wasm": computev1alpha1.WasmModule,
	".txt":  computev1alpha1.TextModule,
	".bin":  computev1alpha1.DataModule,
	".data": computev1alpha1.DataModule,
}

// Options configure one build.
type Options struct {
	// Dir is the project root. Defaults to ".".
	Dir string
	// Entry is the entrypoint relative to Dir. Auto-detected from package.json
	// (module, then main) or common locations when empty.
	Entry string
	// OutDir is the staging directory the bundle is written to.
	OutDir string
	// CompatibilityDate for the emitted BundleManifest.
	CompatibilityDate string
	// CompatibilityFlags for the emitted BundleManifest.
	CompatibilityFlags []string
	// Minify the bundled entrypoint.
	Minify bool
}

// Run builds the project and writes the staged bundle (manifest + modules) to
// opts.OutDir, returning the manifest it wrote.
func Run(opts Options) (computev1alpha1.BundleManifest, error) {
	var manifest computev1alpha1.BundleManifest
	dir := opts.Dir
	if dir == "" {
		dir = "."
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return manifest, fmt.Errorf("resolving project dir: %w", err)
	}
	// Resolve symlinks so paths compare against what esbuild reports in
	// ResolveDir (notably /var vs /private/var on macOS).
	if absDir, err = filepath.EvalSymlinks(absDir); err != nil {
		return manifest, fmt.Errorf("resolving project dir: %w", err)
	}
	entry := opts.Entry
	if entry == "" {
		if entry, err = detectEntry(absDir); err != nil {
			return manifest, err
		}
	}

	collector := &moduleCollector{root: absDir, modules: map[string]collectedModule{}}
	result := esbuild.Build(esbuild.BuildOptions{
		AbsWorkingDir: absDir,
		EntryPoints:   []string{entry},
		Bundle:        true,
		Format:        esbuild.FormatESModule,
		Platform:      esbuild.PlatformBrowser,
		Target:        esbuild.ES2022,
		// Match wrangler's resolution order so packages shipping
		// workerd-specific entrypoints resolve them.
		Conditions:        []string{"workerd", "worker", "browser"},
		MainFields:        []string{"browser", "module", "main"},
		MinifyWhitespace:  opts.Minify,
		MinifyIdentifiers: opts.Minify,
		MinifySyntax:      opts.Minify,
		// Runtime-provided module namespaces pass through to workerd untouched.
		External: []string{"cloudflare:*", "node:*"},
		Plugins:  []esbuild.Plugin{collector.plugin()},
	})
	if len(result.Errors) > 0 {
		msgs := esbuild.FormatMessages(result.Errors, esbuild.FormatMessagesOptions{})
		return manifest, fmt.Errorf("build failed:\n%s", strings.Join(msgs, ""))
	}
	if len(result.OutputFiles) != 1 {
		return manifest, fmt.Errorf("build produced %d outputs, want exactly 1 (code-splitting is not supported)", len(result.OutputFiles))
	}

	modules := map[string][]byte{entryModuleName: result.OutputFiles[0].Contents}
	manifest.Modules = []computev1alpha1.Module{
		{Name: entryModuleName, Type: computev1alpha1.ESModule, Path: entryModuleName},
	}
	for _, path := range collector.sortedPaths() {
		m := collector.modules[path]
		modules[path] = m.content
		manifest.Modules = append(manifest.Modules, computev1alpha1.Module{
			Name: path,
			Type: m.moduleType,
			Path: path,
		})
	}
	manifest.CompatibilityDate = opts.CompatibilityDate
	manifest.CompatibilityFlags = opts.CompatibilityFlags

	if err := bundle.WriteDir(opts.OutDir, manifest, modules); err != nil {
		return manifest, fmt.Errorf("staging bundle: %w", err)
	}
	return manifest, nil
}

// detectEntry finds the project entrypoint: package.json module/main first,
// then common filenames.
func detectEntry(dir string) (string, error) {
	if raw, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil {
		var pkg struct {
			Module string `json:"module"`
			Main   string `json:"main"`
		}
		if err := json.Unmarshal(raw, &pkg); err != nil {
			return "", fmt.Errorf("parsing package.json: %w", err)
		}
		for _, candidate := range []string{pkg.Module, pkg.Main} {
			if candidate != "" {
				if _, err := os.Stat(filepath.Join(dir, candidate)); err == nil {
					return candidate, nil
				}
			}
		}
	}
	for _, candidate := range entryCandidates {
		if _, err := os.Stat(filepath.Join(dir, candidate)); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no entrypoint found in %s: name one in package.json (module or main) or pass --entry", dir)
}

type collectedModule struct {
	moduleType computev1alpha1.ModuleType
	content    []byte
}

// moduleCollector is the esbuild plugin that intercepts wasm/text/data
// imports: the import stays in the output (external, path-normalized to the
// module's bundle path) and the file becomes its own bundle module, matching
// how workerd resolves non-JS modules by name at runtime.
type moduleCollector struct {
	root    string
	mu      sync.Mutex
	modules map[string]collectedModule
}

// collectorResolveMarker tags nested pb.Resolve calls issued by the collector
// itself so its OnResolve hook lets them fall through to esbuild's default
// resolution instead of recursing forever.
type collectorResolveMarker struct{}

func (c *moduleCollector) plugin() esbuild.Plugin {
	exts := make([]string, 0, len(collectedTypes))
	for ext := range collectedTypes {
		exts = append(exts, ext)
	}
	sort.Strings(exts)
	filter := `\.(` + strings.Join(trimDots(exts), "|") + `)$`

	return esbuild.Plugin{
		Name: "apoxy-module-collector",
		Setup: func(pb esbuild.PluginBuild) {
			pb.OnResolve(esbuild.OnResolveOptions{Filter: filter}, func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
				if _, ok := args.PluginData.(collectorResolveMarker); ok {
					// Our own nested resolve: defer to default resolution.
					return esbuild.OnResolveResult{}, nil
				}
				// Run esbuild's real resolver so bare specifiers go through
				// node_modules, workspaces, tsconfig paths, etc.
				res := pb.Resolve(args.Path, esbuild.ResolveOptions{
					ResolveDir: args.ResolveDir,
					Importer:   args.Importer,
					Kind:       args.Kind,
					PluginData: collectorResolveMarker{},
				})
				if len(res.Errors) > 0 {
					msgs := esbuild.FormatMessages(res.Errors, esbuild.FormatMessagesOptions{})
					return esbuild.OnResolveResult{}, fmt.Errorf("resolving module %q: %s", args.Path, strings.Join(msgs, ""))
				}
				abs := res.Path
				if resolved, err := filepath.EvalSymlinks(abs); err == nil {
					abs = resolved
				}
				modPath, err := c.modulePath(args.Path, abs)
				if err != nil {
					return esbuild.OnResolveResult{}, err
				}

				c.mu.Lock()
				_, seen := c.modules[modPath]
				c.mu.Unlock()
				if !seen {
					content, err := os.ReadFile(abs)
					if err != nil {
						return esbuild.OnResolveResult{}, fmt.Errorf("reading module %q: %w", args.Path, err)
					}
					c.mu.Lock()
					c.modules[modPath] = collectedModule{
						moduleType: collectedTypes[filepath.Ext(abs)],
						content:    content,
					}
					c.mu.Unlock()
				}
				// External keeps the import statement in the output; workerd
				// resolves it against the module named modPath at runtime.
				return esbuild.OnResolveResult{Path: "./" + modPath, External: true}, nil
			})
		},
	}
}

// modulePath names a collected module in the bundle's flat namespace: the
// project-relative path when the file lives under the root, else (npm
// packages, workspace symlinks outside the root) the import specifier itself,
// which is stable and collision-free within the importing project.
func (c *moduleCollector) modulePath(specifier, abs string) (string, error) {
	if rel, err := filepath.Rel(c.root, abs); err == nil && filepath.IsLocal(rel) {
		return filepath.ToSlash(rel), nil
	}
	cleaned := path.Clean(strings.TrimPrefix(filepath.ToSlash(specifier), "./"))
	if path.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("module %q resolves outside the project root and cannot be named in the bundle; import it via a bare (package) specifier or move it under the project", specifier)
	}
	return cleaned, nil
}

func (c *moduleCollector) sortedPaths() []string {
	paths := make([]string, 0, len(c.modules))
	for p := range c.modules {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

func trimDots(exts []string) []string {
	out := make([]string, len(exts))
	for i, e := range exts {
		out[i] = strings.TrimPrefix(e, ".")
	}
	return out
}
