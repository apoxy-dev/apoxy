package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy/pkg/workerd/build"
)

// defaultBuildOutDir is where `apoxy build` stages the bundle and where
// `apoxy bundle push` / `apoxy deploy` pick it up.
const defaultBuildOutDir = ".apoxy/build"

// defaultCompatibilityDate is the workerd compatibility date stamped on
// bundles that don't choose one. Fixed (not "today") so rebuilding an
// unchanged project cannot silently change runtime semantics.
const defaultCompatibilityDate = "2025-01-01"

var (
	buildEntry       string
	buildOutDir      string
	buildCompatDate  string
	buildCompatFlags []string
	buildMinify      bool
)

var buildCmd = &cobra.Command{
	Use:   "build [dir]",
	Short: "Build a compute service bundle from a JS/TS project",
	Long: `Bundles the project with esbuild (ESM output, workerd resolution) into a
staged service bundle: JS/TS is bundled into a single entry module, while
.wasm/.txt/.bin/.data imports become separate bundle modules.

The entrypoint is taken from --entry, package.json (module, then main), or
common locations (src/index.ts, index.js, ...).

Examples:
  # Build the current directory into .apoxy/build
  apoxy build

  # Build a specific project and entrypoint
  apoxy build ./my-worker --entry src/main.ts`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		dir := "."
		if len(args) == 1 {
			dir = args[0]
		}
		manifest, err := build.Run(build.Options{
			Dir:                dir,
			Entry:              buildEntry,
			OutDir:             buildOutDir,
			CompatibilityDate:  buildCompatDate,
			CompatibilityFlags: buildCompatFlags,
			Minify:             buildMinify,
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Staged %d module(s) in %s\n", len(manifest.Modules), buildOutDir)
		for _, m := range manifest.Modules {
			fmt.Fprintf(cmd.OutOrStdout(), "  %-14s %s\n", m.Type, m.Path)
		}
		return nil
	},
}

func init() {
	buildCmd.Flags().StringVar(&buildEntry, "entry", "",
		"Entrypoint relative to the project dir (auto-detected when empty)")
	buildCmd.Flags().StringVar(&buildOutDir, "out", defaultBuildOutDir,
		"Staging directory for the built bundle")
	buildCmd.Flags().StringVar(&buildCompatDate, "compatibility-date", defaultCompatibilityDate,
		"workerd compatibility date for the bundle")
	buildCmd.Flags().StringSliceVar(&buildCompatFlags, "compatibility-flags", nil,
		"workerd compatibility flags for the bundle")
	buildCmd.Flags().BoolVar(&buildMinify, "minify", false,
		"Minify the bundled entry module")
	RootCmd.AddCommand(buildCmd)
}
