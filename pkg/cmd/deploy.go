package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/pkg/workerd/build"
)

// deployFieldManager owns exactly one field: the digest `apoxy deploy` pins.
// It is distinct from the manifest's field manager so that a later plain
// `apoxy apply -f service.yaml` (whose file has no digest) cannot prune the
// pin under server-side-apply same-manager semantics.
const deployFieldManager = "apoxy-deploy"

var (
	deployFile           string
	deployEntry          string
	deployNoBuild        bool
	deployDir            string
	deployUsername       string
	deployPasswordStdin  bool
	deployCompatDate     string
	deployCompatFlags    []string
	deployMinify         bool
	deployFieldManagerFl string
	deployForceConflicts bool
)

var deployCmd = &cobra.Command{
	Use:   "deploy [dir]",
	Short: "Build, push, and apply a compute Service end to end",
	Long: `Runs the full push-mode flow: build the project, push the bundle to the
repository named by the Service manifest's spec.source.oci.repo, write the
pushed digest into spec.source.oci.digest, and server-side apply the Service.
The digest is pinned by the CLI so humans never hand-copy it.

The manifest defaults to service.yaml inside the project directory.

Examples:
  # Build ., push to the repo in ./service.yaml, and apply it
  apoxy deploy

  # Deploy a project from another directory (uses my-worker/service.yaml)
  apoxy deploy ./my-worker`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		dir := "."
		if len(args) == 1 {
			dir = args[0]
		}
		manifestPath := deployFile
		stagingDir := deployDir
		if !cmd.Flags().Changed("filename") {
			// The manifest and the staged bundle belong to the project being
			// deployed, not to whatever directory the command runs from.
			manifestPath = filepath.Join(dir, "service.yaml")
		}
		if !cmd.Flags().Changed("dir") {
			stagingDir = filepath.Join(dir, defaultBuildOutDir)
		}

		svc, err := loadComputeService(manifestPath)
		if err != nil {
			return err
		}
		repo, _, err := unstructured.NestedString(svc.Object, "spec", "source", "oci", "repo")
		if err != nil || repo == "" {
			return fmt.Errorf("%s: spec.source.oci.repo must name the bundle repository to push to", manifestPath)
		}
		tag, _, _ := unstructured.NestedString(svc.Object, "spec", "source", "oci", "tag")
		pushRef := repo
		if tag != "" {
			pushRef = repo + ":" + tag
		}

		if !deployNoBuild {
			manifest, err := build.Run(build.Options{
				Dir:                dir,
				Entry:              deployEntry,
				OutDir:             stagingDir,
				CompatibilityDate:  deployCompatDate,
				CompatibilityFlags: deployCompatFlags,
				Minify:             deployMinify,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Built %d module(s)\n", len(manifest.Modules))
		}

		pushedRepo, dig, err := pushBundleDir(cmd.Context(), pushRef, stagingDir, deployUsername, deployPasswordStdin)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Pushed %s@%s\n", pushedRepo, dig)

		// Pin the exact pushed artifact; the controller mints a revision from it.
		if err := unstructured.SetNestedField(svc.Object, dig, "spec", "source", "oci", "digest"); err != nil {
			return fmt.Errorf("setting spec.source.oci.digest: %w", err)
		}
		doc, err := json.Marshal(svc.Object)
		if err != nil {
			return fmt.Errorf("re-encoding Service manifest: %w", err)
		}

		dynClient, mapper, err := dynamicClients()
		if err != nil {
			return err
		}
		name, kind, err := resource.Apply(cmd.Context(), dynClient, mapper, doc, resource.ApplyOptions{
			FieldManager: deployFieldManagerFl,
			Force:        deployForceConflicts,
		})
		if err != nil {
			return err
		}

		// Co-own the digest under a dedicated manager so the pin survives a
		// later `apoxy apply` of a digest-less service.yaml: that apply drops
		// only the manifest manager's claim, and the field stays owned here.
		// Forced: repinning the digest is this command's entire job.
		if err := applyDigestPin(cmd.Context(), svc, dig); err != nil {
			return fmt.Errorf("pinning digest under %s: %w", deployFieldManager, err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s %q applied (digest %s)\n", kind, name, dig)
		return nil
	},
}

// applyDigestPin server-side-applies a minimal patch — identity plus
// spec.source.oci.digest — under deployFieldManager.
func applyDigestPin(ctx context.Context, svc *unstructured.Unstructured, dig string) error {
	pin := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": svc.GetAPIVersion(),
		"kind":       svc.GetKind(),
		"metadata":   map[string]any{"name": svc.GetName()},
		"spec": map[string]any{
			"source": map[string]any{
				"oci": map[string]any{"digest": dig},
			},
		},
	}}
	doc, err := json.Marshal(pin.Object)
	if err != nil {
		return err
	}
	dynClient, mapper, err := dynamicClients()
	if err != nil {
		return err
	}
	_, _, err = resource.Apply(ctx, dynClient, mapper, doc, resource.ApplyOptions{
		FieldManager: deployFieldManager,
		Force:        true,
	})
	return err
}

// loadComputeService reads and sanity-checks the Service manifest so a wrong
// file fails before anything is built or pushed.
func loadComputeService(path string) (*unstructured.Unstructured, error) {
	docs, err := resource.ReadInputs([]string{path}, false)
	if err != nil {
		return nil, err
	}
	var svc *unstructured.Unstructured
	for _, data := range docs {
		for _, doc := range resource.SplitYAMLDocuments(data) {
			u, err := resource.DecodeUnstructured(doc)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			gvk := u.GroupVersionKind()
			if gvk.Group != "compute.apoxy.dev" || gvk.Kind != "Service" {
				return nil, fmt.Errorf("%s: expected a single compute.apoxy.dev Service, found %s", path, gvk)
			}
			if svc != nil {
				return nil, fmt.Errorf("%s: expected a single compute.apoxy.dev Service, found several", path)
			}
			svc = u
		}
	}
	if svc == nil {
		return nil, fmt.Errorf("%s: no resources found", path)
	}
	return svc, nil
}

func init() {
	deployCmd.Flags().StringVarP(&deployFile, "filename", "f", "",
		"Compute Service manifest to deploy (default <dir>/service.yaml)")
	deployCmd.Flags().StringVar(&deployEntry, "entry", "",
		"Entrypoint relative to the project dir (auto-detected when empty)")
	deployCmd.Flags().BoolVar(&deployNoBuild, "no-build", false,
		"Skip the build step and push the already-staged bundle")
	deployCmd.Flags().StringVar(&deployDir, "dir", "",
		"Staging directory for the built bundle (default <dir>/"+defaultBuildOutDir+")")
	deployCmd.Flags().StringVar(&deployCompatDate, "compatibility-date", defaultCompatibilityDate,
		"workerd compatibility date for the bundle")
	deployCmd.Flags().StringSliceVar(&deployCompatFlags, "compatibility-flags", nil,
		"workerd compatibility flags for the bundle")
	deployCmd.Flags().BoolVar(&deployMinify, "minify", false,
		"Minify the bundled entry module")
	deployCmd.Flags().StringVar(&deployUsername, "username", "",
		"Registry username; password comes from --password-stdin or $"+registryPasswordEnv)
	deployCmd.Flags().BoolVar(&deployPasswordStdin, "password-stdin", false,
		"Read the registry password from stdin")
	deployCmd.Flags().StringVar(&deployFieldManagerFl, "field-manager", "apoxy-cli",
		"Name of the field manager for the manifest's server-side apply")
	deployCmd.Flags().BoolVar(&deployForceConflicts, "force-conflicts", false,
		"Force apply even if there are field ownership conflicts")
	RootCmd.AddCommand(deployCmd)
}
