package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/pkg/cmd/utils"
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
	deployName           string
	deployRepo           string
	deployUsername       string
	deployPasswordStdin  bool
	deployCompatDate     string
	deployCompatFlags    []string
	deployMinify         bool
	deployFieldManagerFl string
	deployForceConflicts bool
	deployYes            bool
)

var deployCmd = &cobra.Command{
	Use:   "deploy [path]",
	Short: "Build, push, and apply a compute Service end to end",
	Long: `Runs the full push-mode flow: build the project, push the bundle to the
repository named by the Service manifest's spec.source.oci.repo, write the
pushed digest into spec.source.oci.digest, and server-side apply the Service.
The digest is pinned by the CLI so humans never hand-copy it.

The manifest defaults to service.yaml inside the project directory. When the
project has no service.yaml yet, deploy generates a minimal one with a random
docker-style name (override with --name) and continues.

A file path deploys a standalone worker rooted in the file's directory. For a
nested entrypoint in a project or monorepo package, pass the project directory
and set --entry to the project-relative source path.

Examples:
  # Build ., push to the repo in ./service.yaml, and apply it
  apoxy deploy

  # Deploy a project from another directory (uses my-worker/service.yaml)
  apoxy deploy ./my-worker

  # Deploy a nested entrypoint from a monorepo package
  apoxy deploy ./edge --entry src/worker.js

  # Deploy a single-file worker (dir is the file's directory)
  apoxy deploy ./worker.js`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		if deployName != "" {
			if errs := validation.IsDNS1123Label(deployName); len(errs) > 0 {
				return fmt.Errorf("--name %q: %s", deployName, strings.Join(errs, "; "))
			}
		}
		arg := ""
		if len(args) == 1 {
			arg = args[0]
		}
		dir, entry, err := resolveDeployInput(arg, deployEntry)
		if err != nil {
			return err
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

		if err := confirmDeployTarget(cmd); err != nil {
			return err
		}

		status := newDeployStatus(cmd.OutOrStdout())
		defer status.Close()
		fail := func(err error) error {
			status.Fail()
			return err
		}

		// Bootstrap: no manifest yet means this is a first deploy — generate
		// a minimal one so the command keeps going instead of dead-ending.
		bootstrapped := false
		if _, err := os.Stat(manifestPath); errors.Is(err, os.ErrNotExist) && !cmd.Flags().Changed("filename") {
			bootstrapped = true
			name := deployName
			detail := name
			if name == "" {
				name = generateServiceName()
				detail = name + " (generated; override with --name)"
			}
			status.Start("name")
			status.Done(detail)
			status.Start("service.yaml")
			if err := writeBootstrapManifest(manifestPath, name, deployRepo); err != nil {
				return fail(err)
			}
			status.Done("wrote " + manifestPath)
		}

		svc, err := loadComputeService(manifestPath)
		if err != nil {
			return err
		}
		// --name only chooses the name of a manifest deploy generates; on an
		// existing manifest a mismatch is ambiguous, so refuse rather than
		// silently keeping the file's name.
		if !bootstrapped && cmd.Flags().Changed("name") && svc.GetName() != deployName {
			return fmt.Errorf("%s already names this service %q; --name only applies when deploy generates the manifest (edit the file to rename)", manifestPath, svc.GetName())
		}
		fileRepo, _, err := unstructured.NestedString(svc.Object, "spec", "source", "oci", "repo")
		if err != nil {
			return fmt.Errorf("%s: reading spec.source.oci.repo: %w", manifestPath, err)
		}
		// Repo resolution: the manifest's value, overridden by --repo, falling
		// back to the platform registry (<host>/<project-id>/<service>). A
		// resolved value that isn't in the file goes into the applied spec
		// only — service.yaml keeps recording just what the user chose.
		repo := fileRepo
		if deployRepo != "" {
			repo = deployRepo
		}
		if repo == "" {
			pr, ok := currentPlatformRegistry()
			if !ok {
				return fmt.Errorf("%s: no bundle repository: set spec.source.oci.repo in the file or pass --repo", manifestPath)
			}
			repo = pr.DefaultRepo(svc.GetName())
		}
		if repo != fileRepo {
			if err := unstructured.SetNestedField(svc.Object, repo, "spec", "source", "oci", "repo"); err != nil {
				return fmt.Errorf("setting spec.source.oci.repo: %w", err)
			}
		}
		// A repo deploy invented (not recorded in the file) must be co-owned
		// like the digest, or the next plain `apoxy apply -f service.yaml`
		// (same field manager, no repo field) would prune it from the live
		// object. A file-recorded repo keeps normal manifest ownership.
		pinRepo := ""
		if fileRepo == "" {
			pinRepo = repo
		}
		tag, _, _ := unstructured.NestedString(svc.Object, "spec", "source", "oci", "tag")
		pushRef := repo
		if tag != "" {
			pushRef = repo + ":" + tag
		}

		if !deployNoBuild {
			status.Start("build")
			manifest, err := build.Run(build.Options{
				Dir:                dir,
				Entry:              entry,
				OutDir:             stagingDir,
				CompatibilityDate:  deployCompatDate,
				CompatibilityFlags: deployCompatFlags,
				Minify:             deployMinify,
			})
			if err != nil {
				return fail(err)
			}
			status.Done(fmt.Sprintf("%d module(s) → %s", len(manifest.Modules), stagingDir))
		}

		status.Start("push")
		pushedRepo, dig, err := pushBundleDir(cmd.Context(), pushRef, stagingDir, deployUsername, deployPasswordStdin)
		if err != nil {
			return fail(err)
		}
		status.Done(pushedRepo + "@" + dig)

		doc, err := manifestApplyDoc(svc)
		if err != nil {
			return fmt.Errorf("re-encoding Service manifest: %w", err)
		}

		status.Start("apply")
		dynClient, mapper, err := dynamicClients()
		if err != nil {
			return fail(err)
		}
		name, kind, err := resource.Apply(cmd.Context(), dynClient, mapper, doc, resource.ApplyOptions{
			FieldManager: deployFieldManagerFl,
			Force:        deployForceConflicts,
		})
		if err != nil {
			return fail(err)
		}

		// Co-own the digest (and any repo deploy resolved itself) under a
		// dedicated manager so the pin survives a later `apoxy apply` of a
		// digest-less service.yaml: that apply drops only the manifest
		// manager's claim, and the fields stay owned here. Forced: repinning
		// is this command's entire job.
		if err := applyDigestPin(cmd.Context(), svc, dig, pinRepo); err != nil {
			return fail(fmt.Errorf("pinning digest under %s: %w", deployFieldManager, err))
		}
		status.Done(fmt.Sprintf("%s/%s (digest %s)", kind, name, dig))
		return nil
	},
}

// resolveDeployInput identifies the project root and entrypoint for a deploy.
// A directory path is the project root. A regular file path is standalone
// shorthand, so its directory becomes the project root and its base name is
// the default entrypoint. An explicit entrypoint remains relative to that root.
func resolveDeployInput(arg, entry string) (string, string, error) {
	if arg == "" {
		return ".", entry, nil
	}

	cleanArg := filepath.Clean(arg)
	fi, err := os.Stat(cleanArg)
	if err != nil {
		return "", "", fmt.Errorf("resolving %s: %w", arg, err)
	}
	if fi.IsDir() {
		return cleanArg, entry, nil
	}
	if !fi.Mode().IsRegular() {
		return "", "", fmt.Errorf("resolving %s: path is not a regular file or directory", arg)
	}
	if entry == "" {
		entry = filepath.Base(cleanArg)
	}
	return filepath.Dir(cleanArg), entry, nil
}

// confirmDeployTarget announces which project and API endpoint the deploy
// targets and asks for confirmation, so a stale currentProject can't silently
// receive a deploy meant for another environment. --yes skips the prompt; a
// non-interactive session without --yes refuses rather than assuming.
func confirmDeployTarget(cmd *cobra.Command) error {
	c, err := config.DefaultAPIClient()
	if err != nil {
		return err
	}
	target := describeDeployTarget(cmd.Context(), c.BaseURL, c.ProjectID)
	fmt.Fprintf(cmd.OutOrStdout(), "Deploying to %s\n", target)
	if deployYes {
		return nil
	}
	if !utils.IsInteractive() {
		return fmt.Errorf("refusing to deploy to %s without confirmation; pass --yes", target)
	}
	if !confirm(cmd.Context(), "Continue?") {
		return errors.New("deploy aborted")
	}
	return nil
}

// manifestApplyDoc encodes what the manifest field manager applies: the user's
// Service with spec.source.oci.digest removed, because that field is owned
// solely by deployFieldManager (see applyDigestPin).
//
// Claiming the digest under both managers is what made every re-deploy of
// changed code fail with a field-ownership conflict. Server-side apply reports
// a conflict when a manager sets a field another manager owns to a *different*
// value, so the sequence was: first deploy applies the digest as the manifest
// manager, the forced pin immediately takes ownership, and the next deploy that
// pushes new code applies a digest the pin manager now owns with an older value
// — conflict. Re-deploying identical code never tripped it (same value, so
// ownership is merely shared), which is why this only surfaced on the second
// deploy of *changed* code. Leaving the digest to the pin keeps one owner and
// no conflict at any point.
//
// A digest recorded in the file drops out too: superseding it with the freshly
// pushed artifact is deploy's entire job.
func manifestApplyDoc(svc *unstructured.Unstructured) ([]byte, error) {
	applyDoc := svc.DeepCopy()
	unstructured.RemoveNestedField(applyDoc.Object, "spec", "source", "oci", "digest")
	return json.Marshal(applyDoc.Object)
}

// applyDigestPin server-side-applies a minimal patch — identity plus
// spec.source.oci.digest, and spec.source.oci.repo when deploy resolved the
// repo itself (repo != "") — under deployFieldManager. When a later deploy
// runs with the repo recorded in the manifest, the repo-less pin patch
// releases this manager's repo claim back to the manifest manager.
func applyDigestPin(ctx context.Context, svc *unstructured.Unstructured, dig, repo string) error {
	oci := map[string]any{"digest": dig}
	if repo != "" {
		oci["repo"] = repo
	}
	pin := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": svc.GetAPIVersion(),
		"kind":       svc.GetKind(),
		"metadata":   map[string]any{"name": svc.GetName()},
		"spec": map[string]any{
			"source": map[string]any{"oci": oci},
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
	deployCmd.Flags().StringVar(&deployName, "name", "",
		"Service name for a generated service.yaml (default: a random docker-style name)")
	deployCmd.Flags().StringVar(&deployRepo, "repo", "",
		"Bundle repository to push to, overriding the manifest's spec.source.oci.repo (recorded in a generated service.yaml)")
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
	deployCmd.Flags().BoolVarP(&deployYes, "yes", "y", false,
		"Skip the deploy-target confirmation prompt (required for non-interactive runs)")
	RootCmd.AddCommand(deployCmd)
}
