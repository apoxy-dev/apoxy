package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/client-go/discovery"
	memory "k8s.io/client-go/discovery/cached"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"

	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
)

var (
	applyFiles          []string
	applyFieldManager   string
	applyForceConflicts bool
	applyRecursive      bool
)

// applyCmd is the global apply command for multi-resource operations.
var applyCmd = &cobra.Command{
	Use:   "apply -f <filename>",
	Short: "Apply resources from file(s) or directory",
	Long: `Apply configuration to resources using server-side apply.

Supports multiple files, directories, and stdin. When a directory is specified,
all .yaml, .yml, and .json files are processed.

Examples:
  # Apply a single file
  apoxy apply -f gateway.yaml

  # Apply multiple files
  apoxy apply -f gateway.yaml -f routes.yaml

  # Apply all manifests in a directory
  apoxy apply -f ./manifests/

  # Apply from stdin
  cat manifest.yaml | apoxy apply -f -`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(applyFiles) == 0 {
			return fmt.Errorf("please specify files with -f/--filename")
		}

		cmd.SilenceUsage = true

		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}

		dc, err := discovery.NewDiscoveryClientForConfig(c.RESTConfig)
		if err != nil {
			return fmt.Errorf("failed to create discovery client: %w", err)
		}
		dynClient, err := dynamic.NewForConfig(c.RESTConfig)
		if err != nil {
			return fmt.Errorf("failed to create dynamic client: %w", err)
		}
		mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))

		allData, err := resource.ReadInputs(applyFiles, applyRecursive)
		if err != nil {
			return err
		}

		opts := resource.ApplyOptions{
			FieldManager: applyFieldManager,
			Force:        applyForceConflicts,
		}
		var errs []error
		var applied int
		for _, data := range allData {
			for _, doc := range resource.SplitYAMLDocuments(data) {
				name, kind, err := resource.Apply(cmd.Context(), dynClient, mapper, doc, opts)
				if err != nil {
					errs = append(errs, err)
					fmt.Fprintf(os.Stderr, "error: %v\n", err)
					continue
				}
				fmt.Printf("%s %q applied\n", kind, name)
				applied++
			}
		}

		if len(errs) > 0 {
			fmt.Fprintf(os.Stderr, "\nApplied %d resource(s) with %d error(s)\n", applied, len(errs))
			return fmt.Errorf("failed to apply %d resource(s)", len(errs))
		}
		if applied > 1 {
			fmt.Printf("\nApplied %d resources\n", applied)
		}
		return nil
	},
}

func init() {
	applyCmd.Flags().StringArrayVarP(&applyFiles, "filename", "f", nil,
		"Files or directories containing resources to apply (can be specified multiple times)")
	applyCmd.Flags().StringVar(&applyFieldManager, "field-manager", "apoxy-cli",
		"Name of the field manager for server-side apply")
	applyCmd.Flags().BoolVar(&applyForceConflicts, "force-conflicts", false,
		"Force apply even if there are field ownership conflicts")
	applyCmd.Flags().BoolVarP(&applyRecursive, "recursive", "R", false,
		"Process directories recursively")

	RootCmd.AddCommand(applyCmd)
}
