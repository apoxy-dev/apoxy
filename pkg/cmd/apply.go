package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	memory "k8s.io/client-go/discovery/cached"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"

	"github.com/apoxy-dev/apoxy/client/versioned/scheme"
	"github.com/apoxy-dev/apoxy/config"
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

		// Set up dynamic client and REST mapper.
		dc, err := discovery.NewDiscoveryClientForConfig(c.RESTConfig)
		if err != nil {
			return fmt.Errorf("failed to create discovery client: %w", err)
		}
		dynClient, err := dynamic.NewForConfig(c.RESTConfig)
		if err != nil {
			return fmt.Errorf("failed to create dynamic client: %w", err)
		}
		mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))

		// Collect all file contents.
		var allData [][]byte
		for _, f := range applyFiles {
			data, err := readInput(f, applyRecursive)
			if err != nil {
				return err
			}
			allData = append(allData, data...)
		}

		var errs []error
		var applied int

		for _, data := range allData {
			docs := splitYAMLDocuments(data)
			for _, doc := range docs {
				if len(strings.TrimSpace(string(doc))) == 0 {
					continue
				}

				name, kind, err := applyResource(cmd.Context(), dynClient, mapper, doc)
				if err != nil {
					errs = append(errs, err)
					fmt.Fprintf(os.Stderr, "error: %v\n", err)
				} else {
					fmt.Printf("%s %q applied\n", strings.ToLower(kind), name)
					applied++
				}
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

// readInput reads content from a file, directory, or stdin.
func readInput(path string, recursive bool) ([][]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read stdin: %w", err)
		}
		return [][]byte{data}, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat %s: %w", path, err)
	}

	if info.IsDir() {
		return readDirectory(path, recursive)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	return [][]byte{data}, nil
}

// readDirectory reads all YAML/JSON files from a directory.
func readDirectory(dir string, recursive bool) ([][]byte, error) {
	var result [][]byte

	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories (but continue into them if recursive)
		if info.IsDir() {
			if path != dir && !recursive {
				return filepath.SkipDir
			}
			return nil
		}

		// Only process YAML and JSON files
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}
		result = append(result, data)
		return nil
	}

	if err := filepath.Walk(dir, walkFn); err != nil {
		return nil, err
	}

	return result, nil
}

// splitYAMLDocuments splits a YAML file into multiple documents.
func splitYAMLDocuments(data []byte) [][]byte {
	var docs [][]byte
	for _, doc := range strings.Split(string(data), "\n---") {
		docs = append(docs, []byte(doc))
	}
	return docs
}

// applyResource decodes and applies a single resource using the dynamic client.
func applyResource(
	ctx context.Context,
	dynClient dynamic.Interface,
	mapper *restmapper.DeferredDiscoveryRESTMapper,
	data []byte,
) (name, kind string, err error) {
	// Decode into unstructured object.
	unObj := &unstructured.Unstructured{}
	_, gvk, err := scheme.Codecs.UniversalDeserializer().Decode(data, nil, unObj)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode resource: %w", err)
	}

	name = unObj.GetName()
	if name == "" {
		return "", "", fmt.Errorf("resource name is required")
	}
	kind = gvk.Kind

	// Get the REST mapping for this GVK.
	mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return name, kind, fmt.Errorf("failed to get REST mapping for %s: %w", gvk.String(), err)
	}

	// Encode for patch.
	patchData, err := runtime.Encode(unstructured.UnstructuredJSONScheme, unObj)
	if err != nil {
		return name, kind, fmt.Errorf("failed to encode resource: %w", err)
	}

	// Apply using server-side apply.
	_, err = dynClient.Resource(mapping.Resource).
		Namespace(unObj.GetNamespace()).
		Patch(ctx, name, types.ApplyPatchType, patchData, metav1.PatchOptions{
			FieldManager: applyFieldManager,
			Force:        &applyForceConflicts,
		})
	if err != nil {
		return name, kind, fmt.Errorf("failed to apply %s %q: %w", kind, name, err)
	}

	return name, kind, nil
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
