package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	memory "k8s.io/client-go/discovery/cached"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"

	"github.com/apoxy-dev/apoxy/client/versioned/scheme"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
)

var (
	deleteFiles         []string
	deleteRecursive     bool
	deleteIgnoreNotFound bool
	deleteWait          bool
	deleteWaitTimeout   time.Duration
)

// deleteCmd is the global delete command for multi-resource operations.
var deleteCmd = &cobra.Command{
	Use:   "delete (-f <filename> | <type> <name> [<name>...])",
	Short: "Delete resources by file or type/name",
	Long: `Delete resources identified in file(s), directories, stdin, or by type and name.

Supports two modes:
  1. File-based: delete resources specified in YAML/JSON files, directories, or stdin.
  2. Type+name: delete one or more resources by specifying the resource type and name(s).

When a directory is specified with -f, all .yaml, .yml, and .json files are processed.

Examples:
  # Delete resources in a single file
  apoxy delete -f gateway.yaml

  # Delete resources in multiple files
  apoxy delete -f gateway.yaml -f routes.yaml

  # Delete all resources in a directory
  apoxy delete -f ./manifests/

  # Delete from stdin
  cat manifest.yaml | apoxy delete -f -

  # Delete a resource by type and name
  apoxy delete proxy my-proxy

  # Delete multiple resources by type and name
  apoxy delete backend backend-a backend-b

  # Delete a resource, ignoring if it doesn't exist
  apoxy delete proxy my-proxy --ignore-not-found

  # Delete and wait for the resource to be fully removed
  apoxy delete proxy my-proxy --wait`,
	RunE: func(cmd *cobra.Command, args []string) error {
		hasFiles := len(deleteFiles) > 0
		hasArgs := len(args) > 0

		if !hasFiles && !hasArgs {
			return fmt.Errorf("please specify files with -f/--filename or provide <type> <name>")
		}
		if hasFiles && hasArgs {
			return fmt.Errorf("cannot specify both -f/--filename and type/name arguments")
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

		if hasArgs {
			return deleteByTypeAndName(cmd.Context(), dynClient, mapper, args)
		}
		return deleteFromFiles(cmd.Context(), dynClient, mapper)
	},
}

// deleteFromFiles processes -f flag inputs and deletes each resource found.
func deleteFromFiles(
	ctx context.Context,
	dynClient dynamic.Interface,
	mapper *restmapper.DeferredDiscoveryRESTMapper,
) error {
	allData, err := resource.ReadInputs(deleteFiles, deleteRecursive)
	if err != nil {
		return err
	}

	var errs []error
	var deleted int

	for _, data := range allData {
		for _, doc := range resource.SplitYAMLDocuments(data) {
			name, kind, notFound, err := deleteResource(ctx, dynClient, mapper, doc)
			if err != nil {
				errs = append(errs, err)
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
			} else if notFound {
				fmt.Printf("%s %q not found (ignored)\n", strings.ToLower(kind), name)
			} else {
				fmt.Printf("%s %q deleted\n", strings.ToLower(kind), name)
				deleted++
			}
		}
	}

	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "\nDeleted %d resource(s) with %d error(s)\n", deleted, len(errs))
		return fmt.Errorf("failed to delete %d resource(s)", len(errs))
	}

	if deleted > 1 {
		fmt.Printf("\nDeleted %d resources\n", deleted)
	}
	return nil
}

// deleteResource decodes and deletes a single resource using the dynamic client.
// notFound is true when the resource was not found and --ignore-not-found is set.
func deleteResource(
	ctx context.Context,
	dynClient dynamic.Interface,
	mapper *restmapper.DeferredDiscoveryRESTMapper,
	data []byte,
) (name, kind string, notFound bool, err error) {
	// Decode into unstructured object.
	unObj := &unstructured.Unstructured{}
	_, gvk, err := scheme.Codecs.UniversalDeserializer().Decode(data, nil, unObj)
	if err != nil {
		return "", "", false, fmt.Errorf("failed to decode resource: %w", err)
	}

	name = unObj.GetName()
	if name == "" {
		if fn, ok := resource.LookupDefaultName(*gvk); ok {
			derivedName, err := fn(data)
			if err != nil {
				return "", "", false, err
			}
			unObj.SetName(derivedName)
			name = derivedName
		}
	}
	if name == "" {
		return "", "", false, fmt.Errorf("resource name is required")
	}
	kind = gvk.Kind

	// Get the REST mapping for this GVK.
	mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return name, kind, false, fmt.Errorf("failed to get REST mapping for %s: %w", gvk.String(), err)
	}

	res := dynClient.Resource(mapping.Resource).Namespace(unObj.GetNamespace())

	// Delete the resource.
	err = res.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) && deleteIgnoreNotFound {
			return name, kind, true, nil
		}
		return name, kind, false, fmt.Errorf("failed to delete %s %q: %w", kind, name, err)
	}

	if deleteWait {
		if err := waitForDeletion(ctx, res, name, deleteWaitTimeout); err != nil {
			return name, kind, false, fmt.Errorf("failed waiting for %s %q to be deleted: %w", kind, name, err)
		}
	}

	return name, kind, false, nil
}

// deleteByTypeAndName deletes resources specified as positional arguments: <type> <name> [<name>...].
func deleteByTypeAndName(
	ctx context.Context,
	dynClient dynamic.Interface,
	mapper *restmapper.DeferredDiscoveryRESTMapper,
	args []string,
) error {
	if len(args) < 2 {
		return fmt.Errorf("please specify resource type and at least one name: <type> <name> [<name>...]")
	}

	typeName := args[0]
	names := args[1:]

	// Resolve the user-provided type name to a GroupVersionResource.
	gvr, err := resolveResourceType(mapper, typeName)
	if err != nil {
		return err
	}

	// Resolve the kind name for display purposes.
	displayKind := typeName
	if gvk, err := mapper.KindFor(gvr); err == nil {
		displayKind = strings.ToLower(gvk.Kind)
	}

	var errs []error
	var deleted int

	for _, name := range names {
		// Use .Namespace("") explicitly to match the file-based path's pattern.
		// Cluster-scoped resources are unaffected; if namespace support is added
		// later, this is the call site to update.
		res := dynClient.Resource(gvr).Namespace("")
		err := res.Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) && deleteIgnoreNotFound {
				fmt.Printf("%s %q not found (ignored)\n", displayKind, name)
				continue
			}
			errs = append(errs, fmt.Errorf("failed to delete %s %q: %w", displayKind, name, err))
			fmt.Fprintf(os.Stderr, "error: failed to delete %s %q: %v\n", displayKind, name, err)
			continue
		}

		if deleteWait {
			if err := waitForDeletion(ctx, res, name, deleteWaitTimeout); err != nil {
				errs = append(errs, fmt.Errorf("failed waiting for %s %q to be deleted: %w", displayKind, name, err))
				fmt.Fprintf(os.Stderr, "error: failed waiting for %s %q to be deleted: %v\n", displayKind, name, err)
				continue
			}
		}

		fmt.Printf("%s %q deleted\n", displayKind, name)
		deleted++
	}

	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "\nDeleted %d resource(s) with %d error(s)\n", deleted, len(errs))
		return fmt.Errorf("failed to delete %d resource(s)", len(errs))
	}

	if deleted > 1 {
		fmt.Printf("\nDeleted %d resources\n", deleted)
	}
	return nil
}

// resolveResourceType resolves a user-provided resource type string (e.g. "proxy", "proxies",
// "backends") to a fully qualified GroupVersionResource using the API server's discovery info.
func resolveResourceType(
	mapper *restmapper.DeferredDiscoveryRESTMapper,
	typeName string,
) (schema.GroupVersionResource, error) {
	// Try the user-provided name as a resource (handles both singular and plural).
	fullySpecified := schema.GroupVersionResource{Resource: typeName}
	gvr, err := mapper.ResourceFor(fullySpecified)
	if err == nil {
		return gvr, nil
	}

	return schema.GroupVersionResource{}, fmt.Errorf(
		"unable to find resource type %q: %w",
		typeName, err,
	)
}

// waitForDeletion watches the resource and blocks until it is fully removed or the timeout expires.
func waitForDeletion(
	ctx context.Context,
	res dynamic.ResourceInterface,
	name string,
	timeout time.Duration,
) error {
	// Get the current resourceVersion so the subsequent Watch doesn't miss
	// a deletion that happens between the Get and Watch calls.
	obj, err := res.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to check resource: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	watcher, err := res.Watch(ctx, metav1.ListOptions{
		FieldSelector:   "metadata.name=" + name,
		ResourceVersion: obj.GetResourceVersion(),
	})
	if err != nil {
		return fmt.Errorf("failed to watch resource: %w", err)
	}
	defer watcher.Stop()

	for event := range watcher.ResultChan() {
		if event.Type == watch.Deleted {
			return nil
		}
	}

	// Channel closed — check if context timed out.
	if ctx.Err() != nil {
		return fmt.Errorf("timed out after %v waiting for deletion", timeout)
	}
	return nil
}

func init() {
	deleteCmd.Flags().StringArrayVarP(&deleteFiles, "filename", "f", nil,
		"Files or directories containing resources to delete (can be specified multiple times)")
	deleteCmd.Flags().BoolVarP(&deleteRecursive, "recursive", "R", false,
		"Process directories recursively")
	deleteCmd.Flags().BoolVar(&deleteIgnoreNotFound, "ignore-not-found", false,
		"Treat \"resource not found\" as a successful delete")
	deleteCmd.Flags().BoolVar(&deleteWait, "wait", false,
		"Wait for the resource to be fully deleted before returning")
	deleteCmd.Flags().DurationVar(&deleteWaitTimeout, "timeout", 60*time.Second,
		"Timeout for --wait (e.g. 30s, 2m)")

	RootCmd.AddCommand(deleteCmd)
}
