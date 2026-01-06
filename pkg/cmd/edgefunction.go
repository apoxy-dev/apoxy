package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	"github.com/apoxy-dev/apoxy/client/versioned/scheme"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pretty"
	"github.com/apoxy-dev/apoxy/rest"
)

var (
	showEdgeFunctionLabels bool
	// edgeFunctionFile is the file that contains the configuration to create.
	edgeFunctionFile string
	// edgeFunctionApplyFile is the file that contains the configuration to apply.
	edgeFunctionApplyFile string
	// edgeFunctionFieldManager is the field manager name for server-side apply.
	edgeFunctionFieldManager string
	// edgeFunctionForceConflicts forces apply even if there are conflicts.
	edgeFunctionForceConflicts bool
)

func buildAlphaEdgeFunctionRow(r *v1alpha2.EdgeFunction, labels bool) []interface{} {
	mode := r.Spec.Template.Mode
	revision := r.Status.LiveRevision
	if revision == "" {
		revision = "-"
	}

	var sourceType string
	if r.Spec.Template.Code.JsSource != nil {
		sourceType = "JavaScript"
	} else if r.Spec.Template.Code.WasmSource != nil {
		sourceType = "WebAssembly"
	} else if r.Spec.Template.Code.GoPluginSource != nil {
		sourceType = "Go Plugin"
	} else {
		sourceType = "Unknown"
	}

	if labels {
		return []interface{}{
			r.Name,
			string(mode),
			sourceType,
			revision,
			pretty.SinceString(r.CreationTimestamp.Time),
			labelsToString(r.Labels),
		}
	}
	return []interface{}{
		r.Name,
		string(mode),
		sourceType,
		revision,
		pretty.SinceString(r.CreationTimestamp.Time),
	}
}

func buildAlphaEdgeFunctionHeader(labels bool) pretty.Header {
	if labels {
		return pretty.Header{
			"NAME",
			"MODE",
			"SOURCE TYPE",
			"LIVE REVISION",
			"AGE",
			"LABELS",
		}
	}
	return pretty.Header{
		"NAME",
		"MODE",
		"SOURCE TYPE",
		"LIVE REVISION",
		"AGE",
	}
}

func fmtAlphaEdgeFunction(r *v1alpha2.EdgeFunction) {
	t := pretty.Table{
		Header: buildAlphaEdgeFunctionHeader(false),
		Rows: pretty.Rows{
			buildAlphaEdgeFunctionRow(r, false),
		},
	}
	t.Print()
}

func getAlphaEdgeFunction(ctx context.Context, c *rest.APIClient, name string) error {
	r, err := c.ExtensionsV1alpha2().EdgeFunctions().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	fmtAlphaEdgeFunction(r)
	return nil
}

func listAlphaEdgeFunctions(ctx context.Context, c *rest.APIClient, opts metav1.ListOptions) error {
	edgeFunctions, err := c.ExtensionsV1alpha2().EdgeFunctions().List(ctx, opts)
	if err != nil {
		return err
	}
	t := pretty.Table{
		Header: buildAlphaEdgeFunctionHeader(showEdgeFunctionLabels),
	}
	for _, ef := range edgeFunctions.Items {
		t.Rows = append(t.Rows, buildAlphaEdgeFunctionRow(&ef, showEdgeFunctionLabels))
	}
	t.Print()
	return nil
}

// alphaEdgeFunctionCmd represents the edgefunction command
var alphaEdgeFunctionCmd = &cobra.Command{
	Use:     "edgefunction",
	Short:   "Manage edge function objects",
	Long:    `Edge functions allow you to run custom code at the edge of the Apoxy network.`,
	Aliases: []string{"ef", "edgefunctions", "edgefuncs"},
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		return listAlphaEdgeFunctions(cmd.Context(), c, metav1.ListOptions{})
	},
}

// getAlphaEdgeFunctionCmd represents the get edgefunction command
var getAlphaEdgeFunctionCmd = &cobra.Command{
	Use:       "get <n>",
	Short:     "Get edge function objects",
	ValidArgs: []string{"name"},
	Args:      cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		return getAlphaEdgeFunction(cmd.Context(), c, args[0])
	},
}

// listAlphaEdgeFunctionCmd represents the list edgefunction command
var listAlphaEdgeFunctionCmd = &cobra.Command{
	Use:   "list",
	Short: "List edge function objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		return listAlphaEdgeFunctions(cmd.Context(), c, metav1.ListOptions{})
	},
}

// createAlphaEdgeFunctionCmd represents the create edgefunction command
var createAlphaEdgeFunctionCmd = &cobra.Command{
	Use:   "create [-f filename]",
	Short: "Create edge function objects",
	Long:  `Create edge function objects by providing a configuration as a file or via stdin.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var data []byte
		var err error
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if edgeFunctionFile != "" {
				return fmt.Errorf("cannot use --filename with stdin")
			}
			data, err = io.ReadAll(os.Stdin)
		} else if edgeFunctionFile != "" {
			data, err = os.ReadFile(edgeFunctionFile)
		} else {
			return fmt.Errorf("please provide a configuration via --filename or stdin")
		}
		if err != nil {
			return err
		}

		cmd.SilenceUsage = true

		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}

		// Decode using the apoxy scheme's universal deserializer (handles both YAML and JSON).
		obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to decode input: %w", err)
		}

		edgeFunction, ok := obj.(*v1alpha2.EdgeFunction)
		if !ok {
			return fmt.Errorf("expected EdgeFunction, got %T", obj)
		}

		r, err := c.ExtensionsV1alpha2().EdgeFunctions().Create(cmd.Context(), edgeFunction, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		fmt.Printf("edge function %q created\n", r.Name)
		return nil
	},
}

// deleteAlphaEdgeFunctionCmd represents the delete edgefunction command
var deleteAlphaEdgeFunctionCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete edge function objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}

		for _, name := range args {
			if err = c.ExtensionsV1alpha2().EdgeFunctions().Delete(cmd.Context(), name, metav1.DeleteOptions{}); err != nil {
				return err
			}
			fmt.Printf("edge function %q deleted\n", name)
		}

		return nil
	},
}

// applyAlphaEdgeFunctionCmd applies an EdgeFunction object using server-side apply.
var applyAlphaEdgeFunctionCmd = &cobra.Command{
	Use:   "apply [-f filename]",
	Short: "Apply edge function configuration using server-side apply",
	Long: `Apply edge function configuration using Kubernetes server-side apply.

This command uses server-side apply to create or update edge function objects.
Server-side apply tracks field ownership and allows multiple actors to
manage different fields of the same object without conflicts.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var data []byte
		var err error
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if edgeFunctionApplyFile != "" {
				return fmt.Errorf("cannot use --filename with stdin")
			}
			data, err = io.ReadAll(os.Stdin)
		} else if edgeFunctionApplyFile != "" {
			data, err = os.ReadFile(edgeFunctionApplyFile)
		} else {
			return fmt.Errorf("please provide a configuration via --filename or stdin")
		}
		if err != nil {
			return err
		}

		cmd.SilenceUsage = true

		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}

		// Decode using the apoxy scheme's universal deserializer (handles both YAML and JSON).
		obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to decode input: %w", err)
		}

		edgeFunction, ok := obj.(*v1alpha2.EdgeFunction)
		if !ok {
			return fmt.Errorf("expected EdgeFunction, got %T", obj)
		}

		if edgeFunction.Name == "" {
			return fmt.Errorf("edge function name is required")
		}

		// Server-side apply uses Patch with ApplyPatchType.
		// The data must be a valid JSON representation of the object.
		patchData, err := json.Marshal(edgeFunction)
		if err != nil {
			return fmt.Errorf("failed to marshal edge function: %w", err)
		}

		result, err := c.ExtensionsV1alpha2().EdgeFunctions().Patch(
			cmd.Context(),
			edgeFunction.Name,
			types.ApplyPatchType,
			patchData,
			metav1.PatchOptions{
				FieldManager: edgeFunctionFieldManager,
				Force:        &edgeFunctionForceConflicts,
			},
		)
		if err != nil {
			return err
		}

		fmt.Printf("edge function %q applied\n", result.Name)
		return nil
	},
}

func init() {
	createAlphaEdgeFunctionCmd.PersistentFlags().
		StringVarP(&edgeFunctionFile, "filename", "f", "", "The file that contains the configuration to create.")
	listAlphaEdgeFunctionCmd.PersistentFlags().
		BoolVar(&showEdgeFunctionLabels, "show-labels", false, "Print the edge function's labels.")

	applyAlphaEdgeFunctionCmd.PersistentFlags().
		StringVarP(&edgeFunctionApplyFile, "filename", "f", "", "The file that contains the configuration to apply.")
	applyAlphaEdgeFunctionCmd.PersistentFlags().
		StringVar(&edgeFunctionFieldManager, "field-manager", "apoxy-cli", "Name of the field manager for server-side apply.")
	applyAlphaEdgeFunctionCmd.PersistentFlags().
		BoolVar(&edgeFunctionForceConflicts, "force-conflicts", false, "Force apply even if there are field ownership conflicts.")

	alphaEdgeFunctionCmd.AddCommand(getAlphaEdgeFunctionCmd, listAlphaEdgeFunctionCmd, createAlphaEdgeFunctionCmd, deleteAlphaEdgeFunctionCmd, applyAlphaEdgeFunctionCmd)
	RootCmd.AddCommand(alphaEdgeFunctionCmd)
}
