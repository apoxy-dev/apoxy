package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha2"
	"github.com/apoxy-dev/apoxy-cli/config"
	"github.com/apoxy-dev/apoxy-cli/pkg/cmd/utils"
	"github.com/apoxy-dev/apoxy-cli/pretty"
	"github.com/apoxy-dev/apoxy-cli/rest"
)

var showEdgeFunctionLabels bool

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

// edgeFunctionFile is the file that contains the configuration to create.
var edgeFunctionFile string

// createAlphaEdgeFunctionCmd represents the create edgefunction command
var createAlphaEdgeFunctionCmd = &cobra.Command{
	Use:   "create [-f filename]",
	Short: "Create edge function objects",
	Long:  `Create edge function objects by providing a configuration as a file or via stdin.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load the config to create from a file or stdin.
		var edgeFunctionConfig string
		var err error
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if edgeFunctionFile != "" {
				return fmt.Errorf("cannot use --filename with stdin")
			}
			edgeFunctionConfig, err = utils.ReadStdInAsString()
		} else if edgeFunctionFile != "" {
			edgeFunctionConfig, err = utils.ReadFileAsString(edgeFunctionFile)
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

		// Parse edgeFunctionConfig into an EdgeFunction object.
		edgeFunction := &v1alpha2.EdgeFunction{}
		edgeFunctionJSON, err := utils.YAMLToJSON(edgeFunctionConfig)
		if err != nil {
			// Try assuming that the config is a JSON string?
			slog.Debug("failed to parse edge function config as yaml - assuming input is JSON", "error", err)
			edgeFunctionJSON = edgeFunctionConfig
		}
		err = json.Unmarshal([]byte(edgeFunctionJSON), edgeFunction)
		if err != nil {
			return err
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

func init() {
	createAlphaEdgeFunctionCmd.PersistentFlags().
		StringVarP(&edgeFunctionFile, "filename", "f", "", "The file that contains the configuration to create.")
	listAlphaEdgeFunctionCmd.PersistentFlags().
		BoolVar(&showEdgeFunctionLabels, "show-labels", false, "Print the edge function's labels.")

	alphaEdgeFunctionCmd.AddCommand(getAlphaEdgeFunctionCmd, listAlphaEdgeFunctionCmd, createAlphaEdgeFunctionCmd, deleteAlphaEdgeFunctionCmd)
	rootCmd.AddCommand(alphaEdgeFunctionCmd)
}
