package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cli-runtime/pkg/printers"

	gatewayv1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
	"github.com/apoxy-dev/apoxy/client/versioned/scheme"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/rest"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

var (
	// showGatewayLabels is a flag to show labels in the output.
	showGatewayLabels bool
	// gatewayFile is a flag that specifies the file to read the configuration from.
	gatewayFile string
	// gatewayApplyFile is a flag that specifies the file to read the configuration from for apply.
	gatewayApplyFile string
	// gatewayFieldManager is the field manager name for server-side apply.
	gatewayFieldManager string
	// gatewayForceConflicts forces apply even if there are conflicts.
	gatewayForceConflicts bool
)

// gatewaySinceString returns a string representation of a time.Duration since the provided time.Time.
func gatewaySinceString(t time.Time) string {
	d := time.Since(t).Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	} else {
		return fmt.Sprintf("%dd%dh", int(d.Hours()/24), int(d.Hours())%24)
	}
}

// getListenersSummary returns a summary of gateway listeners.
func getListenersSummary(listeners []gwapiv1.Listener) string {
	if len(listeners) == 0 {
		return "None"
	}
	var parts []string
	for _, l := range listeners {
		parts = append(parts, fmt.Sprintf("%s/%d", l.Protocol, l.Port))
	}
	return strings.Join(parts, ",")
}

func getGatewayTablePrinter(showLabels bool) printers.ResourcePrinter {
	printer := printers.NewTablePrinter(printers.PrintOptions{})

	var columnDefinitions []metav1.TableColumnDefinition
	if showLabels {
		columnDefinitions = []metav1.TableColumnDefinition{
			{Name: "NAME", Type: "string"},
			{Name: "CLASS", Type: "string"},
			{Name: "LISTENERS", Type: "string"},
			{Name: "AGE", Type: "string"},
			{Name: "LABELS", Type: "string"},
		}
	} else {
		columnDefinitions = []metav1.TableColumnDefinition{
			{Name: "NAME", Type: "string"},
			{Name: "CLASS", Type: "string"},
			{Name: "LISTENERS", Type: "string"},
			{Name: "AGE", Type: "string"},
		}
	}

	gatewayPrintFunc := func(obj runtime.Object, w io.Writer) error {
		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			return fmt.Errorf("expected *gatewayv1.Gateway, got %T", obj)
		}

		table := &metav1.Table{
			ColumnDefinitions: columnDefinitions,
		}

		row := metav1.TableRow{
			Cells: []interface{}{
				gw.Name,
				string(gw.Spec.GatewayClassName),
				getListenersSummary(gw.Spec.Listeners),
				gatewaySinceString(gw.CreationTimestamp.Time),
			},
		}
		if showLabels {
			row.Cells = append(row.Cells, labelsToString(gw.Labels))
		}
		table.Rows = append(table.Rows, row)

		return printer.PrintObj(table, w)
	}

	gatewayListPrintFunc := func(obj runtime.Object, w io.Writer) error {
		list, ok := obj.(*gatewayv1.GatewayList)
		if !ok {
			return fmt.Errorf("expected *gatewayv1.GatewayList, got %T", obj)
		}

		table := &metav1.Table{
			ColumnDefinitions: columnDefinitions,
		}

		for _, gw := range list.Items {
			row := metav1.TableRow{
				Cells: []interface{}{
					gw.Name,
					string(gw.Spec.GatewayClassName),
					getListenersSummary(gw.Spec.Listeners),
					gatewaySinceString(gw.CreationTimestamp.Time),
				},
			}
			if showLabels {
				row.Cells = append(row.Cells, labelsToString(gw.Labels))
			}
			table.Rows = append(table.Rows, row)
		}

		return printer.PrintObj(table, w)
	}

	return printers.ResourcePrinterFunc(func(obj runtime.Object, w io.Writer) error {
		switch obj.(type) {
		case *gatewayv1.Gateway:
			return gatewayPrintFunc(obj, w)
		case *gatewayv1.GatewayList:
			return gatewayListPrintFunc(obj, w)
		default:
			return fmt.Errorf("unsupported type: %T", obj)
		}
	})
}

func getGateway(ctx context.Context, c *rest.APIClient, name string) error {
	r, err := c.GatewayV1().Gateways().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	printer := getGatewayTablePrinter(false)
	return printer.PrintObj(r, os.Stdout)
}

func listGateways(ctx context.Context, c *rest.APIClient, opts metav1.ListOptions) error {
	gateways, err := c.GatewayV1().Gateways().List(ctx, opts)
	if err != nil {
		return err
	}
	printer := getGatewayTablePrinter(showGatewayLabels)
	return printer.PrintObj(gateways, os.Stdout)
}

// alphaGatewayCmd represents the gateway command.
var alphaGatewayCmd = &cobra.Command{
	Use:     "gateway",
	Short:   "Manage gateway objects",
	Long:    `The gateway object in the Apoxy API.`,
	Aliases: []string{"gw", "gateways"},
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		return listGateways(cmd.Context(), c, metav1.ListOptions{})
	},
}

// getGatewayCmd gets a single gateway object.
var getGatewayCmd = &cobra.Command{
	Use:       "get <name>",
	Short:     "Get gateway objects",
	ValidArgs: []string{"name"},
	Args:      cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		return getGateway(cmd.Context(), c, args[0])
	},
}

// listGatewayCmd lists gateway objects.
var listGatewayCmd = &cobra.Command{
	Use:   "list",
	Short: "List gateway objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		return listGateways(cmd.Context(), c, metav1.ListOptions{})
	},
}

// createGatewayCmd creates a Gateway object.
var createGatewayCmd = &cobra.Command{
	Use:   "create [-f filename]",
	Short: "Create gateway objects",
	Long:  `Create gateway objects by providing a configuration as a file or via stdin.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var data []byte
		var err error
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if gatewayFile != "" {
				return fmt.Errorf("cannot use --filename with stdin")
			}
			data, err = io.ReadAll(os.Stdin)
		} else if gatewayFile != "" {
			data, err = os.ReadFile(gatewayFile)
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

		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			return fmt.Errorf("expected Gateway, got %T", obj)
		}

		r, err := c.GatewayV1().Gateways().Create(cmd.Context(), gw, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		fmt.Printf("gateway %q created\n", r.Name)
		return nil
	},
}

// deleteGatewayCmd deletes Gateway objects.
var deleteGatewayCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete gateway objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}

		for _, name := range args {
			if err = c.GatewayV1().Gateways().Delete(cmd.Context(), name, metav1.DeleteOptions{}); err != nil {
				return err
			}
			fmt.Printf("gateway %q deleted\n", name)
		}

		return nil
	},
}

// applyGatewayCmd applies a Gateway object using server-side apply.
var applyGatewayCmd = &cobra.Command{
	Use:   "apply [-f filename]",
	Short: "Apply gateway configuration using server-side apply",
	Long: `Apply gateway configuration using Kubernetes server-side apply.

This command uses server-side apply to create or update gateway objects.
Server-side apply tracks field ownership and allows multiple actors to
manage different fields of the same object without conflicts.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var data []byte
		var err error
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if gatewayApplyFile != "" {
				return fmt.Errorf("cannot use --filename with stdin")
			}
			data, err = io.ReadAll(os.Stdin)
		} else if gatewayApplyFile != "" {
			data, err = os.ReadFile(gatewayApplyFile)
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

		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			return fmt.Errorf("expected Gateway, got %T", obj)
		}

		if gw.Name == "" {
			return fmt.Errorf("gateway name is required")
		}

		// Server-side apply uses Patch with ApplyPatchType.
		// The data must be a valid JSON representation of the object.
		patchData, err := json.Marshal(gw)
		if err != nil {
			return fmt.Errorf("failed to marshal gateway: %w", err)
		}

		result, err := c.GatewayV1().Gateways().Patch(
			cmd.Context(),
			gw.Name,
			types.ApplyPatchType,
			patchData,
			metav1.PatchOptions{
				FieldManager: gatewayFieldManager,
				Force:        &gatewayForceConflicts,
			},
		)
		if err != nil {
			return err
		}

		fmt.Printf("gateway %q applied\n", result.Name)
		return nil
	},
}

func init() {
	createGatewayCmd.PersistentFlags().
		StringVarP(&gatewayFile, "filename", "f", "", "The file that contains the configuration to create.")
	listGatewayCmd.PersistentFlags().
		BoolVar(&showGatewayLabels, "show-labels", false, "Print the gateway's labels.")

	applyGatewayCmd.PersistentFlags().
		StringVarP(&gatewayApplyFile, "filename", "f", "", "The file that contains the configuration to apply.")
	applyGatewayCmd.PersistentFlags().
		StringVar(&gatewayFieldManager, "field-manager", "apoxy-cli", "Name of the field manager for server-side apply.")
	applyGatewayCmd.PersistentFlags().
		BoolVar(&gatewayForceConflicts, "force-conflicts", false, "Force apply even if there are field ownership conflicts.")

	alphaGatewayCmd.AddCommand(getGatewayCmd, listGatewayCmd, createGatewayCmd, deleteGatewayCmd, applyGatewayCmd)
	RootCmd.AddCommand(alphaGatewayCmd)
}
