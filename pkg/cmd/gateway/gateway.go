package gateway

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
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	gatewayv1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
	gatewayv1alpha2 "github.com/apoxy-dev/apoxy/api/gateway/v1alpha2"
	"github.com/apoxy-dev/apoxy/client/versioned/scheme"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/rest"
)

var (
	showGatewayLabels     bool
	gatewayFile           string
	gatewayApplyFile      string
	gatewayFieldManager   string
	gatewayForceConflicts bool
)

// sinceString returns a string representation of a time.Duration since the provided time.Time.
func sinceString(t time.Time) string {
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

func labelsToString(labels map[string]string) string {
	var l []string
	for k, v := range labels {
		l = append(l, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(l, ",")
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
				sinceString(gw.CreationTimestamp.Time),
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
					sinceString(gw.CreationTimestamp.Time),
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

// httpRouteReferencesGateway checks if a route references the given gateway name.
func httpRouteReferencesGateway(refs []gwapiv1.ParentReference, gatewayName string) bool {
	for _, ref := range refs {
		if ref.Kind != nil && *ref.Kind != "Gateway" {
			continue
		}
		if string(ref.Name) == gatewayName {
			return true
		}
	}
	return false
}

// getAttachedRoutes fetches all routes that reference the given gateway.
func getAttachedRoutes(ctx context.Context, c *rest.APIClient, gatewayName string) (
	httpRoutes []gatewayv1.HTTPRoute,
	tcpRoutes []gatewayv1alpha2.TCPRoute,
	tlsRoutes []gatewayv1alpha2.TLSRoute,
	err error,
) {
	httpRouteList, err := c.GatewayV1().HTTPRoutes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to list HTTP routes: %w", err)
	}
	for _, route := range httpRouteList.Items {
		if httpRouteReferencesGateway(route.Spec.ParentRefs, gatewayName) {
			httpRoutes = append(httpRoutes, route)
		}
	}

	tcpRouteList, err := c.GatewayV1alpha2().TCPRoutes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to list TCP routes: %w", err)
	}
	for _, route := range tcpRouteList.Items {
		for _, ref := range route.Spec.ParentRefs {
			if ref.Kind != nil && *ref.Kind != "Gateway" {
				continue
			}
			if string(ref.Name) == gatewayName {
				tcpRoutes = append(tcpRoutes, route)
				break
			}
		}
	}

	tlsRouteList, err := c.GatewayV1alpha2().TLSRoutes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to list TLS routes: %w", err)
	}
	for _, route := range tlsRouteList.Items {
		for _, ref := range route.Spec.ParentRefs {
			if ref.Kind != nil && *ref.Kind != "Gateway" {
				continue
			}
			if string(ref.Name) == gatewayName {
				tlsRoutes = append(tlsRoutes, route)
				break
			}
		}
	}

	return httpRoutes, tcpRoutes, tlsRoutes, nil
}

// printAttachedRoutes prints a summary of routes attached to a gateway.
func printAttachedRoutes(httpRoutes []gatewayv1.HTTPRoute, tcpRoutes []gatewayv1alpha2.TCPRoute, tlsRoutes []gatewayv1alpha2.TLSRoute) {
	totalRoutes := len(httpRoutes) + len(tcpRoutes) + len(tlsRoutes)
	if totalRoutes == 0 {
		fmt.Println("\nAttached Routes: None")
		return
	}

	fmt.Printf("\nAttached Routes (%d):\n", totalRoutes)

	if len(httpRoutes) > 0 {
		fmt.Printf("  HTTPRoutes (%d):\n", len(httpRoutes))
		for _, r := range httpRoutes {
			hostnames := "*"
			if len(r.Spec.Hostnames) > 0 {
				var parts []string
				for _, h := range r.Spec.Hostnames {
					parts = append(parts, string(h))
				}
				hostnames = strings.Join(parts, ",")
			}
			fmt.Printf("    - %s (hostnames: %s, rules: %d)\n", r.Name, hostnames, len(r.Spec.Rules))
		}
	}

	if len(tcpRoutes) > 0 {
		fmt.Printf("  TCPRoutes (%d):\n", len(tcpRoutes))
		for _, r := range tcpRoutes {
			fmt.Printf("    - %s (rules: %d)\n", r.Name, len(r.Spec.Rules))
		}
	}

	if len(tlsRoutes) > 0 {
		fmt.Printf("  TLSRoutes (%d):\n", len(tlsRoutes))
		for _, r := range tlsRoutes {
			hostnames := "*"
			if len(r.Spec.Hostnames) > 0 {
				var parts []string
				for _, h := range r.Spec.Hostnames {
					parts = append(parts, string(h))
				}
				hostnames = strings.Join(parts, ",")
			}
			fmt.Printf("    - %s (hostnames: %s, rules: %d)\n", r.Name, hostnames, len(r.Spec.Rules))
		}
	}
}

func getGateway(ctx context.Context, c *rest.APIClient, name string) error {
	r, err := c.GatewayV1().Gateways().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	printer := getGatewayTablePrinter(false)
	if err := printer.PrintObj(r, os.Stdout); err != nil {
		return err
	}

	httpRoutes, tcpRoutes, tlsRoutes, err := getAttachedRoutes(ctx, c, name)
	if err != nil {
		return err
	}
	printAttachedRoutes(httpRoutes, tcpRoutes, tlsRoutes)

	return nil
}

func listGateways(ctx context.Context, c *rest.APIClient, opts metav1.ListOptions) error {
	gateways, err := c.GatewayV1().Gateways().List(ctx, opts)
	if err != nil {
		return err
	}
	printer := getGatewayTablePrinter(showGatewayLabels)
	return printer.PrintObj(gateways, os.Stdout)
}

// Cmd returns the gateway command.
func Cmd() *cobra.Command {
	return cmd
}

// cmd is the gateway command.
var cmd = &cobra.Command{
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

var getCmd = &cobra.Command{
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

var listCmd = &cobra.Command{
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

var createCmd = &cobra.Command{
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

var deleteCmd = &cobra.Command{
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

var applyCmd = &cobra.Command{
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
	createCmd.Flags().StringVarP(&gatewayFile, "filename", "f", "", "The file that contains the configuration to create.")
	listCmd.Flags().BoolVar(&showGatewayLabels, "show-labels", false, "Print the gateway's labels.")

	applyCmd.Flags().StringVarP(&gatewayApplyFile, "filename", "f", "", "The file that contains the configuration to apply.")
	applyCmd.Flags().StringVar(&gatewayFieldManager, "field-manager", "apoxy-cli", "Name of the field manager for server-side apply.")
	applyCmd.Flags().BoolVar(&gatewayForceConflicts, "force-conflicts", false, "Force apply even if there are field ownership conflicts.")

	cmd.AddCommand(getCmd, listCmd, createCmd, deleteCmd, applyCmd, routesCmd)
}
