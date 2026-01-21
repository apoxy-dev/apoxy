package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cli-runtime/pkg/printers"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	gatewayv1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
	gatewayv1alpha2 "github.com/apoxy-dev/apoxy/api/gateway/v1alpha2"
	"github.com/apoxy-dev/apoxy/client/versioned/scheme"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/rest"
)

var (
	showRoutesLabels     bool
	routesFile           string
	routesApplyFile      string
	routesFieldManager   string
	routesForceConflicts bool
)

const (
	routeTypeHTTP = "http"
	routeTypeTCP  = "tcp"
	routeTypeTLS  = "tls"
)

// parseRouteRef parses a route reference in the format [TYPE/]NAME.
// If no type is specified, defaults to "http".
func parseRouteRef(ref string) (routeType, name string) {
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) == 2 {
		return strings.ToLower(parts[0]), parts[1]
	}
	return routeTypeHTTP, ref
}

// routeInfo holds common route information for display.
type routeInfo struct {
	Name      string
	Type      string
	Hostnames string
	Parents   string
	Status    string
	Rules     int
	Age       string
	Labels    map[string]string
}

// collectAllRoutes fetches all routes from the API.
func collectAllRoutes(ctx context.Context, c *rest.APIClient) ([]routeInfo, error) {
	var routes []routeInfo

	// HTTP Routes
	httpRoutes, err := c.GatewayV1().HTTPRoutes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list HTTP routes: %w", err)
	}
	for _, r := range httpRoutes.Items {
		routes = append(routes, routeInfo{
			Name:      r.Name,
			Type:      "HTTPRoute",
			Hostnames: getHTTPHostnames(r.Spec.Hostnames),
			Parents:   getHTTPParents(r.Spec.ParentRefs),
			Status:    getHTTPRouteStatus(r.Status.Parents),
			Rules:     len(r.Spec.Rules),
			Age:       sinceString(r.CreationTimestamp.Time),
			Labels:    r.Labels,
		})
	}

	// TCP Routes
	tcpRoutes, err := c.GatewayV1alpha2().TCPRoutes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list TCP routes: %w", err)
	}
	for _, r := range tcpRoutes.Items {
		routes = append(routes, routeInfo{
			Name:      r.Name,
			Type:      "TCPRoute",
			Hostnames: "-",
			Parents:   getTCPParents(r.Spec.ParentRefs),
			Status:    getTCPRouteStatus(r.Status.Parents),
			Rules:     len(r.Spec.Rules),
			Age:       sinceString(r.CreationTimestamp.Time),
			Labels:    r.Labels,
		})
	}

	// TLS Routes
	tlsRoutes, err := c.GatewayV1alpha2().TLSRoutes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list TLS routes: %w", err)
	}
	for _, r := range tlsRoutes.Items {
		routes = append(routes, routeInfo{
			Name:      r.Name,
			Type:      "TLSRoute",
			Hostnames: getTLSHostnames(r.Spec.Hostnames),
			Parents:   getTLSParents(r.Spec.ParentRefs),
			Status:    getTLSRouteStatus(r.Status.Parents),
			Rules:     len(r.Spec.Rules),
			Age:       sinceString(r.CreationTimestamp.Time),
			Labels:    r.Labels,
		})
	}

	return routes, nil
}

// getHTTPRouteStatus returns the status of an HTTP route from its parent conditions.
func getHTTPRouteStatus(parents []gwapiv1.RouteParentStatus) string {
	if len(parents) == 0 {
		return "Unknown"
	}
	for _, parent := range parents {
		for _, cond := range parent.Conditions {
			if cond.Type == string(gwapiv1.RouteConditionAccepted) {
				if cond.Status == metav1.ConditionTrue {
					return "Accepted"
				}
				return cond.Reason
			}
		}
	}
	return "Unknown"
}

// getTCPRouteStatus returns the status of a TCP route from its parent conditions.
func getTCPRouteStatus(parents []gwapiv1alpha2.RouteParentStatus) string {
	if len(parents) == 0 {
		return "Unknown"
	}
	for _, parent := range parents {
		for _, cond := range parent.Conditions {
			if cond.Type == string(gwapiv1.RouteConditionAccepted) {
				if cond.Status == metav1.ConditionTrue {
					return "Accepted"
				}
				return cond.Reason
			}
		}
	}
	return "Unknown"
}

// getTLSRouteStatus returns the status of a TLS route from its parent conditions.
func getTLSRouteStatus(parents []gwapiv1alpha2.RouteParentStatus) string {
	if len(parents) == 0 {
		return "Unknown"
	}
	for _, parent := range parents {
		for _, cond := range parent.Conditions {
			if cond.Type == string(gwapiv1.RouteConditionAccepted) {
				if cond.Status == metav1.ConditionTrue {
					return "Accepted"
				}
				return cond.Reason
			}
		}
	}
	return "Unknown"
}

func getHTTPHostnames(hostnames []gwapiv1.Hostname) string {
	if len(hostnames) == 0 {
		return "*"
	}
	var parts []string
	for _, h := range hostnames {
		parts = append(parts, string(h))
	}
	return strings.Join(parts, ",")
}

func getHTTPParents(refs []gwapiv1.ParentReference) string {
	if len(refs) == 0 {
		return "None"
	}
	var parts []string
	for _, ref := range refs {
		parts = append(parts, string(ref.Name))
	}
	return strings.Join(parts, ",")
}

func getTCPParents(refs []gwapiv1alpha2.ParentReference) string {
	if len(refs) == 0 {
		return "None"
	}
	var parts []string
	for _, ref := range refs {
		parts = append(parts, string(ref.Name))
	}
	return strings.Join(parts, ",")
}

func getTLSHostnames(hostnames []gwapiv1alpha2.Hostname) string {
	if len(hostnames) == 0 {
		return "*"
	}
	var parts []string
	for _, h := range hostnames {
		parts = append(parts, string(h))
	}
	return strings.Join(parts, ",")
}

func getTLSParents(refs []gwapiv1alpha2.ParentReference) string {
	if len(refs) == 0 {
		return "None"
	}
	var parts []string
	for _, ref := range refs {
		parts = append(parts, string(ref.Name))
	}
	return strings.Join(parts, ",")
}

func getRoutesTablePrinter(showLabels bool) func(routes []routeInfo) error {
	printer := printers.NewTablePrinter(printers.PrintOptions{})

	return func(routes []routeInfo) error {
		var columnDefinitions []metav1.TableColumnDefinition
		if showLabels {
			columnDefinitions = []metav1.TableColumnDefinition{
				{Name: "NAME", Type: "string"},
				{Name: "TYPE", Type: "string"},
				{Name: "HOSTNAMES", Type: "string"},
				{Name: "PARENTS", Type: "string"},
				{Name: "STATUS", Type: "string"},
				{Name: "RULES", Type: "string"},
				{Name: "AGE", Type: "string"},
				{Name: "LABELS", Type: "string"},
			}
		} else {
			columnDefinitions = []metav1.TableColumnDefinition{
				{Name: "NAME", Type: "string"},
				{Name: "TYPE", Type: "string"},
				{Name: "HOSTNAMES", Type: "string"},
				{Name: "PARENTS", Type: "string"},
				{Name: "STATUS", Type: "string"},
				{Name: "RULES", Type: "string"},
				{Name: "AGE", Type: "string"},
			}
		}

		table := &metav1.Table{
			ColumnDefinitions: columnDefinitions,
		}

		for _, r := range routes {
			row := metav1.TableRow{
				Cells: []interface{}{
					r.Name,
					r.Type,
					r.Hostnames,
					r.Parents,
					r.Status,
					fmt.Sprintf("%d", r.Rules),
					r.Age,
				},
			}
			if showLabels {
				row.Cells = append(row.Cells, labelsToString(r.Labels))
			}
			table.Rows = append(table.Rows, row)
		}

		return printer.PrintObj(table, os.Stdout)
	}
}

func listRoutes(ctx context.Context, c *rest.APIClient) error {
	routes, err := collectAllRoutes(ctx, c)
	if err != nil {
		return err
	}
	printer := getRoutesTablePrinter(showRoutesLabels)
	return printer(routes)
}

func getRoute(ctx context.Context, c *rest.APIClient, ref string) error {
	routeType, name := parseRouteRef(ref)

	var routes []routeInfo

	switch routeType {
	case routeTypeHTTP:
		r, err := c.GatewayV1().HTTPRoutes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		routes = append(routes, routeInfo{
			Name:      r.Name,
			Type:      "HTTPRoute",
			Hostnames: getHTTPHostnames(r.Spec.Hostnames),
			Parents:   getHTTPParents(r.Spec.ParentRefs),
			Status:    getHTTPRouteStatus(r.Status.Parents),
			Rules:     len(r.Spec.Rules),
			Age:       sinceString(r.CreationTimestamp.Time),
			Labels:    r.Labels,
		})
	case routeTypeTCP:
		r, err := c.GatewayV1alpha2().TCPRoutes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		routes = append(routes, routeInfo{
			Name:      r.Name,
			Type:      "TCPRoute",
			Hostnames: "-",
			Parents:   getTCPParents(r.Spec.ParentRefs),
			Status:    getTCPRouteStatus(r.Status.Parents),
			Rules:     len(r.Spec.Rules),
			Age:       sinceString(r.CreationTimestamp.Time),
			Labels:    r.Labels,
		})
	case routeTypeTLS:
		r, err := c.GatewayV1alpha2().TLSRoutes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		routes = append(routes, routeInfo{
			Name:      r.Name,
			Type:      "TLSRoute",
			Hostnames: getTLSHostnames(r.Spec.Hostnames),
			Parents:   getTLSParents(r.Spec.ParentRefs),
			Status:    getTLSRouteStatus(r.Status.Parents),
			Rules:     len(r.Spec.Rules),
			Age:       sinceString(r.CreationTimestamp.Time),
			Labels:    r.Labels,
		})
	default:
		return fmt.Errorf("unknown route type: %s (use http, tcp, or tls)", routeType)
	}

	printer := getRoutesTablePrinter(false)
	return printer(routes)
}

func deleteRoute(ctx context.Context, c *rest.APIClient, ref string) error {
	routeType, name := parseRouteRef(ref)

	switch routeType {
	case routeTypeHTTP:
		if err := c.GatewayV1().HTTPRoutes().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
			return err
		}
	case routeTypeTCP:
		if err := c.GatewayV1alpha2().TCPRoutes().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
			return err
		}
	case routeTypeTLS:
		if err := c.GatewayV1alpha2().TLSRoutes().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown route type: %s (use http, tcp, or tls)", routeType)
	}

	fmt.Printf("%sroute %q deleted\n", routeType, name)
	return nil
}

func createRoute(ctx context.Context, c *rest.APIClient, data []byte) error {
	obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to decode input: %w", err)
	}

	switch route := obj.(type) {
	case *gatewayv1.HTTPRoute:
		r, err := c.GatewayV1().HTTPRoutes().Create(ctx, route, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		fmt.Printf("httproute %q created\n", r.Name)
	case *gatewayv1alpha2.TCPRoute:
		r, err := c.GatewayV1alpha2().TCPRoutes().Create(ctx, route, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		fmt.Printf("tcproute %q created\n", r.Name)
	case *gatewayv1alpha2.TLSRoute:
		r, err := c.GatewayV1alpha2().TLSRoutes().Create(ctx, route, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		fmt.Printf("tlsroute %q created\n", r.Name)
	default:
		return fmt.Errorf("expected HTTPRoute, TCPRoute, or TLSRoute, got %T", obj)
	}

	return nil
}

func applyRoute(ctx context.Context, c *rest.APIClient, data []byte) error {
	obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to decode input: %w", err)
	}

	patchOpts := metav1.PatchOptions{
		FieldManager: routesFieldManager,
		Force:        &routesForceConflicts,
	}

	switch route := obj.(type) {
	case *gatewayv1.HTTPRoute:
		if route.Name == "" {
			return fmt.Errorf("route name is required")
		}
		patchData, err := json.Marshal(route)
		if err != nil {
			return fmt.Errorf("failed to marshal route: %w", err)
		}
		r, err := c.GatewayV1().HTTPRoutes().Patch(ctx, route.Name, types.ApplyPatchType, patchData, patchOpts)
		if err != nil {
			return err
		}
		fmt.Printf("httproute %q applied\n", r.Name)
	case *gatewayv1alpha2.TCPRoute:
		if route.Name == "" {
			return fmt.Errorf("route name is required")
		}
		patchData, err := json.Marshal(route)
		if err != nil {
			return fmt.Errorf("failed to marshal route: %w", err)
		}
		r, err := c.GatewayV1alpha2().TCPRoutes().Patch(ctx, route.Name, types.ApplyPatchType, patchData, patchOpts)
		if err != nil {
			return err
		}
		fmt.Printf("tcproute %q applied\n", r.Name)
	case *gatewayv1alpha2.TLSRoute:
		if route.Name == "" {
			return fmt.Errorf("route name is required")
		}
		patchData, err := json.Marshal(route)
		if err != nil {
			return fmt.Errorf("failed to marshal route: %w", err)
		}
		r, err := c.GatewayV1alpha2().TLSRoutes().Patch(ctx, route.Name, types.ApplyPatchType, patchData, patchOpts)
		if err != nil {
			return err
		}
		fmt.Printf("tlsroute %q applied\n", r.Name)
	default:
		return fmt.Errorf("expected HTTPRoute, TCPRoute, or TLSRoute, got %T", obj)
	}

	return nil
}

// routesCmd is the routes subcommand under gateway.
var routesCmd = &cobra.Command{
	Use:     "routes",
	Short:   "Manage gateway routes (HTTP, TCP, TLS)",
	Long:    `Manage routes attached to gateways. Supports HTTPRoute, TCPRoute, and TLSRoute resources.`,
	Aliases: []string{"route", "rt"},
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		return listRoutes(cmd.Context(), c)
	},
}

var listRoutesCmd = &cobra.Command{
	Use:   "list",
	Short: "List all routes",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		return listRoutes(cmd.Context(), c)
	},
}

var getRoutesCmd = &cobra.Command{
	Use:   "get [TYPE/]<name>",
	Short: "Get a route by name",
	Long: `Get a route by name. Optionally specify the type as a prefix.

Examples:
  apoxy gateway routes get my-route        # get HTTPRoute (default)
  apoxy gateway routes get http/my-route   # get HTTPRoute
  apoxy gateway routes get tcp/my-route    # get TCPRoute
  apoxy gateway routes get tls/my-route    # get TLSRoute`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		return getRoute(cmd.Context(), c, args[0])
	},
}

var createRoutesCmd = &cobra.Command{
	Use:   "create [-f filename]",
	Short: "Create a route from file",
	Long:  `Create a route from a YAML or JSON file. The route type is detected from the file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var data []byte
		var err error
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if routesFile != "" {
				return fmt.Errorf("cannot use --filename with stdin")
			}
			data, err = io.ReadAll(os.Stdin)
		} else if routesFile != "" {
			data, err = os.ReadFile(routesFile)
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

		return createRoute(cmd.Context(), c, data)
	},
}

var deleteRoutesCmd = &cobra.Command{
	Use:   "delete [TYPE/]<name>",
	Short: "Delete a route by name",
	Long: `Delete a route by name. Optionally specify the type as a prefix.

Examples:
  apoxy gateway routes delete my-route        # delete HTTPRoute (default)
  apoxy gateway routes delete http/my-route   # delete HTTPRoute
  apoxy gateway routes delete tcp/my-route    # delete TCPRoute
  apoxy gateway routes delete tls/my-route    # delete TLSRoute`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}

		for _, ref := range args {
			if err := deleteRoute(cmd.Context(), c, ref); err != nil {
				return err
			}
		}
		return nil
	},
}

var applyRoutesCmd = &cobra.Command{
	Use:   "apply [-f filename]",
	Short: "Apply a route configuration using server-side apply",
	Long: `Apply a route configuration using Kubernetes server-side apply.
The route type is detected from the file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var data []byte
		var err error
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if routesApplyFile != "" {
				return fmt.Errorf("cannot use --filename with stdin")
			}
			data, err = io.ReadAll(os.Stdin)
		} else if routesApplyFile != "" {
			data, err = os.ReadFile(routesApplyFile)
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

		return applyRoute(cmd.Context(), c, data)
	},
}

func init() {
	listRoutesCmd.Flags().BoolVar(&showRoutesLabels, "show-labels", false, "Print the route's labels")

	createRoutesCmd.Flags().StringVarP(&routesFile, "filename", "f", "", "File containing the route configuration")

	applyRoutesCmd.Flags().StringVarP(&routesApplyFile, "filename", "f", "", "File containing the route configuration")
	applyRoutesCmd.Flags().StringVar(&routesFieldManager, "field-manager", "apoxy-cli", "Name of the field manager for server-side apply")
	applyRoutesCmd.Flags().BoolVar(&routesForceConflicts, "force-conflicts", false, "Force apply even if there are field ownership conflicts")

	routesCmd.AddCommand(listRoutesCmd, getRoutesCmd, createRoutesCmd, deleteRoutesCmd, applyRoutesCmd)
}
