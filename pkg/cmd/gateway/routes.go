package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	sigyaml "sigs.k8s.io/yaml"

	gatewayv1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
	gatewayv1alpha2 "github.com/apoxy-dev/apoxy/api/gateway/v1alpha2"
	"github.com/apoxy-dev/apoxy/client/versioned/scheme"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/rest"
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

// collectAllRoutes fetches all routes from the API and returns both display info
// and raw runtime.Object items (for structured output).
func collectAllRoutes(ctx context.Context, c *rest.APIClient) ([]routeInfo, []runtime.Object, error) {
	var routes []routeInfo
	var objects []runtime.Object

	// HTTP Routes
	httpRoutes, err := c.GatewayV1().HTTPRoutes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list HTTP routes: %w", err)
	}
	for i, r := range httpRoutes.Items {
		routes = append(routes, routeInfo{
			Name:      r.Name,
			Type:      "HTTPRoute",
			Hostnames: getHTTPHostnames(r.Spec.Hostnames),
			Parents:   formatParentRefs(r.Spec.ParentRefs),
			Status:    getHTTPRouteStatus(r.Status.Parents),
			Rules:     len(r.Spec.Rules),
			Age:       sinceString(r.CreationTimestamp.Time),
			Labels:    r.Labels,
		})
		objects = append(objects, &httpRoutes.Items[i])
	}

	// TCP Routes
	tcpRoutes, err := c.GatewayV1alpha2().TCPRoutes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list TCP routes: %w", err)
	}
	for i, r := range tcpRoutes.Items {
		routes = append(routes, routeInfo{
			Name:      r.Name,
			Type:      "TCPRoute",
			Hostnames: "-",
			Parents:   formatParentRefs(r.Spec.ParentRefs),
			Status:    getTCPRouteStatus(r.Status.Parents),
			Rules:     len(r.Spec.Rules),
			Age:       sinceString(r.CreationTimestamp.Time),
			Labels:    r.Labels,
		})
		objects = append(objects, &tcpRoutes.Items[i])
	}

	// TLS Routes
	tlsRoutes, err := c.GatewayV1alpha2().TLSRoutes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list TLS routes: %w", err)
	}
	for i, r := range tlsRoutes.Items {
		routes = append(routes, routeInfo{
			Name:      r.Name,
			Type:      "TLSRoute",
			Hostnames: getTLSHostnames(r.Spec.Hostnames),
			Parents:   formatParentRefs(r.Spec.ParentRefs),
			Status:    getTLSRouteStatus(r.Status.Parents),
			Rules:     len(r.Spec.Rules),
			Age:       sinceString(r.CreationTimestamp.Time),
			Labels:    r.Labels,
		})
		objects = append(objects, &tlsRoutes.Items[i])
	}

	return routes, objects, nil
}

// printStructuredList serializes a slice of runtime.Object as JSON array or
// YAML documents separated by "---".
func printStructuredList(objects []runtime.Object, format string) error {
	// Populate Kind/APIVersion from the scheme.
	for _, obj := range objects {
		gvks, _, err := scheme.Scheme.ObjectKinds(obj)
		if err == nil && len(gvks) > 0 {
			obj.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	switch format {
	case "json":
		data, err := json.MarshalIndent(objects, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	case "yaml":
		for i, obj := range objects {
			if i > 0 {
				fmt.Println("---")
			}
			data, err := json.Marshal(obj)
			if err != nil {
				return fmt.Errorf("failed to marshal JSON: %w", err)
			}
			out, err := sigyaml.JSONToYAML(data)
			if err != nil {
				return fmt.Errorf("failed to convert to YAML: %w", err)
			}
			fmt.Print(string(out))
		}
		return nil
	default:
		return fmt.Errorf("unsupported output format: %q", format)
	}
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

// formatParentRef returns a "kind://name" string for a ParentReference,
// matching the scheme://name convention used in domain targets.
func formatParentRef(ref gwapiv1.ParentReference) string {
	kind := "gateway" // default per Gateway API spec
	if ref.Kind != nil {
		kind = strings.ToLower(string(*ref.Kind))
	}
	return fmt.Sprintf("%s://%s", kind, ref.Name)
}

func formatParentRefs(refs []gwapiv1.ParentReference) string {
	if len(refs) == 0 {
		return "None"
	}
	var parts []string
	for _, ref := range refs {
		parts = append(parts, formatParentRef(ref))
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


func printRoutesTable(routes []routeInfo, showLabels bool) error {
	var colDefs []metav1.TableColumnDefinition
	colDefs = []metav1.TableColumnDefinition{
		{Name: "NAME", Type: "string"},
		{Name: "TYPE", Type: "string"},
		{Name: "HOSTNAMES", Type: "string"},
		{Name: "PARENTS", Type: "string"},
		{Name: "STATUS", Type: "string"},
		{Name: "RULES", Type: "string"},
		{Name: "AGE", Type: "string"},
	}
	if showLabels {
		colDefs = append(colDefs, metav1.TableColumnDefinition{Name: "LABELS", Type: "string"})
	}

	table := &metav1.Table{ColumnDefinitions: colDefs}
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
			row.Cells = append(row.Cells, resource.LabelsToString(r.Labels))
		}
		table.Rows = append(table.Rows, row)
	}

	return resource.PrintTable(table, false)
}

func listRoutes(ctx context.Context, c *rest.APIClient, showLabels bool, outputFormat string) error {
	routes, objects, err := collectAllRoutes(ctx, c)
	if err != nil {
		return err
	}
	if outputFormat != "" {
		return printStructuredList(objects, outputFormat)
	}
	return printRoutesTable(routes, showLabels)
}

func getRoute(ctx context.Context, c *rest.APIClient, ref string, outputFormat string) error {
	routeType, name := parseRouteRef(ref)

	switch routeType {
	case routeTypeHTTP:
		r, err := c.GatewayV1().HTTPRoutes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if outputFormat != "" {
			return resource.PrintStructured(r, outputFormat)
		}
		return printRoutesTable([]routeInfo{{
			Name:      r.Name,
			Type:      "HTTPRoute",
			Hostnames: getHTTPHostnames(r.Spec.Hostnames),
			Parents:   formatParentRefs(r.Spec.ParentRefs),
			Status:    getHTTPRouteStatus(r.Status.Parents),
			Rules:     len(r.Spec.Rules),
			Age:       sinceString(r.CreationTimestamp.Time),
			Labels:    r.Labels,
		}}, false)
	case routeTypeTCP:
		r, err := c.GatewayV1alpha2().TCPRoutes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if outputFormat != "" {
			return resource.PrintStructured(r, outputFormat)
		}
		return printRoutesTable([]routeInfo{{
			Name:      r.Name,
			Type:      "TCPRoute",
			Hostnames: "-",
			Parents:   formatParentRefs(r.Spec.ParentRefs),
			Status:    getTCPRouteStatus(r.Status.Parents),
			Rules:     len(r.Spec.Rules),
			Age:       sinceString(r.CreationTimestamp.Time),
			Labels:    r.Labels,
		}}, false)
	case routeTypeTLS:
		r, err := c.GatewayV1alpha2().TLSRoutes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if outputFormat != "" {
			return resource.PrintStructured(r, outputFormat)
		}
		return printRoutesTable([]routeInfo{{
			Name:      r.Name,
			Type:      "TLSRoute",
			Hostnames: getTLSHostnames(r.Spec.Hostnames),
			Parents:   formatParentRefs(r.Spec.ParentRefs),
			Status:    getTLSRouteStatus(r.Status.Parents),
			Rules:     len(r.Spec.Rules),
			Age:       sinceString(r.CreationTimestamp.Time),
			Labels:    r.Labels,
		}}, false)
	default:
		return fmt.Errorf("unknown route type: %s (use http, tcp, or tls)", routeType)
	}
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

func applyRoute(ctx context.Context, c *rest.APIClient, data []byte, fieldManager string, forceConflicts bool) error {
	obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to decode input: %w", err)
	}

	patchOpts := metav1.PatchOptions{
		FieldManager: fieldManager,
		Force:        &forceConflicts,
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

// buildRoutesCmd constructs the routes subcommand with all flags scoped locally.
func buildRoutesCmd() *cobra.Command {
	var (
		showLabels     bool
		outputFormat   string
		createFile     string
		applyFile      string
		fieldManager   string
		forceConflicts bool
	)

	rootCmd := &cobra.Command{
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
			return listRoutes(cmd.Context(), c, showLabels, outputFormat)
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all routes",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			c, err := config.DefaultAPIClient()
			if err != nil {
				return err
			}
			return listRoutes(cmd.Context(), c, showLabels, outputFormat)
		},
	}

	getCmd := &cobra.Command{
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
			return getRoute(cmd.Context(), c, args[0], outputFormat)
		},
	}

	createCmd := &cobra.Command{
		Use:   "create [-f filename]",
		Short: "Create a route from file",
		Long:  `Create a route from a YAML or JSON file. The route type is detected from the file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := resource.ReadInputData(createFile)
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

	deleteCmd := &cobra.Command{
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

	applyCmd := &cobra.Command{
		Use:   "apply [-f filename]",
		Short: "Apply a route configuration using server-side apply",
		Long: `Apply a route configuration using Kubernetes server-side apply.
The route type is detected from the file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := resource.ReadInputData(applyFile)
			if err != nil {
				return err
			}

			cmd.SilenceUsage = true

			c, err := config.DefaultAPIClient()
			if err != nil {
				return err
			}

			return applyRoute(cmd.Context(), c, data, fieldManager, forceConflicts)
		},
	}

	// Register flags.
	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", "", `Output format: "json" or "yaml". Default is table.`)
	rootCmd.Flags().BoolVar(&showLabels, "show-labels", false, "Print the route's labels.")
	getCmd.Flags().StringVarP(&outputFormat, "output", "o", "", `Output format: "json" or "yaml". Default is table.`)
	listCmd.Flags().StringVarP(&outputFormat, "output", "o", "", `Output format: "json" or "yaml". Default is table.`)
	listCmd.Flags().BoolVar(&showLabels, "show-labels", false, "Print the route's labels.")
	createCmd.Flags().StringVarP(&createFile, "filename", "f", "", "File containing the route configuration.")
	applyCmd.Flags().StringVarP(&applyFile, "filename", "f", "", "File containing the route configuration.")
	applyCmd.Flags().StringVar(&fieldManager, "field-manager", "apoxy-cli", "Name of the field manager for server-side apply.")
	applyCmd.Flags().BoolVar(&forceConflicts, "force-conflicts", false, "Force apply even if there are field ownership conflicts.")

	rootCmd.AddCommand(listCmd, getCmd, createCmd, deleteCmd, applyCmd)
	return rootCmd
}
