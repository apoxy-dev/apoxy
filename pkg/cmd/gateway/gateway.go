package gateway

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	gatewayv1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
	gatewayv1alpha2 "github.com/apoxy-dev/apoxy/api/gateway/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/rest"
)

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

var gatewayResource = &resource.ResourceCommand[*gatewayv1.Gateway, *gatewayv1.GatewayList]{
	Use:      "gateway",
	Aliases:  []string{"gw", "gateways"},
	Short:    "Manage gateway objects",
	Long:     `The gateway object in the Apoxy API.`,
	KindName: "gateway",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*gatewayv1.Gateway, *gatewayv1.GatewayList] {
		return c.GatewayV1().Gateways()
	},
	TablePrinter: &resource.TablePrinterConfig[*gatewayv1.Gateway, *gatewayv1.GatewayList]{
		ObjToTable:  func(g *gatewayv1.Gateway) resource.TableConverter { return g },
		ListToTable: func(l *gatewayv1.GatewayList) resource.TableConverter { return l },
	},
	PostGet: func(ctx context.Context, c *rest.APIClient, name string, _ *gatewayv1.Gateway) error {
		httpRoutes, tcpRoutes, tlsRoutes, err := getAttachedRoutes(ctx, c, name)
		if err != nil {
			return err
		}
		printAttachedRoutes(httpRoutes, tcpRoutes, tlsRoutes)
		return nil
	},
}

// Cmd returns the gateway command with the routes subcommand attached.
func Cmd() *cobra.Command {
	cmd := gatewayResource.Build()
	cmd.AddCommand(buildRoutesCmd())
	return cmd
}
