package cmd

import (
	"strings"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/pretty"
	"github.com/apoxy-dev/apoxy/rest"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// =============================================================================
// EgressGateway
// =============================================================================

func buildEgressGatewayHeader(labels bool) pretty.Header {
	if labels {
		return pretty.Header{
			"NAME",
			"DEFAULT POLICY",
			"LISTENERS",
			"READY",
			"AGE",
			"LABELS",
		}
	}
	return pretty.Header{
		"NAME",
		"DEFAULT POLICY",
		"LISTENERS",
		"READY",
		"AGE",
	}
}

func egressGatewayReadyString(gw *computev1alpha1.EgressGateway) string {
	cond := meta.FindStatusCondition(gw.Status.Conditions, computev1alpha1.EgressGatewayConditionReady)
	if cond == nil {
		return "Unknown"
	}
	return string(cond.Status)
}

func buildEgressGatewayRow(gw *computev1alpha1.EgressGateway, labels bool) []interface{} {
	policy := string(gw.Spec.DefaultPolicy)
	if policy == "" {
		policy = "-"
	}

	if labels {
		return []interface{}{
			gw.Name,
			policy,
			len(gw.Spec.Listeners),
			egressGatewayReadyString(gw),
			pretty.SinceString(gw.CreationTimestamp.Time),
			resource.LabelsToString(gw.Labels),
		}
	}
	return []interface{}{
		gw.Name,
		policy,
		len(gw.Spec.Listeners),
		egressGatewayReadyString(gw),
		pretty.SinceString(gw.CreationTimestamp.Time),
	}
}

var egressGatewayResource = &resource.ResourceCommand[*computev1alpha1.EgressGateway, *computev1alpha1.EgressGatewayList]{
	Use:      "egressgateway",
	Aliases:  []string{"eg", "egressgateways"},
	Short:    "Manage EgressGateway objects",
	Long:     `EgressGateway (compute.apoxy.dev/v1alpha1) declares egress interception listeners and a default policy for compute Services' outbound traffic.`,
	KindName: "egressgateway",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*computev1alpha1.EgressGateway, *computev1alpha1.EgressGatewayList] {
		return c.ComputeV1alpha1().EgressGateways()
	},
	CustomPrinter: &resource.CustomPrinterConfig[*computev1alpha1.EgressGateway, *computev1alpha1.EgressGatewayList]{
		Header:   buildEgressGatewayHeader,
		BuildRow: buildEgressGatewayRow,
		GetItems: func(list *computev1alpha1.EgressGatewayList) []*computev1alpha1.EgressGateway {
			items := make([]*computev1alpha1.EgressGateway, len(list.Items))
			for i := range list.Items {
				items[i] = &list.Items[i]
			}
			return items
		},
	},
}

// =============================================================================
// EgressRoute
// =============================================================================

func buildEgressRouteHeader(labels bool) pretty.Header {
	if labels {
		return pretty.Header{
			"NAME",
			"PARENTS",
			"MATCHES",
			"ACCEPTED",
			"AGE",
			"LABELS",
		}
	}
	return pretty.Header{
		"NAME",
		"PARENTS",
		"MATCHES",
		"ACCEPTED",
		"AGE",
	}
}

// egressRouteParentsString renders spec.parentRefs as "name" or
// "name:sectionName" when a route attaches to a single listener.
func egressRouteParentsString(route *computev1alpha1.EgressRoute) string {
	if len(route.Spec.ParentRefs) == 0 {
		return "-"
	}
	parts := make([]string, len(route.Spec.ParentRefs))
	for i, p := range route.Spec.ParentRefs {
		name := string(p.Name)
		if p.SectionName != nil && *p.SectionName != "" {
			name += ":" + string(*p.SectionName)
		}
		parts[i] = name
	}
	return strings.Join(parts, ",")
}

func egressRouteMatchCount(route *computev1alpha1.EgressRoute) int {
	n := 0
	for _, rule := range route.Spec.Rules {
		n += len(rule.Matches)
	}
	return n
}

// egressRouteAcceptedString summarizes status.parents[].conditions[Accepted]
// across every parent: "Unknown" until the controller has reported on all of
// them, "True" only when every parent accepted the route, else "False".
func egressRouteAcceptedString(route *computev1alpha1.EgressRoute) string {
	if len(route.Status.Parents) == 0 {
		return "Unknown"
	}
	accepted := true
	for _, p := range route.Status.Parents {
		cond := meta.FindStatusCondition(p.Conditions, computev1alpha1.ConditionAccepted)
		if cond == nil {
			return "Unknown"
		}
		if cond.Status != metav1.ConditionTrue {
			accepted = false
		}
	}
	if accepted {
		return "True"
	}
	return "False"
}

func buildEgressRouteRow(route *computev1alpha1.EgressRoute, labels bool) []interface{} {
	if labels {
		return []interface{}{
			route.Name,
			egressRouteParentsString(route),
			egressRouteMatchCount(route),
			egressRouteAcceptedString(route),
			pretty.SinceString(route.CreationTimestamp.Time),
			resource.LabelsToString(route.Labels),
		}
	}
	return []interface{}{
		route.Name,
		egressRouteParentsString(route),
		egressRouteMatchCount(route),
		egressRouteAcceptedString(route),
		pretty.SinceString(route.CreationTimestamp.Time),
	}
}

var egressRouteResource = &resource.ResourceCommand[*computev1alpha1.EgressRoute, *computev1alpha1.EgressRouteList]{
	Use:      "egressroute",
	Aliases:  []string{"er", "egressroutes"},
	Short:    "Manage EgressRoute objects",
	Long:     `EgressRoute (compute.apoxy.dev/v1alpha1) allows destination-matched egress for the compute Services attached to its parent EgressGateway(s).`,
	KindName: "egressroute",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*computev1alpha1.EgressRoute, *computev1alpha1.EgressRouteList] {
		return c.ComputeV1alpha1().EgressRoutes()
	},
	CustomPrinter: &resource.CustomPrinterConfig[*computev1alpha1.EgressRoute, *computev1alpha1.EgressRouteList]{
		Header:   buildEgressRouteHeader,
		BuildRow: buildEgressRouteRow,
		GetItems: func(list *computev1alpha1.EgressRouteList) []*computev1alpha1.EgressRoute {
			items := make([]*computev1alpha1.EgressRoute, len(list.Items))
			for i := range list.Items {
				items[i] = &list.Items[i]
			}
			return items
		},
	},
}

func init() {
	RootCmd.AddCommand(egressGatewayResource.Build())
	RootCmd.AddCommand(egressRouteResource.Build())
}
