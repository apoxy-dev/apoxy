package vpc

import (
	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/rest"
)

var egressGatewayResource = &resource.ResourceCommand[*computev1alpha1.EgressGateway, *computev1alpha1.EgressGatewayList]{
	Use:      "egressgateway",
	Aliases:  []string{"egw", "eg", "egressgateways"},
	Short:    "Manage EgressGateway objects",
	Long:     `EgressGateway (compute.apoxy.dev/v1alpha1) declares egress interception listeners and a default policy for compute Services' outbound traffic.`,
	KindName: "egressgateway",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*computev1alpha1.EgressGateway, *computev1alpha1.EgressGatewayList] {
		return c.ComputeV1alpha1().EgressGateways()
	},
	TablePrinter: &resource.TablePrinterConfig[*computev1alpha1.EgressGateway, *computev1alpha1.EgressGatewayList]{
		ObjToTable:  func(g *computev1alpha1.EgressGateway) resource.TableConverter { return g },
		ListToTable: func(l *computev1alpha1.EgressGatewayList) resource.TableConverter { return l },
	},
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
	TablePrinter: &resource.TablePrinterConfig[*computev1alpha1.EgressRoute, *computev1alpha1.EgressRouteList]{
		ObjToTable:  func(r *computev1alpha1.EgressRoute) resource.TableConverter { return r },
		ListToTable: func(l *computev1alpha1.EgressRouteList) resource.TableConverter { return l },
	},
}
