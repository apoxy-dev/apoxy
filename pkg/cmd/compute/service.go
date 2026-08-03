package compute

import (
	"github.com/spf13/cobra"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/rest"
)

var serviceResource = &resource.ResourceCommand[*computev1alpha1.Service, *computev1alpha1.ServiceList]{
	Use:      "service",
	Aliases:  []string{"svc", "services"},
	Short:    "Manage compute Service objects",
	Long:     `Service (compute.apoxy.dev/v1alpha1) runs a JS/TS worker bundle on the Apoxy edge.`,
	KindName: "service",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*computev1alpha1.Service, *computev1alpha1.ServiceList] {
		return c.ComputeV1alpha1().Services()
	},
	TablePrinter: &resource.TablePrinterConfig[*computev1alpha1.Service, *computev1alpha1.ServiceList]{
		ObjToTable:  func(s *computev1alpha1.Service) resource.TableConverter { return s },
		ListToTable: func(l *computev1alpha1.ServiceList) resource.TableConverter { return l },
	},
}

// serviceCmd builds the `apoxy compute service` command tree, including the
// nested `versions` subcommand (see servicerevision.go).
func serviceCmd() *cobra.Command {
	cmd := serviceResource.Build()
	cmd.AddCommand(serviceVersionsCmd())
	return cmd
}
