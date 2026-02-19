package domain

import (
	"github.com/spf13/cobra"

	corev1alpha3 "github.com/apoxy-dev/apoxy/api/core/v1alpha3"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/rest"
)

var domainResource = &resource.ResourceCommand[*corev1alpha3.Domain, *corev1alpha3.DomainList]{
	Use:      "domain",
	Aliases:  []string{"d", "domains"},
	Short:    "Manage domain objects",
	Long:     `Domains configure DNS records and routing for your services.`,
	KindName: "domain",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*corev1alpha3.Domain, *corev1alpha3.DomainList] {
		return c.CoreV1alpha3().Domains()
	},
	TablePrinter: &resource.TablePrinterConfig[*corev1alpha3.Domain, *corev1alpha3.DomainList]{
		ObjToTable:  func(d *corev1alpha3.Domain) resource.TableConverter { return d },
		ListToTable: func(l *corev1alpha3.DomainList) resource.TableConverter { return l },
	},
	ListFlags: func(cmd *cobra.Command) func() string {
		var zone string
		cmd.Flags().StringVar(&zone, "zone", "", "Filter domains by zone name.")
		return func() string {
			if zone != "" {
				return "spec.zone=" + zone
			}
			return ""
		}
	},
}

var zoneResource = &resource.ResourceCommand[*corev1alpha3.DomainZone, *corev1alpha3.DomainZoneList]{
	Use:      "zone",
	Aliases:  []string{"zones", "dz"},
	Short:    "Manage domain zone objects",
	Long:     `Domain zones represent DNS zones that domains are managed under.`,
	KindName: "domainzone",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*corev1alpha3.DomainZone, *corev1alpha3.DomainZoneList] {
		return c.CoreV1alpha3().DomainZones()
	},
	TablePrinter: &resource.TablePrinterConfig[*corev1alpha3.DomainZone, *corev1alpha3.DomainZoneList]{
		ObjToTable:  func(dz *corev1alpha3.DomainZone) resource.TableConverter { return dz },
		ListToTable: func(l *corev1alpha3.DomainZoneList) resource.TableConverter { return l },
	},
}

// Cmd returns the domain command with the zone subcommand attached.
func Cmd() *cobra.Command {
	cmd := domainResource.Build()
	cmd.AddCommand(zoneResource.Build())
	return cmd
}
