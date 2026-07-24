// Package vpc provides the `apoxy vpc` command tree for managing
// vpc.apoxy.dev objects: networks, services, relays, and tunnels.
package vpc

import (
	"github.com/spf13/cobra"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/rest"
)

var vpcNetworkResource = &resource.ResourceCommand[*vpcv1alpha1.VPCNetwork, *vpcv1alpha1.VPCNetworkList]{
	Use:      "network",
	Aliases:  []string{"net", "networks", "vpcnetwork", "vpcnetworks"},
	Short:    "Manage VPC networks",
	Long:     `VPCNetwork is the domain object for a virtual private network on the Apoxy Edge fabric.`,
	KindName: "vpcnetwork",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*vpcv1alpha1.VPCNetwork, *vpcv1alpha1.VPCNetworkList] {
		return c.VpcV1alpha1().VPCNetworks()
	},
	TablePrinter: &resource.TablePrinterConfig[*vpcv1alpha1.VPCNetwork, *vpcv1alpha1.VPCNetworkList]{
		ObjToTable:  func(n *vpcv1alpha1.VPCNetwork) resource.TableConverter { return n },
		ListToTable: func(l *vpcv1alpha1.VPCNetworkList) resource.TableConverter { return l },
	},
}

var vpcServiceResource = &resource.ResourceCommand[*vpcv1alpha1.VPCService, *vpcv1alpha1.VPCServiceList]{
	Use:      "service",
	Aliases:  []string{"svc", "services", "vpcservice", "vpcservices"},
	Short:    "Manage VPC services",
	Long:     `VPCService selects tunnels within a VPC network and exposes their endpoints.`,
	KindName: "vpcservice",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*vpcv1alpha1.VPCService, *vpcv1alpha1.VPCServiceList] {
		return c.VpcV1alpha1().VPCServices()
	},
	TablePrinter: &resource.TablePrinterConfig[*vpcv1alpha1.VPCService, *vpcv1alpha1.VPCServiceList]{
		ObjToTable:  func(s *vpcv1alpha1.VPCService) resource.TableConverter { return s },
		ListToTable: func(l *vpcv1alpha1.VPCServiceList) resource.TableConverter { return l },
	},
}

var vpcRelayResource = &resource.ResourceCommand[*vpcv1alpha1.Relay, *vpcv1alpha1.RelayList]{
	Use:      "relay",
	Aliases:  []string{"relays"},
	Short:    "Inspect relays",
	Long:     `Relay objects are registered by tunnel relays and are read-only from the CLI.`,
	KindName: "relay",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*vpcv1alpha1.Relay, *vpcv1alpha1.RelayList] {
		return c.VpcV1alpha1().Relays()
	},
	TablePrinter: &resource.TablePrinterConfig[*vpcv1alpha1.Relay, *vpcv1alpha1.RelayList]{
		ObjToTable:  func(r *vpcv1alpha1.Relay) resource.TableConverter { return r },
		ListToTable: func(l *vpcv1alpha1.RelayList) resource.TableConverter { return l },
	},
}

var vpcTunnelResource = &resource.ResourceCommand[*vpcv1alpha1.Tunnel, *vpcv1alpha1.TunnelList]{
	Use:      "tunnel",
	Aliases:  []string{"tunnels"},
	Short:    "Inspect tunnels",
	Long:     `Tunnel objects represent live agent connections and are read-only from the CLI.`,
	KindName: "tunnel",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*vpcv1alpha1.Tunnel, *vpcv1alpha1.TunnelList] {
		return c.VpcV1alpha1().Tunnels()
	},
	TablePrinter: &resource.TablePrinterConfig[*vpcv1alpha1.Tunnel, *vpcv1alpha1.TunnelList]{
		ObjToTable:  func(t *vpcv1alpha1.Tunnel) resource.TableConverter { return t },
		ListToTable: func(l *vpcv1alpha1.TunnelList) resource.TableConverter { return l },
	},
}

// Cmd returns the `vpc` parent command.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "vpc",
		Short:   "Manage VPC networking objects",
		Long:    `Manage vpc.apoxy.dev objects: networks, services, relays, and tunnels.`,
		Aliases: []string{"vpcs"},
	}
	cmd.AddCommand(
		vpcNetworkResource.Build(),
		vpcServiceResource.Build(),
		readOnly(vpcRelayResource.Build()),
		readOnly(vpcTunnelResource.Build()),
	)
	return cmd
}

// readOnly strips the mutating subcommands (create/delete/apply) from a built
// resource command, leaving get/list for inspection-only kinds. Relays and
// Tunnels are owned by relays and the connect path, so the CLI never writes them.
func readOnly(cmd *cobra.Command) *cobra.Command {
	var remove []*cobra.Command
	for _, sub := range cmd.Commands() {
		switch sub.Name() {
		case "create", "delete", "apply":
			remove = append(remove, sub)
		}
	}
	cmd.RemoveCommand(remove...)
	return cmd
}
