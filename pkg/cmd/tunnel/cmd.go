package tunnel

import (
	"github.com/spf13/cobra"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/rest"
)

var tunnelResource = &resource.ResourceCommand[*corev1alpha.TunnelNode, *corev1alpha.TunnelNodeList]{
	Use:      "tunnel",
	Aliases:  []string{"tunnels", "tn"},
	Short:    "Manage tunnels",
	Long:     "Manage WireGuard tunnels state and connect to the remote Apoxy Edge fabric.",
	KindName: "tunnelnode",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*corev1alpha.TunnelNode, *corev1alpha.TunnelNodeList] {
		return c.CoreV1alpha().TunnelNodes()
	},
	TablePrinter: &resource.TablePrinterConfig[*corev1alpha.TunnelNode, *corev1alpha.TunnelNodeList]{
		ObjToTable:  func(t *corev1alpha.TunnelNode) resource.TableConverter { return t },
		ListToTable: func(l *corev1alpha.TunnelNodeList) resource.TableConverter { return l },
	},
}

// Cmd returns the tunnel command with the run subcommand attached.
func Cmd() *cobra.Command {
	cmd := tunnelResource.Build()

	// Register run-specific flags.
	tunnelRunCmd.Flags().StringVarP(&tunnelNodePcapPath, "pcap", "p", "", "Path to the TunnelNode file to create.")
	tunnelRunCmd.Flags().StringVarP(&tunnelModeS, "mode", "m", "user", "Mode to run the TunnelNode in.")
	tunnelRunCmd.Flags().BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "Skip TLS certificate verification.")
	tunnelRunCmd.Flags().StringSliceVar(&preserveDefaultGw, "preserve-default-gw-dsts", []string{}, "Preserve default gateway.")
	tunnelRunCmd.Flags().StringVar(&socksListenAddr, "socks-addr", "localhost:1080", "Listen address for SOCKS proxy.")
	tunnelRunCmd.Flags().IntVar(&minConns, "min-conns", 1, "Minimum number of connections to maintain.")
	tunnelRunCmd.Flags().StringVar(&dnsListenAddr, "dns-addr", "127.0.0.1:8053", "Listen address for the DNS proxy. Note that you must configure backplane to use this address as well.")
	tunnelRunCmd.Flags().BoolVar(&autoCreate, "auto", false, "Automatically create TunnelNode if it doesn't exist.")
	tunnelRunCmd.Flags().StringVar(&healthAddr, "health-addr", ":8080", "Listen address for health endpoint (default: :8080).")
	tunnelRunCmd.Flags().StringVar(&metricsAddr, "metrics-addr", ":8081", "Listen address for metrics endpoint (default: :8081).")
	tunnelRunCmd.Flags().BoolVar(&noTUI, "no-tui", false, "Disable TUI interface.")
	tunnelRunCmd.Flags().StringVar(&endpointSelection, "endpoint-selection", "latency",
		"Endpoint selection strategy: 'latency' (default) or 'random'")

	cmd.AddCommand(tunnelRunCmd)
	return cmd
}
