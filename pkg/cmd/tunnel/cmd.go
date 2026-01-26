package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cli-runtime/pkg/printers"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	apoxyscheme "github.com/apoxy-dev/apoxy/client/versioned/scheme"
	"github.com/apoxy-dev/apoxy/config"
)

const (
	// resyncPeriod is the interval at which the informer will resync its cache.
	resyncPeriod = 30 * time.Second
)

// printTunnelNodeTable prints a TunnelNode or TunnelNodeList as a table.
func printTunnelNodeTable(ctx context.Context, obj interface{}, w io.Writer) error {
	printer := printers.NewTablePrinter(printers.PrintOptions{})

	var table *metav1.Table
	var err error

	switch v := obj.(type) {
	case *corev1alpha.TunnelNode:
		table, err = v.ConvertToTable(ctx, &metav1.TableOptions{})
	case *corev1alpha.TunnelNodeList:
		table, err = v.ConvertToTable(ctx, &metav1.TableOptions{})
	default:
		return fmt.Errorf("unsupported type: %T", obj)
	}

	if err != nil {
		return err
	}

	return printer.PrintObj(table, w)
}

// tunnelCmd implements the `tunnel` command that creates a secure tunnel
// to the remote Apoxy Edge fabric.
var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Manage tunnels",
	Long:  "Manage WireGuard tunnels state and connect to the remote Apoxy Edge fabric.",
}

var (
	tunnelNodeFile string
	// tunnelNodeApplyFile is the file that contains the configuration to apply.
	tunnelNodeApplyFile string
	// tunnelNodeFieldManager is the field manager name for server-side apply.
	tunnelNodeFieldManager string
	// tunnelNodeForceConflicts forces apply even if there are conflicts.
	tunnelNodeForceConflicts bool
	// noTUI disables the TUI interface.
	noTUI bool
	// endpointSelection is the endpoint selection strategy.
	endpointSelection string
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a TunnelNode",
	Long:  "Create a TunnelNode object from a file or stdin.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		var data []byte
		var err error
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if tunnelNodeFile != "" {
				return fmt.Errorf("cannot use --file with stdin")
			}
			data, err = io.ReadAll(os.Stdin)
		} else if tunnelNodeFile != "" {
			data, err = os.ReadFile(tunnelNodeFile)
		} else {
			return fmt.Errorf("either --file or stdin must be specified")
		}
		if err != nil {
			return err
		}

		cmd.SilenceUsage = true

		client, err := config.DefaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		// Decode using the apoxy scheme's universal deserializer (handles both YAML and JSON).
		obj, _, err := apoxyscheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to decode input: %w", err)
		}

		tunnelNode, ok := obj.(*corev1alpha.TunnelNode)
		if !ok {
			return fmt.Errorf("expected TunnelNode, got %T", obj)
		}

		r, err := client.CoreV1alpha().TunnelNodes().Create(ctx, tunnelNode, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create TunnelNode: %w", err)
		}

		fmt.Printf("tunnelnode %q created\n", r.Name)
		return nil
	},
}

var getCmd = &cobra.Command{
	Use:   "get [name]",
	Short: "Get a TunnelNode",
	Long:  "Get a TunnelNode object(s).",
	Args:  cobra.RangeArgs(0, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		cmd.SilenceUsage = true

		client, err := config.DefaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		if len(args) == 0 { // List all TunnelNodes
			tunnelNodes, err := client.CoreV1alpha().TunnelNodes().List(ctx, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("unable to list TunnelNodes: %w", err)
			}
			return printTunnelNodeTable(ctx, tunnelNodes, os.Stdout)
		}

		tunnelNode, err := client.CoreV1alpha().TunnelNodes().Get(ctx, args[0], metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("unable to get TunnelNode: %w", err)
		}
		return printTunnelNodeTable(ctx, tunnelNode, os.Stdout)
	},
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a TunnelNode",
	Long:  "Update a TunnelNode object from a file or stdin.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		var data []byte
		var err error
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if tunnelNodeFile != "" {
				return fmt.Errorf("cannot use --file with stdin")
			}
			data, err = io.ReadAll(os.Stdin)
		} else if tunnelNodeFile != "" {
			data, err = os.ReadFile(tunnelNodeFile)
		} else {
			return fmt.Errorf("either --file or stdin must be specified")
		}
		if err != nil {
			return err
		}

		cmd.SilenceUsage = true

		client, err := config.DefaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		// Decode using the apoxy scheme's universal deserializer (handles both YAML and JSON).
		obj, _, err := apoxyscheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to decode input: %w", err)
		}

		tunnelNode, ok := obj.(*corev1alpha.TunnelNode)
		if !ok {
			return fmt.Errorf("expected TunnelNode, got %T", obj)
		}

		r, err := client.CoreV1alpha().TunnelNodes().Update(ctx, tunnelNode, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("unable to update TunnelNode: %w", err)
		}

		fmt.Printf("tunnelnode %q updated\n", r.Name)
		return nil
	},
}

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a TunnelNode",
	Long:  "Delete a TunnelNode object.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		cmd.SilenceUsage = true

		client, err := config.DefaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		tunnelNodeName := args[0]

		err = client.CoreV1alpha().TunnelNodes().Delete(ctx, tunnelNodeName, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("unable to delete TunnelNode: %w", err)
		}

		fmt.Printf("tunnelnode %q deleted\n", tunnelNodeName)
		return nil
	},
}

// applyCmd applies a TunnelNode object using server-side apply.
var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply TunnelNode configuration using server-side apply",
	Long: `Apply TunnelNode configuration using Kubernetes server-side apply.

This command uses server-side apply to create or update TunnelNode objects.
Server-side apply tracks field ownership and allows multiple actors to
manage different fields of the same object without conflicts.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		var data []byte
		var err error
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if tunnelNodeApplyFile != "" {
				return fmt.Errorf("cannot use --file with stdin")
			}
			data, err = io.ReadAll(os.Stdin)
		} else if tunnelNodeApplyFile != "" {
			data, err = os.ReadFile(tunnelNodeApplyFile)
		} else {
			return fmt.Errorf("either --file or stdin must be specified")
		}
		if err != nil {
			return err
		}

		cmd.SilenceUsage = true

		client, err := config.DefaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		// Decode using the apoxy scheme's universal deserializer (handles both YAML and JSON).
		obj, _, err := apoxyscheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to decode input: %w", err)
		}

		tunnelNode, ok := obj.(*corev1alpha.TunnelNode)
		if !ok {
			return fmt.Errorf("expected TunnelNode, got %T", obj)
		}

		if tunnelNode.Name == "" {
			return fmt.Errorf("tunnelnode name is required")
		}

		// Server-side apply uses Patch with ApplyPatchType.
		// The data must be a valid JSON representation of the object.
		patchData, err := json.Marshal(tunnelNode)
		if err != nil {
			return fmt.Errorf("failed to marshal tunnelnode: %w", err)
		}

		result, err := client.CoreV1alpha().TunnelNodes().Patch(
			ctx,
			tunnelNode.Name,
			types.ApplyPatchType,
			patchData,
			metav1.PatchOptions{
				FieldManager: tunnelNodeFieldManager,
				Force:        &tunnelNodeForceConflicts,
			},
		)
		if err != nil {
			return fmt.Errorf("unable to apply TunnelNode: %w", err)
		}

		fmt.Printf("tunnelnode %q applied\n", result.Name)
		return nil
	},
}

func init() {
	createCmd.Flags().StringVarP(&tunnelNodeFile, "file", "f", "", "Path to the TunnelNode file to create.")

	updateCmd.Flags().StringVarP(&tunnelNodeFile, "file", "f", "", "Path to the TunnelNode file to update.")

	applyCmd.Flags().StringVarP(&tunnelNodeApplyFile, "file", "f", "", "Path to the TunnelNode file to apply.")
	applyCmd.Flags().StringVar(&tunnelNodeFieldManager, "field-manager", "apoxy-cli", "Name of the field manager for server-side apply.")
	applyCmd.Flags().BoolVar(&tunnelNodeForceConflicts, "force-conflicts", false, "Force apply even if there are field ownership conflicts.")

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

	tunnelCmd.AddCommand(createCmd)
	tunnelCmd.AddCommand(getCmd)
	tunnelCmd.AddCommand(updateCmd)
	tunnelCmd.AddCommand(deleteCmd)
	tunnelCmd.AddCommand(applyCmd)
	tunnelCmd.AddCommand(tunnelRunCmd)
}

func Cmd() *cobra.Command {
	return tunnelCmd
}
