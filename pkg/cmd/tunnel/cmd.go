package tunnel

import (
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy/config"
)

const (
	// resyncPeriod is the interval at which the informer will resync its cache.
	resyncPeriod = 30 * time.Second
)

// tunnelCmd implements the `tunnel` command that creates a secure tunnel
// to the remote Apoxy Edge fabric.
var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Manage tunnels",
	Long:  "Manage WireGuard tunnels state and connect to the remote Apoxy Edge fabric.",
}

var tunnelNodeFile string

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a TunnelNode",
	Long:  "Create a TunnelNode object from a file or stdin.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		cmd.SilenceUsage = true

		client, err := config.DefaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		var tunnelNode *corev1alpha.TunnelNode
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if tunnelNodeFile != "" {
				return fmt.Errorf("cannot use --file with stdin")
			}
			tunnelNode, err = loadTunnelNodeFromStdin()
		} else if tunnelNodeFile != "" {
			tunnelNode, err = loadTunnelNodeFromPath(tunnelNodeFile)
		} else {
			return fmt.Errorf("either --file or stdin must be specified")
		}
		if err != nil {
			return fmt.Errorf("failed to load TunnelNode: %w", err)
		}

		_, err = client.CoreV1alpha().TunnelNodes().Create(ctx, tunnelNode, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create TunnelNode: %w", err)
		}

		return nil
	},
}

var getCmd = &cobra.Command{
	Use:   "get",
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

		tunnelNodeName := ""
		if len(args) > 0 {
			tunnelNodeName = args[0]
		}
		if tunnelNodeName == "" { // List all TunnelNodes
			tunnelNodes, err := client.CoreV1alpha().TunnelNodes().List(ctx, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("unable to list TunnelNodes: %w", err)
			}

			for _, tunnelNode := range tunnelNodes.Items {
				fmt.Printf("TunnelNode: %v\n", tunnelNode)
			}
			return nil
		}

		tunnelNode, err := client.CoreV1alpha().TunnelNodes().Get(ctx, tunnelNodeName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("unable to get TunnelNode: %w", err)
		}

		fmt.Printf("TunnelNode: %v\n", tunnelNode)

		return nil
	},
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a TunnelNode",
	Long:  "Update a TunnelNode object from a file or stdin.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		cmd.SilenceUsage = true

		client, err := config.DefaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		var tunnelNode *corev1alpha.TunnelNode
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if tunnelNodeFile != "" {
				return fmt.Errorf("cannot use --file with stdin")
			}
			tunnelNode, err = loadTunnelNodeFromStdin()
		} else if tunnelNodeFile != "" {
			tunnelNode, err = loadTunnelNodeFromPath(tunnelNodeFile)
		} else {
			return fmt.Errorf("either --file or stdin must be specified")
		}

		_, err = client.CoreV1alpha().TunnelNodes().Update(ctx, tunnelNode, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("unable to update TunnelNode: %w", err)
		}

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

		return nil
	},
}

func loadTunnelNodeFromPath(path string) (*corev1alpha.TunnelNode, error) {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	obj, gvk, err := decodeFn(yamlFile, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TunnelNode: %w", err)
	}

	tunnelNode, ok := obj.(*corev1alpha.TunnelNode)
	if !ok {
		return nil, fmt.Errorf("not a TunnelNode object: %v", gvk)
	}

	return tunnelNode, nil
}

func loadTunnelNodeFromStdin() (*corev1alpha.TunnelNode, error) {
	decoder := yaml.NewYAMLOrJSONDecoder(os.Stdin, 4096)
	for {
		var obj interface{}
		err := decoder.Decode(&obj)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, nil
			}
			return nil, fmt.Errorf("failed to decode TunnelNode: %w", err)
		}

		tunnelNode, ok := obj.(*corev1alpha.TunnelNode)
		if !ok {
			return nil, fmt.Errorf("not a TunnelNode object: %v", reflect.TypeOf(obj))
		}

		return tunnelNode, nil
	}
}

func init() {
	createCmd.Flags().StringVarP(&tunnelNodeFile, "file", "f", "", "Path to the TunnelNode file to create.")
	updateCmd.Flags().StringVarP(&tunnelNodeFile, "file", "f", "", "Path to the TunnelNode file to update.")
	tunnelRunCmd.Flags().StringVarP(&tunnelNodePcapPath, "pcap", "p", "", "Path to the TunnelNode file to create.")
	tunnelRunCmd.Flags().StringVarP(&tunnelModeS, "mode", "m", "user", "Mode to run the TunnelNode in.")
	tunnelRunCmd.Flags().BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "Skip TLS certificate verification")

	tunnelCmd.AddCommand(createCmd)
	tunnelCmd.AddCommand(getCmd)
	tunnelCmd.AddCommand(updateCmd)
	tunnelCmd.AddCommand(deleteCmd)
	tunnelCmd.AddCommand(tunnelRunCmd)
}

func Cmd() *cobra.Command {
	return tunnelCmd
}
