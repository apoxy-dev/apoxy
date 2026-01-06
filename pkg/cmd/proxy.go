package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cli-runtime/pkg/printers"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	"github.com/apoxy-dev/apoxy/client/versioned/scheme"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/rest"
)

var (
	// showProxyLabels is a flag to show labels in the output.
	showProxyLabels bool
	// proxyFile is a flag that specifies the file to read the configuration from.
	proxyFile string
	// proxyApplyFile is a flag that specifies the file to read the configuration from for apply.
	proxyApplyFile string
	// proxyFieldManager is the field manager name for server-side apply.
	proxyFieldManager string
	// proxyForceConflicts forces apply even if there are conflicts.
	proxyForceConflicts bool
)

func labelsToString(labels map[string]string) string {
	var l []string
	for k, v := range labels {
		l = append(l, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(l, ",")
}

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

func getProxyTablePrinter(showLabels bool) printers.ResourcePrinter {
	printer := printers.NewTablePrinter(printers.PrintOptions{})

	// Define columns based on whether labels are shown
	var columnDefinitions []metav1.TableColumnDefinition
	if showLabels {
		columnDefinitions = []metav1.TableColumnDefinition{
			{Name: "NAME", Type: "string"},
			{Name: "PROVIDER", Type: "string"},
			{Name: "REPLICAS", Type: "string"},
			{Name: "AGE", Type: "string"},
			{Name: "LABELS", Type: "string"},
		}
	} else {
		columnDefinitions = []metav1.TableColumnDefinition{
			{Name: "NAME", Type: "string"},
			{Name: "PROVIDER", Type: "string"},
			{Name: "REPLICAS", Type: "string"},
			{Name: "AGE", Type: "string"},
		}
	}

	// Custom print function for Proxy
	proxyPrintFunc := func(obj runtime.Object, w io.Writer) error {
		proxy, ok := obj.(*corev1alpha2.Proxy)
		if !ok {
			return fmt.Errorf("expected *corev1alpha2.Proxy, got %T", obj)
		}

		table := &metav1.Table{
			ColumnDefinitions: columnDefinitions,
		}

		replicaCount := fmt.Sprintf("%d", len(proxy.Status.Replicas))
		row := metav1.TableRow{
			Cells: []interface{}{
				proxy.Name,
				proxy.Spec.Provider,
				replicaCount,
				sinceString(proxy.CreationTimestamp.Time),
			},
		}
		if showLabels {
			row.Cells = append(row.Cells, labelsToString(proxy.Labels))
		}
		table.Rows = append(table.Rows, row)

		return printer.PrintObj(table, w)
	}

	// Custom print function for ProxyList
	proxyListPrintFunc := func(obj runtime.Object, w io.Writer) error {
		list, ok := obj.(*corev1alpha2.ProxyList)
		if !ok {
			return fmt.Errorf("expected *corev1alpha2.ProxyList, got %T", obj)
		}

		table := &metav1.Table{
			ColumnDefinitions: columnDefinitions,
		}

		for _, proxy := range list.Items {
			replicaCount := fmt.Sprintf("%d", len(proxy.Status.Replicas))
			row := metav1.TableRow{
				Cells: []interface{}{
					proxy.Name,
					proxy.Spec.Provider,
					replicaCount,
					sinceString(proxy.CreationTimestamp.Time),
				},
			}
			if showLabels {
				row.Cells = append(row.Cells, labelsToString(proxy.Labels))
			}
			table.Rows = append(table.Rows, row)
		}

		return printer.PrintObj(table, w)
	}

	// Return a delegating printer that handles both types
	return printers.ResourcePrinterFunc(func(obj runtime.Object, w io.Writer) error {
		switch obj.(type) {
		case *corev1alpha2.Proxy:
			return proxyPrintFunc(obj, w)
		case *corev1alpha2.ProxyList:
			return proxyListPrintFunc(obj, w)
		default:
			return fmt.Errorf("unsupported type: %T", obj)
		}
	})
}

func getProxy(ctx context.Context, c *rest.APIClient, name string) error {
	r, err := c.CoreV1alpha2().Proxies().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	printer := getProxyTablePrinter(false)
	return printer.PrintObj(r, os.Stdout)
}

func listProxies(ctx context.Context, c *rest.APIClient, opts metav1.ListOptions) error {
	proxies, err := c.CoreV1alpha2().Proxies().List(ctx, opts)
	if err != nil {
		return err
	}
	printer := getProxyTablePrinter(showProxyLabels)
	return printer.PrintObj(proxies, os.Stdout)
}

// alphaProxyCmd represents the proxy command
var alphaProxyCmd = &cobra.Command{
	Use:     "proxy",
	Short:   "Manage proxy objects",
	Long:    `The controllers object in the Apoxy API.`,
	Aliases: []string{"p", "proxies"},
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		return listProxies(cmd.Context(), c, metav1.ListOptions{})
	},
}

// getProxyCmd gets a single proxy object.
var getProxyCmd = &cobra.Command{
	Use:       "get <name>",
	Short:     "Get proxy objects",
	ValidArgs: []string{"name"},
	Args:      cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		return getProxy(cmd.Context(), c, args[0])
	},
}

// listProxyCmd lists proxy objects.
var listProxyCmd = &cobra.Command{
	Use:   "list",
	Short: "List proxy objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		return listProxies(cmd.Context(), c, metav1.ListOptions{})
	},
}

// createProxyCmd creates a Proxy object.
var createProxyCmd = &cobra.Command{
	Use:   "create [-f filename]",
	Short: "Create proxy objects",
	Long:  `Create proxy objects by providing a configuration as a file or via stdin.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var data []byte
		var err error
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if proxyFile != "" {
				return fmt.Errorf("cannot use --filename with stdin")
			}
			data, err = io.ReadAll(os.Stdin)
		} else if proxyFile != "" {
			data, err = os.ReadFile(proxyFile)
		} else {
			return fmt.Errorf("please provide a configuration via --filename or stdin")
		}
		if err != nil {
			return err
		}

		cmd.SilenceUsage = true

		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}

		// Decode using the apoxy scheme's universal deserializer (handles both YAML and JSON).
		obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to decode input: %w", err)
		}

		proxy, ok := obj.(*corev1alpha2.Proxy)
		if !ok {
			return fmt.Errorf("expected Proxy, got %T", obj)
		}

		r, err := c.CoreV1alpha2().Proxies().Create(cmd.Context(), proxy, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		fmt.Printf("proxy %q created\n", r.Name)
		return nil
	},
}

// deleteProxyCmd deletes Proxy objects.
var deleteProxyCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete proxy objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}

		for _, name := range args {
			if err = c.CoreV1alpha2().Proxies().Delete(cmd.Context(), name, metav1.DeleteOptions{}); err != nil {
				return err
			}
			fmt.Printf("proxy %q deleted\n", name)
		}

		return nil
	},
}

// applyProxyCmd applies a Proxy object using server-side apply.
var applyProxyCmd = &cobra.Command{
	Use:   "apply [-f filename]",
	Short: "Apply proxy configuration using server-side apply",
	Long: `Apply proxy configuration using Kubernetes server-side apply.

This command uses server-side apply to create or update proxy objects.
Server-side apply tracks field ownership and allows multiple actors to
manage different fields of the same object without conflicts.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var data []byte
		var err error
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if proxyApplyFile != "" {
				return fmt.Errorf("cannot use --filename with stdin")
			}
			data, err = io.ReadAll(os.Stdin)
		} else if proxyApplyFile != "" {
			data, err = os.ReadFile(proxyApplyFile)
		} else {
			return fmt.Errorf("please provide a configuration via --filename or stdin")
		}
		if err != nil {
			return err
		}

		cmd.SilenceUsage = true

		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}

		// Decode using the apoxy scheme's universal deserializer (handles both YAML and JSON).
		obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to decode input: %w", err)
		}

		proxy, ok := obj.(*corev1alpha2.Proxy)
		if !ok {
			return fmt.Errorf("expected Proxy, got %T", obj)
		}

		if proxy.Name == "" {
			return fmt.Errorf("proxy name is required")
		}

		// Server-side apply uses Patch with ApplyPatchType.
		// The data must be a valid JSON representation of the object.
		patchData, err := json.Marshal(proxy)
		if err != nil {
			return fmt.Errorf("failed to marshal proxy: %w", err)
		}

		result, err := c.CoreV1alpha2().Proxies().Patch(
			cmd.Context(),
			proxy.Name,
			types.ApplyPatchType,
			patchData,
			metav1.PatchOptions{
				FieldManager: proxyFieldManager,
				Force:        &proxyForceConflicts,
			},
		)
		if err != nil {
			return err
		}

		fmt.Printf("proxy %q applied\n", result.Name)
		return nil
	},
}

func init() {
	createProxyCmd.PersistentFlags().
		StringVarP(&proxyFile, "filename", "f", "", "The file that contains the configuration to create.")
	listProxyCmd.PersistentFlags().
		BoolVar(&showProxyLabels, "show-labels", false, "Print the proxy's labels.")

	applyProxyCmd.PersistentFlags().
		StringVarP(&proxyApplyFile, "filename", "f", "", "The file that contains the configuration to apply.")
	applyProxyCmd.PersistentFlags().
		StringVar(&proxyFieldManager, "field-manager", "apoxy-cli", "Name of the field manager for server-side apply.")
	applyProxyCmd.PersistentFlags().
		BoolVar(&proxyForceConflicts, "force-conflicts", false, "Force apply even if there are field ownership conflicts.")

	alphaProxyCmd.AddCommand(getProxyCmd, listProxyCmd, createProxyCmd, deleteProxyCmd, applyProxyCmd)
	RootCmd.AddCommand(alphaProxyCmd)
}
