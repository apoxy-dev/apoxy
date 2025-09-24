package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/apoxy-dev/apoxy/api/controllers/v1alpha1"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/cmd/utils"
	"github.com/apoxy-dev/apoxy/pretty"
	"github.com/apoxy-dev/apoxy/rest"
)

var showProxyLabels bool

func labelsToString(labels map[string]string) string {
	var l []string
	for k, v := range labels {
		l = append(l, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(l, ",")
}

func buildAlphaProxyRow(r *v1alpha1.Proxy, labels bool) []interface{} {
	if labels {
		return []interface{}{
			r.Name,
			r.Spec.Provider,
			r.Status.Phase,
			pretty.SinceString(r.CreationTimestamp.Time),
			labelsToString(r.Labels),
		}
	}
	return []interface{}{
		r.Name,
		r.Spec.Provider,
		r.Status.Phase,
		pretty.SinceString(r.CreationTimestamp.Time),
	}
}

func buildAlphaProxyHeader(labels bool) pretty.Header {
	if labels {
		return pretty.Header{
			"NAME",
			"PROVIDER",
			"STATUS",
			"AGE",
			"LABELS",
		}
	}
	return pretty.Header{
		"NAME",
		"PROVIDER",
		"STATUS",
		"AGE",
	}
}

func fmtAlphaProxy(r *v1alpha1.Proxy) {
	t := pretty.Table{
		Header: buildAlphaProxyHeader(false),
		Rows: pretty.Rows{
			buildAlphaProxyRow(r, false),
		},
	}
	t.Print()
}

func getAlphaProxy(ctx context.Context, c *rest.APIClient, name string) error {
	r, err := c.ControllersV1alpha1().Proxies().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	fmtAlphaProxy(r)
	return nil
}

func listAlphaProxies(ctx context.Context, c *rest.APIClient, opts metav1.ListOptions) error {
	proxies, err := c.ControllersV1alpha1().Proxies().List(ctx, opts)
	if err != nil {
		return err
	}
	t := pretty.Table{
		Header: buildAlphaProxyHeader(showProxyLabels),
	}
	for _, p := range proxies.Items {
		t.Rows = append(t.Rows, buildAlphaProxyRow(&p, showProxyLabels))
	}
	t.Print()
	return nil
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
		return listAlphaProxies(cmd.Context(), c, metav1.ListOptions{})
	},
}

// getAlphaProxyCmd represents the get proxy command
var getAlphaProxyCmd = &cobra.Command{
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
		return getAlphaProxy(cmd.Context(), c, args[0])
	},
}

// listAlphaProxyCmd represents the list proxy command
var listAlphaProxyCmd = &cobra.Command{
	Use:   "list",
	Short: "List proxy objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		return listAlphaProxies(cmd.Context(), c, metav1.ListOptions{})
	},
}

// proxyFile is the file that contains the configuration to create.
var proxyFile string

// createAlphaProxyCmd represents the create proxy command
var createAlphaProxyCmd = &cobra.Command{
	Use:   "create [-f filename]",
	Short: "Create proxy objects",
	Long:  `Create proxy objects by providing a configuration as a file or via stdin.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load the config to create from a file or stdin.
		var proxyConfig string
		var err error
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if proxyFile != "" {
				return fmt.Errorf("cannot use --filename with stdin")
			}
			proxyConfig, err = utils.ReadStdInAsString()
		} else if proxyFile != "" {
			proxyConfig, err = utils.ReadFileAsString(proxyFile)
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

		// Parse proxyConfig into a proxy object.
		proxy := &v1alpha1.Proxy{}
		proxyJSON, err := utils.YAMLToJSON(proxyConfig)
		if err != nil {
			// Try assuming that the config is a JSON string?
			slog.Debug("failed to parse proxy config as yaml - assuming input is JSON", "error", err)
			proxyJSON = proxyConfig
		}
		err = json.Unmarshal([]byte(proxyJSON), proxy)
		if err != nil {
			return err
		}

		r, err := c.ControllersV1alpha1().Proxies().Create(cmd.Context(), proxy, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		fmt.Printf("proxy %q created\n", r.Name)
		return nil
	},
}

// deleteAlphaProxyCmd represents the delete proxy command
var deleteAlphaProxyCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete proxy objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}

		for _, name := range args {
			if err = c.ControllersV1alpha1().Proxies().Delete(cmd.Context(), name, metav1.DeleteOptions{}); err != nil {
				return err
			}
			fmt.Printf("proxy %q deleted\n", name)
		}

		return nil
	},
}

func init() {
	createAlphaProxyCmd.PersistentFlags().
		StringVarP(&proxyFile, "filename", "f", "", "The file that contains the configuration to create.")
	listAlphaProxyCmd.PersistentFlags().
		BoolVar(&showProxyLabels, "show-labels", false, "Print the proxy's labels.")
	// TODO: add flags for proxy config as raw envoy config

	alphaProxyCmd.AddCommand(getAlphaProxyCmd, listAlphaProxyCmd, createAlphaProxyCmd, deleteAlphaProxyCmd)
	RootCmd.AddCommand(alphaProxyCmd)
}
