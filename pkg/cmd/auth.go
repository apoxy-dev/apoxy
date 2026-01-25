package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy/config"
)

var (
	checkOnly    bool
	dashboardURL string
	apiBaseURL   string
)

// authCmd represents the auth command
var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate this CLI",
	Long: `If you are not authenticated, this will open a browser window to login via the Apoxy Dashboard.

If your CLI is already authenticated this will return information about your session.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.Load()
		if err != nil {
			fmt.Println(err)
			return
		}

		// Override dashboard URL if provided
		if dashboardURL != "" {
			cfg.DashboardURL = dashboardURL
		}

		var opts []config.AuthenticatorOption
		if apiBaseURL != "" {
			opts = append(opts, config.WithAPIBaseURL(apiBaseURL))
		}

		auth := config.NewAuthenticator(cfg, opts...)
		ok, err := auth.Check()

		if ok && err == nil {
			fmt.Println("Authenticated")
			os.Exit(0)
		} else if checkOnly { // If we're only checking, exit with an error.
			fmt.Println("Invalid authentication")
			os.Exit(1)
		}

		fmt.Println("Authentication required. Opening browser...")
		auth.Authenticate()
		if err := config.Store(cfg); err != nil {
			fmt.Println(err)
		}
	},
}

func init() {
	authCmd.PersistentFlags().BoolVar(&checkOnly, "check", false, "only check the authentication status")
	authCmd.PersistentFlags().StringVar(&dashboardURL, "dashboard-url", "", "dashboard URL for authentication (default: https://dashboard.apoxy.dev)")
	authCmd.PersistentFlags().StringVar(&apiBaseURL, "api-base-url", "", "API base URL (default: https://api.apoxy.dev)")
	RootCmd.AddCommand(authCmd)
}
