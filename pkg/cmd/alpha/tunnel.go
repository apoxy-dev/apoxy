package alpha

import "github.com/spf13/cobra"

var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Manage tunnels",
	Long:  "Manage icx tunnels and connect to the remote Apoxy Edge fabric.",
}
