package alpha

import (
	"github.com/spf13/cobra"
)

var alphaCmd = &cobra.Command{
	Use:   "alpha",
	Short: "Alpha features that are still under development",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// Cmd returns the alpha command.
func Cmd() *cobra.Command {
	return alphaCmd
}

func init() {
	alphaCmd.AddCommand(tunnelCmd)
	alphaCmd.AddCommand(domainRecordResource.Build())
}
