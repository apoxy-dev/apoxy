package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy/build"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "The version of this CLI",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(build.Version())
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
