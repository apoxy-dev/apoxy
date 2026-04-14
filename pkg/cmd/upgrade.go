package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/getsavvyinc/upgrade-cli"
	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy/build"
)

const (
	owner = "apoxy-dev"
	repo  = "apoxy-cli"
)

var upgradeForce bool

// upgradeCmd upgrade the CLI to the latest version.
var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade Apoxy CLI to the latest version",
	Long:  "Upgrade Apoxy CLI to the latest version.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		if build.IsDev() && !upgradeForce {
			fmt.Printf("Skipping upgrade for dev build %s. Use --force to override.\n", build.Version())
			return nil
		}

		p, err := os.Executable()
		if err != nil {
			return fmt.Errorf("unable to find the current executable: %w", err)
		}
		v := build.BuildVersion

		u := upgrade.NewUpgrader(owner, repo, p)
		if ok, err := u.IsNewVersionAvailable(context.Background(), v); err != nil {
			return fmt.Errorf("unable to check for new version: %w", err)
		} else if !ok {
			return nil
		}

		fmt.Println("Upgrading Apoxy CLI to the latest version...")
		if err := u.Upgrade(cmd.Context(), v); err != nil {
			return fmt.Errorf("unable to upgrade to the latest version: %w", err)
		} else {
			fmt.Println("Upgrade complete!")
		}

		return nil
	},
}

func init() {
	upgradeCmd.Flags().BoolVar(&upgradeForce, "force", false, "Force upgrade even for dev builds.")
	RootCmd.AddCommand(upgradeCmd)
}
