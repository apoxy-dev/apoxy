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

		upgraded, err := runUpgradeInPlace(cmd.Context())
		if err != nil {
			return err
		}
		if !upgraded {
			return nil
		}
		fmt.Println("Upgrade complete!")
		return nil
	},
}

// runUpgradeInPlace replaces the running binary with the latest release, if a
// newer one is available. Returns (upgraded, error). Dev-build guarding is the
// caller's responsibility.
func runUpgradeInPlace(ctx context.Context) (bool, error) {
	p, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("unable to find the current executable: %w", err)
	}

	u := upgrade.NewUpgrader(owner, repo, p)
	ok, err := u.IsNewVersionAvailable(ctx, build.BuildVersion)
	if err != nil {
		return false, fmt.Errorf("unable to check for new version: %w", err)
	}
	if !ok {
		return false, nil
	}

	fmt.Println("Upgrading Apoxy CLI to the latest version...")
	if err := u.Upgrade(ctx, build.BuildVersion); err != nil {
		return false, fmt.Errorf("unable to upgrade to the latest version: %w", err)
	}
	return true, nil
}

func init() {
	upgradeCmd.Flags().BoolVar(&upgradeForce, "force", false, "Force upgrade even for dev builds.")
	RootCmd.AddCommand(upgradeCmd)
}
