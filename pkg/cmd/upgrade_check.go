package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getsavvyinc/upgrade-cli/release"
	"github.com/hashicorp/go-version"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/build"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/cmd/utils"
)

const (
	upgradeCheckInterval = 24 * time.Hour
	upgradeCheckTimeout  = 1 * time.Second
)

// skipUpgradeCheckCommands are top-level subcommands where the upgrade prompt
// should not run — long-running, interactive, or noise-sensitive commands.
var skipUpgradeCheckCommands = map[string]bool{
	"run":        true,
	"dev":        true,
	"tunnel":     true,
	"upgrade":    true,
	"version":    true,
	"help":       true,
	"completion": true,
}

// maybePromptUpgrade checks once per upgradeCheckInterval whether a newer CLI
// release is available and, if so, prompts the user (y/N/never). On "y" the
// upgrade runs in-place and the process exits.
func maybePromptUpgrade(cmd *cobra.Command) {
	if !shouldRunUpgradeCheck(cmd) {
		return
	}

	cfg, err := config.Load()
	if err != nil {
		return
	}
	if cfg.UpgradeCheck == nil {
		cfg.UpgradeCheck = &configv1alpha1.UpgradeCheckState{}
	}
	state := cfg.UpgradeCheck

	now := time.Now()
	if state.LastChecked != nil && now.Sub(state.LastChecked.Time) < upgradeCheckInterval {
		return
	}
	state.LastChecked = &metav1.Time{Time: now}
	defer func() { _ = config.Store(cfg) }()

	ctx, cancel := context.WithTimeout(cmd.Context(), upgradeCheckTimeout)
	defer cancel()
	info, err := release.NewReleaseGetter(repo, owner).GetLatestRelease(ctx)
	if err != nil {
		return
	}
	latest := info.TagName
	state.LatestVersion = latest

	current, err := version.NewVersion(build.BuildVersion)
	if err != nil {
		return
	}
	latestVer, err := version.NewVersion(latest)
	if err != nil {
		return
	}
	if !latestVer.GreaterThan(current) {
		return
	}
	if state.DismissedVersion != "" {
		if dismissed, err := version.NewVersion(state.DismissedVersion); err == nil && !latestVer.GreaterThan(dismissed) {
			return
		}
	}

	switch promptUpgrade(build.BuildVersion, latest) {
	case promptYes:
		_ = config.Store(cfg) // persist LastChecked before exec-replace
		if _, err := runUpgradeInPlace(cmd.Context()); err != nil {
			fmt.Fprintf(os.Stderr, "Upgrade failed: %v\n", err)
			return
		}
		fmt.Fprintln(os.Stderr, "Upgrade complete. Re-run your command.")
		os.Exit(0)
	case promptNever:
		state.DismissedVersion = latest
	}
}

func shouldRunUpgradeCheck(cmd *cobra.Command) bool {
	if build.IsDev() {
		return false
	}
	if os.Getenv("APOXY_NO_UPGRADE_CHECK") != "" {
		return false
	}
	if skipByCommand(cmd) {
		return false
	}
	return utils.IsInteractive()
}

func skipByCommand(cmd *cobra.Command) bool {
	parts := strings.Fields(cmd.CommandPath())
	if len(parts) < 2 {
		return true
	}
	return skipUpgradeCheckCommands[parts[1]]
}

type promptResult int

const (
	promptNo promptResult = iota
	promptYes
	promptNever
)

func promptUpgrade(current, latest string) promptResult {
	fmt.Fprintf(os.Stderr, "\nA new Apoxy CLI version is available: %s → %s\n", current, latest)
	fmt.Fprint(os.Stderr, "Upgrade now? [y/N/never]: ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return promptNo
	}
	switch strings.ToLower(strings.TrimSpace(scanner.Text())) {
	case "y", "yes":
		return promptYes
	case "never":
		return promptNever
	default:
		return promptNo
	}
}
