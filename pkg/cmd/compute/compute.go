// Package compute provides the `apoxy compute` command tree for managing
// compute.apoxy.dev objects: services and their revisions.
package compute

import (
	"github.com/spf13/cobra"
)

// Cmd returns the `compute` parent command.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compute",
		Short: "Manage compute objects",
		Long:  `Manage compute.apoxy.dev objects: services and their revisions.`,
	}

	cmd.AddCommand(
		serviceCmd(),
		// apoxy compute servicerevisions: the standard, generic
		// object-access command, following the same resource.ResourceCommand
		// pattern as every other kind. `apoxy compute service versions` is
		// the friendlier front door, but the kind is listed here too.
		readOnly(serviceRevisionResource.Build()),
	)
	return cmd
}

// readOnly strips the mutating subcommands (create/delete/apply) from a built
// resource command, leaving get/list for inspection-only kinds.
func readOnly(cmd *cobra.Command) *cobra.Command {
	var remove []*cobra.Command
	for _, sub := range cmd.Commands() {
		switch sub.Name() {
		case "create", "delete", "apply":
			remove = append(remove, sub)
		}
	}
	cmd.RemoveCommand(remove...)
	return cmd
}
