package cmd

import (
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/meta"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/pretty"
	"github.com/apoxy-dev/apoxy/rest"
)

func buildServiceRevisionHeader(labels bool) pretty.Header {
	if labels {
		return pretty.Header{
			"NAME",
			"SERVICE",
			"DIGEST",
			"READY",
			"AGE",
			"LABELS",
		}
	}
	return pretty.Header{
		"NAME",
		"SERVICE",
		"DIGEST",
		"READY",
		"AGE",
	}
}

// serviceRevisionOwnerString returns the owning Service's name. ServiceRevisionSpec
// carries no back-reference, so the owner is read from metadata.ownerReferences.
func serviceRevisionOwnerString(rev *computev1alpha1.ServiceRevision) string {
	for _, ref := range rev.OwnerReferences {
		if ref.Kind == "Service" {
			return ref.Name
		}
	}
	return "-"
}

// serviceRevisionDigestString shortens a resolved "sha256:..." digest to a
// docker-style 12-char prefix, falling back to the tag when unresolved.
func serviceRevisionDigestString(rev *computev1alpha1.ServiceRevision) string {
	digest := rev.Spec.Bundle.Digest
	if digest == "" {
		if rev.Spec.Bundle.Tag != "" {
			return rev.Spec.Bundle.Tag
		}
		return "-"
	}
	if i := strings.Index(digest, ":"); i >= 0 && len(digest) >= i+13 {
		return digest[:i+13]
	}
	return digest
}

func serviceRevisionReadyString(rev *computev1alpha1.ServiceRevision) string {
	cond := meta.FindStatusCondition(rev.Status.Conditions, computev1alpha1.ConditionReady)
	if cond == nil {
		return "Unknown"
	}
	return string(cond.Status)
}

func buildServiceRevisionRow(rev *computev1alpha1.ServiceRevision, labels bool) []interface{} {
	if labels {
		return []interface{}{
			rev.Name,
			serviceRevisionOwnerString(rev),
			serviceRevisionDigestString(rev),
			serviceRevisionReadyString(rev),
			pretty.SinceString(rev.CreationTimestamp.Time),
			resource.LabelsToString(rev.Labels),
		}
	}
	return []interface{}{
		rev.Name,
		serviceRevisionOwnerString(rev),
		serviceRevisionDigestString(rev),
		serviceRevisionReadyString(rev),
		pretty.SinceString(rev.CreationTimestamp.Time),
	}
}

// serviceRevisionServiceLabel links a minted ServiceRevision back to its owning
// Service. Set by ServiceReconciler (pkg/workerd/manager/service_reconciler.go).
const serviceRevisionServiceLabel = "compute.apoxy.dev/service"

// serviceRevisionListLong documents the optional positional argument on the
// nested `apoxy service versions [name]` command and its `list` subcommand.
// The generic ResourceCommand help only prints "[name]" in the usage line,
// which reads ambiguously next to `get <name>` (a *revision* name) - so spell
// out that this one is the owning Service.
const serviceRevisionListLong = `ServiceRevision (compute.apoxy.dev/v1alpha1) is an immutable, digest-pinned snapshot minted by the controller each time a Service's template changes.

The optional [name] argument is the name of the owning Service, not of a
revision: it restricts the list to that Service's revisions by matching the
` + serviceRevisionServiceLabel + ` label. Omit it to list every revision in the
project. A Service name that does not exist is not an error - it simply matches
nothing and prints an empty table.

Use ` + "`apoxy service versions get <revision>`" + ` to inspect a single revision, whose
name is the owning Service's name plus a short hash of its template and bundle.`

// serviceRevisionExample is shared by the nested command and its list
// subcommand. --show-labels is only registered on list (see
// resource.ResourceCommand.Build), so the example that uses it says so.
const serviceRevisionExample = `  # List every revision in the project.
  apoxy service versions

  # List the revisions of the "checkout" Service.
  apoxy service versions checkout

  # Same, but also print each revision's labels (--show-labels is only
  # available on the list subcommand).
  apoxy service versions list checkout --show-labels

  # Inspect a single revision as YAML.
  apoxy service versions get checkout-3f9a1c7b2d -o yaml`

// serviceRevisionResource lists ServiceRevision (compute.apoxy.dev/v1alpha1)
// objects. Revisions are minted and deleted by the controller, never authored
// by users, so only the read-only get/list subcommands are exposed. This is
// the standard object-access config, used as-is for the hidden top-level
// `apoxy servicerevisions` command; the nested `apoxy service versions`
// command (see init) adds ListArgLabelSelector on a copy of this config.
var serviceRevisionResource = &resource.ResourceCommand[*computev1alpha1.ServiceRevision, *computev1alpha1.ServiceRevisionList]{
	Use:      "servicerevisions",
	Aliases:  []string{"servicerevision"},
	Short:    "List ServiceRevision objects",
	Long:     `ServiceRevision (compute.apoxy.dev/v1alpha1) is an immutable, digest-pinned snapshot minted by the controller each time a Service's template changes.`,
	KindName: "servicerevision",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*computev1alpha1.ServiceRevision, *computev1alpha1.ServiceRevisionList] {
		return c.ComputeV1alpha1().ServiceRevisions()
	},
	CustomPrinter: &resource.CustomPrinterConfig[*computev1alpha1.ServiceRevision, *computev1alpha1.ServiceRevisionList]{
		Header:   buildServiceRevisionHeader,
		BuildRow: buildServiceRevisionRow,
		GetItems: func(list *computev1alpha1.ServiceRevisionList) []*computev1alpha1.ServiceRevision {
			items := make([]*computev1alpha1.ServiceRevision, len(list.Items))
			for i := range list.Items {
				items[i] = &list.Items[i]
			}
			return items
		},
	},
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

func init() {
	// apoxy servicerevisions / apoxy servicerevision: the standard, generic
	// object-access commands, following the same resource.ResourceCommand
	// pattern as every other kind (apoxy service, apoxy build, ...). Still
	// early: not yet ready to advertise ServiceRevision as a first-class
	// object on its own, so this stays hidden from help output.
	topLevel := readOnly(serviceRevisionResource.Build())
	topLevel.Hidden = true
	RootCmd.AddCommand(topLevel)

	// apoxy service versions [name] (alias: revisions): the default way to
	// inspect a Service's revision history. An optional positional service
	// name scopes the list, mirroring `apoxy service get <name>` rather
	// than a --service flag. Visible.
	nestedResource := *serviceRevisionResource
	nestedResource.ListArgLabelSelector = func(name string) string {
		return serviceRevisionServiceLabel + "=" + name
	}
	nested := readOnly(nestedResource.Build())
	nested.Use = "versions [name]"
	nested.Aliases = []string{"revisions"}
	nested.Long = serviceRevisionListLong
	nested.Example = serviceRevisionExample
	// Build() gives list only the generic Short and no Long at all, so the
	// argument explanation has to be repeated here rather than inherited.
	if listCmd, _, err := nested.Find([]string{"list"}); err == nil {
		listCmd.Use = "list [name]"
		listCmd.Short = "List a Service's revisions"
		listCmd.Long = serviceRevisionListLong
		listCmd.Example = serviceRevisionExample
	}
	serviceCmd.AddCommand(nested)
}
