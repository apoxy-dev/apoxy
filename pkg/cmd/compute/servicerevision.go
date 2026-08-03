package compute

import (
	"github.com/spf13/cobra"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/rest"
)

// serviceRevisionServiceLabel links a minted ServiceRevision back to its owning
// Service. Set by ServiceReconciler (pkg/workerd/manager/service_reconciler.go).
const serviceRevisionServiceLabel = "compute.apoxy.dev/service"

// serviceRevisionListLong documents the optional positional argument on the
// nested `apoxy compute service versions [name]` command and its `list`
// subcommand. The generic ResourceCommand help only prints "[name]" in the
// usage line, which reads ambiguously next to `get <name>` (a *revision*
// name) - so spell out that this one is the owning Service.
const serviceRevisionListLong = `ServiceRevision (compute.apoxy.dev/v1alpha1) is an immutable, digest-pinned snapshot minted by the controller each time a Service's template changes.

The optional [name] argument is the name of the owning Service, not of a
revision: it restricts the list to that Service's revisions by matching the
` + serviceRevisionServiceLabel + ` label. Omit it to list every revision in the
project. A Service name that does not exist is not an error - it simply matches
nothing and prints an empty table.

Use ` + "`apoxy compute service versions get <revision>`" + ` to inspect a single revision, whose
name is the owning Service's name plus a short hash of its template and bundle.`

// serviceRevisionExample is shared by the nested command and its list
// subcommand. --show-labels is only registered on list (see
// resource.ResourceCommand.Build), so the example that uses it says so.
const serviceRevisionExample = `  # List every revision in the project.
  apoxy compute service versions

  # List the revisions of the "checkout" Service.
  apoxy compute service versions checkout

  # Same, but also print each revision's labels (--show-labels is only
  # available on the list subcommand).
  apoxy compute service versions list checkout --show-labels

  # Inspect a single revision as YAML.
  apoxy compute service versions get checkout-3f9a1c7b2d -o yaml`

// serviceRevisionResource lists ServiceRevision (compute.apoxy.dev/v1alpha1)
// objects. Revisions are minted and deleted by the controller, never authored
// by users, so only the read-only get/list subcommands are exposed. This is
// the standard object-access config, used as-is for the hidden
// `apoxy compute servicerevisions` command; the nested
// `apoxy compute service versions` command adds ListArgLabelSelector on a
// copy of this config (see serviceVersionsCmd).
var serviceRevisionResource = &resource.ResourceCommand[*computev1alpha1.ServiceRevision, *computev1alpha1.ServiceRevisionList]{
	Use:      "servicerevisions",
	Aliases:  []string{"servicerevision"},
	Short:    "List ServiceRevision objects",
	Long:     `ServiceRevision (compute.apoxy.dev/v1alpha1) is an immutable, digest-pinned snapshot minted by the controller each time a Service's template changes.`,
	KindName: "servicerevision",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*computev1alpha1.ServiceRevision, *computev1alpha1.ServiceRevisionList] {
		return c.ComputeV1alpha1().ServiceRevisions()
	},
	TablePrinter: &resource.TablePrinterConfig[*computev1alpha1.ServiceRevision, *computev1alpha1.ServiceRevisionList]{
		ObjToTable:  func(r *computev1alpha1.ServiceRevision) resource.TableConverter { return r },
		ListToTable: func(l *computev1alpha1.ServiceRevisionList) resource.TableConverter { return l },
	},
}

// serviceVersionsCmd builds `apoxy compute service versions [name]` (alias:
// revisions): the default way to inspect a Service's revision history. An
// optional positional service name scopes the list, mirroring
// `apoxy compute service get <name>` rather than a --service flag.
func serviceVersionsCmd() *cobra.Command {
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
	return nested
}
