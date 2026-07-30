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

// serviceRevisionResource lists ServiceRevision (compute.apoxy.dev/v1alpha1)
// objects. Revisions are minted and deleted by the controller, never authored
// by users, so only the read-only get/list subcommands are exposed.
var serviceRevisionResource = &resource.ResourceCommand[*computev1alpha1.ServiceRevision, *computev1alpha1.ServiceRevisionList]{
	Use:      "servicerevisions",
	Aliases:  []string{"servicerevision"},
	Short:    "List ServiceRevision objects",
	Long:     `ServiceRevision (compute.apoxy.dev/v1alpha1) is an immutable, digest-pinned snapshot minted by the controller each time a Service's template changes.`,
	KindName: "servicerevision",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*computev1alpha1.ServiceRevision, *computev1alpha1.ServiceRevisionList] {
		return c.ComputeV1alpha1().ServiceRevisions()
	},
	ListLabelFlags: func(cmd *cobra.Command) func() string {
		var service string
		cmd.Flags().StringVar(&service, "service", "", "Filter to revisions owned by this Service.")
		return func() string {
			if service == "" {
				return ""
			}
			return serviceRevisionServiceLabel + "=" + service
		}
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
	// Still early: not yet ready to advertise. Reachable as `apoxy
	// servicerevisions`/`apoxy servicerevision` and as `apoxy service
	// versions`/`apoxy service revisions`, but hidden from help output.
	topLevel := readOnly(serviceRevisionResource.Build())
	topLevel.Hidden = true
	RootCmd.AddCommand(topLevel)

	nested := readOnly(serviceRevisionResource.Build())
	nested.Use = "versions"
	nested.Aliases = []string{"revisions"}
	nested.Hidden = true
	serviceCmd.AddCommand(nested)
}
