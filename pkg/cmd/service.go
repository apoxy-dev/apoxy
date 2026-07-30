package cmd

import (
	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/pretty"
	"github.com/apoxy-dev/apoxy/rest"
	"k8s.io/apimachinery/pkg/api/meta"
)

func buildServiceHeader(labels bool) pretty.Header {
	if labels {
		return pretty.Header{
			"NAME",
			"SOURCE",
			"LIVE REVISION",
			"READY",
			"AGE",
			"LABELS",
		}
	}
	return pretty.Header{
		"NAME",
		"SOURCE",
		"LIVE REVISION",
		"READY",
		"AGE",
	}
}

// serviceSourceString renders spec.source's populated variant (OCI or Git —
// exactly one is ever set) as a single column value.
func serviceSourceString(svc *computev1alpha1.Service) string {
	switch {
	case svc.Spec.Source.OCI != nil:
		return svc.Spec.Source.OCI.Repo
	case svc.Spec.Source.Git != nil:
		return "git:" + svc.Spec.Source.Git.URL
	default:
		return "-"
	}
}

// serviceReadyString reports the Ready condition's status, or "Unknown" when
// the controller hasn't reconciled the Service yet.
func serviceReadyString(svc *computev1alpha1.Service) string {
	cond := meta.FindStatusCondition(svc.Status.Conditions, computev1alpha1.ConditionReady)
	if cond == nil {
		return "Unknown"
	}
	return string(cond.Status)
}

func buildServiceRow(svc *computev1alpha1.Service, labels bool) []interface{} {
	liveRevision := svc.Status.LiveRevision
	if liveRevision == "" {
		liveRevision = "-"
	}

	if labels {
		return []interface{}{
			svc.Name,
			serviceSourceString(svc),
			liveRevision,
			serviceReadyString(svc),
			pretty.SinceString(svc.CreationTimestamp.Time),
			resource.LabelsToString(svc.Labels),
		}
	}
	return []interface{}{
		svc.Name,
		serviceSourceString(svc),
		liveRevision,
		serviceReadyString(svc),
		pretty.SinceString(svc.CreationTimestamp.Time),
	}
}

var serviceResource = &resource.ResourceCommand[*computev1alpha1.Service, *computev1alpha1.ServiceList]{
	Use:      "service",
	Aliases:  []string{"svc", "services"},
	Short:    "Manage compute Service objects",
	Long:     `Service (compute.apoxy.dev/v1alpha1) runs a JS/TS worker bundle on the Apoxy edge.`,
	KindName: "service",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*computev1alpha1.Service, *computev1alpha1.ServiceList] {
		return c.ComputeV1alpha1().Services()
	},
	CustomPrinter: &resource.CustomPrinterConfig[*computev1alpha1.Service, *computev1alpha1.ServiceList]{
		Header:   buildServiceHeader,
		BuildRow: buildServiceRow,
		GetItems: func(list *computev1alpha1.ServiceList) []*computev1alpha1.Service {
			items := make([]*computev1alpha1.Service, len(list.Items))
			for i := range list.Items {
				items[i] = &list.Items[i]
			}
			return items
		},
	},
}

// serviceCmd is the built `apoxy service` command tree; servicerevision.go
// hangs the hidden `versions`/`revisions` subcommand off it.
var serviceCmd = serviceResource.Build()

func init() {
	RootCmd.AddCommand(serviceCmd)
}
