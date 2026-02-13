package cmd

import (
	"github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/cmd/resource"
	"github.com/apoxy-dev/apoxy/pretty"
	"github.com/apoxy-dev/apoxy/rest"
)

func buildAlphaEdgeFunctionHeader(labels bool) pretty.Header {
	if labels {
		return pretty.Header{
			"NAME",
			"MODE",
			"SOURCE TYPE",
			"LIVE REVISION",
			"AGE",
			"LABELS",
		}
	}
	return pretty.Header{
		"NAME",
		"MODE",
		"SOURCE TYPE",
		"LIVE REVISION",
		"AGE",
	}
}

func buildAlphaEdgeFunctionRow(r *v1alpha2.EdgeFunction, labels bool) []interface{} {
	mode := r.Spec.Template.Mode
	revision := r.Status.LiveRevision
	if revision == "" {
		revision = "-"
	}

	var sourceType string
	if r.Spec.Template.Code.JsSource != nil {
		sourceType = "JavaScript"
	} else if r.Spec.Template.Code.WasmSource != nil {
		sourceType = "WebAssembly"
	} else if r.Spec.Template.Code.GoPluginSource != nil {
		sourceType = "Go Plugin"
	} else {
		sourceType = "Unknown"
	}

	if labels {
		return []interface{}{
			r.Name,
			string(mode),
			sourceType,
			revision,
			pretty.SinceString(r.CreationTimestamp.Time),
			resource.LabelsToString(r.Labels),
		}
	}
	return []interface{}{
		r.Name,
		string(mode),
		sourceType,
		revision,
		pretty.SinceString(r.CreationTimestamp.Time),
	}
}

var edgeFunctionResource = &resource.ResourceCommand[*v1alpha2.EdgeFunction, *v1alpha2.EdgeFunctionList]{
	Use:      "edgefunction",
	Aliases:  []string{"ef", "edgefunctions", "edgefuncs"},
	Short:    "Manage edge function objects",
	Long:     `Edge functions allow you to run custom code at the edge of the Apoxy network.`,
	KindName: "edge function",
	ClientFunc: func(c *rest.APIClient) resource.ResourceClient[*v1alpha2.EdgeFunction, *v1alpha2.EdgeFunctionList] {
		return c.ExtensionsV1alpha2().EdgeFunctions()
	},
	CustomPrinter: &resource.CustomPrinterConfig[*v1alpha2.EdgeFunction, *v1alpha2.EdgeFunctionList]{
		Header:   buildAlphaEdgeFunctionHeader,
		BuildRow: buildAlphaEdgeFunctionRow,
		GetItems: func(list *v1alpha2.EdgeFunctionList) []*v1alpha2.EdgeFunction {
			items := make([]*v1alpha2.EdgeFunction, len(list.Items))
			for i := range list.Items {
				items[i] = &list.Items[i]
			}
			return items
		},
	},
}

func init() {
	RootCmd.AddCommand(edgeFunctionResource.Build())
}
