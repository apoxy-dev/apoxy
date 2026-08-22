// +k8s:openapi-gen=true
// +kubebuilder:object:generate=true
// +groupName=metrics.apoxy.dev
// +k8s:deepcopy-gen=package,register

// Package v1alpha1 contains the metrics.apoxy.dev API group: the metric
// catalog (Metric), the per-project schema registry (MetricSource), the
// time-series result of a catalog recipe (MetricSeriesSet), and the per-object
// snapshot kinds returned by the <owner>/<name>/metrics connect subresources.
// All kinds are cluster-scoped, because the apiserver serves exactly one
// project. Storage for this group is custom and is mounted by the deployment
// that owns the ClickHouse read model. See
// docs/design-plans/2026-08-20-project-metrics-api.mdx in the apoxy-cloud
// repository for the design.
package v1alpha1 // import "github.com/apoxy-dev/apoxy/api/metrics/v1alpha1"
