package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MetricSeriesSet is the result of metrics/<name>/series: one labeled series
// per group value, each with one point per time bucket. It carries no
// ObjectMeta, because it is a query result rather than a stored object.
type MetricSeriesSet struct {
	metav1.TypeMeta `json:",inline"`

	// Metric echoes the queried recipe name.
	Metric string `json:"metric"`

	// ScopeKind and ScopeName echo the resolved scope. ScopeName is empty for
	// a whole-project read.
	ScopeKind string `json:"scopeKind,omitempty"`
	ScopeName string `json:"scopeName,omitempty"`

	// Since and Until are the resolved half-open [since, until) window bounds.
	Since metav1.Time `json:"since"`
	Until metav1.Time `json:"until"`

	// Step is the applied bucket width, rounded up to the source granularity.
	Step metav1.Duration `json:"step"`

	// DataUpTo is the end of the last complete bucket, so a client can tell a
	// partial trailing bucket from a drop in traffic.
	DataUpTo metav1.Time `json:"dataUpTo"`

	// Truncated is set when more groups matched than top returned.
	Truncated bool `json:"truncated"`

	// TotalCount is how many groups had data in the window.
	TotalCount int `json:"totalCount"`

	// Units maps a measure name to its display unit, echoed from the catalog.
	Units map[string]string `json:"units,omitempty"`

	// Series is the labeled lines.
	Series []MetricSeries `json:"series"`
}

var _ runtime.Object = &MetricSeriesSet{}

// MetricSeries is one labeled line. A read with no groupBy returns exactly one
// series with empty labels.
type MetricSeries struct {
	// Labels is the group key and value, for example {route: api}.
	Labels map[string]string `json:"labels,omitempty"`

	// Points are the buckets, ordered by timestamp.
	Points []MetricPoint `json:"points"`
}

// MetricPoint is one bucket of one series.
type MetricPoint struct {
	// Timestamp is the bucket start.
	Timestamp metav1.Time `json:"timestamp"`

	// Values are the recipe's measures for the bucket.
	Values Measures `json:"values"`
}
