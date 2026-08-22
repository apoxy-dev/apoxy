package v1alpha1

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/apoxy-dev/apoxy/api/resource"
	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

const (
	// ManagedLabel marks a recipe that the server compiled into the binary and
	// wrote to storage at startup. It is informational and is set by the
	// server; a client write of the label is stripped by admission.
	ManagedLabel = "metrics.apoxy.dev/managed"

	// ReservedNamePrefix is the name prefix admission reserves for built-in
	// recipes, so a user recipe cannot shadow one.
	ReservedNamePrefix = "http."

	// ReservedNameSeries is the one name a recipe may not take, because it
	// would collide with the series subresource path element.
	ReservedNameSeries = "series"
)

// MetricConditionCompiled reports whether spec.prql compiles against the
// current schema registry. A recipe that stops compiling after a discovered
// attribute disappears is skipped by snapshots and is a 422 from series.
const MetricConditionCompiled = "Compiled"

// MetricType tells a client how to render a recipe.
type MetricType string

const (
	// MetricTypeCounter is a monotonic count or sum aggregate.
	MetricTypeCounter MetricType = "counter"
	// MetricTypeGauge is a point-in-time value.
	MetricTypeGauge MetricType = "gauge"
	// MetricTypeHistogram is a distribution queried as quantile columns.
	MetricTypeHistogram MetricType = "histogram"
)

// MeasureType is the value domain of one measure. A client formats an integer
// measure without a decimal part.
type MeasureType string

const (
	// MeasureTypeInteger is a whole-number measure, such as a request count.
	MeasureTypeInteger MeasureType = "integer"
	// MeasureTypeFloat is a fractional measure, such as a latency percentile.
	MeasureTypeFloat MeasureType = "float"
)

// MetricSpec is what a person writes. Everything derived from the fragment
// lives in status.
type MetricSpec struct {
	// PRQL is the aggregate-only recipe fragment: [filter|derive]* aggregate
	// {...}. It states no from, no group, and no time_bucket. The source comes
	// from spec.source, the grouping from the groupBy parameter, the bucket
	// from the step parameter, and the scope from the scope parameters.
	// +required
	PRQL string `json:"prql"`

	// Source is the table the fragment reads. When it is empty the server
	// resolves it on write from the fields the fragment uses.
	// +optional
	Source string `json:"source,omitempty"`

	// Type tells a client how to render the recipe.
	// +optional
	Type MetricType `json:"type,omitempty"`

	// Unit is the display unit of the recipe as a whole, when every measure
	// shares one. Per-measure units are in status.measures[].unit.
	// +optional
	Unit string `json:"unit,omitempty"`

	// Scopes are the owner kinds this recipe applies to. An empty list means
	// every kind the source supports.
	// +optional
	Scopes []string `json:"scopes,omitempty"`

	// DefaultDimension is the key a client groups by when it has no better
	// choice. It falls back to status.keys[0].
	// +optional
	DefaultDimension string `json:"defaultDimension,omitempty"`

	// DefaultColumns are the measures a client shows first. The first entry is
	// also the default orderBy.
	// +optional
	DefaultColumns []string `json:"defaultColumns,omitempty"`

	// Description is a one-line human summary.
	// +optional
	Description string `json:"description,omitempty"`
}

// MetricMeasure is one output column of a compiled recipe.
type MetricMeasure struct {
	// Name is the measure name, the key it takes in a Measures map.
	// +required
	Name string `json:"name"`

	// Type is the value domain of the measure.
	// +optional
	Type MeasureType `json:"type,omitempty"`

	// Unit is the display unit ("" for a plain count, By for bytes, ms for a
	// duration). It is echoed in the units map of every snapshot and series
	// response.
	// +optional
	Unit string `json:"unit,omitempty"`

	// Reaggregate reports whether the measure can be summed across buckets. It
	// is false for a percentile, which must be recomputed from the histogram.
	// +optional
	Reaggregate bool `json:"reaggregate,omitempty"`
}

// MetricStatus is what the server derives by compiling the fragment against
// the schema registry on create and update. A client cannot supply these
// fields; admission rejects a write that tries.
type MetricStatus struct {
	// Source is the resolved source table.
	// +optional
	Source string `json:"source,omitempty"`

	// Measures are the output columns of the compiled fragment.
	// +optional
	Measures []MetricMeasure `json:"measures,omitempty"`

	// Keys are the groupable dimensions: every role: key field of the resolved
	// source. A groupBy that is not in this list is a 400.
	// +optional
	Keys []string `json:"keys,omitempty"`

	// Conditions: Compiled.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty,omitzero"`
}

var _ resource.StatusSubResource = &MetricStatus{}

func (s *MetricStatus) SubResourceName() string {
	return "status"
}

func (s *MetricStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	if parent, ok := obj.(*Metric); ok {
		parent.Status = *s
	}
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Metric is a stored recipe: a PRQL aggregate fragment plus presentation
// preferences. It is the only typed query surface; there is no ad-hoc typed
// query endpoint. Its name is the path element of the series subresource.
type Metric struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the recipe a person writes.
	// +required
	Spec MetricSpec `json:"spec,omitempty"`

	// Status is what the server derives by compiling the recipe.
	// +optional
	Status MetricStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &Metric{}
	_ resource.Object                      = &Metric{}
	_ resource.ObjectWithStatusSubResource = &Metric{}
	_ rest.SingularNameProvider            = &Metric{}
	_ resourcestrategy.TableConverter      = &Metric{}
	_ resourcestrategy.Validater           = &Metric{}
)

func (m *Metric) GetObjectMeta() *metav1.ObjectMeta { return &m.ObjectMeta }

func (m *Metric) NamespaceScoped() bool { return false }

func (m *Metric) New() runtime.Object { return &Metric{} }

func (m *Metric) NewList() runtime.Object { return &MetricList{} }

func (m *Metric) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "metrics",
	}
}

func (m *Metric) IsStorageVersion() bool { return true }

func (m *Metric) GetSingularName() string { return "metric" }

func (m *Metric) GetStatus() resource.StatusSubResource { return &m.Status }

func metricColumns() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: "Name of the recipe"},
		{Name: "Type", Type: "string", Description: "counter, gauge, or histogram"},
		{Name: "Unit", Type: "string", Description: "Display unit"},
		{Name: "Source", Type: "string", Description: "Resolved source table"},
	}
}

// metricSource prefers the resolved source, because spec.source is optional.
func metricSource(m *Metric) string {
	if m.Status.Source != "" {
		return m.Status.Source
	}
	return m.Spec.Source
}

func metricRow(m *Metric) metav1.TableRow {
	return metav1.TableRow{
		Cells: []interface{}{
			m.Name,
			string(m.Spec.Type),
			m.Spec.Unit,
			metricSource(m),
		},
		Object: runtime.RawExtension{Object: m},
	}
}

// ConvertToTable renders the catalog for kubectl get metrics.
func (m *Metric) ConvertToTable(_ context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = metricColumns()
	}
	table.Rows = append(table.Rows, metricRow(m))
	table.ResourceVersion = m.ResourceVersion
	return table, nil
}

// Validate rejects a recipe that admission must never store. The compile step
// runs in the deployment that owns the PRQL engine; this covers the name rules
// and the one required field, which every deployment shares.
func (m *Metric) Validate(_ context.Context) field.ErrorList {
	var errs field.ErrorList
	if m.Spec.PRQL == "" {
		errs = append(errs, field.Required(field.NewPath("spec", "prql"), "a recipe needs a PRQL fragment"))
	}
	if m.Name == ReservedNameSeries {
		errs = append(errs, field.Invalid(field.NewPath("metadata", "name"), m.Name,
			fmt.Sprintf("%q is reserved by the series subresource", ReservedNameSeries)))
	}
	return errs
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MetricList is the catalog: every recipe this project can query.
type MetricList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Metric `json:"items"`
}

var (
	_ resource.ObjectList             = &MetricList{}
	_ resourcestrategy.TableConverter = &MetricList{}
)

func (l *MetricList) GetListMeta() *metav1.ListMeta { return &l.ListMeta }

// ConvertToTable renders the catalog for kubectl get metrics.
func (l *MetricList) ConvertToTable(_ context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = metricColumns()
	}
	for i := range l.Items {
		table.Rows = append(table.Rows, metricRow(&l.Items[i]))
	}
	setListMeta(table, &l.ListMeta)
	return table, nil
}
