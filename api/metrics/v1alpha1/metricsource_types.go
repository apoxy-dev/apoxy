package v1alpha1

import (
	"context"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/apoxy-dev/apoxy/api/resource"
	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

// FieldRole says what a source field can be used for in a recipe.
type FieldRole string

const (
	// FieldRoleTime is the bucket column of the source.
	FieldRoleTime FieldRole = "time"
	// FieldRoleKey is a groupable dimension. The groupBy parameter accepts
	// exactly these fields.
	FieldRoleKey FieldRole = "key"
	// FieldRoleMeasure is a value column a recipe aggregates.
	FieldRoleMeasure FieldRole = "measure"
)

// MetricSourceField is one column or discovered attribute of a source.
type MetricSourceField struct {
	// Name is the field name as a recipe writes it.
	// +required
	Name string `json:"name"`

	// Type is the field type: string, integer, float, timestamp, or histogram.
	// +optional
	Type string `json:"type,omitempty"`

	// Role says whether the field is the time bucket, a groupable key, or a
	// measure.
	// +optional
	Role FieldRole `json:"role,omitempty"`

	// Discovered is true for a field found by sampling log attributes, which
	// can therefore disappear, and false for a table column or a static field,
	// which cannot.
	// +optional
	Discovered bool `json:"discovered,omitempty"`

	// Reaggregate reports whether the measure can be summed across buckets. It
	// is false for a percentile.
	// +optional
	Reaggregate bool `json:"reaggregate,omitempty"`
}

// MetricSourceSpec is empty. Granularity, retention, and the field list are
// facts about the table, not settings, so they live in status.
type MetricSourceSpec struct{}

// MetricSourceStatus is the derived description of one source.
type MetricSourceStatus struct {
	// Granularity is the bucket width of the source: row for raw logs, 1m or
	// 1h for a rollup. It is the minimum step a series read can ask for.
	// +optional
	Granularity string `json:"granularity,omitempty"`

	// Retention is how long the source keeps data.
	// +optional
	Retention string `json:"retention,omitempty"`

	// Scopes are the owner kinds a scopeKind parameter accepts for this
	// source.
	// +optional
	Scopes []string `json:"scopes,omitempty"`

	// Fields are the columns and discovered attributes of the source.
	// +optional
	Fields []MetricSourceField `json:"fields,omitempty"`

	// Metrics are the recipes that read this source.
	// +optional
	Metrics []string `json:"metrics,omitempty"`

	// DiscoveredAt is when the attribute sample last ran.
	// +optional
	DiscoveredAt *metav1.Time `json:"discoveredAt,omitempty"`
}

// +kubebuilder:object:root=true

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MetricSource is one entry of the per-project schema registry. It is derived
// on read and never stored, so a recipe author can see what a source keeps and
// what it can be grouped by.
type MetricSource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is empty.
	// +optional
	Spec MetricSourceSpec `json:"spec,omitempty"`

	// Status is the derived description of the source.
	// +optional
	Status MetricSourceStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                  = &MetricSource{}
	_ resource.Object                 = &MetricSource{}
	_ rest.SingularNameProvider       = &MetricSource{}
	_ resourcestrategy.TableConverter = &MetricSource{}
)

func (s *MetricSource) GetObjectMeta() *metav1.ObjectMeta { return &s.ObjectMeta }

func (s *MetricSource) NamespaceScoped() bool { return false }

func (s *MetricSource) New() runtime.Object { return &MetricSource{} }

func (s *MetricSource) NewList() runtime.Object { return &MetricSourceList{} }

func (s *MetricSource) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "metricsources",
	}
}

func (s *MetricSource) IsStorageVersion() bool { return true }

func (s *MetricSource) GetSingularName() string { return "metricsource" }

func metricSourceColumns() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: "Name of the source"},
		{Name: "Granularity", Type: "string", Description: "Bucket width"},
		{Name: "Retention", Type: "string", Description: "How long the source keeps data"},
		{Name: "Fields", Type: "integer", Description: "Number of fields"},
	}
}

func metricSourceRow(s *MetricSource) metav1.TableRow {
	return metav1.TableRow{
		Cells: []interface{}{
			s.Name,
			s.Status.Granularity,
			s.Status.Retention,
			strconv.Itoa(len(s.Status.Fields)),
		},
		Object: runtime.RawExtension{Object: s},
	}
}

// ConvertToTable renders the registry for kubectl get metricsources.
func (s *MetricSource) ConvertToTable(_ context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = metricSourceColumns()
	}
	table.Rows = append(table.Rows, metricSourceRow(s))
	table.ResourceVersion = s.ResourceVersion
	return table, nil
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MetricSourceList is every source this project can read.
type MetricSourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MetricSource `json:"items"`
}

var (
	_ resource.ObjectList             = &MetricSourceList{}
	_ resourcestrategy.TableConverter = &MetricSourceList{}
)

func (l *MetricSourceList) GetListMeta() *metav1.ListMeta { return &l.ListMeta }

// ConvertToTable renders the registry for kubectl get metricsources.
func (l *MetricSourceList) ConvertToTable(_ context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = metricSourceColumns()
	}
	for i := range l.Items {
		table.Rows = append(table.Rows, metricSourceRow(&l.Items[i]))
	}
	setListMeta(table, &l.ListMeta)
	return table, nil
}
