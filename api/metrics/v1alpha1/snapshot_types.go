package v1alpha1

import (
	"context"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"

	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

// Built-in recipe and measure names the snapshot table columns read. A
// snapshot carries every applicable recipe; the table shows the three a human
// scans a list by.
const (
	// MetricHTTPRequests is the built-in request-count recipe.
	MetricHTTPRequests = "http.requests"
	// MetricHTTPLatency is the built-in latency-percentile recipe.
	MetricHTTPLatency = "http.latency"

	// MeasureTotal is the request-count measure of http.requests.
	MeasureTotal = "total"
	// MeasureStatus5xx is the 5xx-count measure of http.requests.
	MeasureStatus5xx = "status_5xx"
	// MeasureP99 is the 99th-percentile measure of http.latency.
	MeasureP99 = "p99"
)

// SnapshotMeta is the window every snapshot kind echoes. It is inlined rather
// than nested so the wire shape stays flat, as the design states.
type SnapshotMeta struct {
	// Timestamp is when the snapshot was computed.
	Timestamp metav1.Time `json:"timestamp"`

	// Window is until minus since.
	Window metav1.Duration `json:"window"`

	// Since and Until are the resolved half-open [since, until) window bounds.
	Since metav1.Time `json:"since"`
	Until metav1.Time `json:"until"`

	// DataUpTo is the end of the last complete bucket.
	DataUpTo metav1.Time `json:"dataUpTo"`
}

// RouteMetrics is one route's share of a listener.
type RouteMetrics struct {
	// Kind is the route kind, for example HTTPRoute.
	Kind string `json:"kind,omitempty"`
	// Name is the route name.
	Name string `json:"name,omitempty"`
	// Rule is the rule index inside the route, when the telemetry carries one.
	Rule *int32 `json:"rule,omitempty"`
	// Metrics is every evaluated recipe for the route.
	Metrics MetricsMap `json:"metrics,omitempty"`
}

// ListenerMetrics is one listener's share of a Gateway. It cuts its own route
// list, so truncated and totalCount sit here rather than on the Gateway.
type ListenerMetrics struct {
	// Name is the listener name.
	Name string `json:"name,omitempty"`
	// Metrics is every evaluated recipe for the listener.
	Metrics MetricsMap `json:"metrics,omitempty"`
	// Routes is present only with include=routes, ranked by orderBy.
	Routes []RouteMetrics `json:"routes,omitempty"`
	// Truncated is set when top cut the route list.
	Truncated bool `json:"truncated,omitempty"`
	// TotalCount is how many routes had traffic in the window.
	TotalCount int `json:"totalCount,omitempty"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GatewayMetrics is the snapshot returned by gateways/<name>/metrics.
type GatewayMetrics struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	SnapshotMeta      `json:",inline"`

	// Metrics is the Gateway totals, one entry per evaluated recipe.
	Metrics MetricsMap `json:"metrics,omitempty"`
	// Units maps a measure name to its display unit, echoed from the catalog.
	Units map[string]string `json:"units,omitempty"`
	// Listeners is the first nesting level, always present.
	Listeners []ListenerMetrics `json:"listeners,omitempty"`
}

// RuleMetrics is one rule's share of an HTTPRoute.
type RuleMetrics struct {
	// Rule is the rule index inside the route.
	Rule int32 `json:"rule"`
	// Metrics is every evaluated recipe for the rule.
	Metrics MetricsMap `json:"metrics,omitempty"`
}

// BackendMetrics is one backend's share of an HTTPRoute.
type BackendMetrics struct {
	// Kind is the backend kind, for example Backend or Service.
	Kind string `json:"kind,omitempty"`
	// Name is the backend name.
	Name string `json:"name,omitempty"`
	// Metrics is every evaluated recipe for the backend.
	Metrics MetricsMap `json:"metrics,omitempty"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// HTTPRouteMetrics is the snapshot returned by httproutes/<name>/metrics. It
// cuts its own leaf lists, so truncated and totalCount sit on it.
type HTTPRouteMetrics struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	SnapshotMeta      `json:",inline"`

	// Metrics is the route totals, one entry per evaluated recipe.
	Metrics MetricsMap `json:"metrics,omitempty"`
	// Units maps a measure name to its display unit.
	Units map[string]string `json:"units,omitempty"`
	// Rules is present only with include=rules.
	Rules []RuleMetrics `json:"rules,omitempty"`
	// Backends is present only with include=backends.
	Backends []BackendMetrics `json:"backends,omitempty"`
	// Truncated is set when top cut a leaf list.
	Truncated bool `json:"truncated,omitempty"`
	// TotalCount is how many leaf rows had traffic in the window.
	TotalCount int `json:"totalCount,omitempty"`
}

// ReplicaGauges is the one non-telemetry field of a snapshot: it comes from
// the owner status, not from the read model.
type ReplicaGauges struct {
	// Desired is the requested replica count.
	Desired int32 `json:"desired"`
	// Ready is how many replicas report ready.
	Ready int32 `json:"ready"`
	// Available is how many replicas serve traffic.
	Available int32 `json:"available"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ProxyMetrics is the snapshot returned by proxies/<name>/metrics. It has no
// nested table, so it takes no include token.
type ProxyMetrics struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	SnapshotMeta      `json:",inline"`

	// Metrics is the Proxy totals, one entry per evaluated recipe.
	Metrics MetricsMap `json:"metrics,omitempty"`
	// Units maps a measure name to its display unit.
	Units map[string]string `json:"units,omitempty"`
	// Replicas comes from the owner status.
	Replicas ReplicaGauges `json:"replicas,omitempty,omitzero"`
}

// RevisionMetrics is one revision's share of a compute Service.
type RevisionMetrics struct {
	// Name is the revision name.
	Name string `json:"name,omitempty"`
	// Metrics is every evaluated recipe for the revision.
	Metrics MetricsMap `json:"metrics,omitempty"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ServiceMetrics is the snapshot returned by services/<name>/metrics. It cuts
// its own revision list, so truncated and totalCount sit on it.
type ServiceMetrics struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	SnapshotMeta      `json:",inline"`

	// Metrics is the Service totals, one entry per evaluated recipe.
	Metrics MetricsMap `json:"metrics,omitempty"`
	// Units maps a measure name to its display unit.
	Units map[string]string `json:"units,omitempty"`
	// Revisions is present only with include=revisions.
	Revisions []RevisionMetrics `json:"revisions,omitempty"`
	// Truncated is set when top cut the revision list.
	Truncated bool `json:"truncated,omitempty"`
	// TotalCount is how many revisions had traffic in the window.
	TotalCount int `json:"totalCount,omitempty"`
}

// VPCServiceMetrics is one VPC service's share of a VPCNetwork.
type VPCServiceMetrics struct {
	// Name is the VPCService name.
	Name string `json:"name,omitempty"`
	// Metrics is every evaluated recipe for the service.
	Metrics MetricsMap `json:"metrics,omitempty"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCNetworkMetrics is the snapshot returned by vpcnetworks/<name>/metrics. It
// cuts its own service list, so truncated and totalCount sit on it.
type VPCNetworkMetrics struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	SnapshotMeta      `json:",inline"`

	// Metrics is the network totals, one entry per evaluated recipe.
	Metrics MetricsMap `json:"metrics,omitempty"`
	// Units maps a measure name to its display unit.
	Units map[string]string `json:"units,omitempty"`
	// Services is present only with include=services.
	Services []VPCServiceMetrics `json:"services,omitempty"`
	// Truncated is set when top cut the service list.
	Truncated bool `json:"truncated,omitempty"`
	// TotalCount is how many services had traffic in the window.
	TotalCount int `json:"totalCount,omitempty"`
}

var (
	_ resourcestrategy.TableConverter = &GatewayMetrics{}
	_ resourcestrategy.TableConverter = &HTTPRouteMetrics{}
	_ resourcestrategy.TableConverter = &ProxyMetrics{}
	_ resourcestrategy.TableConverter = &ServiceMetrics{}
	_ resourcestrategy.TableConverter = &VPCNetworkMetrics{}
)

// snapshotColumns are the columns every snapshot kind prints.
func snapshotColumns() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: "Name of the owner object"},
		{Name: "Window", Type: "string", Description: "Window the snapshot covers"},
		{Name: "Requests", Type: "string", Description: "http.requests total"},
		{Name: "5xx", Type: "string", Description: "http.requests status_5xx"},
		{Name: "P99", Type: "string", Description: "http.latency p99"},
	}
}

// measure reads one measure out of a snapshot metrics map, printing an em dash
// when the recipe was not evaluated.
func measure(m MetricsMap, metric, name string) string {
	vals, ok := m[metric]
	if !ok {
		return "-"
	}
	v, ok := vals[name]
	if !ok {
		return "-"
	}
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', 2, 64)
}

// snapshotTable renders one snapshot row with the shared columns.
func snapshotTable(tableOptions runtime.Object, obj runtime.Object, name string, meta SnapshotMeta, m MetricsMap) *metav1.Table {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = snapshotColumns()
	}
	table.Rows = append(table.Rows, metav1.TableRow{
		Cells: []interface{}{
			name,
			meta.Window.Duration.String(),
			measure(m, MetricHTTPRequests, MeasureTotal),
			measure(m, MetricHTTPRequests, MeasureStatus5xx),
			measure(m, MetricHTTPLatency, MeasureP99),
		},
		Object: runtime.RawExtension{Object: obj},
	})
	return table
}

// ConvertToTable renders the snapshot for kubectl get and apoxy get.
func (s *GatewayMetrics) ConvertToTable(_ context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return snapshotTable(tableOptions, s, s.Name, s.SnapshotMeta, s.Metrics), nil
}

// ConvertToTable renders the snapshot for kubectl get and apoxy get.
func (s *HTTPRouteMetrics) ConvertToTable(_ context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return snapshotTable(tableOptions, s, s.Name, s.SnapshotMeta, s.Metrics), nil
}

// ConvertToTable renders the snapshot for kubectl get and apoxy get.
func (s *ProxyMetrics) ConvertToTable(_ context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return snapshotTable(tableOptions, s, s.Name, s.SnapshotMeta, s.Metrics), nil
}

// ConvertToTable renders the snapshot for kubectl get and apoxy get.
func (s *ServiceMetrics) ConvertToTable(_ context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return snapshotTable(tableOptions, s, s.Name, s.SnapshotMeta, s.Metrics), nil
}

// ConvertToTable renders the snapshot for kubectl get and apoxy get.
func (s *VPCNetworkMetrics) ConvertToTable(_ context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return snapshotTable(tableOptions, s, s.Name, s.SnapshotMeta, s.Metrics), nil
}
