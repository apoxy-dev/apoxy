package v1

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/duration"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type GatewayClass struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec gwapiv1.GatewayClassSpec `json:"spec,omitempty"`

	Status GatewayClassStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &GatewayClass{}
	_ resource.Object                      = &GatewayClass{}
	_ resource.ObjectWithStatusSubResource = &GatewayClass{}
	_ rest.SingularNameProvider            = &GatewayClass{}
)

func (p *GatewayClass) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *GatewayClass) NamespaceScoped() bool {
	return false
}

func (p *GatewayClass) New() runtime.Object {
	return &GatewayClass{}
}

func (p *GatewayClass) NewList() runtime.Object {
	return &GatewayClassList{}
}

func (p *GatewayClass) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "gatewayclasses",
	}
}

func (p *GatewayClass) IsStorageVersion() bool {
	return true
}

func (p *GatewayClass) GetSingularName() string {
	return "gatewayclass"
}

func (p *GatewayClass) GetStatus() resource.StatusSubResource {
	return &p.Status
}

type GatewayClassStatus struct {
	gwapiv1.GatewayClassStatus
}

var _ resource.StatusSubResource = &GatewayClassStatus{}

func (s *GatewayClassStatus) SubResourceName() string {
	return "status"
}

func (s *GatewayClassStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*GatewayClass)
	if ok {
		parent.Status = *s
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type GatewayClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GatewayClass `json:"items"`
}

var _ resource.ObjectList = &GatewayClassList{}

func (pl *GatewayClassList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// +kubebuilder:object:root=true

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Gateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec gwapiv1.GatewaySpec `json:"spec,omitempty"`

	Status GatewayStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &Gateway{}
	_ resource.Object                      = &Gateway{}
	_ resource.ObjectWithStatusSubResource = &Gateway{}
	_ rest.SingularNameProvider            = &Gateway{}
)

func (p *Gateway) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *Gateway) NamespaceScoped() bool {
	return false
}

func (p *Gateway) New() runtime.Object {
	return &Gateway{}
}

func (p *Gateway) NewList() runtime.Object {
	return &GatewayList{}
}

func (p *Gateway) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "gateways",
	}
}

func (p *Gateway) IsStorageVersion() bool {
	return true
}

func (p *Gateway) GetSingularName() string {
	return "gateway"
}

func (p *Gateway) GetStatus() resource.StatusSubResource {
	return &p.Status
}

type GatewayStatus struct {
	gwapiv1.GatewayStatus
}

var _ resource.StatusSubResource = &GatewayStatus{}

func (s *GatewayStatus) SubResourceName() string {
	return "status"
}

func (s *GatewayStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*Gateway)
	if ok {
		parent.Status = *s
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type GatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Gateway `json:"items"`
}

var _ resource.ObjectList = &GatewayList{}

func (pl *GatewayList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// +kubebuilder:object:root=true

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type HTTPRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec gwapiv1.HTTPRouteSpec `json:"spec,omitempty"`

	Status HTTPRouteStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &HTTPRoute{}
	_ resource.Object                      = &HTTPRoute{}
	_ resource.ObjectWithStatusSubResource = &HTTPRoute{}
	_ rest.SingularNameProvider            = &HTTPRoute{}
)

func (p *HTTPRoute) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *HTTPRoute) NamespaceScoped() bool {
	return false
}

func (p *HTTPRoute) New() runtime.Object {
	return &HTTPRoute{}
}

func (p *HTTPRoute) NewList() runtime.Object {
	return &HTTPRouteList{}
}

func (p *HTTPRoute) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "httproutes",
	}
}

func (p *HTTPRoute) IsStorageVersion() bool {
	return true
}

func (p *HTTPRoute) GetSingularName() string {
	return "httproute"
}

func (p *HTTPRoute) GetStatus() resource.StatusSubResource {
	return &p.Status
}

type HTTPRouteStatus struct {
	gwapiv1.HTTPRouteStatus
}

var _ resource.StatusSubResource = &HTTPRouteStatus{}

func (s *HTTPRouteStatus) SubResourceName() string {
	return "status"
}

func (s *HTTPRouteStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*HTTPRoute)
	if ok {
		parent.Status = *s
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type HTTPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HTTPRoute `json:"items"`
}

var _ resource.ObjectList = &HTTPRouteList{}

func (pl *HTTPRouteList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// +kubebuilder:object:root=true

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type GRPCRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec gwapiv1.GRPCRouteSpec `json:"spec,omitempty"`

	Status GRPCRouteStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &GRPCRoute{}
	_ resource.Object                      = &GRPCRoute{}
	_ resource.ObjectWithStatusSubResource = &GRPCRoute{}
	_ rest.SingularNameProvider            = &GRPCRoute{}
)

func (p *GRPCRoute) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *GRPCRoute) NamespaceScoped() bool {
	return false
}

func (p *GRPCRoute) New() runtime.Object {
	return &GRPCRoute{}
}

func (p *GRPCRoute) NewList() runtime.Object {
	return &GRPCRouteList{}
}

func (p *GRPCRoute) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "grpcroutes",
	}
}

func (p *GRPCRoute) IsStorageVersion() bool {
	return true
}

func (p *GRPCRoute) GetSingularName() string {
	return "grpcroute"
}

func (p *GRPCRoute) GetStatus() resource.StatusSubResource {
	return &p.Status
}

type GRPCRouteStatus struct {
	gwapiv1.GRPCRouteStatus
}

var _ resource.StatusSubResource = &GRPCRouteStatus{}

func (s *GRPCRouteStatus) SubResourceName() string {
	return "status"
}

func (s *GRPCRouteStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*GRPCRoute)
	if ok {
		parent.Status = *s
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type GRPCRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GRPCRoute `json:"items"`
}

var _ resource.ObjectList = &GRPCRouteList{}

func (pl *GRPCRouteList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// formatAge formats a time as a Kubernetes-style age string.
func formatAge(t time.Time) string {
	if t.IsZero() {
		return "<unknown>"
	}
	return duration.ShortHumanDuration(time.Since(t))
}

// getListenersSummary returns a summary of gateway listeners.
func getListenersSummary(listeners []gwapiv1.Listener) string {
	if len(listeners) == 0 {
		return "None"
	}
	var parts []string
	for _, l := range listeners {
		parts = append(parts, fmt.Sprintf("%s/%d", l.Protocol, l.Port))
	}
	return strings.Join(parts, ",")
}

// getParentRefsSummary returns a summary of parent references.
func getParentRefsSummary(refs []gwapiv1.ParentReference) string {
	if len(refs) == 0 {
		return "None"
	}
	var parts []string
	for _, ref := range refs {
		parts = append(parts, string(ref.Name))
	}
	return strings.Join(parts, ",")
}

// getHostnamesSummary returns a summary of hostnames
func getHostnamesSummary(hostnames []gwapiv1.Hostname) string {
	if len(hostnames) == 0 {
		return "*"
	}
	var parts []string
	for _, h := range hostnames {
		parts = append(parts, string(h))
	}
	return strings.Join(parts, ",")
}

var _ resourcestrategy.TableConverter = &GatewayClass{}

func (gc *GatewayClass) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return gatewayClassToTable(gc, tableOptions)
}

func gatewayClassToTable(gc *GatewayClass, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the gateway class"},
			{Name: "Controller", Type: "string", Description: "Controller that manages this class"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	table.Rows = append(table.Rows, metav1.TableRow{
		Cells: []interface{}{
			gc.Name,
			string(gc.Spec.ControllerName),
			formatAge(gc.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: gc},
	})
	table.ResourceVersion = gc.ResourceVersion
	return table, nil
}

var _ resourcestrategy.TableConverter = &GatewayClassList{}

func (l *GatewayClassList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the gateway class"},
			{Name: "Controller", Type: "string", Description: "Controller that manages this class"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	for i := range l.Items {
		gc := &l.Items[i]
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				gc.Name,
				string(gc.Spec.ControllerName),
				formatAge(gc.CreationTimestamp.Time),
			},
			Object: runtime.RawExtension{Object: gc},
		})
	}
	table.ResourceVersion = l.ResourceVersion
	table.Continue = l.Continue
	table.RemainingItemCount = l.RemainingItemCount
	return table, nil
}

var _ resourcestrategy.TableConverter = &Gateway{}

func (g *Gateway) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return gatewayToTable(g, tableOptions)
}

func gatewayToTable(g *Gateway, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the gateway"},
			{Name: "Class", Type: "string", Description: "Gateway class"},
			{Name: "Listeners", Type: "string", Description: "Listener configuration"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	table.Rows = append(table.Rows, metav1.TableRow{
		Cells: []interface{}{
			g.Name,
			string(g.Spec.GatewayClassName),
			getListenersSummary(g.Spec.Listeners),
			formatAge(g.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: g},
	})
	table.ResourceVersion = g.ResourceVersion
	return table, nil
}

var _ resourcestrategy.TableConverter = &GatewayList{}

func (l *GatewayList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the gateway"},
			{Name: "Class", Type: "string", Description: "Gateway class"},
			{Name: "Listeners", Type: "string", Description: "Listener configuration"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	for i := range l.Items {
		g := &l.Items[i]
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				g.Name,
				string(g.Spec.GatewayClassName),
				getListenersSummary(g.Spec.Listeners),
				formatAge(g.CreationTimestamp.Time),
			},
			Object: runtime.RawExtension{Object: g},
		})
	}
	table.ResourceVersion = l.ResourceVersion
	table.Continue = l.Continue
	table.RemainingItemCount = l.RemainingItemCount
	return table, nil
}

var _ resourcestrategy.TableConverter = &HTTPRoute{}

func (r *HTTPRoute) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return httpRouteToTable(r, tableOptions)
}

func httpRouteToTable(r *HTTPRoute, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the HTTP route"},
			{Name: "Hostnames", Type: "string", Description: "Hostnames for the route"},
			{Name: "Parents", Type: "string", Description: "Parent gateway references"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	table.Rows = append(table.Rows, metav1.TableRow{
		Cells: []interface{}{
			r.Name,
			getHostnamesSummary(r.Spec.Hostnames),
			getParentRefsSummary(r.Spec.ParentRefs),
			formatAge(r.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: r},
	})
	table.ResourceVersion = r.ResourceVersion
	return table, nil
}

var _ resourcestrategy.TableConverter = &HTTPRouteList{}

func (l *HTTPRouteList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the HTTP route"},
			{Name: "Hostnames", Type: "string", Description: "Hostnames for the route"},
			{Name: "Parents", Type: "string", Description: "Parent gateway references"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	for i := range l.Items {
		r := &l.Items[i]
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				r.Name,
				getHostnamesSummary(r.Spec.Hostnames),
				getParentRefsSummary(r.Spec.ParentRefs),
				formatAge(r.CreationTimestamp.Time),
			},
			Object: runtime.RawExtension{Object: r},
		})
	}
	table.ResourceVersion = l.ResourceVersion
	table.Continue = l.Continue
	table.RemainingItemCount = l.RemainingItemCount
	return table, nil
}

var _ resourcestrategy.TableConverter = &GRPCRoute{}

func (r *GRPCRoute) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return grpcRouteToTable(r, tableOptions)
}

func grpcRouteToTable(r *GRPCRoute, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the gRPC route"},
			{Name: "Hostnames", Type: "string", Description: "Hostnames for the route"},
			{Name: "Parents", Type: "string", Description: "Parent gateway references"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	table.Rows = append(table.Rows, metav1.TableRow{
		Cells: []interface{}{
			r.Name,
			getHostnamesSummary(r.Spec.Hostnames),
			getParentRefsSummary(r.Spec.ParentRefs),
			formatAge(r.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: r},
	})
	table.ResourceVersion = r.ResourceVersion
	return table, nil
}

var _ resourcestrategy.TableConverter = &GRPCRouteList{}

func (l *GRPCRouteList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the gRPC route"},
			{Name: "Hostnames", Type: "string", Description: "Hostnames for the route"},
			{Name: "Parents", Type: "string", Description: "Parent gateway references"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	for i := range l.Items {
		r := &l.Items[i]
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				r.Name,
				getHostnamesSummary(r.Spec.Hostnames),
				getParentRefsSummary(r.Spec.ParentRefs),
				formatAge(r.CreationTimestamp.Time),
			},
			Object: runtime.RawExtension{Object: r},
		})
	}
	table.ResourceVersion = l.ResourceVersion
	table.Continue = l.Continue
	table.RemainingItemCount = l.RemainingItemCount
	return table, nil
}
