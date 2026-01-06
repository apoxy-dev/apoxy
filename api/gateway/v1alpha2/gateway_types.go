package v1alpha2

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
	gwapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TLSRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec gwapiv1alpha2.TLSRouteSpec `json:"spec,omitempty"`

	Status TLSRouteStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &TLSRoute{}
	_ resource.Object                      = &TLSRoute{}
	_ resource.ObjectWithStatusSubResource = &TLSRoute{}
	_ rest.SingularNameProvider            = &TLSRoute{}
)

func (p *TLSRoute) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *TLSRoute) NamespaceScoped() bool {
	return false
}

func (p *TLSRoute) New() runtime.Object {
	return &TLSRoute{}
}

func (p *TLSRoute) NewList() runtime.Object {
	return &TLSRouteList{}
}

func (p *TLSRoute) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "tlsroutes",
	}
}

func (p *TLSRoute) IsStorageVersion() bool {
	return true
}

func (p *TLSRoute) GetSingularName() string {
	return "tlsroute"
}

func (p *TLSRoute) GetStatus() resource.StatusSubResource {
	return &p.Status
}

type TLSRouteStatus struct {
	gwapiv1alpha2.TLSRouteStatus
}

var _ resource.StatusSubResource = &TLSRouteStatus{}

func (s *TLSRouteStatus) SubResourceName() string {
	return "status"
}

func (s *TLSRouteStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*TLSRoute)
	if ok {
		parent.Status = *s
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type TLSRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TLSRoute `json:"items"`
}

var _ resource.ObjectList = &TLSRouteList{}

func (pl *TLSRouteList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// +kubebuilder:object:root=true

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TCPRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec gwapiv1alpha2.TCPRouteSpec `json:"spec,omitempty"`

	Status TCPRouteStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &TCPRoute{}
	_ resource.Object                      = &TCPRoute{}
	_ resource.ObjectWithStatusSubResource = &TCPRoute{}
	_ rest.SingularNameProvider            = &TCPRoute{}
)

func (p *TCPRoute) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *TCPRoute) NamespaceScoped() bool {
	return false
}

func (p *TCPRoute) New() runtime.Object {
	return &TCPRoute{}
}

func (p *TCPRoute) NewList() runtime.Object {
	return &TCPRouteList{}
}

func (p *TCPRoute) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "tcproutes",
	}
}

func (p *TCPRoute) IsStorageVersion() bool {
	return true
}

func (p *TCPRoute) GetSingularName() string {
	return "tcproute"
}

func (p *TCPRoute) GetStatus() resource.StatusSubResource {
	return &p.Status
}

type TCPRouteStatus struct {
	gwapiv1alpha2.TCPRouteStatus
}

var _ resource.StatusSubResource = &TCPRouteStatus{}

func (s *TCPRouteStatus) SubResourceName() string {
	return "status"
}

func (s *TCPRouteStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*TCPRoute)
	if ok {
		parent.Status = *s
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type TCPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TCPRoute `json:"items"`
}

var _ resource.ObjectList = &TCPRouteList{}

func (pl *TCPRouteList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// +kubebuilder:object:root=true

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type UDPRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec gwapiv1alpha2.UDPRouteSpec `json:"spec,omitempty"`

	Status UDPRouteStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &UDPRoute{}
	_ resource.Object                      = &UDPRoute{}
	_ resource.ObjectWithStatusSubResource = &UDPRoute{}
	_ rest.SingularNameProvider            = &UDPRoute{}
)

func (p *UDPRoute) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *UDPRoute) NamespaceScoped() bool {
	return false
}

func (p *UDPRoute) New() runtime.Object {
	return &UDPRoute{}
}

func (p *UDPRoute) NewList() runtime.Object {
	return &UDPRouteList{}
}

func (p *UDPRoute) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "udproutes",
	}
}

func (p *UDPRoute) IsStorageVersion() bool {
	return true
}

func (p *UDPRoute) GetSingularName() string {
	return "udproute"
}

func (p *UDPRoute) GetStatus() resource.StatusSubResource {
	return &p.Status
}

type UDPRouteStatus struct {
	gwapiv1alpha2.UDPRouteStatus
}

var _ resource.StatusSubResource = &UDPRouteStatus{}

func (s *UDPRouteStatus) SubResourceName() string {
	return "status"
}

func (s *UDPRouteStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*UDPRoute)
	if ok {
		parent.Status = *s
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type UDPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []UDPRoute `json:"items"`
}

var _ resource.ObjectList = &UDPRouteList{}

func (pl *UDPRouteList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// formatAge formats a time as a Kubernetes-style age string.
func formatAge(t time.Time) string {
	if t.IsZero() {
		return "<unknown>"
	}
	return duration.ShortHumanDuration(time.Since(t))
}

// getParentRefsSummary returns a summary of parent references.
func getParentRefsSummary(refs []gwapiv1alpha2.ParentReference) string {
	if len(refs) == 0 {
		return "None"
	}
	var parts []string
	for _, ref := range refs {
		parts = append(parts, string(ref.Name))
	}
	return strings.Join(parts, ",")
}

// getSNIsSummary returns a summary of SNI hostnames for TLS routes.
func getSNIsSummary(hostnames []gwapiv1alpha2.Hostname) string {
	if len(hostnames) == 0 {
		return "*"
	}
	var parts []string
	for _, h := range hostnames {
		parts = append(parts, string(h))
	}
	return strings.Join(parts, ",")
}

// getRulesSummary returns a summary of the number of rules.
func getRulesSummary(count int) string {
	return fmt.Sprintf("%d", count)
}

var (
	_ resourcestrategy.TableConverter = &TLSRoute{}
	_ resourcestrategy.TableConverter = &TLSRouteList{}
)

func (r *TLSRoute) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return tlsRouteToTable(r, tableOptions)
}

func tlsRouteToTable(r *TLSRoute, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the TLS route"},
			{Name: "Hostnames", Type: "string", Description: "SNI hostnames for the route"},
			{Name: "Parents", Type: "string", Description: "Parent gateway references"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	table.Rows = append(table.Rows, metav1.TableRow{
		Cells: []interface{}{
			r.Name,
			getSNIsSummary(r.Spec.Hostnames),
			getParentRefsSummary(r.Spec.ParentRefs),
			formatAge(r.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: r},
	})
	table.ResourceVersion = r.ResourceVersion
	return table, nil
}

func (l *TLSRouteList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the TLS route"},
			{Name: "Hostnames", Type: "string", Description: "SNI hostnames for the route"},
			{Name: "Parents", Type: "string", Description: "Parent gateway references"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	for i := range l.Items {
		r := &l.Items[i]
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				r.Name,
				getSNIsSummary(r.Spec.Hostnames),
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

var (
	_ resourcestrategy.TableConverter = &TCPRoute{}
	_ resourcestrategy.TableConverter = &TCPRouteList{}
)

func (r *TCPRoute) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return tcpRouteToTable(r, tableOptions)
}

func tcpRouteToTable(r *TCPRoute, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the TCP route"},
			{Name: "Rules", Type: "string", Description: "Number of routing rules"},
			{Name: "Parents", Type: "string", Description: "Parent gateway references"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	table.Rows = append(table.Rows, metav1.TableRow{
		Cells: []interface{}{
			r.Name,
			getRulesSummary(len(r.Spec.Rules)),
			getParentRefsSummary(r.Spec.ParentRefs),
			formatAge(r.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: r},
	})
	table.ResourceVersion = r.ResourceVersion
	return table, nil
}

func (l *TCPRouteList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the TCP route"},
			{Name: "Rules", Type: "string", Description: "Number of routing rules"},
			{Name: "Parents", Type: "string", Description: "Parent gateway references"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	for i := range l.Items {
		r := &l.Items[i]
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				r.Name,
				getRulesSummary(len(r.Spec.Rules)),
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

var (
	_ resourcestrategy.TableConverter = &UDPRoute{}
	_ resourcestrategy.TableConverter = &UDPRouteList{}
)

func (r *UDPRoute) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return udpRouteToTable(r, tableOptions)
}

func udpRouteToTable(r *UDPRoute, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the UDP route"},
			{Name: "Rules", Type: "string", Description: "Number of routing rules"},
			{Name: "Parents", Type: "string", Description: "Parent gateway references"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	table.Rows = append(table.Rows, metav1.TableRow{
		Cells: []interface{}{
			r.Name,
			getRulesSummary(len(r.Spec.Rules)),
			getParentRefsSummary(r.Spec.ParentRefs),
			formatAge(r.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: r},
	})
	table.ResourceVersion = r.ResourceVersion
	return table, nil
}

func (l *UDPRouteList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the UDP route"},
			{Name: "Rules", Type: "string", Description: "Number of routing rules"},
			{Name: "Parents", Type: "string", Description: "Parent gateway references"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	for i := range l.Items {
		r := &l.Items[i]
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				r.Name,
				getRulesSummary(len(r.Spec.Rules)),
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
