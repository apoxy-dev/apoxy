package v1alpha1

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/apoxy-dev/apoxy/api/resource"
	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

type VPCServiceSpec struct {
	// The VPCNetwork this service belongs to. Selection is scoped to Tunnels
	// of this network.
	// +required
	NetworkRef VPCNetworkRef `json:"networkRef"`

	// Selects member Tunnels by their labels (agents declare labels at
	// connect; the relay stamps them onto Tunnel metadata labels).
	// +required
	Selector *metav1.LabelSelector `json:"selector"`
}

// VPCServiceEndpoint is one live member of the service.
type VPCServiceEndpoint struct {
	// The member Tunnel (one connection).
	TunnelRef TunnelRef `json:"tunnelRef"`

	// The member's overlay addresses. Plural per member (dual-stack); only
	// the IPv6 ULA is published to the shared DNS zone.
	// +optional
	Addresses []string `json:"addresses,omitempty"`
}

type VPCServiceStatus struct {
	// Live members and their overlay addresses (the "endpoints view").
	// +optional
	Endpoints []VPCServiceEndpoint `json:"endpoints,omitempty,omitzero"`

	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty,omitzero"`
}

var _ resource.StatusSubResource = &VPCServiceStatus{}

func (ps *VPCServiceStatus) SubResourceName() string {
	return "status"
}

func (ps *VPCServiceStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*VPCService)
	if ok {
		parent.Status = *ps
	}
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCService is service-like addressing over Tunnels, modeled on the
// Kubernetes Service: a label selector over Tunnel objects (which play
// Endpoints), a stable DNS name, and the target for DomainRecords and routes.
// User-authored.
type VPCService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the specification of the service.
	// +required
	Spec VPCServiceSpec `json:"spec,omitempty"`

	// Status is the status of the service.
	// +optional
	Status VPCServiceStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &VPCService{}
	_ resource.Object                      = &VPCService{}
	_ resource.ObjectWithStatusSubResource = &VPCService{}
	_ rest.SingularNameProvider            = &VPCService{}
	_ resourcestrategy.TableConverter      = &VPCService{}
)

func (s *VPCService) GetObjectMeta() *metav1.ObjectMeta {
	return &s.ObjectMeta
}

func (s *VPCService) NamespaceScoped() bool {
	return false
}

func (s *VPCService) New() runtime.Object {
	return &VPCService{}
}

func (s *VPCService) NewList() runtime.Object {
	return &VPCServiceList{}
}

func (s *VPCService) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "vpcservices",
	}
}

func (s *VPCService) IsStorageVersion() bool {
	return true
}

func (s *VPCService) GetSingularName() string {
	return "vpcservice"
}

func (s *VPCService) GetStatus() resource.StatusSubResource {
	return &s.Status
}

// getVPCServiceSelector renders the member selector in kubectl's compact form.
func getVPCServiceSelector(s *VPCService) string {
	if s.Spec.Selector == nil {
		return "<none>"
	}
	return metav1.FormatLabelSelector(s.Spec.Selector)
}

func vpcServiceColumns() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: "Name of the service"},
		{Name: "Network", Type: "string", Description: "Owning VPCNetwork"},
		{Name: "Selector", Type: "string", Description: "Member Tunnel selector"},
		{Name: "Endpoints", Type: "string", Description: "Live member count"},
		{Name: "Age", Type: "string", Description: "Time since creation"},
	}
}

func vpcServiceRow(s *VPCService) metav1.TableRow {
	return metav1.TableRow{
		Cells: []interface{}{
			s.Name,
			s.Spec.NetworkRef.Name,
			getVPCServiceSelector(s),
			fmt.Sprintf("%d", len(s.Status.Endpoints)),
			formatAge(s.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: s},
	}
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (s *VPCService) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = vpcServiceColumns()
	}
	table.Rows = append(table.Rows, vpcServiceRow(s))
	table.ResourceVersion = s.ResourceVersion
	return table, nil
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCServiceList contains a list of VPCService objects.
type VPCServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPCService `json:"items"`
}

var (
	_ resource.ObjectList             = &VPCServiceList{}
	_ resourcestrategy.TableConverter = &VPCServiceList{}
)

func (sl *VPCServiceList) GetListMeta() *metav1.ListMeta {
	return &sl.ListMeta
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (sl *VPCServiceList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = vpcServiceColumns()
	}
	for i := range sl.Items {
		table.Rows = append(table.Rows, vpcServiceRow(&sl.Items[i]))
	}
	setListMeta(table, &sl.ListMeta)
	return table, nil
}

// VPCServiceRef is a reference to a VPCService.
type VPCServiceRef struct {
	// Name of the VPCService. Required.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`
}
