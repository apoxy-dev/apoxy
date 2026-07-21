package v1alpha1

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/apoxy-dev/apoxy/api/resource"
	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

// EgressGatewaySpec configures per-network egress-gateway (exit-node)
// semantics: agents may advertise default routes and the relay SNATs strictly
// within this network's routing domain.
//
// NOTE: the current relay implementation is a relay-global boolean, so this
// field is not honored until per-network routing-domain semantics land in the
// relay router (APO-729).
type EgressGatewaySpec struct {
	// Whether the egress gateway is enabled. Default is false.
	// +optional
	Enabled bool `json:"enabled,omitempty"`
}

// VPCNetworkDNS is the DNS configuration pushed to attaching tunnels and
// vpc-bound sandboxes. Mirrors the wire ConnectResponse.DNS shape.
type VPCNetworkDNS struct {
	// DNS server addresses.
	// +optional
	Servers []string `json:"servers,omitempty"`

	// DNS search domains.
	// +optional
	SearchDomains []string `json:"searchDomains,omitempty"`

	// The ndots resolver option.
	// +optional
	NDots *int `json:"ndots,omitempty"`
}

type VPCNetworkSpec struct {
	// Per-network egress-gateway (exit-node) semantics. Not honored until the
	// relay router implements per-network routing domains (APO-729).
	// +optional
	EgressGateway *EgressGatewaySpec `json:"egressGateway,omitempty"`

	// DNS pushed to attaching tunnels and vpc-bound sandboxes.
	// +optional
	DNS *VPCNetworkDNS `json:"dns,omitempty"`
}

// VPCNetworkCredentials carries the network's connect credential.
type VPCNetworkCredentials struct {
	// Bearer token for authenticating with the network's relays.
	Token string `json:"token,omitempty"`
}

type VPCNetworkStatus struct {
	// Credentials for authenticating with the network's relays.
	// +optional
	Credentials *VPCNetworkCredentials `json:"credentials,omitempty,omitzero"`

	// The ULA prefix of the network's overlay address space. Relay discovery
	// is a live list of Relay objects, not derived state here.
	// +optional
	OverlayCIDR string `json:"overlayCIDR,omitempty"`

	// Conditions: Ready, InfraProvisioned.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty,omitzero"`
}

var _ resource.StatusSubResource = &VPCNetworkStatus{}

func (ps *VPCNetworkStatus) SubResourceName() string {
	return "status"
}

func (ps *VPCNetworkStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*VPCNetwork)
	if ok {
		parent.Status = *ps
	}
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCNetwork is a private connectivity domain: the routing and key domain
// that Tunnels and compute vpc bindings attach to.
type VPCNetwork struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the specification of the network.
	// +required
	Spec VPCNetworkSpec `json:"spec,omitempty"`

	// Status is the status of the network.
	// +optional
	Status VPCNetworkStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &VPCNetwork{}
	_ resource.Object                      = &VPCNetwork{}
	_ resource.ObjectWithStatusSubResource = &VPCNetwork{}
	_ rest.SingularNameProvider            = &VPCNetwork{}
	_ resourcestrategy.TableConverter      = &VPCNetwork{}
)

func (n *VPCNetwork) GetObjectMeta() *metav1.ObjectMeta {
	return &n.ObjectMeta
}

func (n *VPCNetwork) NamespaceScoped() bool {
	return false
}

func (n *VPCNetwork) New() runtime.Object {
	return &VPCNetwork{}
}

func (n *VPCNetwork) NewList() runtime.Object {
	return &VPCNetworkList{}
}

func (n *VPCNetwork) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "vpcnetworks",
	}
}

func (n *VPCNetwork) IsStorageVersion() bool {
	return true
}

func (n *VPCNetwork) GetSingularName() string {
	return "vpcnetwork"
}

func (n *VPCNetwork) GetStatus() resource.StatusSubResource {
	return &n.Status
}

// getVPCNetworkEgress summarizes the egress-gateway setting.
func getVPCNetworkEgress(n *VPCNetwork) string {
	if n.Spec.EgressGateway != nil && n.Spec.EgressGateway.Enabled {
		return "Enabled"
	}
	return "Disabled"
}

func vpcNetworkColumns() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: "Name of the network"},
		{Name: "Egress", Type: "string", Description: "Egress gateway setting"},
		{Name: "CIDR", Type: "string", Description: "Overlay address space"},
		{Name: "Age", Type: "string", Description: "Time since creation"},
	}
}

func vpcNetworkRow(n *VPCNetwork) metav1.TableRow {
	return metav1.TableRow{
		Cells: []interface{}{
			n.Name,
			getVPCNetworkEgress(n),
			n.Status.OverlayCIDR,
			formatAge(n.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: n},
	}
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (n *VPCNetwork) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = vpcNetworkColumns()
	}
	table.Rows = append(table.Rows, vpcNetworkRow(n))
	table.ResourceVersion = n.ResourceVersion
	return table, nil
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCNetworkList contains a list of VPCNetwork objects.
type VPCNetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPCNetwork `json:"items"`
}

var (
	_ resource.ObjectList             = &VPCNetworkList{}
	_ resourcestrategy.TableConverter = &VPCNetworkList{}
)

func (nl *VPCNetworkList) GetListMeta() *metav1.ListMeta {
	return &nl.ListMeta
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (nl *VPCNetworkList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = vpcNetworkColumns()
	}
	for i := range nl.Items {
		table.Rows = append(table.Rows, vpcNetworkRow(&nl.Items[i]))
	}
	setListMeta(table, &nl.ListMeta)
	return table, nil
}

// VPCNetworkRef is a reference to a VPCNetwork.
type VPCNetworkRef struct {
	// Name of the VPCNetwork. Required.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`
}
