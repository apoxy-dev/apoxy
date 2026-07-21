package v1alpha1

import (
	"context"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/apoxy-dev/apoxy/api/resource"
	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

const (
	// LabelNetwork is stamped by the relay on every Tunnel with the name of
	// the VPCNetwork the connection belongs to. Scopes VPCService selection.
	LabelNetwork = "vpc.apoxy.dev/network"

	// LabelTunnelName is stamped by the relay with the wire connect name
	// (the /v1/tunnel/:name path segment). Migration-minted VPCServices
	// select on it so legacy DNS names keep resolving.
	LabelTunnelName = "tunnel.apoxy.dev/name"

	// LabelAgentInstance is stamped by the relay with the agent process's
	// instance UUID (carried in the connect request), grouping the Tunnels of
	// one agent process across relays.
	LabelAgentInstance = "vpc.apoxy.dev/agent-instance"
)

// TunnelSpec carries the connection's immutable joins, stamped by the owning
// relay at create.
type TunnelSpec struct {
	// The VPCNetwork the connection belongs to.
	// +required
	NetworkRef VPCNetworkRef `json:"networkRef"`

	// The relay terminating the connection.
	// +required
	RelayRef RelayRef `json:"relayRef"`
}

type TunnelStatus struct {
	// Overlay addresses allocated to the connection by the owning relay from
	// its leased blocks. Dual-stack: one IPv6 ULA prefix plus one IPv4 CGNAT
	// address for egress through the connection (ingress never rides v4).
	// +optional
	Addresses []string `json:"addresses,omitempty,omitzero"`

	// Agent-declared prefixes reachable behind this connection, bounded by
	// credential claims and rejected by the relay when out of bounds.
	// +optional
	AdvertisedRoutes []string `json:"advertisedRoutes,omitempty,omitzero"`
}

var _ resource.StatusSubResource = &TunnelStatus{}

func (ps *TunnelStatus) SubResourceName() string {
	return "status"
}

func (ps *TunnelStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*Tunnel)
	if ok {
		parent.Status = *ps
	}
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Tunnel tracks one live connection - the Endpoints analog to VPCService's
// Service. Created complete by the owning relay at connect, deleted at
// disconnect, never patched in steady state, and never user-authored. The
// name is the connection ID; metadata labels carry the agent-declared labels
// plus the relay-stamped identity labels (LabelNetwork, LabelTunnelName,
// LabelAgentInstance).
type Tunnel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the specification of the connection.
	// +required
	Spec TunnelSpec `json:"spec,omitempty"`

	// Status is the status of the connection.
	// +optional
	Status TunnelStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &Tunnel{}
	_ resource.Object                      = &Tunnel{}
	_ resource.ObjectWithStatusSubResource = &Tunnel{}
	_ rest.SingularNameProvider            = &Tunnel{}
	_ resourcestrategy.TableConverter      = &Tunnel{}
)

func (t *Tunnel) GetObjectMeta() *metav1.ObjectMeta {
	return &t.ObjectMeta
}

func (t *Tunnel) NamespaceScoped() bool {
	return false
}

func (t *Tunnel) New() runtime.Object {
	return &Tunnel{}
}

func (t *Tunnel) NewList() runtime.Object {
	return &TunnelList{}
}

func (t *Tunnel) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "tunnels",
	}
}

func (t *Tunnel) IsStorageVersion() bool {
	return true
}

func (t *Tunnel) GetSingularName() string {
	return "tunnel"
}

func (t *Tunnel) GetStatus() resource.StatusSubResource {
	return &t.Status
}

func tunnelColumns() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: "Connection ID"},
		{Name: "Network", Type: "string", Description: "Owning VPCNetwork"},
		{Name: "Relay", Type: "string", Description: "Terminating relay"},
		{Name: "Addresses", Type: "string", Description: "Overlay addresses"},
		{Name: "Age", Type: "string", Description: "Time since connect"},
	}
}

func tunnelRow(t *Tunnel) metav1.TableRow {
	return metav1.TableRow{
		Cells: []interface{}{
			t.Name,
			t.Spec.NetworkRef.Name,
			t.Spec.RelayRef.Name,
			strings.Join(t.Status.Addresses, ","),
			formatAge(t.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: t},
	}
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (t *Tunnel) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = tunnelColumns()
	}
	table.Rows = append(table.Rows, tunnelRow(t))
	table.ResourceVersion = t.ResourceVersion
	return table, nil
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TunnelList contains a list of Tunnel objects.
type TunnelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Tunnel `json:"items"`
}

var (
	_ resource.ObjectList             = &TunnelList{}
	_ resourcestrategy.TableConverter = &TunnelList{}
)

func (tl *TunnelList) GetListMeta() *metav1.ListMeta {
	return &tl.ListMeta
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (tl *TunnelList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = tunnelColumns()
	}
	for i := range tl.Items {
		table.Rows = append(table.Rows, tunnelRow(&tl.Items[i]))
	}
	setListMeta(table, &tl.ListMeta)
	return table, nil
}

// TunnelRef is a reference to a Tunnel.
type TunnelRef struct {
	// Name of the Tunnel. Required.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`
}
