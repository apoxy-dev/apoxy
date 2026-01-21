package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apirest "k8s.io/apiserver/pkg/registry/rest"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/builder/resource"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:subresource:log

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Tunnel represents a tunnel network.
type Tunnel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the specification of the tunnel.
	// +required
	Spec TunnelSpec `json:"spec,omitempty"`

	// Status is the status of the tunnel network.
	// +optional
	Status TunnelStatus `json:"status,omitempty"`
}

type EgressGatewaySpec struct {
	// Whether the egress gateway is enabled. Default is false.
	// When enabled, the egress gateway will be used to route traffic from the
	// tunnel agent to the internet. Traffic will be SNAT'ed.
	// +optional
	Enabled bool `json:"enabled,omitempty"`
}

type TunnelSpec struct {
	// Configures egress gateway mode on the tunnel. In this mode, the tunnel
	// relay acts as a gateway for outbound connections originating from the
	// agent side in addition to its default mode (where the connections arrive
	// in the direction of the agent).
	// +optional
	EgressGateway *EgressGatewaySpec `json:"egressGateway,omitempty"`
}

type TunnelCredentials struct {
	// Bearer token for authentication with tunnel relays.
	Token string `json:"token,omitempty"`
}

type TunnelStatus struct {
	// Credentials for authenticating with tunnel relays.
	// +optional
	Credentials *TunnelCredentials `json:"credentials,omitempty,omitzero"`

	// A list of public relay hosts for this network.
	// +optional
	Addresses []string `json:"addresses,omitempty,omitzero"`
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

var (
	_ runtime.Object                       = &Tunnel{}
	_ resource.Object                      = &Tunnel{}
	_ resource.ObjectWithStatusSubResource = &Tunnel{}
	_ apirest.SingularNameProvider            = &Tunnel{}
)

func (p *Tunnel) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *Tunnel) NamespaceScoped() bool {
	return false
}

func (p *Tunnel) New() runtime.Object {
	return &Tunnel{}
}

func (p *Tunnel) NewList() runtime.Object {
	return &TunnelList{}
}

func (p *Tunnel) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "tunnels",
	}
}

func (p *Tunnel) IsStorageVersion() bool {
	return true
}

func (p *Tunnel) GetSingularName() string {
	return "tunnel"
}

func (p *Tunnel) GetStatus() resource.StatusSubResource {
	return &p.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TunnelList contains a list of Tunnel objects.
type TunnelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Tunnel `json:"items"`
}

var _ resource.ObjectList = &TunnelList{}

func (pl *TunnelList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// TunnelRef is a reference to a Tunnel.
type TunnelRef struct {
	// Name of the Tunnel. Required.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`
}
