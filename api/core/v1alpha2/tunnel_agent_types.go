package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:subresource:log

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TunnelAgent represents a tunnel agent.
type TunnelAgent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the specification of the tunnel agent.
	// +required
	Spec TunnelAgentSpec `json:"spec,omitempty,omitzero"`

	// Status is the status of the tunnel agent.
	// +optional
	Status TunnelAgentStatus `json:"status,omitempty,omitzero"`
}

// TunnelAgentSpec represents the specification of a tunnel agent.
type TunnelAgentSpec struct {
	// Reference to the Tunnel this agent belongs to.
	// +required
	TunnelRef TunnelRef `json:"tunnelRef,omitempty,omitzero"`
}

// TunnelAgentConnection represents a connection between a tunnel agent and a relay.
type TunnelAgentConnection struct {
	// ID is the unique identifier of the connection.
	// +required
	ID string `json:"id"`

	// ConnectedAt is the time when the agent was connected to the tunnel node.
	// +optional
	ConnectedAt *metav1.Time `json:"connectedAt,omitempty,omitzero"`

	// Address is the address of the agent assigned to this connection.
	// +optional
	Address string `json:"address,omitempty,omitzero"`

	// RelayAddress is the address of the relay managing this connection.
	// +optional
	RelayAddress string `json:"relayAddress,omitempty,omitzero"`

	// VNI is the virtual network identifier assigned to this connection.
	// +optional
	VNI uint32 `json:"vni,omitempty,omitzero"`
}

// TunnelAgentStatus represents the status of a tunnel agent.
type TunnelAgentStatus struct {
	// Overlay CIDR of the agent. Currently we're using a /96 prefix which
	// can be used for 4in6 tunneling.
	// +optional
	Prefix string `json:"prefix,omitempty,omitzero"`

	// Connections are active connections between the agent and (potentially multiple) relays.
	// +optional
	Connections []TunnelAgentConnection `json:"connections,omitempty,omitzero"`
}

var _ resource.StatusSubResource = &TunnelAgentStatus{}

func (ps *TunnelAgentStatus) SubResourceName() string {
	return "status"
}

func (ps *TunnelAgentStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*TunnelAgent).Status = *ps
}

var (
	_ runtime.Object                       = &TunnelAgent{}
	_ resource.Object                      = &TunnelAgent{}
	_ resource.ObjectWithStatusSubResource = &TunnelAgent{}
	_ rest.SingularNameProvider            = &TunnelAgent{}
)

func (p *TunnelAgent) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *TunnelAgent) NamespaceScoped() bool {
	return false
}

func (p *TunnelAgent) New() runtime.Object {
	return &TunnelAgent{}
}

func (p *TunnelAgent) NewList() runtime.Object {
	return &TunnelAgentList{}
}

func (p *TunnelAgent) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "TunnelAgents",
	}
}

func (p *TunnelAgent) IsStorageVersion() bool {
	return true
}

func (p *TunnelAgent) GetSingularName() string {
	return "TunnelAgent"
}

func (p *TunnelAgent) GetStatus() resource.StatusSubResource {
	return &p.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TunnelAgentList contains a list of TunnelAgent objects.
type TunnelAgentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TunnelAgent `json:"items"`
}

var _ resource.ObjectList = &TunnelAgentList{}

func (pl *TunnelAgentList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// TunnelAgentRef is a reference to a TunnelAgent.
type TunnelAgentRef struct {
	// Name of the tunnel agent. Required.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}
