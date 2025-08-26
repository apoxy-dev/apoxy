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

	Spec   TunnelAgentSpec   `json:"spec,omitempty"`
	Status TunnelAgentStatus `json:"status,omitempty"`
}

type TunnelAgentSpec struct {
	// Reference to the Tunnel this agent belongs to.
	TunnelRef TunnelRef `json:"tunnelRef"`
}

type TunnelCredentials struct {
	// Bearer token for authentication with tunnel relays.
	Token string `json:"token,omitempty"`
}

type TunnelAgentStatus struct {
	// Credentials for authenticating with tunnel relays.
	Credentials *TunnelCredentials `json:"credentials,omitempty"`
	// Overlay CIDR of the agent. Currently we're using a /96 prefix which
	// can be used for 4in6 tunneling.
	Prefix string `json:"prefix,omitempty"`
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
