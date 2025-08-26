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

// TunnelEndpoint represents a tunnel endpoint.
// It is created whenever an agent connects to a relay.
type TunnelEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TunnelEndpointSpec   `json:"spec,omitempty"`
	Status TunnelEndpointStatus `json:"status,omitempty"`
}

type TunnelEndpointSpec struct {
	// Reference to the TunnelAgent this endpoint belongs to.
	TunnelAgentRef TunnelAgentRef `json:"tunnelAgentRef"`
	// Public address/port of the endpoint.
	Address string `json:"address,omitempty"`
	// VNI is the GENEVE network identifier for this endpoint.
	VNI int `json:"vni,omitempty"`
	// TODO: the address of the relay this endpoint is connected to?
}

type TunnelEndpointStatus struct {
	// TODO: stats?
}

var _ resource.StatusSubResource = &TunnelEndpointStatus{}

func (ps *TunnelEndpointStatus) SubResourceName() string {
	return "status"
}

func (ps *TunnelEndpointStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*TunnelEndpoint).Status = *ps
}

var (
	_ runtime.Object                       = &TunnelEndpoint{}
	_ resource.Object                      = &TunnelEndpoint{}
	_ resource.ObjectWithStatusSubResource = &TunnelEndpoint{}
	_ rest.SingularNameProvider            = &TunnelEndpoint{}
)

func (p *TunnelEndpoint) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *TunnelEndpoint) NamespaceScoped() bool {
	return false
}

func (p *TunnelEndpoint) New() runtime.Object {
	return &TunnelEndpoint{}
}

func (p *TunnelEndpoint) NewList() runtime.Object {
	return &TunnelEndpointList{}
}

func (p *TunnelEndpoint) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "TunnelEndpoints",
	}
}

func (p *TunnelEndpoint) IsStorageVersion() bool {
	return true
}

func (p *TunnelEndpoint) GetSingularName() string {
	return "TunnelEndpoint"
}

func (p *TunnelEndpoint) GetStatus() resource.StatusSubResource {
	return &p.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TunnelEndpointList contains a list of TunnelEndpoint objects.
type TunnelEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TunnelEndpoint `json:"items"`
}

var _ resource.ObjectList = &TunnelEndpointList{}

func (pl *TunnelEndpointList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}
