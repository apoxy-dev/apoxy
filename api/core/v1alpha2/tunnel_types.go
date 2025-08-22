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

// Tunnel represents a tunnel network.
type Tunnel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TunnelSpec   `json:"spec,omitempty"`
	Status TunnelStatus `json:"status,omitempty"`
}

type EgressGatewaySpec struct {
	// Whether the egress gateway is enabled. Default is false.
	// When enabled, the egress gateway will be used to route traffic from the
	// tunnel client to the internet. Traffic will be SNAT'ed.
	// +optional
	Enabled bool `json:"enabled,omitempty"`
}

type TunnelSpec struct {
	// Configures egress gateway mode on the tunnel. In this mode, the tunnel
	// server acts as a gateway for outbound connections originating from the
	// client side in addition to its default mode (where the connections
	// arrive in the direction of the client).
	// +optional
	EgressGateway *EgressGatewaySpec `json:"egressGateway,omitempty"`
	// FUTURE (dpeckett): Add a JWKS URL for validating per endpoint JWTs.
}

type TunnelCredentials struct {
	// Bearer token for authentication with the tunnel server.
	Token string `json:"token,omitempty"`
	// FUTURE (dpeckett): We should use per endpoint JWTs instead of a single token.
}

type TunnelStatus struct {
	// A list of public addresses of the server instances for this network.
	Addresses []string `json:"addresses,omitempty"`
	// Credentials for the tunnel server.
	Credentials *TunnelCredentials `json:"credentials,omitempty"`
}

var _ resource.StatusSubResource = &TunnelStatus{}

func (ps *TunnelStatus) SubResourceName() string {
	return "status"
}

func (ps *TunnelStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*Tunnel).Status = *ps
}

var (
	_ runtime.Object                       = &Tunnel{}
	_ resource.Object                      = &Tunnel{}
	_ resource.ObjectWithStatusSubResource = &Tunnel{}
	_ rest.SingularNameProvider            = &Tunnel{}
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
		Resource: "Tunnels",
	}
}

func (p *Tunnel) IsStorageVersion() bool {
	return true
}

func (p *Tunnel) GetSingularName() string {
	return "Tunnel"
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
