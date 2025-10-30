package v1alpha

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

// TunnelNode represents a node in the tunnel network.
type TunnelNode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TunnelNodeSpec   `json:"spec,omitempty"`
	Status TunnelNodeStatus `json:"status,omitempty"`
}

type EgressGatewaySpec struct {
	// Whether the egress gateway is enabled. Default is false.
	// When enabled, the egress gateway will be used to route traffic from the tunnel
	// node to the internet. Traffic will be SNAT'ed.
	// +optional
	Enabled bool `json:"enabled,omitempty"`
}

type TunnelNodeSpec struct {
	// Configures Egress Gateway mode on the Tunnel Node. In this mode, the Tunnel
	// Node acts as a gateway for outbound connections originating from the
	// Agent side in addition to its default mode (where the connections arrive in the
	// direction of the Agent).
	// +optional
	EgressGateway *EgressGatewaySpec `json:"egressGateway,omitempty"`

	// Specifies the default upstream used when this tunnel is referenced without
	// an explicit host and port to forward traffic to. If unspecified, the default
	// upstream is "127.0.0.1:8080".
	// +optional
	DefaultUpstream string `json:"defaultUpstream,omitempty"`
}

type AgentStatus struct {
	// Name is the name of the agent. Must be unique within the tunnel node.
	Name string `json:"name,omitempty"`

	// ConnectedAt is the time when the agent was connected to the tunnel node.
	ConnectedAt *metav1.Time `json:"connectedAt,omitempty"`

	// Private address of the proxy servicing the tunnel.
	// Valid values are IPv4, IPv6, or a hostname.
	PrivateAddress string `json:"privateAddress,omitempty"`

	// Overlay address of the agent. Currently we're using a /96 prefix which
	// can be used for 4in6 tunneling.
	AgentAddress string `json:"agentAddress,omitempty"`

	// Extra addresses of the agent (for additional v4/v6 overlays, if configured).
	// +optional
	AgentAddresses []string `json:"agentAddresses,omitempty"`
}

type TunnelNodeCredentials struct {
	// Signed JWT token for the tunnel transport connection.
	Token string `json:"token,omitempty"`
}

type TunnelNodeStatus struct {
	// One or more addresses used by agents to establish a tunnel.
	Addresses []string `json:"addresses,omitempty"`

	// Credentials for the tunnel node proxy.
	Credentials *TunnelNodeCredentials `json:"credentials,omitempty"`

	// Agents is a list of agents connected to the tunnel node.
	Agents []AgentStatus `json:"agents,omitempty"`
}

var _ resource.StatusSubResource = &TunnelNodeStatus{}

func (ps *TunnelNodeStatus) SubResourceName() string {
	return "status"
}

func (ps *TunnelNodeStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*TunnelNode).Status = *ps
}

var (
	_ runtime.Object                       = &TunnelNode{}
	_ resource.Object                      = &TunnelNode{}
	_ resource.ObjectWithStatusSubResource = &TunnelNode{}
	_ rest.SingularNameProvider            = &TunnelNode{}
)

func (p *TunnelNode) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *TunnelNode) NamespaceScoped() bool {
	return false
}

func (p *TunnelNode) New() runtime.Object {
	return &TunnelNode{}
}

func (p *TunnelNode) NewList() runtime.Object {
	return &TunnelNodeList{}
}

func (p *TunnelNode) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "tunnelnodes",
	}
}

func (p *TunnelNode) IsStorageVersion() bool {
	return true
}

func (p *TunnelNode) GetSingularName() string {
	return "tunnelnode"
}

func (p *TunnelNode) GetStatus() resource.StatusSubResource {
	return &p.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TunnelNodeList contains a list of TunnelNode objects.
type TunnelNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TunnelNode `json:"items"`
}

var _ resource.ObjectList = &TunnelNodeList{}

func (pl *TunnelNodeList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}
