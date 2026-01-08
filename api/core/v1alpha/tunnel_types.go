package v1alpha

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/duration"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
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

// formatAge formats a time as a Kubernetes-style age string.
func formatAge(t time.Time) string {
	if t.IsZero() {
		return "<unknown>"
	}
	return duration.ShortHumanDuration(time.Since(t))
}

// getOverlayAddresses collects overlay addresses from all agents.
func getOverlayAddresses(agents []AgentStatus) string {
	var addrs []string
	for _, agent := range agents {
		if agent.AgentAddress != "" {
			addrs = append(addrs, agent.AgentAddress)
		}
		addrs = append(addrs, agent.AgentAddresses...)
	}
	if len(addrs) == 0 {
		return "<none>"
	}
	return strings.Join(addrs, ",")
}

// getEndpoints returns the public endpoints as a string.
func getEndpoints(addresses []string) string {
	if len(addresses) == 0 {
		return "<none>"
	}
	return strings.Join(addresses, ",")
}

var _ resourcestrategy.TableConverter = &TunnelNode{}

func (tn *TunnelNode) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return tunnelNodeToTable(tn, tableOptions)
}

func tunnelNodeToTable(tn *TunnelNode, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the tunnel node"},
			{Name: "Endpoints", Type: "string", Description: "Public endpoints for tunnel connections"},
			{Name: "Overlay Addresses", Type: "string", Description: "Overlay network addresses"},
			{Name: "Agents", Type: "string", Description: "Number of connected agents"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	table.Rows = append(table.Rows, metav1.TableRow{
		Cells: []interface{}{
			tn.Name,
			getEndpoints(tn.Status.Addresses),
			getOverlayAddresses(tn.Status.Agents),
			fmt.Sprintf("%d", len(tn.Status.Agents)),
			formatAge(tn.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: tn},
	})
	table.ResourceVersion = tn.ResourceVersion
	return table, nil
}

var _ resourcestrategy.TableConverter = &TunnelNodeList{}

func (l *TunnelNodeList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the tunnel node"},
			{Name: "Endpoints", Type: "string", Description: "Public endpoints for tunnel connections"},
			{Name: "Overlay Addresses", Type: "string", Description: "Overlay network addresses"},
			{Name: "Agents", Type: "string", Description: "Number of connected agents"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	for i := range l.Items {
		tn := &l.Items[i]
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				tn.Name,
				getEndpoints(tn.Status.Addresses),
				getOverlayAddresses(tn.Status.Agents),
				fmt.Sprintf("%d", len(tn.Status.Agents)),
				formatAge(tn.CreationTimestamp.Time),
			},
			Object: runtime.RawExtension{Object: tn},
		})
	}
	table.ResourceVersion = l.ResourceVersion
	table.Continue = l.Continue
	table.RemainingItemCount = l.RemainingItemCount
	return table, nil
}
