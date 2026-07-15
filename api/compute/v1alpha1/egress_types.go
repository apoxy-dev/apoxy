package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/apoxy-dev/apoxy/api/resource"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

// =============================================================================
// EgressGateway
// =============================================================================

// DefaultEgressGatewayName is the well-known gateway name a Service resolves
// to when it has no egress block (or an empty gatewayRef). The name always
// resolves: when no EgressGateway object with this name exists, the control
// plane compiles a built-in allow-all gateway, so egress works out of the box
// (Cloudflare parity). Creating an EgressGateway named "default" overrides
// the built-in — e.g. to tighten the project-wide default policy.
const DefaultEgressGatewayName = "default"

// EgressControllerName identifies the compute egress controller in
// EgressRoute status.parents entries.
const EgressControllerName gwapiv1.GatewayController = "compute.apoxy.dev/egress-controller"

// EgressDefaultPolicy controls the action for outbound traffic matching no
// attached EgressRoute rule.
// +kubebuilder:validation:Enum=allow-all;deny-all
type EgressDefaultPolicy string

const (
	EgressPolicyAllowAll EgressDefaultPolicy = "allow-all"
	EgressPolicyDenyAll  EgressDefaultPolicy = "deny-all"
)

// EgressListenerProtocol selects the interception layer of a listener. UDP is
// deliberately absent: the sandbox netstack is fail-closed on UDP and the
// gateway data plane has no UDP shape.
// +kubebuilder:validation:Enum=TCP;TLS;HTTP;HTTPS
type EgressListenerProtocol string

const (
	EgressProtocolTCP   EgressListenerProtocol = "TCP"
	EgressProtocolTLS   EgressListenerProtocol = "TLS"
	EgressProtocolHTTP  EgressListenerProtocol = "HTTP"
	EgressProtocolHTTPS EgressListenerProtocol = "HTTPS"
)

// EgressTLSMode controls TLS handling on a listener.
// +kubebuilder:validation:Enum=Passthrough;Terminate
type EgressTLSMode string

const (
	EgressTLSPassthrough EgressTLSMode = "Passthrough"
	EgressTLSTerminate   EgressTLSMode = "Terminate"
)

// SecretKeyRef names one key of a core.apoxy.dev SecretStore (cluster-scoped,
// same project). The project apiserver has no corev1 Secrets; SecretStore is
// its only secret primitive, so egress reuses the same store+key addressing
// as SecretBinding. The store's scopes must admit the "compute" surface; that
// check happens at resolve time in the control plane, not at admission.
type SecretKeyRef struct {
	// Store names the SecretStore.
	Store corev1alpha.ObjectName `json:"store"`
	// Key within the store's values map.
	Key string `json:"key"`
}

// EgressListenerTLS configures TLS handling for a listener.
type EgressListenerTLS struct {
	// Mode controls TLS handling.
	//   Passthrough: SNI-route only, no termination.
	//   Terminate:   MITM decrypt for L7 inspection, re-encrypt to upstream.
	// +optional
	// +kubebuilder:default=Passthrough
	Mode EgressTLSMode `json:"mode,omitempty"`

	// CACertRef names the SecretStore key holding the PEM-encoded CA
	// certificate + key bundle used for on-the-fly certificate minting.
	// Required when mode=Terminate; forbidden for Passthrough.
	// +optional
	CACertRef *SecretKeyRef `json:"caCertRef,omitempty"`
}

// EgressListener declares an interception capability by protocol layer.
// Routes reference a listener via parentRef.sectionName.
type EgressListener struct {
	// Name identifies this listener within the gateway.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`

	// Protocol selects the interception layer.
	Protocol EgressListenerProtocol `json:"protocol"`

	// Port constrains interception to a single destination port. If unset,
	// all ports are intercepted at this protocol layer.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port *int32 `json:"port,omitempty"`

	// TLS configures TLS handling. Only meaningful when protocol=TLS
	// (Passthrough vs Terminate); forbidden for TCP/HTTP/HTTPS.
	// +optional
	TLS *EgressListenerTLS `json:"tls,omitempty"`
}

// EgressGatewaySpec defines the desired state of an EgressGateway.
type EgressGatewaySpec struct {
	// DefaultPolicy applies to traffic that matches no attached route.
	// Defaults to deny-all: an explicitly created gateway fails closed. (The
	// implicit built-in "default" gateway — which exists only when no object
	// named "default" does — is allow-all; see DefaultEgressGatewayName.)
	// +optional
	// +kubebuilder:default=deny-all
	DefaultPolicy EgressDefaultPolicy `json:"defaultPolicy,omitempty"`

	// Listeners declare interception capabilities by protocol layer.
	// Routes attach to a specific listener by name via parentRef.sectionName.
	// +kubebuilder:validation:MinItems=1
	Listeners []EgressListener `json:"listeners"`
}

// EgressGatewayConditionReady is the readiness summary on
// EgressGateway.Status.Conditions. The control plane only pushes a
// listener's BackendAddress to the data plane once Ready=True.
const EgressGatewayConditionReady = "Ready"

// EgressListenerStatus describes the observed state of a single listener.
type EgressListenerStatus struct {
	Name string `json:"name"`

	// Port is the TCP port the gateway data plane listens on for this
	// listener.
	// +optional
	Port int32 `json:"port,omitempty"`

	// BackendAddress is the host:port the sandbox-side dialer uses to reach
	// this listener's data plane. Empty means the listener exists but its
	// data plane isn't ready yet; the dialer skips it.
	// +optional
	BackendAddress string `json:"backendAddress,omitempty"`

	// AttachedRoutes counts the EgressRoutes attached to this listener.
	AttachedRoutes int32 `json:"attachedRoutes"`

	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// EgressGatewayStatus describes the observed state of an EgressGateway.
type EgressGatewayStatus struct {
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// +optional
	Listeners []EgressListenerStatus `json:"listeners,omitempty"`
}

var _ resource.StatusSubResource = &EgressGatewayStatus{}

func (s *EgressGatewayStatus) SubResourceName() string { return "status" }

func (s *EgressGatewayStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	if parent, ok := obj.(*EgressGateway); ok {
		parent.Status = *s
	}
}

// EgressGateway mediates outbound network access for compute Services.
// Egress is transparent to worker code: there are no bindings and no fetch
// wrapper — plain fetch() works, and enforcement happens host-side (sandbox
// netstack + gateway data plane), never inside workerd. A Service selects a
// gateway via spec.template.spec.egress.gatewayRef; with no egress block it
// uses the project "default" gateway (see DefaultEgressGatewayName).
//
// NOT YET ENFORCED: the egress control/data planes are still landing, and
// until they do the runtime denies all worker egress regardless of gateway
// configuration. The API is stable; these semantics take effect when
// enforcement ships.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type EgressGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              EgressGatewaySpec   `json:"spec,omitempty"`
	Status            EgressGatewayStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &EgressGateway{}
	_ resource.Object                      = &EgressGateway{}
	_ resource.ObjectWithStatusSubResource = &EgressGateway{}
	_ rest.SingularNameProvider            = &EgressGateway{}
)

func (g *EgressGateway) GetObjectMeta() *metav1.ObjectMeta     { return &g.ObjectMeta }
func (g *EgressGateway) NamespaceScoped() bool                 { return false }
func (g *EgressGateway) New() runtime.Object                   { return &EgressGateway{} }
func (g *EgressGateway) NewList() runtime.Object               { return &EgressGatewayList{} }
func (g *EgressGateway) IsStorageVersion() bool                { return true }
func (g *EgressGateway) GetSingularName() string               { return "egressgateway" }
func (g *EgressGateway) GetStatus() resource.StatusSubResource { return &g.Status }
func (g *EgressGateway) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "egressgateways",
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type EgressGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EgressGateway `json:"items"`
}

var _ resource.ObjectList = &EgressGatewayList{}

func (l *EgressGatewayList) GetListMeta() *metav1.ListMeta { return &l.ListMeta }

// =============================================================================
// EgressRoute
// =============================================================================

// EgressRouteProtocol selects the L4 protocol of a match. UDP is defined for
// forward compatibility but rejected by validation for now (the sandbox
// netstack is fail-closed on UDP).
// +kubebuilder:validation:Enum=TCP;UDP
type EgressRouteProtocol string

const (
	EgressRouteProtocolTCP EgressRouteProtocol = "TCP"
	EgressRouteProtocolUDP EgressRouteProtocol = "UDP"
)

// EgressPortMatch matches a single port or an inclusive port range.
// Exactly one of Port or the StartPort/EndPort pair must be set.
type EgressPortMatch struct {
	// Port matches a single destination port.
	// +optional
	Port *int32 `json:"port,omitempty"`

	// StartPort + EndPort define an inclusive range. Both must be set
	// together. Mutually exclusive with Port.
	// +optional
	StartPort *int32 `json:"startPort,omitempty"`
	// +optional
	EndPort *int32 `json:"endPort,omitempty"`
}

// EgressRouteMatch defines match criteria for outbound traffic. Dimensions
// are ANDed within a match; matches are ORed within a rule.
type EgressRouteMatch struct {
	// DestinationCIDRs matches by IP range. Single IPs as /32 or /128.
	// IPv4 and IPv6 CIDRs are both honored.
	// +optional
	// +listType=set
	DestinationCIDRs []string `json:"destinationCIDRs,omitempty"`

	// DestinationHostnames matches by hostname. Exact (`api.openai.com`) and
	// wildcard (`*.openai.com`) forms are accepted (gwapiv1.Hostname
	// semantics — a wildcard matches exactly one prefix label). On
	// TLS-terminated listeners the match runs against SNI.
	// +optional
	// +listType=set
	DestinationHostnames []gwapiv1.Hostname `json:"destinationHostnames,omitempty"`

	// Ports restricts to specific destination ports or port ranges.
	// +optional
	Ports []EgressPortMatch `json:"ports,omitempty"`

	// Protocol selects TCP or UDP. If unset, inherits from the parent
	// listener. UDP is not yet supported.
	// +optional
	Protocol *EgressRouteProtocol `json:"protocol,omitempty"`
}

// EgressRouteRule defines one allow rule within an EgressRoute.
//
// A `mode` field (values: gateway | direct, default gateway) is RESERVED
// here for per-destination egress mode selection: `gateway` transits the
// EgressGateway data plane; `direct` is policy-checked in the host netstack
// but dials upstream without gateway transit. It is intentionally not
// defined yet — its compiled wire slot is the reserved field 6 of
// apoxy.workerd.v1.EgressRule.
type EgressRouteRule struct {
	// Matches lists the destinations this rule admits.
	// +kubebuilder:validation:MinItems=1
	Matches []EgressRouteMatch `json:"matches"`
}

// EgressRouteSpec defines the desired state of an EgressRoute.
type EgressRouteSpec struct {
	// ParentRefs attaches this route to EgressGateway listeners. Group and
	// kind default to compute.apoxy.dev/EgressGateway and, when set, must be
	// exactly that; namespace must be unset (all compute kinds are
	// cluster-scoped). sectionName selects a single listener by name; absent
	// attaches to every listener.
	// +kubebuilder:validation:MinItems=1
	ParentRefs []gwapiv1.ParentReference `json:"parentRefs"`

	// +kubebuilder:validation:MinItems=1
	Rules []EgressRouteRule `json:"rules"`
}

// EgressRouteStatus describes the observed state of an EgressRoute.
type EgressRouteStatus struct {
	// +optional
	Parents []gwapiv1.RouteParentStatus `json:"parents,omitempty"`
}

var _ resource.StatusSubResource = &EgressRouteStatus{}

func (s *EgressRouteStatus) SubResourceName() string { return "status" }

func (s *EgressRouteStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	if parent, ok := obj.(*EgressRoute); ok {
		parent.Status = *s
	}
}

// EgressRoute allows destination hostname/CIDR/port matched egress for the
// Services attached to its parent EgressGateway(s). Traffic matching no
// route falls to the gateway's defaultPolicy.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type EgressRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              EgressRouteSpec   `json:"spec,omitempty"`
	Status            EgressRouteStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &EgressRoute{}
	_ resource.Object                      = &EgressRoute{}
	_ resource.ObjectWithStatusSubResource = &EgressRoute{}
	_ rest.SingularNameProvider            = &EgressRoute{}
)

func (r *EgressRoute) GetObjectMeta() *metav1.ObjectMeta     { return &r.ObjectMeta }
func (r *EgressRoute) NamespaceScoped() bool                 { return false }
func (r *EgressRoute) New() runtime.Object                   { return &EgressRoute{} }
func (r *EgressRoute) NewList() runtime.Object               { return &EgressRouteList{} }
func (r *EgressRoute) IsStorageVersion() bool                { return true }
func (r *EgressRoute) GetSingularName() string               { return "egressroute" }
func (r *EgressRoute) GetStatus() resource.StatusSubResource { return &r.Status }
func (r *EgressRoute) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "egressroutes",
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type EgressRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EgressRoute `json:"items"`
}

var _ resource.ObjectList = &EgressRouteList{}

func (l *EgressRouteList) GetListMeta() *metav1.ListMeta { return &l.ListMeta }
