package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/apoxy-dev/apoxy/api/resource"
	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

type VPCServiceSpec struct {
	// The VPCNetwork this service belongs to. Selection is scoped to Tunnels
	// of this network.
	// +required
	NetworkRef VPCNetworkRef `json:"networkRef"`

	// The DNS label under which the service is published in the project's
	// vpc zone: <hostname>.<network>.vpc.apoxy.net. Defaults to the object
	// name. Must be a valid DNS label; unique within the VPCNetwork
	// (enforced at admission).
	// +optional
	Hostname string `json:"hostname,omitempty"`

	// Selects member Tunnels by their labels (agents declare labels at
	// connect; the relay stamps them onto Tunnel metadata labels).
	// +required
	Selector *metav1.LabelSelector `json:"selector"`

	// The application protocol the members speak, using the Gateway API
	// (GEP-1911) vocabulary: "kubernetes.io/h2c" for cleartext HTTP/2 and
	// "grpc" for gRPC (which implies h2c). Empty means HTTP/1.1. Routes that
	// reference this service use it to pick the upstream protocol.
	// +optional
	AppProtocol string `json:"appProtocol,omitempty"`
}

// Application protocol values accepted in spec.appProtocol.
const (
	// AppProtocolH2C selects cleartext HTTP/2 (GEP-1911 standard value).
	AppProtocolH2C = "kubernetes.io/h2c"

	// AppProtocolGRPC selects gRPC, which is carried over cleartext HTTP/2.
	AppProtocolGRPC = "grpc"
)

// MembershipSelector converts spec.selector into the label selector used to
// pick member Tunnels, and is the single definition of which selectors are
// usable as a membership rule.
//
// It rejects the two degenerate shapes that LabelSelectorAsSelector maps to
// something silently surprising: nil becomes labels.Nothing() (the service can
// never have endpoints) and empty becomes labels.Everything() (every Tunnel in
// the network becomes a member). Neither is distinguishable from a spec whose
// author left the field out. Validation rejects both at admission, but every
// caller must re-check: update validation is ratcheted, so an object stored
// before that rule can still carry either shape, and expanding its empty
// selector into the whole network would publish unrelated members under its
// name.
func (s *VPCServiceSpec) MembershipSelector() (labels.Selector, error) {
	if s.Selector == nil {
		return nil, errors.New("no selector is set, so no Tunnel can ever be a member")
	}
	if len(s.Selector.MatchLabels) == 0 && len(s.Selector.MatchExpressions) == 0 {
		return nil, errors.New("the selector is empty, which would make every Tunnel in the network a member; " +
			"to select the whole network use matchExpressions with an Exists operator on " + LabelNetwork)
	}
	sel, err := metav1.LabelSelectorAsSelector(s.Selector)
	if err != nil {
		return nil, fmt.Errorf("the selector is not a valid label selector: %w", err)
	}
	return sel, nil
}

// VPCServiceEndpoint is one live member of the service.
type VPCServiceEndpoint struct {
	// The member Tunnel (one connection).
	TunnelRef TunnelRef `json:"tunnelRef"`

	// The member's overlay addresses. Plural per member (dual-stack); only
	// the IPv6 ULA is published to the shared DNS zone.
	// +optional
	Addresses []string `json:"addresses,omitempty"`
}

// VPCService condition types. Reconciled and Ready are deliberately separate:
// a service whose membership was computed correctly and came back empty is
// fully reconciled but not usable, and collapsing the two makes an
// unreachable service indistinguishable from a working one.
const (
	// VPCServiceConditionReconciled reports whether the endpoints view in
	// status reflects current membership. It is about the controller having
	// done its job, not about the service being usable.
	VPCServiceConditionReconciled = "Reconciled"

	// VPCServiceConditionReady reports whether the service has at least one
	// usable endpoint, i.e. whether traffic sent to its DNS name can land
	// anywhere.
	VPCServiceConditionReady = "Ready"
)

// VPCService condition reasons.
const (
	// VPCServiceReasonEndpointsComputed marks a successful membership
	// recompute (Reconciled).
	VPCServiceReasonEndpointsComputed = "EndpointsComputed"

	// VPCServiceReasonEndpointsAvailable marks a service with at least one
	// usable endpoint (Ready).
	VPCServiceReasonEndpointsAvailable = "EndpointsAvailable"

	// VPCServiceReasonNoEndpoints marks a reconciled service with no usable
	// endpoint: no member Tunnel matched, or the ones that did are not
	// carrying overlay addresses yet.
	VPCServiceReasonNoEndpoints = "NoEndpoints"

	// VPCServiceReasonNetworkNotFound marks a service whose spec.networkRef
	// names a VPCNetwork that does not exist. Admission rejects this at
	// create; it is still reachable by deleting the network afterwards.
	VPCServiceReasonNetworkNotFound = "NetworkNotFound"

	// VPCServiceReasonInvalidSelector marks a service whose spec.selector is
	// missing or cannot be converted to a label selector, so membership
	// cannot be computed at all.
	VPCServiceReasonInvalidSelector = "InvalidSelector"
)

type VPCServiceStatus struct {
	// Live members and their overlay addresses (the "endpoints view"). Only
	// usable members appear here: a Tunnel with no overlay address yet is
	// not an endpoint traffic can land on, so it is not counted as one.
	// +optional
	Endpoints []VPCServiceEndpoint `json:"endpoints,omitempty,omitzero"`

	// Conditions: Reconciled, Ready.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty,omitzero"`
}

var _ resource.StatusSubResource = &VPCServiceStatus{}

func (ps *VPCServiceStatus) SubResourceName() string {
	return "status"
}

func (ps *VPCServiceStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*VPCService)
	if ok {
		parent.Status = *ps
	}
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCService is service-like addressing over Tunnels, modeled on the
// Kubernetes Service: a label selector over Tunnel objects (which play
// Endpoints), a stable DNS name, and the target for DomainRecords and routes.
// User-authored.
type VPCService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the specification of the service.
	// +required
	Spec VPCServiceSpec `json:"spec,omitempty"`

	// Status is the status of the service.
	// +optional
	Status VPCServiceStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &VPCService{}
	_ resource.Object                      = &VPCService{}
	_ resource.ObjectWithStatusSubResource = &VPCService{}
	_ rest.SingularNameProvider            = &VPCService{}
	_ resourcestrategy.TableConverter      = &VPCService{}
)

func (s *VPCService) GetObjectMeta() *metav1.ObjectMeta {
	return &s.ObjectMeta
}

func (s *VPCService) NamespaceScoped() bool {
	return false
}

func (s *VPCService) New() runtime.Object {
	return &VPCService{}
}

func (s *VPCService) NewList() runtime.Object {
	return &VPCServiceList{}
}

func (s *VPCService) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "vpcservices",
	}
}

func (s *VPCService) IsStorageVersion() bool {
	return true
}

func (s *VPCService) GetSingularName() string {
	return "vpcservice"
}

func (s *VPCService) GetStatus() resource.StatusSubResource {
	return &s.Status
}

// DNSHostname returns the effective DNS label the service is published
// under: spec.hostname when set, the object name otherwise.
func (s *VPCService) DNSHostname() string {
	if s.Spec.Hostname != "" {
		return s.Spec.Hostname
	}
	return s.Name
}

// MemberAddrs returns the service's member endpoint addresses from
// status.endpoints. Members may be recorded as plain addresses or as prefixes
// (overlay /96s); the base address is returned either way. Entries that parse
// as neither are returned in skipped so callers can log them with their own
// context. This is the single parser for every DNS plane publishing
// VPCService members (backplane/Envoy, workerd resident push) — family
// filtering, when a plane needs it, is applied on the returned addrs.
func (s *VPCService) MemberAddrs() (addrs []netip.Addr, skipped []string) {
	for _, ep := range s.Status.Endpoints {
		for _, a := range ep.Addresses {
			addr, ok := parseMemberAddr(a)
			if !ok {
				skipped = append(skipped, a)
				continue
			}
			addrs = append(addrs, addr)
		}
	}
	return addrs, skipped
}

// parseMemberAddr parses one recorded member address, accepting both a plain
// address and an overlay prefix and returning the base address either way.
func parseMemberAddr(s string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr, true
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr(), true
	}
	return netip.Addr{}, false
}

// HasUsableAddress reports whether the member carries at least one address
// traffic can actually be sent to. A member with no addresses — or only
// garbage ones — resolves to nothing, so counting it as an endpoint would
// report a service as having members it cannot reach.
func (e VPCServiceEndpoint) HasUsableAddress() bool {
	for _, a := range e.Addresses {
		if _, ok := parseMemberAddr(a); ok {
			return true
		}
	}
	return false
}

// getVPCServiceSelector renders the member selector in kubectl's compact form.
func getVPCServiceSelector(s *VPCService) string {
	if s.Spec.Selector == nil {
		return "<none>"
	}
	return metav1.FormatLabelSelector(s.Spec.Selector)
}

// getVPCServiceReady renders the Ready condition's status and, when the
// service is not ready, the reason. A zero-endpoint service has to be
// distinguishable from a working one in default output, not just in -o yaml:
// the endpoint count alone never said whether 0 members was expected.
func getVPCServiceReady(s *VPCService) (status, reason string) {
	c := meta.FindStatusCondition(s.Status.Conditions, VPCServiceConditionReady)
	if c == nil {
		return "Unknown", ""
	}
	if c.Status == metav1.ConditionTrue {
		return string(c.Status), ""
	}
	return string(c.Status), c.Reason
}

func vpcServiceColumns() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: "Name of the service"},
		{Name: "Network", Type: "string", Description: "Owning VPCNetwork"},
		{Name: "Selector", Type: "string", Description: "Member Tunnel selector"},
		{Name: "Endpoints", Type: "string", Description: "Usable member count"},
		{Name: "Ready", Type: "string", Description: "Whether traffic to the service name can land on a member"},
		{Name: "Reason", Type: "string", Description: "Why the service is not ready"},
		{Name: "Age", Type: "string", Description: "Time since creation"},
	}
}

func vpcServiceRow(s *VPCService) metav1.TableRow {
	ready, reason := getVPCServiceReady(s)
	return metav1.TableRow{
		Cells: []interface{}{
			s.Name,
			s.Spec.NetworkRef.Name,
			getVPCServiceSelector(s),
			fmt.Sprintf("%d", len(s.Status.Endpoints)),
			ready,
			reason,
			formatAge(s.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: s},
	}
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (s *VPCService) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = vpcServiceColumns()
	}
	table.Rows = append(table.Rows, vpcServiceRow(s))
	table.ResourceVersion = s.ResourceVersion
	return table, nil
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCServiceList contains a list of VPCService objects.
type VPCServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPCService `json:"items"`
}

var (
	_ resource.ObjectList             = &VPCServiceList{}
	_ resourcestrategy.TableConverter = &VPCServiceList{}
)

func (sl *VPCServiceList) GetListMeta() *metav1.ListMeta {
	return &sl.ListMeta
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (sl *VPCServiceList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = vpcServiceColumns()
	}
	for i := range sl.Items {
		table.Rows = append(table.Rows, vpcServiceRow(&sl.Items[i]))
	}
	setListMeta(table, &sl.ListMeta)
	return table, nil
}

// VPCServiceRef is a reference to a VPCService.
type VPCServiceRef struct {
	// Name of the VPCService. Required.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`
}
