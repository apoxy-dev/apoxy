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

// RelaySpec is write-once: created by the relay on start (or selector
// change), deleted on shutdown, never mutated in steady state. Liveness lives
// in the relay's Lease, not here.
type RelaySpec struct {
	// Underlay host:port endpoints agents dial (QUIC control and Geneve data
	// share the port).
	// +required
	Addresses []string `json:"addresses"`

	// Scopes which networks this relay serves. Empty selects all networks.
	// +optional
	NetworkSelector *metav1.LabelSelector `json:"networkSelector,omitempty"`
}

type RelayStatus struct {
	// Alive-and-accepting. Flipped by the lease watcher on expiry/renewal
	// transitions (crash) and by the relay itself at drain start. The only
	// liveness signal consumers see; count connections via Tunnels by
	// relayRef.
	// +optional
	Ready bool `json:"ready,omitempty"`

	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty,omitzero"`
}

var _ resource.StatusSubResource = &RelayStatus{}

func (ps *RelayStatus) SubResourceName() string {
	return "status"
}

func (ps *RelayStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*Relay)
	if ok {
		parent.Status = *ps
	}
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Relay tracks one relay instance serving tunnel connections.
type Relay struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the specification of the relay.
	// +required
	Spec RelaySpec `json:"spec,omitempty"`

	// Status is the status of the relay.
	// +optional
	Status RelayStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &Relay{}
	_ resource.Object                      = &Relay{}
	_ resource.ObjectWithStatusSubResource = &Relay{}
	_ rest.SingularNameProvider            = &Relay{}
	_ resourcestrategy.TableConverter      = &Relay{}
)

func (r *Relay) GetObjectMeta() *metav1.ObjectMeta {
	return &r.ObjectMeta
}

func (r *Relay) NamespaceScoped() bool {
	return false
}

func (r *Relay) New() runtime.Object {
	return &Relay{}
}

func (r *Relay) NewList() runtime.Object {
	return &RelayList{}
}

func (r *Relay) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "relays",
	}
}

func (r *Relay) IsStorageVersion() bool {
	return true
}

func (r *Relay) GetSingularName() string {
	return "relay"
}

func (r *Relay) GetStatus() resource.StatusSubResource {
	return &r.Status
}

// getRelayReady renders the readiness bit kubectl-style.
func getRelayReady(r *Relay) string {
	if r.Status.Ready {
		return "True"
	}
	return "False"
}

func relayColumns() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: "Name of the relay"},
		{Name: "Addresses", Type: "string", Description: "Underlay endpoints agents dial"},
		{Name: "Ready", Type: "string", Description: "Alive and accepting connections"},
		{Name: "Age", Type: "string", Description: "Time since creation"},
	}
}

func relayRow(r *Relay) metav1.TableRow {
	return metav1.TableRow{
		Cells: []interface{}{
			r.Name,
			strings.Join(r.Spec.Addresses, ","),
			getRelayReady(r),
			formatAge(r.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: r},
	}
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (r *Relay) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = relayColumns()
	}
	table.Rows = append(table.Rows, relayRow(r))
	table.ResourceVersion = r.ResourceVersion
	return table, nil
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RelayList contains a list of Relay objects.
type RelayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Relay `json:"items"`
}

var (
	_ resource.ObjectList             = &RelayList{}
	_ resourcestrategy.TableConverter = &RelayList{}
)

func (rl *RelayList) GetListMeta() *metav1.ListMeta {
	return &rl.ListMeta
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (rl *RelayList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if !noHeaders(tableOptions) {
		table.ColumnDefinitions = relayColumns()
	}
	for i := range rl.Items {
		table.Rows = append(table.Rows, relayRow(&rl.Items[i]))
	}
	setListMeta(table, &rl.ListMeta)
	return table, nil
}

// RelayRef is a reference to a Relay.
type RelayRef struct {
	// Name of the Relay. Required.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`
}
