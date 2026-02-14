package v1alpha2

import (
	"context"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type DomainZone struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec DomainZoneSpec `json:"spec,omitempty"`

	Status DomainZoneStatus `json:"status,omitempty"`
}

type DomainZoneSpec struct {
	// RegistrationConfig contains configuration for domain registration.
	// +optional
	RegistrationConfig *RegistrationConfig `json:"registrationConfig,omitempty"`

	// Nameservers to use for this domain zone.
	// If not specified, defaults to Apoxy's nameservers.
	// +optional
	Nameservers []string `json:"nameservers,omitempty"`
}

// RegistrationConfig contains configuration for domain registration.
type RegistrationConfig struct {
	// AutoRenew indicates whether the domain should be automatically renewed.
	// +optional
	AutoRenew bool `json:"autoRenew,omitempty"`

	// RegistrationPeriodYears is the number of years to register the domain for.
	// +optional
	RegistrationPeriodYears int `json:"registrationPeriodYears,omitempty"`

	// Registrant contains the registrant contact information.
	// +optional
	Registrant *Registrant `json:"registrant,omitempty"`
}

// Registrant contains contact information for domain registration.
type Registrant struct {
	// FirstName of the registrant.
	// +optional
	FirstName string `json:"firstName,omitempty"`

	// LastName of the registrant.
	// +optional
	LastName string `json:"lastName,omitempty"`

	// Email of the registrant.
	// +optional
	Email string `json:"email,omitempty"`

	// Phone number of the registrant.
	// +optional
	Phone string `json:"phone,omitempty"`

	// Organization of the registrant.
	// +optional
	Organization string `json:"organization,omitempty"`

	// Address of the registrant.
	// +optional
	Address *Address `json:"address,omitempty"`
}

// Address contains postal address information.
type Address struct {
	// Address line 1.
	// +optional
	AddressLine1 string `json:"addressLine1,omitempty"`

	// Address line 2.
	// +optional
	AddressLine2 string `json:"addressLine2,omitempty"`

	// City.
	// +optional
	City string `json:"city,omitempty"`

	// State or province.
	// +optional
	StateProvince string `json:"stateProvince,omitempty"`

	// PostalCode or ZIP code.
	// +optional
	PostalCode string `json:"postalCode,omitempty"`

	// Country code (ISO 3166-1 alpha-2).
	// +optional
	Country string `json:"country,omitempty"`
}

// DomainZonePhase is the phase of the domain zone.
type DomainZonePhase string

const (
	// Indicates that the domain zone is pending.
	// In order to become active, the domain owner must update the
	// nameservers with the registrar to point to the Apoxy nameservers.
	DomainZonePhasePending DomainZonePhase = "Pending"
	// PaymentRequired indicates that payment is required for domain registration.
	DomainZonePhasePaymentRequired DomainZonePhase = "PaymentRequired"
	// Registering indicates that domain registration is in progress.
	DomainZonePhaseRegistering DomainZonePhase = "Registering"
	// PendingNameservers indicates that the domain is registered but nameservers need to be updated.
	DomainZonePhasePendingNameservers DomainZonePhase = "PendingNameservers"
	// Active phase of the domain zone. User can create records in the domain zone.
	DomainZonePhaseActive DomainZonePhase = "Active"
	// Expiring indicates that the domain is expiring soon and needs renewal.
	DomainZonePhaseExpiring DomainZonePhase = "Expiring"
	// Expired indicates that the domain has expired.
	DomainZonePhaseExpired DomainZonePhase = "Expired"
	// Error indicates that an unrecoverable error occurred.
	DomainZonePhaseError DomainZonePhase = "Error"
)

type DomainZoneStatus struct {
	// Phase of the domain zone.
	Phase DomainZonePhase `json:"phase,omitempty"`

	// RegistrationStatus contains information about domain registration.
	// +optional
	RegistrationStatus *RegistrationStatus `json:"registrationStatus,omitempty"`

	// Nameservers contains information about nameserver configuration.
	// +optional
	Nameservers *NameserverStatus `json:"nameservers,omitempty"`

	// Conditions of the domain zone.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// RegistrationStatus contains information about domain registration.
type RegistrationStatus struct {
	// RegistrationID is the unique identifier for the registration.
	// +optional
	RegistrationID string `json:"registrationID,omitempty"`

	// EstimatedCost is the estimated cost for registration or renewal.
	// +optional
	EstimatedCost string `json:"estimatedCost,omitempty"`

	// PaymentURL is the URL to complete payment for registration or renewal.
	// +optional
	PaymentURL string `json:"paymentURL,omitempty"`

	// RegisteredAt is the time when the domain was registered.
	// +optional
	RegisteredAt *metav1.Time `json:"registeredAt,omitempty"`

	// ExpiresAt is the time when the domain registration expires.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// Error contains error information if registration failed.
	// +optional
	Error string `json:"error,omitempty"`
}

// NameserverStatus contains information about nameserver configuration.
type NameserverStatus struct {
	// Required nameservers that should be configured.
	// +optional
	Required []string `json:"required,omitempty"`

	// Current nameservers that are actually configured.
	// +optional
	Current []string `json:"current,omitempty"`
}

var _ resource.StatusSubResource = &DomainZoneStatus{}

func (as *DomainZoneStatus) SubResourceName() string {
	return "status"
}

func (as *DomainZoneStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*DomainZone)
	if ok {
		parent.Status = *as
	}
}

var (
	_ runtime.Object                       = &DomainZone{}
	_ resource.Object                      = &DomainZone{}
	_ resource.ObjectWithStatusSubResource = &DomainZone{}
	_ rest.SingularNameProvider            = &DomainZone{}
	_ resourcestrategy.TableConverter      = &DomainZone{}
)

func (a *DomainZone) GetObjectMeta() *metav1.ObjectMeta {
	return &a.ObjectMeta
}

func (a *DomainZone) NamespaceScoped() bool {
	return false
}

func (a *DomainZone) New() runtime.Object {
	return &DomainZone{}
}

func (a *DomainZone) NewList() runtime.Object {
	return &DomainZoneList{}
}

func (a *DomainZone) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "domainzones",
	}
}

func (a *DomainZone) IsStorageVersion() bool {
	return true
}

func (a *DomainZone) GetSingularName() string {
	return "domainzones"
}

func (a *DomainZone) GetStatus() resource.StatusSubResource {
	return &a.Status
}

//+kubebuilder:object:root=true
//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DomainZoneList is a list of Domain resources.
type DomainZoneList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DomainZone `json:"items"`
}

var (
	_ resource.ObjectList             = &DomainZoneList{}
	_ resourcestrategy.TableConverter = &DomainZoneList{}
)

func (pl *DomainZoneList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// ConvertToTable implements rest.TableConvertor for pretty printing.
func (dz *DomainZone) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the domain zone"},
			{Name: "Status", Type: "string", Description: "Current phase of the domain zone"},
			{Name: "Nameservers", Type: "string", Description: "Required nameservers"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	table.Rows = append(table.Rows, metav1.TableRow{
		Cells: []interface{}{
			dz.Name,
			string(dz.Status.Phase),
			getDomainZoneNameservers(dz),
			formatAge(dz.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: dz},
	})
	table.ResourceVersion = dz.ResourceVersion
	return table, nil
}

// ConvertToTable implements rest.TableConvertor for pretty printing.
func (dzl *DomainZoneList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the domain zone"},
			{Name: "Status", Type: "string", Description: "Current phase of the domain zone"},
			{Name: "Nameservers", Type: "string", Description: "Required nameservers"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	for i := range dzl.Items {
		dz := &dzl.Items[i]
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				dz.Name,
				string(dz.Status.Phase),
				getDomainZoneNameservers(dz),
				formatAge(dz.CreationTimestamp.Time),
			},
			Object: runtime.RawExtension{Object: dz},
		})
	}
	table.ResourceVersion = dzl.ResourceVersion
	table.Continue = dzl.Continue
	table.RemainingItemCount = dzl.RemainingItemCount
	return table, nil
}

func getDomainZoneNameservers(dz *DomainZone) string {
	if dz.Status.Nameservers == nil || len(dz.Status.Nameservers.Required) == 0 {
		return ""
	}
	return strings.Join(dz.Status.Nameservers.Required, ",")
}
