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

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TLSCertificate represents a TLS certificate and private key pair.
// This matches the Kubernetes TLS secret type but is specific to that use case.
// The public/private key pair must exist beforehand.
// The public key certificate must be PEM encoded and match the given private key.
type TLSCertificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TLSCertificateSpec   `json:"spec,omitempty"`
	Status TLSCertificateStatus `json:"status,omitempty"`
}

// TLSCertificateSpec defines the desired state of TLSCertificate
type TLSCertificateSpec struct {
	// Certificate is the PEM-encoded TLS certificate.
	// This should contain one or more certificate blocks.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Certificate string `json:"certificate"`

	// PrivateKey is the PEM-encoded private key corresponding to the certificate.
	// This must match the public key in the certificate.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	PrivateKey string `json:"privateKey"`
}

// TLSCertificateStatus defines the observed state of TLSCertificate
type TLSCertificateStatus struct {
	// NotBefore is the time before which the certificate is not valid.
	// +optional
	NotBefore *metav1.Time `json:"notBefore,omitempty"`

	// NotAfter is the time after which the certificate is not valid.
	// +optional
	NotAfter *metav1.Time `json:"notAfter,omitempty"`

	// Issuer is the issuer of the certificate.
	// +optional
	Issuer string `json:"issuer,omitempty"`

	// Subject is the subject of the certificate.
	// +optional
	Subject string `json:"subject,omitempty"`

	// DNSNames is the list of DNS names in the certificate's Subject Alternative Names.
	// +optional
	DNSNames []string `json:"dnsNames,omitempty"`

	// Conditions represent the latest available observations of the TLSCertificate's state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TLSCertificateList contains a list of TLSCertificate
type TLSCertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TLSCertificate `json:"items"`
}

// GetGroupVersionResource returns the GroupVersionResource for TLSCertificate.
func (in *TLSCertificate) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    GroupVersion.Group,
		Version:  GroupVersion.Version,
		Resource: "tlscertificates",
	}
}

// GetObjectMeta returns the object metadata for TLSCertificate.
func (in *TLSCertificate) GetObjectMeta() *metav1.ObjectMeta {
	return &in.ObjectMeta
}

// IsStorageVersion returns true if TLSCertificate is the storage version.
func (in *TLSCertificate) IsStorageVersion() bool {
	return true
}

// NamespaceScoped returns false as TLSCertificate is cluster-scoped.
func (in *TLSCertificate) NamespaceScoped() bool {
	return false
}

// New returns a new TLSCertificate.
func (in *TLSCertificate) New() runtime.Object {
	return &TLSCertificate{}
}

// NewList returns a new TLSCertificateList.
func (in *TLSCertificate) NewList() runtime.Object {
	return &TLSCertificateList{}
}

// GetStatus returns the status of the TLSCertificate.
func (in *TLSCertificate) GetStatus() resource.StatusSubResource {
	return in.Status
}

// TLSCertificateStatus implements the StatusSubResource interface.
var _ resource.StatusSubResource = &TLSCertificateStatus{}

func (in TLSCertificateStatus) SubResourceName() string {
	return "status"
}

// CopyTo copies the status to the given parent resource.
func (in TLSCertificateStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*TLSCertificate).Status = in
}

var _ resource.Object = &TLSCertificate{}
var _ resource.ObjectList = &TLSCertificateList{}
var _ resource.ObjectWithStatusSubResource = &TLSCertificate{}

// GetListMeta returns the list metadata.
func (in *TLSCertificateList) GetListMeta() *metav1.ListMeta {
	return &in.ListMeta
}

// TableConvertor returns a TableConvertor for TLSCertificate.
func (in *TLSCertificate) TableConvertor() rest.TableConvertor {
	return nil
}
