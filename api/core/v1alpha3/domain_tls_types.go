package v1alpha3

// DomainTLSSpec configures TLS certificate provisioning for a domain.
type DomainTLSSpec struct {
	// The Certificate Authority used to issue the TLS certificate.
	// Currently supports "letsencrypt".
	// +optional
	CertificateAuthority string `json:"certificateAuthority,omitempty"`
}
