package v1alpha3

// DomainTLSSpec configures TLS certificate provisioning for a domain.
type DomainTLSSpec struct {
	// The Certificate Authority used to issue the TLS certificate.
	// Currently supports "letsencrypt".
	// +optional
	CertificateAuthority string `json:"certificateAuthority,omitempty"`

	// Disabled turns off certificate provisioning for this domain, leaving it
	// served over plain HTTP.
	//
	// TLS is the default for every ref target — omitting the whole `tls` block
	// gets you a managed certificate — so this field is the only way to ask
	// for an HTTP-only hostname. Use it when traffic must flow before a
	// certificate can exist: during a migration you can prove ownership with
	// the `_apoxy-challenge` delegation, serve HTTP immediately, then clear
	// this field to have the certificate issued.
	//
	// A domain that already holds a certificate keeps serving it until the
	// certificate is removed; setting this only stops future issuance and
	// renewal.
	// +optional
	Disabled bool `json:"disabled,omitempty"`
}

// Enabled reports whether Apoxy should provision and serve a certificate for
// this domain. A nil spec means no TLS at all (the shape non-ref targets
// carry); a present spec means TLS unless it was explicitly disabled.
func (s *DomainTLSSpec) Enabled() bool {
	return s != nil && !s.Disabled
}
