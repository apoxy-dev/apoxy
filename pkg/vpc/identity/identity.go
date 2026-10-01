// Package identity is the VPC agent identity: the SPIFFE ID in agent certs,
// the cert check that relays and peers use, and the enroll client.
package identity

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

// CertLifetime is the life of an agent cert.
const CertLifetime = 24 * time.Hour

// ID names one agent in one VPC of one project. Its URI form is
// spiffe://<project>/vpc/<vpc-uid>/agent/<name>.
type ID struct {
	// Project ID. It is the SPIFFE trust domain.
	Project string
	// UID of the VPCNetwork.
	VPC string
	// Agent name, a DNS label.
	Agent string
}

// URI returns the SPIFFE ID of id.
func (id ID) URI() *url.URL {
	return &url.URL{Scheme: "spiffe", Host: id.Project, Path: "/vpc/" + id.VPC + "/agent/" + id.Agent}
}

func (id ID) String() string { return id.URI().String() }

// Validate checks each part of id.
func (id ID) Validate() error {
	if err := validateTrustDomain(id.Project); err != nil {
		return fmt.Errorf("invalid project %q: %w", id.Project, err)
	}
	if err := validateSegment(id.VPC); err != nil {
		return fmt.Errorf("invalid VPC UID %q: %w", id.VPC, err)
	}
	return ValidateAgentName(id.Agent)
}

// ValidateAgentName checks that name is a DNS label.
func ValidateAgentName(name string) error {
	if errs := validation.IsDNS1123Label(name); len(errs) > 0 {
		return fmt.Errorf("invalid agent name %q: %s", name, strings.Join(errs, "; "))
	}
	return nil
}

// ParseID parses a SPIFFE ID of the form spiffe://<project>/vpc/<vpc-uid>/agent/<name>.
func ParseID(s string) (ID, error) {
	u, err := url.Parse(s)
	if err != nil {
		return ID{}, fmt.Errorf("invalid SPIFFE ID %q: %w", s, err)
	}
	return parseURI(u)
}

func parseURI(u *url.URL) (ID, error) {
	if u.Scheme != "spiffe" || u.Opaque != "" || u.User != nil || u.Port() != "" ||
		u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return ID{}, fmt.Errorf("SPIFFE ID %q is not of the form spiffe://<project>/vpc/<vpc-uid>/agent/<name>", u)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "vpc" || parts[2] != "agent" {
		return ID{}, fmt.Errorf("SPIFFE ID %q is not of the form spiffe://<project>/vpc/<vpc-uid>/agent/<name>", u)
	}
	id := ID{Project: u.Host, VPC: parts[1], Agent: parts[3]}
	if err := id.Validate(); err != nil {
		return ID{}, err
	}
	return id, nil
}

// IDFromCert returns the ID in the one URI SAN of cert.
func IDFromCert(cert *x509.Certificate) (ID, error) {
	if len(cert.URIs) != 1 {
		return ID{}, fmt.Errorf("agent cert must have exactly one URI SAN, it has %d", len(cert.URIs))
	}
	return parseURI(cert.URIs[0])
}

// validateTrustDomain applies the SPIFFE trust domain rules.
func validateTrustDomain(s string) error {
	if s == "" || len(s) > 255 {
		return errors.New("must be 1-255 characters")
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return errors.New("must contain only lowercase letters, digits, '.', '-' and '_'")
		}
	}
	return nil
}

// validateSegment applies the SPIFFE path segment rules.
func validateSegment(s string) error {
	if s == "" || s == "." || s == ".." {
		return errors.New("must not be empty, '.' or '..'")
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return errors.New("must contain only letters, digits, '.', '-' and '_'")
		}
	}
	return nil
}
