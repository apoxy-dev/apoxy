package identity

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
)

var (
	// ErrWrongProject is returned when the cert names another project.
	ErrWrongProject = errors.New("agent cert is for another project")
	// ErrWrongVPC is returned when the cert names another VPC.
	ErrWrongVPC = errors.New("agent cert is for another VPC")
	// ErrRevoked is returned when the revocation list matches the cert.
	ErrRevoked = errors.New("agent cert is revoked")
)

// VerifyOptions are the inputs of Verify.
type VerifyOptions struct {
	// CA bundle. Required.
	Roots *x509.CertPool
	// Project and VPC UID of the attach.
	Project string
	VPC     string
	// Revocation list of the VPC.
	Revoked []vpcv1alpha1.RevokedAgent
	// Time of the check. Zero means now.
	Now time.Time
	// Key usages the cert must allow. Nil means client auth.
	KeyUsages []x509.ExtKeyUsage
}

// Verify checks an agent cert chain (leaf first) with no network call: the
// chain goes to a CA in Roots, the cert is valid at Now, the SAN names the
// project and VPC of the attach, and the revocation list does not match.
func Verify(chain []*x509.Certificate, opts VerifyOptions) (ID, error) {
	if len(chain) == 0 {
		return ID{}, errors.New("no agent cert")
	}
	if opts.Roots == nil {
		return ID{}, errors.New("no CA bundle")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	usages := opts.KeyUsages
	if usages == nil {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     usages,
	}); err != nil {
		return ID{}, fmt.Errorf("agent cert does not verify: %w", err)
	}
	id, err := IDFromCert(leaf)
	if err != nil {
		return ID{}, err
	}
	if id.Project != opts.Project {
		return ID{}, ErrWrongProject
	}
	if id.VPC != opts.VPC {
		return ID{}, ErrWrongVPC
	}
	if IsRevoked(leaf, id.Agent, opts.Revoked) {
		return ID{}, ErrRevoked
	}
	return id, nil
}

// IsRevoked reports whether list revokes cert, the cert of agent: an entry
// for agent with RevokedAt at or after the cert NotBefore.
func IsRevoked(cert *x509.Certificate, agent string, list []vpcv1alpha1.RevokedAgent) bool {
	for _, r := range list {
		if r.Name == agent && !cert.NotBefore.After(r.RevokedAt.Time) {
			return true
		}
	}
	return false
}

// RevokedKeep is the cert life and 10 minutes for clock differences. An older entry revokes no
// valid cert.
const RevokedKeep = CertLifetime + 10*time.Minute

// LiveRevoked returns the entries of list from now - RevokedKeep on. For a cert valid at now,
// IsRevoked gives the same answer without the other entries.
func LiveRevoked(list []vpcv1alpha1.RevokedAgent, now time.Time) []vpcv1alpha1.RevokedAgent {
	from := now.Add(-RevokedKeep)
	var out []vpcv1alpha1.RevokedAgent
	for _, r := range list {
		if !r.RevokedAt.Time.Before(from) {
			out = append(out, r)
		}
	}
	return out
}

// NewPool parses a PEM CA bundle. Each block must be a CA cert.
func NewPool(bundle []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	n := 0
	for rest := bundle; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("CA bundle has a %q block", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA bundle cert: %w", err)
		}
		if !c.IsCA {
			return nil, fmt.Errorf("CA bundle cert %q is not a CA", c.Subject)
		}
		pool.AddCert(c)
		n++
	}
	if n == 0 {
		return nil, errors.New("CA bundle has no certs")
	}
	return pool, nil
}
