// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
)

// Trust is the agent trust data that the relay keeps locally. The cert check
// makes no apiserver call.
type Trust interface {
	// AgentCA returns the pool of the agent CA.
	AgentCA() (*x509.CertPool, error)
	// Revoked returns the revocation list of a VPC. An error, for example
	// for data that is too old, rejects the cert.
	Revoked(project, vpcUID string) ([]vpcv1alpha1.RevokedAgent, error)
}

// checkCert checks the agent cert chain (leaf first) of a new session: the
// chain goes to the agent CA, the SAN is an agent ID, and the agent is not
// revoked in the VPC of the SAN.
func (r *Router) checkCert(chain []*x509.Certificate, now time.Time) (identity.ID, error) {
	if r.trust == nil {
		return identity.ID{}, errors.New("relay has no trust data")
	}
	if len(chain) == 0 {
		return identity.ID{}, errors.New("no agent cert")
	}
	// The SAN only selects the revocation list here. Verify checks it.
	san, err := identity.IDFromCert(chain[0])
	if err != nil {
		return identity.ID{}, err
	}
	roots, err := r.trust.AgentCA()
	if err != nil {
		return identity.ID{}, fmt.Errorf("no agent CA: %w", err)
	}
	revoked, err := r.trust.Revoked(san.Project, san.VPC)
	if err != nil {
		return identity.ID{}, fmt.Errorf("no revocation list: %w", err)
	}
	return identity.Verify(chain, identity.VerifyOptions{
		Roots:   roots,
		Project: san.Project,
		VPC:     san.VPC,
		Revoked: revoked,
		Now:     now,
	})
}
