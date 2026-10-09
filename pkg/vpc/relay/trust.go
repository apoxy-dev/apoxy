// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// Trust is the agent trust data that the relay keeps locally. The cert check
// makes no apiserver call.
type Trust interface {
	// AgentCA returns the pool of the agent CA of a project. An error, for
	// example for a project with no CA, rejects the cert.
	AgentCA(project string) (*x509.CertPool, error)
	// Revoked returns the revocation list of a VPC. An error, for example
	// for data that is too old, rejects the cert.
	Revoked(project, vpcUID string) ([]vpcv1alpha1.RevokedAgent, error)
	// RelayRoots returns the roots for the relay cert of a grant in a project.
	// A nil pool with no error means the system roots. An error refuses the grant.
	RelayRoots(project string) (*x509.CertPool, error)
}

// checkCert checks the agent cert chain (leaf first) of a new session: the
// chain goes to the agent CA of the project in the SAN, the SAN is an agent
// ID, and the agent is not revoked in the VPC of the SAN.
func (r *Router) checkCert(chain []*x509.Certificate, now time.Time) (identity.ID, error) {
	if r.trust == nil {
		return identity.ID{}, errors.New("relay has no trust data")
	}
	if len(chain) == 0 {
		return identity.ID{}, errors.New("no agent cert")
	}
	// The SAN only selects the CA and the revocation list here. Verify checks it.
	san, err := identity.IDFromCert(chain[0])
	if err != nil {
		return identity.ID{}, err
	}
	roots, err := r.trust.AgentCA(san.Project)
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

// TLSConfig returns a copy of base whose handshake fails for an agent cert
// that fails the check.
func (r *Router) TLSConfig(base *tls.Config) *tls.Config {
	c := base.Clone()
	c.MinVersion = tls.VersionTLS13
	c.NextProtos = []string{dp.ALPNRelay}
	// ClientCAs does not check the SAN or revocations, so the relay checks.
	c.ClientAuth = tls.RequireAnyClientCert
	c.VerifyConnection = r.verifyConnection
	return c
}

func (r *Router) verifyConnection(cs tls.ConnectionState) error {
	if cs.NegotiatedProtocol != dp.ALPNRelay {
		return nil
	}
	_, err := r.checkCert(cs.PeerCertificates, time.Now())
	return err
}

// Recheck closes the sessions whose agent cert now fails the check. Call it
// when the agent CA or a revocation list changes.
func (r *Router) Recheck() {
	now := time.Now()
	r.mu.RLock()
	sessions := make([]*Session, 0, len(r.sessions))
	for s := range r.sessions {
		if s.chain != nil {
			sessions = append(sessions, s)
		}
	}
	r.mu.RUnlock()
	for _, s := range sessions {
		if _, err := r.checkCert(s.chain, now); err != nil {
			slog.Info("Closing relay session after a trust change", "agent", s.id.ID, "error", err)
			s.close(dp.RelayCloseCode_RELAY_CLOSE_CODE_CERT, "agent cert rejected")
		}
	}
}
