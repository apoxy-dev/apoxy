// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// Trust is the agent trust data that the relay keeps locally. The cert check makes no apiserver
// call.
type Trust interface {
	// AgentCA returns the pool of the agent CA of a project. An error, for example for a project
	// with no CA or for data that is too old, rejects the cert.
	AgentCA(project string) (*x509.CertPool, error)
	// Revoked returns the revocation list of a VPC. An error, for example for data that is too
	// old, rejects the cert.
	Revoked(project, vpcUID string) ([]vpcv1alpha1.RevokedAgent, error)
}

// trustGen is the trust data value of one tenant. A new value comes at each Recheck, and each A
// of the tenant then checks its cert again.
type trustGen struct{ n uint64 }

// checkCert checks the agent cert chain (leaf first) at now: the agent CA of the SAN project, an
// agent ID SAN, and no revocation.
func checkCert(trust Trust, chain []*x509.Certificate, now time.Time) (identity.ID, error) {
	if trust == nil {
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
	roots, err := trust.AgentCA(san.Project)
	if err != nil {
		return identity.ID{}, fmt.Errorf("no agent CA: %w", err)
	}
	revoked, err := trust.Revoked(san.Project, san.VPC)
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

// TLSConfig returns a copy of base whose handshake fails for an agent cert that fails the check.
// With a mesh, a client that offers apoxy-mesh/1 gets the mesh config.
func (r *Router) TLSConfig(base *tls.Config) *tls.Config {
	c := base.Clone()
	if r.mesh != nil {
		next := c.GetConfigForClient
		c.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			if slices.Contains(chi.SupportedProtos, dpv1.ALPNMesh) {
				return r.mesh.tls, nil
			}
			if next != nil {
				return next(chi)
			}
			return nil, nil
		}
	}
	c.MinVersion = tls.VersionTLS13
	c.NextProtos = []string{dpv1.ALPNRelay}
	// ClientCAs does not check the SAN or revocations, so the relay checks.
	c.ClientAuth = tls.RequireAnyClientCert
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if cs.NegotiatedProtocol != dpv1.ALPNRelay {
			return nil
		}
		_, err := checkCert(r.cfg.Trust, cs.PeerCertificates, time.Now())
		return err
	}
	return c
}
