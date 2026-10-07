// SPDX-License-Identifier: AGPL-3.0-only

package vpctest

import (
	"crypto/x509"
	"sync"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
)

// Trust is a relay.Trust that trusts one agent CA for all projects and
// revokes no agent.
type Trust struct {
	mu   sync.Mutex
	pool *x509.CertPool
}

var _ relay.Trust = (*Trust)(nil)

// NewTrust returns a Trust for ca.
func NewTrust(ca *CA) *Trust { return &Trust{pool: ca.Pool()} }

// SetCA trusts ca in place of the CA before it.
func (t *Trust) SetCA(ca *CA) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pool = ca.Pool()
}

func (t *Trust) AgentCA(string) (*x509.CertPool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pool, nil
}

func (t *Trust) Revoked(string, string) ([]vpcv1alpha1.RevokedAgent, error) { return nil, nil }
