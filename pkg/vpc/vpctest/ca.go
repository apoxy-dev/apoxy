// SPDX-License-Identifier: AGPL-3.0-only

package vpctest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
)

// CA signs agent certs or relay certs.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA returns a CA that is valid from 24 hours ago to 24 hours from now.
func NewCA() (*CA, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA cert: %w", err)
	}
	return &CA{Cert: cert, Key: key}, nil
}

func newKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to make key: %w", err)
	}
	return key, nil
}

// Pool returns a pool with only the CA cert.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

var serial atomic.Int64

func (ca *CA) sign(tmpl *x509.Certificate, key *ecdsa.PrivateKey) ([]byte, error) {
	tmpl.SerialNumber = big.NewInt(serial.Add(1) + 10)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign cert: %w", err)
	}
	return der, nil
}

// Credential issues a credential for agent name, valid for life.
func (ca *CA) Credential(project, vpc, name string, life time.Duration) (*identity.Credential, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	id := identity.ID{Project: project, VPC: vpc, Agent: name}
	der, err := ca.sign(&x509.Certificate{
		URIs:      []*url.URL{id.URI()},
		NotBefore: time.Now().Add(-time.Second), NotAfter: time.Now().Add(life),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, key)
	if err != nil {
		return nil, err
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	return identity.NewCredential(key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), bundle)
}

// RelayCert issues a relay cert that names only id.
func (ca *CA) RelayCert(id string) (*tls.Certificate, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	der, err := ca.sign(&x509.Certificate{
		DNSNames:  []string{id},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
