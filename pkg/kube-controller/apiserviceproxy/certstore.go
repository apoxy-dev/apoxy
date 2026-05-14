package apiserviceproxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/cert"
)

// certBundle is an immutable view of one validated client-cert generation.
// Both reads and writes are full-pointer swaps via certStore; nothing inside
// is mutated after the bundle is published.
type certBundle struct {
	cert     tls.Certificate
	rootCAs  *x509.CertPool
	fp       string
	notAfter time.Time
}

// certStore holds the live cert bundle behind an atomic pointer so the
// reverse proxy's transport, the metrics emitter, and the watcher can all
// read/write without locks.
type certStore struct {
	cur atomic.Pointer[certBundle]
}

func newCertStore() *certStore { return &certStore{} }

func (s *certStore) Load() *certBundle  { return s.cur.Load() }
func (s *certStore) Store(b *certBundle) { s.cur.Store(b) }

// loadBundleFromDisk reads tls.crt/tls.key/ca.crt out of a Kubernetes
// Secret-mount directory (kubelet exposes the live generation via the
// ..data symlink in the parent dir). Returns os.ErrNotExist if any of the
// three keys is missing — callers treat that as "Secret not yet projected"
// rather than a hard failure.
func loadBundleFromDisk(dir string) (*certBundle, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, tlsSecretCert))
	if err != nil {
		return nil, fmt.Errorf("read tls.crt: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, tlsSecretKey))
	if err != nil {
		return nil, fmt.Errorf("read tls.key: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, tlsSecretCA))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read ca.crt: %w", err)
	}
	return bundleFromPEM(certPEM, keyPEM, caPEM)
}

// bundleFromPEM validates the cert/key pair, parses the leaf to extract its
// fingerprint + expiry, and builds the upstream root pool. All validation
// happens before construction so a partial-write race surfaces as an error
// rather than a half-populated bundle.
func bundleFromPEM(certPEM, keyPEM, caPEM []byte) (*certBundle, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid tls.crt/tls.key pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("tls.crt contained no certificates")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	roots, err := buildUpstreamRootCAs(caPEM)
	if err != nil {
		return nil, err
	}
	return &certBundle{
		cert:     pair,
		rootCAs:  roots,
		fp:       cert.Fingerprint(pair.Certificate[0]),
		notAfter: leaf.NotAfter,
	}, nil
}
