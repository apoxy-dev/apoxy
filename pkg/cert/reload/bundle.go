// Package reload provides hot-reloading of TLS keypairs that are rotated in
// place on disk (e.g. cert-manager rewriting a Kubernetes Secret mount). A
// long-lived process that loads its keypair once at startup keeps serving
// the stale leaf until it restarts; once that leaf expires, every TLS
// handshake fails. The primitives here — a validated Bundle, an atomic
// Store, an fsnotify-backed Watch, and a Reloader exposing
// tls.Config.GetCertificate — let a server pick up rotations without a
// restart.
//
// This is the single implementation shared by the kube-controller upstream
// client cert, the tunnelproxy QUIC server cert, and the tunnel relay.
package reload

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/cert"
)

// systemCertPool is a package var so tests can stub the system root pool.
var systemCertPool = x509.SystemCertPool

// Standard file names inside a Kubernetes TLS Secret mount.
const (
	SecretCertFile = "tls.crt"
	SecretKeyFile  = "tls.key"
	SecretCAFile   = "ca.crt"
)

// Paths locates the cert, key, and optional CA files on disk.
type Paths struct {
	Cert string
	Key  string
	CA   string // optional; empty means there is no CA file to read
}

// FromDir returns the standard Kubernetes Secret-mount layout under dir
// (tls.crt / tls.key / ca.crt).
func FromDir(dir string) Paths {
	return Paths{
		Cert: filepath.Join(dir, SecretCertFile),
		Key:  filepath.Join(dir, SecretKeyFile),
		CA:   filepath.Join(dir, SecretCAFile),
	}
}

// Bundle is an immutable view of one validated keypair generation. It is
// published via Store as a whole-pointer swap; nothing inside is mutated
// after publication, so readers need no locks.
type Bundle struct {
	Cert        tls.Certificate
	RootCAs     *x509.CertPool // system pool plus the optional CA file
	Fingerprint string
	NotAfter    time.Time
}

// LoadBundle reads and validates the keypair (and optional CA) from disk. A
// missing CA file is tolerated (RootCAs falls back to the system pool); a
// missing or malformed cert/key surfaces as an error so a partial-write
// race is retried rather than published.
func LoadBundle(p Paths) (*Bundle, error) {
	certPEM, err := os.ReadFile(p.Cert)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p.Cert, err)
	}
	keyPEM, err := os.ReadFile(p.Key)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p.Key, err)
	}
	var caPEM []byte
	if p.CA != "" {
		caPEM, err = os.ReadFile(p.CA)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read %s: %w", p.CA, err)
		}
	}
	return BundleFromPEM(certPEM, keyPEM, caPEM)
}

// BundleFromPEM validates the keypair, parses the leaf to extract its
// fingerprint + expiry, and builds the root pool. All validation happens
// before construction so a half-written input surfaces as an error rather
// than a partially-populated bundle.
func BundleFromPEM(certPEM, keyPEM, caPEM []byte) (*Bundle, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid cert/key pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("certificate contained no certificates")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	pair.Leaf = leaf
	roots, err := buildRootCAs(caPEM)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		Cert:        pair,
		RootCAs:     roots,
		Fingerprint: cert.Fingerprint(pair.Certificate[0]),
		NotAfter:    leaf.NotAfter,
	}, nil
}

// buildRootCAs returns the system pool, optionally augmented with caPEM.
// Used by client-side consumers (kube-controller upstream proxy); server-
// side consumers ignore Bundle.RootCAs.
func buildRootCAs(caPEM []byte) (*x509.CertPool, error) {
	roots, err := systemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if len(caPEM) == 0 {
		return roots, nil
	}
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}
	return roots, nil
}
