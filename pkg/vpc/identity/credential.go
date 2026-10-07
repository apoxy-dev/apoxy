package identity

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"
)

// Credential is an agent key, its cert, the CA bundle and the relays from
// enroll.
type Credential struct {
	Key      *ecdsa.PrivateKey
	Cert     *x509.Certificate
	CABundle []byte
	ID       ID
	// Relays that serve the VPC, and the PEM roots of their certs. Empty
	// roots mean the system roots.
	Relays     []Relay
	RelayRoots []byte

	renewAt time.Time
}

// Relay is one relay that the agent can dial.
type Relay struct {
	// ID is the name in the relay cert.
	ID string `json:"id"`
	// Addresses are host:port.
	Addresses []string `json:"addresses"`
}

// NewCredential joins a key with its PEM cert and PEM CA bundle. The cert
// must be for the key and have an agent SAN.
func NewCredential(key *ecdsa.PrivateKey, certPEM, caBundle []byte) (*Credential, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("agent cert is not a PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse agent cert: %w", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("agent cert is not for the agent key")
	}
	id, err := IDFromCert(cert)
	if err != nil {
		return nil, err
	}
	if _, err := NewPool(caBundle); err != nil {
		return nil, err
	}
	return &Credential{Key: key, Cert: cert, CABundle: caBundle, ID: id, renewAt: renewTime(cert)}, nil
}

// renewJitter returns a random duration from 0 to n, without n. Tests replace it.
var renewJitter = rand.N[time.Duration]

// renewTime returns a random time from 1/2 to 5/6 of the life of cert. Agents
// that enroll at the same time then renew at different times.
func renewTime(cert *x509.Certificate) time.Time {
	life := cert.NotAfter.Sub(cert.NotBefore)
	at := life / 2
	if spread := life / 3; spread > 0 {
		at += renewJitter(spread)
	}
	return cert.NotBefore.Add(at)
}

// SetRelays sets the relays and their PEM roots. Empty roots mean the
// system roots.
func (c *Credential) SetRelays(relays []Relay, roots []byte) error {
	if len(roots) == 0 {
		roots = nil
	} else if _, err := NewPool(roots); err != nil {
		return fmt.Errorf("relay roots: %w", err)
	}
	c.Relays, c.RelayRoots = relays, roots
	return nil
}

// RelayPool returns the relay roots, or nil for the system roots.
func (c *Credential) RelayPool() *x509.CertPool {
	if len(c.RelayRoots) == 0 {
		return nil
	}
	// SetRelays checked the roots.
	pool, _ := NewPool(c.RelayRoots)
	return pool
}

// RenewAt is the time to renew the cert: a random time from 1/2 to 5/6 of the
// cert life. NewCredential sets it one time. The credential file does not have it.
func (c *Credential) RenewAt() time.Time { return c.renewAt }

// TLSCertificate returns the key and cert for a tls.Config.
func (c *Credential) TLSCertificate() *tls.Certificate {
	return &tls.Certificate{
		Certificate: [][]byte{c.Cert.Raw},
		PrivateKey:  c.Key,
		Leaf:        c.Cert,
	}
}

// credentialFile is the disk form of a Credential.
type credentialFile struct {
	Key         string  `json:"key"`
	Certificate string  `json:"certificate"`
	CABundle    string  `json:"caBundle"`
	Relays      []Relay `json:"relays,omitempty"`
	RelayRoots  string  `json:"relayRoots,omitempty"`
}

// SaveCredential writes the key, cert, CA bundle and relays to one file at
// path with mode 0600. A rename makes the write atomic, so a reader never
// sees a key without its cert.
func SaveCredential(path string, c *Credential) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.Key)
	if err != nil {
		return fmt.Errorf("failed to encode agent key: %w", err)
	}
	data, err := json.Marshal(credentialFile{
		Key:         string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})),
		CABundle:    string(c.CABundle),
		Relays:      c.Relays,
		RelayRoots:  string(c.RelayRoots),
	})
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create credential dir: %w", err)
	}
	f, err := os.CreateTemp(dir, ".credential-*")
	if err != nil {
		return fmt.Errorf("failed to create credential file: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	// CreateTemp makes the file with mode 0600.
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("failed to write credential file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("failed to sync credential file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close credential file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("failed to replace credential file: %w", err)
	}
	return nil
}

// LoadCredential reads a file that SaveCredential wrote.
func LoadCredential(path string) (*Credential, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f credentialFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse credential file: %w", err)
	}
	block, _ := pem.Decode([]byte(f.Key))
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("credential file has no PEM PRIVATE KEY")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse agent key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("agent key is not ECDSA")
	}
	c, err := NewCredential(key, []byte(f.Certificate), []byte(f.CABundle))
	if err != nil {
		return nil, err
	}
	if err := c.SetRelays(f.Relays, []byte(f.RelayRoots)); err != nil {
		return nil, err
	}
	return c, nil
}
