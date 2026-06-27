package reload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/cert"
)

// makeCertPEM mints a self-signed leaf. We don't need a real chain —
// BundleFromPEM only validates parse, not trust.
func makeCertPEM(t *testing.T) (certPEM, keyPEM []byte, fp string, notAfter time.Time) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	notAfter = time.Now().Add(48 * time.Hour).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "reload-test"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	fp = cert.Fingerprint(der)
	return
}

func writeKeyPairDir(t *testing.T, dir string, certPEM, keyPEM []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, SecretCertFile), certPEM, 0o400))
	require.NoError(t, os.WriteFile(filepath.Join(dir, SecretKeyFile), keyPEM, 0o400))
	require.NoError(t, os.WriteFile(filepath.Join(dir, SecretCAFile), nil, 0o400))
}

func TestLoadBundle_RoundTrip(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM, wantFP, wantExp := makeCertPEM(t)
	dir := t.TempDir()
	writeKeyPairDir(t, dir, certPEM, keyPEM)

	b, err := LoadBundle(FromDir(dir))
	require.NoError(t, err)
	require.Equal(t, wantFP, b.Fingerprint)
	require.True(t, b.NotAfter.Equal(wantExp))
	require.NotNil(t, b.RootCAs)
	require.NotNil(t, b.Cert.Leaf)
}

func TestLoadBundle_BadKeyPair(t *testing.T) {
	t.Parallel()
	certPEM, _, _, _ := makeCertPEM(t)
	_, otherKey, _, _ := makeCertPEM(t)
	dir := t.TempDir()
	writeKeyPairDir(t, dir, certPEM, otherKey)

	_, err := LoadBundle(FromDir(dir))
	require.Error(t, err)
}

func TestLoadBundle_MissingCert(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := LoadBundle(FromDir(dir))
	require.Error(t, err)
}

func TestLoadBundle_MissingCAToleratedWhenPathUnset(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM, _, _ := makeCertPEM(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, SecretCertFile), certPEM, 0o400))
	require.NoError(t, os.WriteFile(filepath.Join(dir, SecretKeyFile), keyPEM, 0o400))
	// No ca.crt written, and CA path left empty: server-side consumers
	// (tunnel/relay) have no CA file.
	b, err := LoadBundle(Paths{Cert: filepath.Join(dir, SecretCertFile), Key: filepath.Join(dir, SecretKeyFile)})
	require.NoError(t, err)
	require.NotNil(t, b.RootCAs) // falls back to system pool
}

func TestBuildRootCAs_PreservesSystemRootsAndAppendsCA(t *testing.T) {
	caPEM := selfSignedCAPEM(t)

	orig := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }
	t.Cleanup(func() { systemCertPool = orig })

	roots, err := buildRootCAs(caPEM)
	require.NoError(t, err)

	parsed := x509.NewCertPool()
	require.True(t, parsed.AppendCertsFromPEM(caPEM))
	subjects := roots.Subjects()
	require.Len(t, subjects, 1)
	require.Equal(t, parsed.Subjects()[0], subjects[0])
}

func selfSignedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "reload-test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
