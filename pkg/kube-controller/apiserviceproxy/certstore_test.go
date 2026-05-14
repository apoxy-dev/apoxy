package apiserviceproxy

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

// makeClientCertPEM mints a self-signed leaf usable as an mTLS client
// cert. We don't need a real chain — bundleFromPEM only validates parse,
// not trust.
func makeClientCertPEM(t *testing.T) (certPEM, keyPEM []byte, fp string, notAfter time.Time) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	notAfter = time.Now().Add(48 * time.Hour).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "kube-controller-test"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	fp = cert.Fingerprint(parsed.Raw)
	return
}

func TestLoadBundleFromDisk_RoundTrip(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM, wantFP, wantExp := makeClientCertPEM(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o400))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o400))
	// ca.crt empty is allowed.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.crt"), nil, 0o400))

	b, err := loadBundleFromDisk(dir)
	require.NoError(t, err)
	require.Equal(t, wantFP, b.fp)
	require.True(t, b.notAfter.Equal(wantExp))
	require.NotNil(t, b.rootCAs)
}

func TestLoadBundleFromDisk_BadKeyPair(t *testing.T) {
	t.Parallel()
	certPEM, _, _, _ := makeClientCertPEM(t)
	_, otherKey, _, _ := makeClientCertPEM(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o400))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), otherKey, 0o400))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.crt"), nil, 0o400))

	_, err := loadBundleFromDisk(dir)
	require.Error(t, err)
}

func TestLoadBundleFromDisk_MissingCert(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := loadBundleFromDisk(dir)
	require.Error(t, err)
}
