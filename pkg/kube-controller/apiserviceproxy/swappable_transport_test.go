package apiserviceproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/cert/reload"
)

// makeServerCert produces a self-signed leaf usable for a TLS test
// server, plus a root pool containing the same cert so a client built
// against it trusts the handshake.
func makeServerCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "swap-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return pair, pool
}

func TestSwappableTransport_HandshakePicksUpSwap(t *testing.T) {
	t.Parallel()

	serverCert, _ := makeServerCert(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	srv.StartTLS()
	defer srv.Close()

	// Build an initial transport with a trust pool that does NOT contain
	// the server's leaf — handshake must fail.
	emptyPool := x509.NewCertPool()
	emptyBundle := &reload.Bundle{RootCAs: emptyPool}
	tr := newSwappableTransport(buildTransport(emptyBundle, false))
	client := &http.Client{Transport: tr}

	_, err := client.Get(srv.URL)
	require.Error(t, err, "handshake should fail before swap")

	// Swap to a transport whose trust pool includes the server cert and
	// confirm the next request succeeds. New TCP dial means new handshake
	// — exactly the path a kubelet-driven Secret rotation hits.
	_, serverPool := makeServerCertSame(t, serverCert)
	goodBundle := &reload.Bundle{RootCAs: serverPool}
	tr.Store(buildTransport(goodBundle, false))

	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// makeServerCertSame returns a pool containing the given server cert's
// leaf, used to verify the swap-in-trust-pool path. Returning a fresh
// (cert, pool) on every call would be misleading — the test cares about
// "same server, different client trust."
func makeServerCertSame(t *testing.T, c tls.Certificate) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	require.NotEmpty(t, c.Certificate)
	pool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	require.NoError(t, err)
	pool.AddCert(leaf)
	return c, pool
}
