// SPDX-License-Identifier: AGPL-3.0-only

package peerconn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

const (
	alpnRelay = "test-relay"
	alpnPeer  = "test-peer"
)

// fakeQC is a relay session. ReceiveDatagram returns the frames on in, and
// SendDatagram puts copies on sent (nil sent discards them).
type fakeQC struct {
	in   chan []byte
	sent chan []byte
	err  error
}

func newFakeQC() *fakeQC {
	return &fakeQC{in: make(chan []byte, 16), sent: make(chan []byte, 16)}
}

func (f *fakeQC) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case b := <-f.in:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeQC) SendDatagram(b []byte) error {
	if f.err != nil {
		return f.err
	}
	if f.sent != nil {
		f.sent <- bytes.Clone(b)
	}
	return nil
}

// pki issues certs from one test CA.
type pki struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newPKI(t testing.TB) *pki {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &pki{cert: cert, key: key, pool: pool}
}

func (p *pki) issue(t testing.TB, name string) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newTransport(t testing.TB) *quic.Transport {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: pc}
	t.Cleanup(func() {
		_ = tr.Close()
		_ = pc.Close()
	})
	return tr
}
