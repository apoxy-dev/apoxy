package v1alpha2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// generateTestCertificate generates a self-signed certificate and private key for testing
func generateTestCertificate(keyType string) (certPEM, keyPEM string, err error) {
	var privateKey interface{}
	var privateKeyBytes []byte
	var keyPEMType string

	switch keyType {
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", "", err
		}
		privateKey = key
		privateKeyBytes = x509.MarshalPKCS1PrivateKey(key)
		keyPEMType = "RSA PRIVATE KEY"

	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", "", err
		}
		privateKey = key
		privateKeyBytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return "", "", err
		}
		keyPEMType = "EC PRIVATE KEY"

	default:
		return "", "", nil
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		DNSNames:              []string{"test.example.com", "*.test.example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	var publicKey interface{}
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		publicKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &k.PublicKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return "", "", err
	}

	// Encode certificate to PEM
	certPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Encode private key to PEM
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  keyPEMType,
		Bytes: privateKeyBytes,
	})

	return string(certPEMBlock), string(keyPEMBlock), nil
}

func TestTLSCertificateValidation(t *testing.T) {
	ctx := context.Background()

	t.Run("valid RSA certificate", func(t *testing.T) {
		certPEM, keyPEM, err := generateTestCertificate("rsa")
		if err != nil {
			t.Fatalf("failed to generate test certificate: %v", err)
		}

		tlsCert := &TLSCertificate{
			Spec: TLSCertificateSpec{
				Certificate: certPEM,
				PrivateKey:  keyPEM,
			},
		}

		errs := tlsCert.Validate(ctx)
		if len(errs) > 0 {
			t.Errorf("expected no validation errors, got: %v", errs)
		}
	})

	t.Run("valid ECDSA certificate", func(t *testing.T) {
		certPEM, keyPEM, err := generateTestCertificate("ecdsa")
		if err != nil {
			t.Fatalf("failed to generate test certificate: %v", err)
		}

		tlsCert := &TLSCertificate{
			Spec: TLSCertificateSpec{
				Certificate: certPEM,
				PrivateKey:  keyPEM,
			},
		}

		errs := tlsCert.Validate(ctx)
		if len(errs) > 0 {
			t.Errorf("expected no validation errors, got: %v", errs)
		}
	})

	t.Run("invalid certificate PEM", func(t *testing.T) {
		tlsCert := &TLSCertificate{
			Spec: TLSCertificateSpec{
				Certificate: "not a valid PEM",
				PrivateKey:  "not a valid PEM",
			},
		}

		errs := tlsCert.Validate(ctx)
		if len(errs) == 0 {
			t.Error("expected validation errors for invalid PEM")
		}
	})

	t.Run("mismatched certificate and key", func(t *testing.T) {
		// Generate two different certificates
		certPEM1, _, err := generateTestCertificate("rsa")
		if err != nil {
			t.Fatalf("failed to generate test certificate: %v", err)
		}

		_, keyPEM2, err := generateTestCertificate("rsa")
		if err != nil {
			t.Fatalf("failed to generate test certificate: %v", err)
		}

		tlsCert := &TLSCertificate{
			Spec: TLSCertificateSpec{
				Certificate: certPEM1,
				PrivateKey:  keyPEM2,
			},
		}

		errs := tlsCert.Validate(ctx)
		if len(errs) == 0 {
			t.Error("expected validation errors for mismatched certificate and key")
		}
	})

	t.Run("wrong key type", func(t *testing.T) {
		// Generate RSA certificate but ECDSA key
		certPEM, _, err := generateTestCertificate("rsa")
		if err != nil {
			t.Fatalf("failed to generate test certificate: %v", err)
		}

		_, keyPEM, err := generateTestCertificate("ecdsa")
		if err != nil {
			t.Fatalf("failed to generate test certificate: %v", err)
		}

		tlsCert := &TLSCertificate{
			Spec: TLSCertificateSpec{
				Certificate: certPEM,
				PrivateKey:  keyPEM,
			},
		}

		errs := tlsCert.Validate(ctx)
		if len(errs) == 0 {
			t.Error("expected validation errors for wrong key type")
		}
	})
}

func TestTLSCertificateDefault(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertificate("rsa")
	if err != nil {
		t.Fatalf("failed to generate test certificate: %v", err)
	}

	tlsCert := &TLSCertificate{
		Spec: TLSCertificateSpec{
			Certificate: certPEM,
			PrivateKey:  keyPEM,
		},
	}

	tlsCert.Default()

	// Check that status fields were populated
	if tlsCert.Status.NotBefore == nil {
		t.Error("expected NotBefore to be set")
	}
	if tlsCert.Status.NotAfter == nil {
		t.Error("expected NotAfter to be set")
	}
	if tlsCert.Status.Issuer == "" {
		t.Error("expected Issuer to be set")
	}
	if tlsCert.Status.Subject == "" {
		t.Error("expected Subject to be set")
	}
	if len(tlsCert.Status.DNSNames) == 0 {
		t.Error("expected DNSNames to be set")
	}
}
