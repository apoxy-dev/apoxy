package v1alpha2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
)

var _ resourcestrategy.Defaulter = &TLSCertificate{}
var _ resourcestrategy.Validater = &TLSCertificate{}
var _ resourcestrategy.ValidateUpdater = &TLSCertificate{}

// Default sets the default values for a TLSCertificate.
func (r *TLSCertificate) Default() {
	// Parse certificate to populate status fields
	if r.Spec.Certificate != "" {
		if cert, err := parseCertificate(r.Spec.Certificate); err == nil {
			r.Status.NotBefore = &metav1.Time{Time: cert.NotBefore}
			r.Status.NotAfter = &metav1.Time{Time: cert.NotAfter}
			r.Status.Issuer = cert.Issuer.String()
			r.Status.Subject = cert.Subject.String()
			r.Status.DNSNames = cert.DNSNames
		}
	}
}

func (r *TLSCertificate) Validate(ctx context.Context) field.ErrorList {
	return r.validate()
}

func (r *TLSCertificate) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	t := &TLSCertificate{}
	// XXX: Conversion needs to happen in apiserver-runtime before validation hooks are called.
	if mv, ok := obj.(resource.MultiVersionObject); ok {
		mv.ConvertToStorageVersion(t)
	} else if t, ok = obj.(*TLSCertificate); !ok {
		return field.ErrorList{
			field.Invalid(field.NewPath("kind"), obj.GetObjectKind().GroupVersionKind().Kind, "expected TLSCertificate"),
		}
	}

	return t.validate()
}

func (r *TLSCertificate) validate() field.ErrorList {
	errs := field.ErrorList{}

	// Validate certificate is PEM encoded
	cert, err := parseCertificate(r.Spec.Certificate)
	if err != nil {
		errs = append(errs, field.Invalid(
			field.NewPath("spec", "certificate"),
			"<redacted>",
			fmt.Sprintf("invalid PEM-encoded certificate: %v", err),
		))
		return errs
	}

	// Validate private key is PEM encoded
	privateKey, err := parsePrivateKey(r.Spec.PrivateKey)
	if err != nil {
		errs = append(errs, field.Invalid(
			field.NewPath("spec", "privateKey"),
			"<redacted>",
			fmt.Sprintf("invalid PEM-encoded private key: %v", err),
		))
		return errs
	}

	// Validate that the private key matches the certificate's public key
	if err := validateKeyPair(cert, privateKey); err != nil {
		errs = append(errs, field.Invalid(
			field.NewPath("spec", "privateKey"),
			"<redacted>",
			fmt.Sprintf("private key does not match certificate public key: %v", err),
		))
	}

	return errs
}

// parseCertificate parses a PEM-encoded certificate and returns the first certificate found.
func parseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block type must be CERTIFICATE, got %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// parsePrivateKey parses a PEM-encoded private key and returns the private key.
// Supports RSA, ECDSA, and Ed25519 keys.
func parsePrivateKey(keyPEM string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Try parsing as PKCS8 first (most common format)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try parsing as PKCS1 RSA private key
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try parsing as EC private key
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key: unsupported key type or format")
}

// validateKeyPair validates that the private key matches the certificate's public key.
func validateKeyPair(cert *x509.Certificate, privateKey crypto.PrivateKey) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("certificate has RSA public key but private key is not RSA")
		}
		if pub.N.Cmp(priv.N) != 0 || pub.E != priv.E {
			return fmt.Errorf("RSA private key does not match certificate public key")
		}

	case *ecdsa.PublicKey:
		priv, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("certificate has ECDSA public key but private key is not ECDSA")
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fmt.Errorf("ECDSA private key does not match certificate public key")
		}

	case ed25519.PublicKey:
		priv, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return fmt.Errorf("certificate has Ed25519 public key but private key is not Ed25519")
		}
		// Ed25519 private key contains the public key in the last 32 bytes
		if len(priv) != ed25519.PrivateKeySize {
			return fmt.Errorf("invalid Ed25519 private key size")
		}
		derivedPub := priv.Public().(ed25519.PublicKey)
		if !derivedPub.Equal(pub) {
			return fmt.Errorf("Ed25519 private key does not match certificate public key")
		}

	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}

	return nil
}
