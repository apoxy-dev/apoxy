// Package cabundle checks a PEM CA bundle for distrusted certificate
// authorities.
package cabundle

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Distrusted are the eMudhra CAs compromised per https://emudhra.we-have-a-problem.com/.
var Distrusted = struct {
	// CertSHA256 maps a root's DER SHA-256 to its name.
	CertSHA256 map[string]string
	// SPKISHA256 maps an intermediate's SPKI SHA-256 to its name; it matches every cross-sign of the key.
	SPKISHA256 map[string]string
}{
	CertSHA256: map[string]string{
		"86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B": "emSign ECC Root CA - G3",
		"7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D": "emSign Root TLS CA - G3",
	},
	SPKISHA256: map[string]string{
		"EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105": "EM DV TLS CA - G3B",
		"43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B": "EM OV TLS CA - G3B",
		"E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41": "EM EV TLS CA - G3B",
		"49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F": "EM DV TLS CA - G3C",
		"63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8": "EM OV TLS CA - G3C",
		"5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0": "EM EV TLS CA - G3C",
		"EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6": "EM OV CS CA - G3B",
		"92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30": "EM OV CS CA - G3C",
	},
}

// Check fails if the PEM bundle holds no certificates, a block it cannot
// read, or any Distrusted certificate or key.
func Check(bundle []byte) error {
	var found []string
	n, blocks := 0, 0
	for rest := bundle; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks++
		der, err := certificateDER(block)
		if err != nil {
			return fmt.Errorf("PEM block %d: %w", blocks, err)
		}
		n++
		certSum := sha256.Sum256(der)
		if name, ok := Distrusted.CertSHA256[fmt.Sprintf("%X", certSum)]; ok {
			found = append(found, fmt.Sprintf("%s (certificate SHA-256 %X)", name, certSum))
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			// An unparsed certificate could hide a distrusted key.
			return fmt.Errorf("certificate %d: %w", n, err)
		}
		spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if name, ok := Distrusted.SPKISHA256[fmt.Sprintf("%X", spkiSum)]; ok {
			found = append(found, fmt.Sprintf("%s (SPKI SHA-256 %X, subject %q)", name, spkiSum, cert.Subject.String()))
		}
	}
	// A block Go skips as malformed may still load in BoringSSL.
	if begins := bytes.Count(bundle, []byte("-----BEGIN ")); begins != blocks {
		return fmt.Errorf("bundle has %d PEM BEGIN lines but %d readable blocks", begins, blocks)
	}
	if n == 0 {
		return errors.New("no certificates in the bundle")
	}
	if len(found) > 0 {
		return fmt.Errorf("bundle trusts distrusted eMudhra CAs: %s", strings.Join(found, "; "))
	}
	return nil
}

// certificateDER returns the certificate in a block of any type BoringSSL
// loads as one, and rejects every other type.
func certificateDER(block *pem.Block) ([]byte, error) {
	switch block.Type {
	case "CERTIFICATE", "X509 CERTIFICATE":
		return block.Bytes, nil
	case "TRUSTED CERTIFICATE":
		// OpenSSL appends the X509_CERT_AUX trust settings to the certificate.
		var cert asn1.RawValue
		if _, err := asn1.Unmarshal(block.Bytes, &cert); err != nil {
			return nil, fmt.Errorf("TRUSTED CERTIFICATE: %w", err)
		}
		return cert.FullBytes, nil
	default:
		return nil, fmt.Errorf("unexpected block type %q", block.Type)
	}
}

// Variant is one platform image's CA bundle.
type Variant struct {
	Platform string
	// Missing is set when the image ships no bundle and so trusts no CA.
	Missing bool
	Bundle  []byte
}

// CheckImage fails if the image has no variants, a variant's bundle fails
// Check, or a variant ships no bundle and allowMissing is false.
func CheckImage(image string, variants []Variant, allowMissing bool) error {
	if len(variants) == 0 {
		return fmt.Errorf("%s: no variants", image)
	}
	for _, v := range variants {
		if v.Missing {
			if allowMissing {
				continue
			}
			return fmt.Errorf("%s %s: no CA bundle", image, v.Platform)
		}
		if err := Check(v.Bundle); err != nil {
			return fmt.Errorf("%s %s: %w", image, v.Platform, err)
		}
	}
	return nil
}
