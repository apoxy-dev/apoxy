// Package cert provides X.509 fingerprint helpers used by the CLI's cert
// subcommands. Mirrors github.com/apoxy-dev/apoxy-cloud/core/cert so the
// CLI doesn't pull a cosmos module dependency.
package cert

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

// FingerprintSize is the byte length of a SHA1 cert fingerprint.
const FingerprintSize = sha1.Size

// Fingerprint returns the lowercase hex SHA1 of the cert's DER bytes. The
// resulting string is the canonical form cosmos persists and what
// ext_authz / RevokeServiceCert compare against.
func Fingerprint(certDER []byte) string {
	return fmt.Sprintf("%x", sha1.Sum(certDER))
}

// NormalizeFingerprint validates and lowercases a SHA1 fingerprint string.
func NormalizeFingerprint(s string) (string, error) {
	s = strings.ToLower(s)
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != FingerprintSize {
		return "", fmt.Errorf("fingerprint must be a 40-character SHA1 hex string")
	}
	return s, nil
}
