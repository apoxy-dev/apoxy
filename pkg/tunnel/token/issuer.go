package token

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/golang-jwt/jwt/v5"
)

// TokenIssuer is an interface for issuing JWT tokens.
type TokenIssuer interface {
	IssueToken(subject string, ttl time.Duration) (string, jwt.Claims, error)
}

// Issuer implements TokenIssuer for issuing JWT tokens.
type Issuer struct {
	privateKey *ecdsa.PrivateKey
	kid        string
}

func NewIssuer(privateKeyPEM []byte) (*Issuer, error) {
	privateKey, err := cryptoutils.ParseEllipticPrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &Issuer{
		privateKey: privateKey,
		kid:        fingerprint(&privateKey.PublicKey),
	}, nil
}

func (i *Issuer) IssueToken(subject string, ttl time.Duration) (string, jwt.Claims, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, &jwt.RegisteredClaims{
		Subject:   subject,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	})

	// kid goes into the header because it needs to be read
	// *before* the token is verified.
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4
	token.Header[jwkset.HeaderKID] = i.kid
	token.Header["alg"] = jwt.SigningMethodES256.Alg()

	tokenString, err := token.SignedString(i.privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, token.Claims, nil
}
