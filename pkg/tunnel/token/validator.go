package token

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
)

// JWTValidator validates JWT tokens.
type JWTValidator interface {
	// Validate validates the token and returns its claims.
	Validate(tokenStr string) (jwt.Claims, error)
}

// Validator extends JWTValidator with the ability to retrieve the public key.
// Use this interface when you need to serve JWKS endpoints locally.
// For remote validation (e.g., RemoteValidator), use JWTValidator instead.
type Validator interface {
	JWTValidator
	// PublicKeyPEM returns the PEM-encoded public key used for validation.
	PublicKeyPEM() []byte
}

func validate(keyFunc jwt.Keyfunc, tokenStr string) (jwt.Claims, error) {
	token, err := jwt.Parse(
		tokenStr,
		keyFunc,
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	tokenClaims := token.Claims
	if tokenClaims == nil {
		return nil, errors.New("failed to parse claims")
	}

	return tokenClaims, nil
}

// InMemoryValidator validates JWT tokens signed with an ECDSA public key.
// It implements the Validator interface.
type InMemoryValidator struct {
	publicKey    *ecdsa.PublicKey
	publicKeyPEM []byte
}

// NewInMemoryValidator creates a new Validator with the public key.
func NewInMemoryValidator(publicKeyPEM []byte) (*InMemoryValidator, error) {
	publicKey, err := cryptoutils.ParseEllipticPublicKeyPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA public key: %w", err)
	}

	return &InMemoryValidator{
		publicKey:    publicKey,
		publicKeyPEM: publicKeyPEM,
	}, nil
}

// Validate validates the token is valid.
func (v *InMemoryValidator) Validate(tokenStr string) (jwt.Claims, error) {
	return validate(func(token *jwt.Token) (any, error) {
		return v.publicKey, nil
	}, tokenStr)
}

// PublicKeyPEM returns the PEM-encoded public key used for validation.
func (v *InMemoryValidator) PublicKeyPEM() []byte {
	return v.publicKeyPEM
}

type RemoteValidator struct {
	rkf keyfunc.Keyfunc
}

// NewRemoteValidator creates a new Validator with the public key.
func NewRemoteValidator(ctx context.Context, urls []string) (*RemoteValidator, error) {
	fn, err := keyfunc.NewDefaultOverrideCtx(ctx, urls, keyfunc.Override{
		HTTPTimeout:      10 * time.Second,
		RateLimitWaitMax: 10 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create keyfunc: %w", err)
	}
	return &RemoteValidator{rkf: fn}, nil
}

// Validate validates the token is valid.
func (v *RemoteValidator) Validate(tokenStr string) (jwt.Claims, error) {
	return validate(func(token *jwt.Token) (any, error) {
		key, err := v.rkf.Keyfunc(token)
		if err != nil {
			slog.Error("failed to get key", slog.Any("error", err))
			return nil, err
		}
		if key == nil {
			slog.Error("key is nil")
			return nil, errors.New("key is nil")
		}
		switch key.(type) {
		case *ecdsa.PublicKey:
			return key, nil
		default:
			slog.Error("unsupported key type", "type", reflect.TypeOf(key))
			return nil, errors.New("unsupported key type")
		}
	}, tokenStr)
}
