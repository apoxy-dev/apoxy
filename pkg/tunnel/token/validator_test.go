package token_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"
)

func TestInMemoryValidator(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)

	privateKey, err := cryptoutils.ParseEllipticPrivateKeyPEM(privateKeyPEM)
	require.NoError(t, err)

	issuer, err := token.NewIssuer(privateKeyPEM)
	require.NoError(t, err)

	validator, err := token.NewInMemoryValidator(publicKeyPEM)
	require.NoError(t, err)

	t.Run("Valid", func(t *testing.T) {
		subject := uuid.New().String()

		authToken, _, err := issuer.IssueToken(subject, time.Minute*5)
		require.NoError(t, err)

		claims, err := validator.Validate(authToken)
		require.NoError(t, err)

		sub, err := claims.GetSubject()
		require.NoError(t, err)

		require.Equal(t, subject, sub)
	})

	t.Run("Expired", func(t *testing.T) {
		subject := uuid.New().String()

		// Create a token that expires in the past
		authToken, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"sub": subject,
			"iat": time.Now().Add(-time.Hour).Unix(),
			"exp": time.Now().Add(-time.Minute).Unix(),
		}).SignedString(privateKey)
		require.NoError(t, err)

		_, err = validator.Validate(authToken)
		require.Error(t, err)
	})
}

func TestRemoteValidator(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)

	jwksHandler, err := token.NewJWKSHandler(publicKeyPEM)
	require.NoError(t, err)

	server := httptest.NewServer(jwksHandler)
	defer server.Close()

	issuer, err := token.NewIssuer(privateKeyPEM)
	require.NoError(t, err)

	validator, err := token.NewRemoteValidator(context.Background(), []string{server.URL})
	require.NoError(t, err)

	t.Run("Valid", func(t *testing.T) {
		subject := uuid.New().String()

		authToken, _, err := issuer.IssueToken(subject, time.Minute*5)
		require.NoError(t, err)

		_, err = validator.Validate(authToken)
		require.NoError(t, err)
	})
}
