package token_test

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"
)

func TestStaticTokenValidator(t *testing.T) {
	v := token.NewStaticTokenValidator()
	v.SetToken("corp", "s3cret")
	v.SetToken("gone", "whatever")
	v.RemoveToken("gone")

	cases := []struct {
		name    string
		network string
		token   string
		wantErr bool
	}{
		{name: "match", network: "corp", token: "s3cret"},
		{name: "wrong token", network: "corp", token: "nope", wantErr: true},
		{name: "unknown network", network: "other", token: "s3cret", wantErr: true},
		{name: "removed network", network: "gone", token: "whatever", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authz, err := v.Validate(context.Background(), tc.network, tc.token)
			if tc.wantErr {
				require.ErrorIs(t, err, token.ErrUnauthorized)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.network, authz.Network)
			require.Empty(t, authz.AllowedLabelSets)
			require.Empty(t, authz.AllowedRoutes)
		})
	}
}

func TestAuthzResultPermits(t *testing.T) {
	bounded := &token.AuthzResult{
		Network: "corp",
		AllowedLabelSets: []map[string]string{
			{"app": "payments", "env": "prod"},
			{"app": "billing"},
		},
		AllowedRoutes: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("fd00::/64"),
		},
	}
	unbounded := &token.AuthzResult{Network: "corp"}

	routeCases := []struct {
		name  string
		authz *token.AuthzResult
		route string
		want  bool
	}{
		{name: "unbounded permits anything", authz: unbounded, route: "0.0.0.0/0", want: true},
		{name: "contained v4", authz: bounded, route: "10.1.0.0/16", want: true},
		{name: "exact match", authz: bounded, route: "10.0.0.0/8", want: true},
		{name: "wider than allowed", authz: bounded, route: "10.0.0.0/7", want: false},
		{name: "outside allowed", authz: bounded, route: "192.168.0.0/24", want: false},
		{name: "contained v6", authz: bounded, route: "fd00::1/128", want: true},
		{name: "outside v6", authz: bounded, route: "fd01::/64", want: false},
	}
	for _, tc := range routeCases {
		t.Run("route/"+tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.authz.PermitsRoute(netip.MustParsePrefix(tc.route)))
		})
	}

	labelCases := []struct {
		name   string
		authz  *token.AuthzResult
		labels map[string]string
		want   bool
	}{
		{name: "unbounded permits anything", authz: unbounded, labels: map[string]string{"x": "y"}, want: true},
		{name: "subset of first set", authz: bounded, labels: map[string]string{"app": "payments"}, want: true},
		{name: "full first set", authz: bounded, labels: map[string]string{"app": "payments", "env": "prod"}, want: true},
		{name: "subset of second set", authz: bounded, labels: map[string]string{"app": "billing"}, want: true},
		{name: "empty labels always permitted", authz: bounded, labels: nil, want: true},
		{name: "wrong value", authz: bounded, labels: map[string]string{"app": "fraud"}, want: false},
		{name: "extra key beyond any set", authz: bounded, labels: map[string]string{"app": "payments", "team": "x"}, want: false},
		{name: "mix of two sets", authz: bounded, labels: map[string]string{"app": "billing", "env": "prod"}, want: false},
	}
	for _, tc := range labelCases {
		t.Run("labels/"+tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.authz.PermitsLabels(tc.labels))
		})
	}
}

func TestMultiTenantValidator(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)

	privateKey, err := cryptoutils.ParseEllipticPrivateKeyPEM(privateKeyPEM)
	require.NoError(t, err)

	jwksHandler, err := token.NewJWKSHandler(publicKeyPEM)
	require.NoError(t, err)

	server := httptest.NewServer(jwksHandler)
	defer server.Close()

	const audience = "relay-test"
	projectID := uuid.NewString()

	sign := func(t *testing.T, mutate func(*token.Claims)) string {
		t.Helper()
		claims := token.Claims{
			RegisteredClaims: jwtv5.RegisteredClaims{
				Issuer:    projectID,
				Audience:  jwtv5.ClaimStrings{audience},
				ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(5 * time.Minute)),
				IssuedAt:  jwtv5.NewNumericDate(time.Now()),
			},
			Net: "corp",
		}
		if mutate != nil {
			mutate(&claims)
		}
		tokenStr, err := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims).SignedString(privateKey)
		require.NoError(t, err)
		return tokenStr
	}

	newValidator := func() *token.MultiTenantValidator {
		// The JWKS handler serves the key set on every path, so the issuer
		// placeholder can go anywhere in the URL.
		return token.NewMultiTenantValidator(server.URL+"/%s"+token.JWKSURI, audience)
	}

	cases := []struct {
		name    string
		token   func(t *testing.T) string
		network string
		wantErr bool
		check   func(t *testing.T, authz *token.AuthzResult)
	}{
		{
			name:    "valid unbounded",
			token:   func(t *testing.T) string { return sign(t, nil) },
			network: "corp",
			check: func(t *testing.T, authz *token.AuthzResult) {
				require.Equal(t, "corp", authz.Network)
				require.Empty(t, authz.AllowedLabelSets)
				require.Empty(t, authz.AllowedRoutes)
			},
		},
		{
			name: "valid with bounds",
			token: func(t *testing.T) string {
				return sign(t, func(c *token.Claims) {
					c.AllowedLabelSets = []map[string]string{{"app": "payments"}}
					c.AllowedRoutes = []string{"10.0.0.0/8"}
				})
			},
			network: "corp",
			check: func(t *testing.T, authz *token.AuthzResult) {
				require.Equal(t, []map[string]string{{"app": "payments"}}, authz.AllowedLabelSets)
				require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, authz.AllowedRoutes)
			},
		},
		{
			name: "wrong audience",
			token: func(t *testing.T) string {
				return sign(t, func(c *token.Claims) { c.Audience = jwtv5.ClaimStrings{"other-relay"} })
			},
			network: "corp",
			wantErr: true,
		},
		{
			name:    "wrong network",
			token:   func(t *testing.T) string { return sign(t, nil) },
			network: "other",
			wantErr: true,
		},
		{
			name: "expired",
			token: func(t *testing.T) string {
				return sign(t, func(c *token.Claims) {
					c.ExpiresAt = jwtv5.NewNumericDate(time.Now().Add(-time.Minute))
				})
			},
			network: "corp",
			wantErr: true,
		},
		{
			name: "missing expiration",
			token: func(t *testing.T) string {
				return sign(t, func(c *token.Claims) { c.ExpiresAt = nil })
			},
			network: "corp",
			wantErr: true,
		},
		{
			name: "non-ES256 rejected",
			token: func(t *testing.T) string {
				claims := token.Claims{
					RegisteredClaims: jwtv5.RegisteredClaims{
						Issuer:    projectID,
						Audience:  jwtv5.ClaimStrings{audience},
						ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(5 * time.Minute)),
					},
					Net: "corp",
				}
				tokenStr, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims).SignedString([]byte("hmac-key"))
				require.NoError(t, err)
				return tokenStr
			},
			network: "corp",
			wantErr: true,
		},
		{
			name: "bad CIDR in claim",
			token: func(t *testing.T) string {
				return sign(t, func(c *token.Claims) { c.AllowedRoutes = []string{"not-a-cidr"} })
			},
			network: "corp",
			wantErr: true,
		},
		{
			name:    "garbage token",
			token:   func(t *testing.T) string { return "not.a.jwt" },
			network: "corp",
			wantErr: true,
		},
		{
			name: "non-uuid issuer rejected before any fetch",
			token: func(t *testing.T) string {
				return sign(t, func(c *token.Claims) { c.Issuer = "evil.com/jwks.json#" })
			},
			network: "corp",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newValidator()
			authz, err := v.Validate(context.Background(), tc.network, tc.token(t))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.check != nil {
				tc.check(t, authz)
			}
		})
	}
}
