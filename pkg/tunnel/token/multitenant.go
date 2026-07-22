package token

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

// Claims is the tunnel credential claim shape: the issuer identifies the
// project (and thus the JWKS endpoint), the audience identifies the relay
// deployment, and the net claim binds the credential to a single network.
// The optional allowed-label-sets and allowed-routes claims bound what the
// credential may declare at connect time.
type Claims struct {
	jwt.RegisteredClaims
	// Net is the network (tunnel name) the credential is bound to.
	Net string `json:"net"`
	// AllowedLabelSets bounds the labels an agent may declare. Empty means
	// unbounded.
	AllowedLabelSets []map[string]string `json:"allowedLabelSets,omitempty"`
	// AllowedRoutes bounds the CIDRs an agent may advertise. Empty means
	// unbounded.
	AllowedRoutes []string `json:"allowedRoutes,omitempty"`
}

// MultiTenantValidator validates per-network JWTs by extracting the issuer
// (iss) claim and fetching JWKS from the appropriate per-project endpoint.
// It implements the TokenValidator interface.
type MultiTenantValidator struct {
	// jwksURLFormat is the format string for constructing JWKS URLs.
	// It should contain a %s placeholder for the issuer.
	// Example: "http://apiserver.%s.svc:8444/.well-known/jwks.json"
	jwksURLFormat string
	// audience is the relay audience the credential must be scoped to.
	audience string
	// ctx bounds the lifetime of cached keyfuncs' background JWKS refresh
	// goroutines. It outlives any single request; cancel via Close.
	ctx    context.Context
	cancel context.CancelFunc
	// sf collapses concurrent keyfunc construction for the same issuer so the
	// JWKS fetch happens once, outside mu.
	sf singleflight.Group

	mu       sync.RWMutex
	keyfuncs map[string]keyfunc.Keyfunc
}

// NewMultiTenantValidator creates a new multi-tenant JWT validator. The
// jwksURLFormat should contain a %s placeholder for the issuer; audience is
// the relay audience presented credentials must carry.
func NewMultiTenantValidator(jwksURLFormat, audience string) *MultiTenantValidator {
	ctx, cancel := context.WithCancel(context.Background())
	return &MultiTenantValidator{
		jwksURLFormat: jwksURLFormat,
		audience:      audience,
		ctx:           ctx,
		cancel:        cancel,
		keyfuncs:      make(map[string]keyfunc.Keyfunc),
	}
}

// Close stops the background JWKS refresh for all cached issuers.
func (v *MultiTenantValidator) Close() {
	v.cancel()
}

// extractIssuer extracts the issuer claim from a JWT token without validating it.
func extractIssuer(tokenStr string) (string, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid token format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode payload: %w", err)
	}

	var payload struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", fmt.Errorf("failed to parse payload: %w", err)
	}

	if payload.Iss == "" {
		return "", errors.New("missing issuer claim")
	}

	return payload.Iss, nil
}

// getOrCreateKeyfunc returns a cached keyfunc or creates a new one for the
// given issuer. The JWKS fetch happens outside mu (guarded by singleflight so
// only one fetch per issuer runs at a time), so a slow or unreachable endpoint
// for one issuer never stalls validation for others. The keyfunc's background
// refresh is bound to the validator's lifetime context, not any request.
func (v *MultiTenantValidator) getOrCreateKeyfunc(issuer string) (keyfunc.Keyfunc, error) {
	v.mu.RLock()
	kf, ok := v.keyfuncs[issuer]
	v.mu.RUnlock()
	if ok {
		return kf, nil
	}

	created, err, _ := v.sf.Do(issuer, func() (any, error) {
		// Another caller may have installed it between our RUnlock and here.
		v.mu.RLock()
		kf, ok := v.keyfuncs[issuer]
		v.mu.RUnlock()
		if ok {
			return kf, nil
		}

		jwksURL := fmt.Sprintf(v.jwksURLFormat, issuer)
		slog.Info("Creating keyfunc for issuer", slog.String("issuer", issuer), slog.String("url", jwksURL))

		kf, err := keyfunc.NewDefaultOverrideCtx(v.ctx, []string{jwksURL}, keyfunc.Override{
			HTTPTimeout:       10 * time.Second,
			RefreshUnknownKID: rate.NewLimiter(rate.Every(1*time.Second), 5),
			RateLimitWaitMax:  15 * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create keyfunc for issuer %s: %w", issuer, err)
		}

		v.mu.Lock()
		v.keyfuncs[issuer] = kf
		v.mu.Unlock()
		return kf, nil
	})
	if err != nil {
		return nil, err
	}
	return created.(keyfunc.Keyfunc), nil
}

// Validate validates the JWT for the given network and returns the resulting
// authorization. The credential must be an ES256 JWT with a required
// expiration, carry the validator's audience, and its net claim must match
// the requested network.
func (v *MultiTenantValidator) Validate(_ context.Context, network, tokenStr string) (*AuthzResult, error) {
	issuer, err := extractIssuer(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("failed to extract issuer: %w", err)
	}

	// The issuer is read from the yet-unverified token and interpolated into the
	// JWKS URL, so it must be a trusted, injection-free shape before any fetch:
	// a project UUID. This both blocks URL/SSRF injection via a crafted iss and
	// bounds the keyfunc cache to real project identifiers.
	if _, err := uuid.Parse(issuer); err != nil {
		return nil, fmt.Errorf("issuer %q is not a valid project id: %w", issuer, ErrUnauthorized)
	}

	kf, err := v.getOrCreateKeyfunc(issuer)
	if err != nil {
		return nil, err
	}

	var claims Claims
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&claims,
		func(token *jwt.Token) (any, error) {
			key, err := kf.Keyfunc(token)
			if err != nil {
				return nil, err
			}
			if key == nil {
				return nil, errors.New("key is nil")
			}
			switch key.(type) {
			case *ecdsa.PublicKey:
				return key, nil
			case jwt.VerificationKeySet:
				// Returned when the token has no kid header; the jwt library
				// tries each key in the set. ES256-only enforcement still
				// applies via WithValidMethods.
				return key, nil
			default:
				slog.Warn("Unsupported credential key type", slog.String("type", reflect.TypeOf(key).String()))
				return nil, errors.New("unsupported key type")
			}
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithAudience(v.audience),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	if claims.Net != network {
		return nil, fmt.Errorf("credential is bound to network %q, not %q: %w", claims.Net, network, ErrUnauthorized)
	}

	allowedRoutes := make([]netip.Prefix, 0, len(claims.AllowedRoutes))
	for _, cidr := range claims.AllowedRoutes {
		pfx, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed route %q in credential: %w", cidr, err)
		}
		allowedRoutes = append(allowedRoutes, pfx)
	}

	return &AuthzResult{
		Network:          network,
		AllowedLabelSets: claims.AllowedLabelSets,
		AllowedRoutes:    allowedRoutes,
	}, nil
}

// RemoveIssuer removes a cached keyfunc for an issuer, forcing a refresh on
// next validation.
func (v *MultiTenantValidator) RemoveIssuer(issuer string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.keyfuncs, issuer)
}
