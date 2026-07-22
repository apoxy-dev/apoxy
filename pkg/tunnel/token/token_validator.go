package token

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/netip"
	"sync"
)

// ErrUnauthorized is returned by TokenValidator implementations when the
// presented credential is missing, malformed, or does not authenticate for the
// requested network.
var ErrUnauthorized = errors.New("unauthorized")

// AuthzResult is what a validated credential authorizes.
type AuthzResult struct {
	// Network is the network (tunnel name) the credential is bound to.
	Network string
	// AllowedLabelSets bounds the labels an agent may declare. Empty means
	// unbounded. A declared label map is permitted iff it is a subset of at
	// least one set.
	AllowedLabelSets []map[string]string
	// AllowedRoutes bounds the CIDRs an agent may advertise. Empty means
	// unbounded. A route is permitted iff it is contained within at least one
	// allowed prefix.
	AllowedRoutes []netip.Prefix
}

// PermitsRoute reports whether the credential permits advertising the given
// route. An empty AllowedRoutes list permits everything.
func (a *AuthzResult) PermitsRoute(route netip.Prefix) bool {
	if len(a.AllowedRoutes) == 0 {
		return true
	}
	for _, allowed := range a.AllowedRoutes {
		if allowed.Bits() <= route.Bits() && allowed.Contains(route.Masked().Addr()) {
			return true
		}
	}
	return false
}

// PermitsLabels reports whether the credential permits declaring the given
// labels: the declared map must be a subset of at least one allowed set. An
// empty AllowedLabelSets list permits everything.
func (a *AuthzResult) PermitsLabels(labels map[string]string) bool {
	if len(a.AllowedLabelSets) == 0 {
		return true
	}
	for _, allowed := range a.AllowedLabelSets {
		subset := true
		for k, v := range labels {
			if av, ok := allowed[k]; !ok || av != v {
				subset = false
				break
			}
		}
		if subset {
			return true
		}
	}
	return false
}

// TokenValidator authenticates a tunnel credential presented for a network and
// returns what it authorizes.
type TokenValidator interface {
	// Validate authenticates tokenStr for the given network (tunnel name) and
	// returns the resulting authorization, or an error if the credential does
	// not authenticate.
	Validate(ctx context.Context, network, tokenStr string) (*AuthzResult, error)
}

// StaticTokenValidator authorizes agents by comparing the presented token
// against a per-network static bearer token. Matching credentials are
// unbounded: any labels and routes may be declared.
type StaticTokenValidator struct {
	mu     sync.RWMutex
	tokens map[string]string
}

// NewStaticTokenValidator creates an empty static per-network token validator.
func NewStaticTokenValidator() *StaticTokenValidator {
	return &StaticTokenValidator{tokens: make(map[string]string)}
}

// SetToken sets the bearer token for a network.
func (v *StaticTokenValidator) SetToken(network, token string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tokens[network] = token
}

// RemoveToken removes the bearer token for a network.
func (v *StaticTokenValidator) RemoveToken(network string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.tokens, network)
}

// Validate compares the presented token against the network's stored token.
func (v *StaticTokenValidator) Validate(_ context.Context, network, tokenStr string) (*AuthzResult, error) {
	v.mu.RLock()
	stored, ok := v.tokens[network]
	v.mu.RUnlock()

	if !ok || subtle.ConstantTimeCompare([]byte(stored), []byte(tokenStr)) != 1 {
		return nil, ErrUnauthorized
	}
	return &AuthzResult{Network: network}, nil
}
