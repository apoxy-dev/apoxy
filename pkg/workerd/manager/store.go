// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"sync"

	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
)

// Store caches resolved WorkerDefinitions by demux id. The resident reconciler
// warms it (gating ServiceRevision readiness on a successful resolve), and the
// control server reads it on the dispatcher's pull path so a warmed revision is
// served without a second registry round-trip.
//
// The cache is an optimization, not the source of truth: a cold Get resolves on
// demand. WorkerLoader caches the isolate by id on the workerd side, so the
// control server is only hit on a dispatcher cache miss (first request per
// revision, or after a resident restart).
type Store struct {
	resolver *Resolver

	mu   sync.RWMutex
	defs map[string]host.WorkerDefinition
}

// NewStore returns a Store backed by resolver.
func NewStore(resolver *Resolver) *Store {
	return &Store{resolver: resolver, defs: make(map[string]host.WorkerDefinition)}
}

// Warm resolves id and caches the result. Returns the resolve error unchanged
// (the caller decides readiness / HTTP status).
func (s *Store) Warm(ctx context.Context, id string) (host.WorkerDefinition, error) {
	def, err := s.resolver.Resolve(ctx, id)
	if err != nil {
		return host.WorkerDefinition{}, err
	}
	s.mu.Lock()
	s.defs[id] = def
	s.mu.Unlock()
	return def, nil
}

// Get returns the cached definition for id, resolving (and caching) on a miss.
func (s *Store) Get(ctx context.Context, id string) (host.WorkerDefinition, error) {
	s.mu.RLock()
	def, ok := s.defs[id]
	s.mu.RUnlock()
	if ok {
		return def, nil
	}
	return s.Warm(ctx, id)
}

// Invalidate drops a cached definition (the revision was deleted). The workerd
// isolate idles out on its own; M1 issues no explicit unload.
func (s *Store) Invalidate(id string) {
	s.mu.Lock()
	delete(s.defs, id)
	s.mu.Unlock()
}

// cached reports whether id is in the cache (test/diagnostic helper).
func (s *Store) cached(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.defs[id]
	return ok
}
