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

	// demuxMu guards demux, the latest service -> live revision selection the
	// resident reconciler computed. The control server's /resolve handler serves
	// it so the dispatcher resolves a service to its revision-bearing id in the
	// resident, instead of the backplane stamping the revision into the Envoy
	// demux header.
	demuxMu sync.RWMutex
	demux   map[string]string
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

// cached reports whether id is warmed (in the cache). The publish path uses this
// as THIS node's per-revision readiness signal: a revision is serveable on this
// node once its definition has resolved into the store.
func (s *Store) cached(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.defs[id]
	return ok
}

// setDemux records the latest service -> live revision selection the resident
// reconciler computed. The control server's /resolve handler serves it so the
// dispatcher resolves a service to its revision-bearing id in the resident,
// instead of the backplane stamping the revision into the Envoy demux header.
func (s *Store) setDemux(demux map[string]string) {
	cp := make(map[string]string, len(demux))
	for k, v := range demux {
		cp[k] = v
	}
	s.demuxMu.Lock()
	s.demux = cp
	s.demuxMu.Unlock()
}

// publishRoute records one service's live revision, leaving every other
// service's routing untouched. The resident reconciler publishes each service
// the moment it warms rather than accumulating a whole catalog and swapping it
// in at the end: a cold store after a restart would otherwise hold every
// service in the project unroutable until the slowest registry pull finished.
func (s *Store) publishRoute(serviceName, revisionName string) {
	s.demuxMu.Lock()
	defer s.demuxMu.Unlock()
	if s.demux == nil {
		s.demux = make(map[string]string)
	}
	s.demux[serviceName] = revisionName
}

// pruneRoutes drops routing for services absent from keep — deleted services,
// and services whose every revision failed to warm with nothing previously
// serving. Paired with publishRoute to complete a reconcile pass.
func (s *Store) pruneRoutes(keep map[string]struct{}) {
	s.demuxMu.Lock()
	defer s.demuxMu.Unlock()
	for service := range s.demux {
		if _, ok := keep[service]; !ok {
			delete(s.demux, service)
		}
	}
}

// liveRevision returns the revision the resident currently serves for the bare
// service key, and whether one exists. A present-but-empty value reads as "no
// live revision" so the contract matches the dispatcher's resolve gate
// structurally, not by each caller remembering to re-check for empty.
func (s *Store) liveRevision(serviceKey string) (string, bool) {
	s.demuxMu.RLock()
	defer s.demuxMu.RUnlock()
	rev := s.demux[serviceKey]
	return rev, rev != ""
}

// demuxSnapshot returns a copy of the current routing state.
func (s *Store) demuxSnapshot() map[string]string {
	s.demuxMu.RLock()
	defer s.demuxMu.RUnlock()
	snapshot := make(map[string]string, len(s.demux))
	for service, revision := range s.demux {
		snapshot[service] = revision
	}
	return snapshot
}

// retain removes cached definitions not present in keep.
func (s *Store) retain(keep map[string]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.defs {
		if _, ok := keep[id]; !ok {
			delete(s.defs, id)
		}
	}
}
