// SPDX-License-Identifier: AGPL-3.0-only

// Package workerd holds the apiserver-side data plane of the APO-796
// ServiceManager integration: a private, node-local channel over which the
// co-located workerd-manager publishes the resident workerd's socket and the
// per-service live-revision demux map, plus the registry the Gateway-API xDS
// translator reads to inject the resident cluster and the x-apoxy-service demux
// header.
//
// In the apoxy CLI dev runtime the apiserver — not the backplane — runs the
// Gateway-API to xDS translation (the backplane's Envoy is an xDS client), so
// the registry and publish receiver live here, alongside the translator. The
// channel is deliberately NOT the customer-facing compute API: the manager and
// its resident are a runtime artifact no API surfaces; the manager publishes the
// resident socket (and the live-revision map it derives from the control plane)
// directly to this private endpoint.
package workerd

import (
	"strings"
	"sync"
)

// Snapshot is the published routing state the manager pushes to the apiserver.
// It is the wire contract of the private publish channel (see Server) and mirrors
// apoxy-cli pkg/workerd/manager.PublishSnapshot and apoxy-cloud
// backplane/workerd.Snapshot — keep the JSON field tags in sync across all three.
type Snapshot struct {
	// ResidentSocket is the host AF_UNIX path the resident workerd's dispatcher
	// listens on (the manager's host.ResidentInstance.InboundSocket). Envoy
	// reaches every workerd Service through a single static cluster pointing at
	// this socket.
	ResidentSocket string `json:"residentSocket"`
	// Demux maps a project-qualified service key "<project>:<service>" to its live
	// ServiceRevision name. The translator sets
	// `x-apoxy-service: <project>:<service>:<liveRevision>` on requests so the
	// dispatcher demuxes to the right isolate. The key is project-qualified
	// (matching the manager's serviceDemuxKey) so two projects' same-named
	// services never collide on a shared backplane.
	Demux map[string]string `json:"demux"`
}

// Registry is the concurrency-safe holder of the latest published Snapshot. The
// private publish server writes it; the translator hook reads it. A zero/empty
// registry means workerd routing is not active, so the hook is a no-op.
type Registry struct {
	mu   sync.RWMutex
	snap Snapshot
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Set replaces the published snapshot.
func (r *Registry) Set(s Snapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Copy the map so a later caller mutation can't race readers.
	demux := make(map[string]string, len(s.Demux))
	for k, v := range s.Demux {
		demux[k] = v
	}
	r.snap = Snapshot{ResidentSocket: s.ResidentSocket, Demux: demux}
}

// ResidentSocket returns the published resident socket, or "" if none.
func (r *Registry) ResidentSocket() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snap.ResidentSocket
}

// Active reports whether a resident socket has been published, i.e. whether the
// translator should inject the resident cluster and demux routes.
func (r *Registry) Active() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snap.ResidentSocket != ""
}

// DemuxHeader returns the x-apoxy-service demux header value
// ("<project>:<service>:<liveRevision>") for a bare compute Service name, or
// ok=false if no live revision is published for it.
//
// The translator only knows the Service name from the HTTPRoute backendRef, not
// the publishing manager's project id, so the lookup matches on the service
// segment of each project-qualified key. The dev apiserver serves a single
// project, so the match is unambiguous; the project id (a UUID) and the service
// name (a DNS-1123 label) contain no ':' so "<project>:<service>" splits cleanly.
func (r *Registry) DemuxHeader(service string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for key, rev := range r.snap.Demux {
		if rev == "" {
			continue
		}
		i := strings.LastIndex(key, ":")
		if i < 0 {
			continue
		}
		if key[i+1:] == service {
			return key + ":" + rev, true
		}
	}
	return "", false
}
