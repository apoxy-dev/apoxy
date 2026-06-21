// SPDX-License-Identifier: AGPL-3.0-only

// Package workerd holds the apiserver-side data plane of the APO-796
// ServiceManager integration: a private, node-local channel over which each
// co-located workerd-manager publishes its resident workerd's socket and the
// per-service revision THAT node currently serves (its node-local readiness),
// plus the registry the Gateway-API xDS translator reads to inject the resident
// cluster and the x-apoxy-service demux header.
//
// In the apoxy CLI dev runtime the apiserver — not the backplane — runs the
// Gateway-API to xDS translation (the backplane's Envoy is an xDS client), so
// the registry and publish receiver live here, alongside the translator. The
// channel is deliberately NOT the customer-facing compute API: the manager and
// its resident are a runtime artifact no API surfaces; the manager publishes its
// node's resident socket and the live-revision map it derives from LOCAL warm
// state directly to this private endpoint.
package workerd

import (
	"sort"
	"strings"
	"sync"
)

// Snapshot is one node's published routing state. It is the wire contract of the
// private publish channel (see Server) and mirrors apoxy-cli
// pkg/workerd/manager.PublishSnapshot and apoxy-cloud backplane/workerd.Snapshot
// — keep the JSON field tags in sync across all three.
type Snapshot struct {
	// NodeID identifies the backplane node (the backplane's --replica / Proxy
	// replica name) whose co-located workerd-manager published this row. The
	// registry keys rows by node so two backplanes' residents never collide.
	NodeID string `json:"nodeId"`
	// ResidentSocket is the host AF_UNIX path this node's resident workerd
	// dispatcher listens on. Envoy reaches every workerd Service through a single
	// static cluster pointing at this socket. All replicas of a Proxy mount the
	// resident UDS at the same path, so any node's socket is correct for the one
	// cluster the translator injects.
	ResidentSocket string `json:"residentSocket"`
	// Demux maps a project-qualified service key "<project>:<service>" to the
	// ServiceRevision THIS node currently serves for it (the newest revision this
	// node has warmed). The translator reads only presence-with-a-non-empty-value
	// and stamps `x-apoxy-service: <project>:<service>` (NO revision); the
	// resident's dispatcher resolves the revision itself (via the manager's
	// /resolve endpoint), so a rollout never re-translates xDS.
	Demux map[string]string `json:"demux"`
}

// Registry is the concurrency-safe holder of the latest published Snapshot PER
// NODE. Each co-located workerd-manager (1:1 with a backplane) publishes its own
// node row; the translator reads an AGGREGATE view because xDS translation is
// per-IR-key (per-Proxy), not per-node — one snapshot is fanned to every replica
// of a Proxy. In dedicated mode (one backplane per project apiserver, the
// `apoxy dev` topology) there is exactly one node, so the aggregate is exact.
// True per-replica divergence within a shared Proxy is a design follow-up (the
// per-IR-key translator cannot send different clusters to different replicas);
// the aggregate resolves it deterministically (lowest NodeID wins) until then.
//
// A zero/empty registry means workerd routing is not active, so the translator
// hook is a no-op.
type Registry struct {
	mu    sync.RWMutex
	nodes map[string]Snapshot // keyed by Snapshot.NodeID

	// notify coalesces "the registry changed" signals to one waiting consumer (the
	// xds-translator runner), which re-runs translation so a publish that arrives
	// AFTER the initial translation still injects the resident cluster/header. The
	// watchable IR bus dedups by value, so re-storing the IR can't force this; a
	// dedicated signal is the seam. Buffered(1) + non-blocking send = coalescing.
	notify chan struct{}
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{nodes: make(map[string]Snapshot), notify: make(chan struct{}, 1)}
}

// Notify returns a channel that receives a value whenever a publish changes the
// registry. Consumers re-read the aggregate via the read methods. Sends are
// coalesced, so a consumer may see one wakeup for several rapid publishes.
func (r *Registry) Notify() <-chan struct{} { return r.notify }

// signal wakes a Notify consumer without blocking if one isn't ready.
func (r *Registry) signal() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// Upsert replaces a single node's published snapshot. A snapshot with an empty
// NodeID is the singleton/anonymous node (dev/dedicated, where there is only one).
func (r *Registry) Upsert(s Snapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Copy the map so a later caller mutation can't race readers.
	demux := make(map[string]string, len(s.Demux))
	for k, v := range s.Demux {
		demux[k] = v
	}
	next := Snapshot{NodeID: s.NodeID, ResidentSocket: s.ResidentSocket, Demux: demux}
	// The reconciler republishes on every reconcile, but a value-identical
	// snapshot would re-translate every IR key for no output delta — only wake
	// the translator when this node's row actually changed.
	if prev, ok := r.nodes[s.NodeID]; ok && snapshotsEqual(prev, next) {
		return
	}
	r.nodes[s.NodeID] = next
	r.signal()
}

// Delete drops a node's row (the backplane/node disconnected). Wiring node
// disconnect to this is a follow-up; today rows are replaced on each republish.
func (r *Registry) Delete(nodeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.nodes[nodeID]; !ok {
		return
	}
	delete(r.nodes, nodeID)
	r.signal()
}

// snapshotsEqual reports whether two node rows carry the same routing state
// (resident socket + demux map). NodeID is the map key, so it is always equal
// for the two rows compared here.
func snapshotsEqual(a, b Snapshot) bool {
	if a.ResidentSocket != b.ResidentSocket || len(a.Demux) != len(b.Demux) {
		return false
	}
	for k, v := range a.Demux {
		if b.Demux[k] != v {
			return false
		}
	}
	return true
}

// ResidentSocket returns a published resident socket, or "" if none. All replicas
// of a Proxy mount the resident UDS at the same path, so any node's socket is the
// correct target for the single cluster the translator injects.
func (r *Registry) ResidentSocket() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, id := range r.sortedNodeIDsLocked() {
		if s := r.nodes[id].ResidentSocket; s != "" {
			return s
		}
	}
	return ""
}

// Active reports whether any node has published a resident socket, i.e. whether
// the translator should inject the resident cluster and demux routes. Order is
// irrelevant for a presence check, so it skips the sorted-node-id pass that
// ResidentSocket uses for deterministic selection.
func (r *Registry) Active() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, n := range r.nodes {
		if n.ResidentSocket != "" {
			return true
		}
	}
	return false
}

// DemuxHeader returns the x-apoxy-service demux header value
// ("<project>:<service>") for a bare compute Service name, aggregated across
// nodes, or ok=false if no node serves a live revision for it. The revision is
// deliberately NOT included: the resident's dispatcher resolves the live revision
// itself (via the manager's /resolve endpoint), so a rollout never re-translates
// xDS. A node advertising an empty revision for a service does not count as live.
//
// The translator only knows the Service name from the HTTPRoute backendRef, not
// the publishing manager's project id, so the lookup matches on the service
// segment of each project-qualified key. The dev apiserver serves a single
// project and a single node, so the match is unambiguous; the project id (a UUID)
// and the service name (a DNS-1123 label) contain no ':' so "<project>:<service>"
// splits cleanly. Across multiple nodes the lowest NodeID wins deterministically.
func (r *Registry) DemuxHeader(service string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, id := range r.sortedNodeIDsLocked() {
		for key, rev := range r.nodes[id].Demux {
			if rev == "" {
				continue
			}
			i := strings.LastIndex(key, ":")
			if i < 0 {
				continue
			}
			if key[i+1:] == service {
				return key, true
			}
		}
	}
	return "", false
}

// sortedNodeIDsLocked returns the node ids in deterministic order. Caller holds mu.
func (r *Registry) sortedNodeIDsLocked() []string {
	ids := make([]string, 0, len(r.nodes))
	for id := range r.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
