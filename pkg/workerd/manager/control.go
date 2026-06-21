// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
)

// workerPath is the control endpoint the dispatcher's WorkerLoader callback
// fetches worker definitions from: GET /worker?id=<project>:<service>:<revision>.
// Must match pkg/workerd/host/dispatcher.js.
const workerPath = "/worker"

// resolvePath is the control endpoint the dispatcher resolves a service to its
// live revision id through: GET /resolve?service=<project>:<service>. The
// dispatcher uses the returned id as its WorkerLoader cache key and its /worker
// argument, so the revision is never stamped into the Envoy demux header and a
// rollout never re-translates Envoy config. Must match pkg/workerd/host/dispatcher.js.
const resolvePath = "/resolve"

// ControlServer is the manager side of the dispatcher control channel: an HTTP
// server that serves WorkerCode payloads the resident's WorkerLoader callback
// pulls. It listens on a host loopback TCP address; the clrk control forwarder
// bridges the dispatcher's in-sandbox connections to it (see host.ResidentConfig).
// It is TCP, not AF_UNIX: the Sentry's plugin seccomp only allows socket() for
// AF_INET/AF_INET6, so the forwarder cannot dial a host unix socket.
type ControlServer struct {
	store *Store
}

// NewControlServer returns a control server backed by store.
func NewControlServer(store *Store) *ControlServer {
	return &ControlServer{store: store}
}

// resolveResponse is the /resolve body: the full demux id the dispatcher loads
// (and pulls via /worker), plus the bare revision for observability.
type resolveResponse struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}

// Handler is the control HTTP handler (exported for tests via httptest).
func (c *ControlServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(workerPath, c.handleWorker)
	mux.HandleFunc(resolvePath, c.handleResolve)
	return mux
}

// handleResolve maps a project-qualified service key "<project>:<service>" to the
// revision-bearing demux id the resident currently serves for it. The dispatcher
// resolves here (rather than reading the revision off the Envoy header) so the
// revision lives entirely in the resident; the backplane routes here only once a
// revision is live, so a miss is a brief rollout-edge window the dispatcher
// surfaces as a 503.
func (c *ControlServer) handleResolve(w http.ResponseWriter, req *http.Request) {
	service := req.URL.Query().Get("service")
	if service == "" {
		http.Error(w, "missing service", http.StatusBadRequest)
		return
	}
	rev, ok := c.store.liveRevision(service)
	if !ok {
		http.Error(w, "no live revision for service "+service, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resolveResponse{ID: service + ":" + rev, Revision: rev}); err != nil {
		slog.Error("Failed to encode resolve response", "service", service, "error", err)
	}
}

func (c *ControlServer) handleWorker(w http.ResponseWriter, req *http.Request) {
	id := req.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	def, err := c.store.Get(req.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, errRevisionNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		default:
			// Bundle pull / build failure: a 502 the dispatcher surfaces to the
			// client (and retries on the next request once the bundle resolves).
			slog.Error("Failed to resolve worker definition", "id", id, "error", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(def); err != nil {
		slog.Error("Failed to encode worker definition", "id", id, "error", err)
	}
}

// ServeTCP listens on the host loopback TCP address addr (e.g. "127.0.0.1:2024")
// and serves the control API until ctx is cancelled. The address is in the
// manager's own netns, which the Sentry's control forwarder shares, so a guest
// dispatcher reaches it through the forwarder's host TCP dial.
func (c *ControlServer) ServeTCP(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on control addr %s: %w", addr, err)
	}

	srv := &http.Server{Handler: c.Handler()}
	// Close (not Shutdown) on cancel so an in-flight pull during teardown doesn't
	// wedge shutdown; the dispatcher retries. AfterFunc's stop() cancels the
	// watcher if Serve returns first (e.g. a listener error), so it never leaks.
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()

	slog.Info("Serving workerd control channel", "addr", addr)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serving control channel: %w", err)
	}
	return nil
}
