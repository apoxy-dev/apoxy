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
	"os"
	"path/filepath"
)

// workerPath is the control endpoint the dispatcher's WorkerLoader callback
// fetches worker definitions from: GET /worker?id=<service>:<revision>.
// Must match pkg/workerd/host/dispatcher.js.
const workerPath = "/worker"

// ControlServer is the manager side of the dispatcher control channel: an HTTP
// server that serves WorkerCode payloads the resident's WorkerLoader callback
// pulls. It listens on a host AF_UNIX socket; the clrk control forwarder bridges
// the dispatcher's in-sandbox TCP connections to it (see host.ResidentConfig).
type ControlServer struct {
	store *Store
}

// NewControlServer returns a control server backed by store.
func NewControlServer(store *Store) *ControlServer {
	return &ControlServer{store: store}
}

// Handler is the control HTTP handler (exported for tests via httptest).
func (c *ControlServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(workerPath, c.handleWorker)
	return mux
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

// ServeUnix listens on a host AF_UNIX socket at socketPath and serves the
// control API until ctx is cancelled. It removes a stale socket first and
// creates the parent directory.
func (c *ControlServer) ServeUnix(ctx context.Context, socketPath string) error {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return fmt.Errorf("creating control socket dir: %w", err)
	}
	// A leftover socket from a previous incarnation blocks bind.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing stale control socket: %w", err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listening on control socket %s: %w", socketPath, err)
	}

	srv := &http.Server{Handler: c.Handler()}
	// Close (not Shutdown) on cancel so an in-flight pull during teardown doesn't
	// wedge shutdown; the dispatcher retries. AfterFunc's stop() cancels the
	// watcher if Serve returns first (e.g. a listener error), so it never leaks.
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()

	slog.Info("Serving workerd control channel", "socket", socketPath)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serving control channel: %w", err)
	}
	return nil
}
