// SPDX-License-Identifier: AGPL-3.0-only

package workerd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
)

// publishPath is the private publish endpoint the workerd-manager POSTs a
// Snapshot to. It is the wire contract; keep it in sync with the manager's
// publisher (apoxy-cli pkg/workerd/manager.httpPublisher).
const publishPath = "/publish"

// Server is the private HTTP server each co-located workerd-manager publishes its
// node's routing snapshot to. It listens on a loopback address by default, never
// on a customer-reachable interface, and writes each accepted snapshot into the
// shared Registry the translator reads.
type Server struct {
	registry *Registry

	// AllowNonLoopback, when true, permits Serve to bind a non-loopback address.
	// DEV ONLY: with the tight backplane↔resident coupling reflected in dev, the
	// workerd-manager runs in the BACKPLANE's netns (not the apiserver's), so it
	// reaches this apiserver-hosted channel over the container network by name
	// rather than loopback. The channel still trusts its caller, so this must only
	// be enabled on a private network (the dev docker bridge).
	AllowNonLoopback bool
}

// NewServer returns a publish server writing to registry.
func NewServer(registry *Registry) *Server {
	return &Server{registry: registry}
}

// Handler is the publish HTTP handler (exported for tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(publishPath, s.handlePublish)
	return mux
}

func (s *Server) handlePublish(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost && req.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var snap Snapshot
	if err := json.NewDecoder(req.Body).Decode(&snap); err != nil {
		http.Error(w, fmt.Sprintf("decoding snapshot: %v", err), http.StatusBadRequest)
		return
	}
	if snap.ResidentSocket == "" {
		http.Error(w, "snapshot is missing residentSocket", http.StatusBadRequest)
		return
	}
	s.registry.Upsert(snap)
	slog.Info("Published workerd routing snapshot",
		"node", snap.NodeID, "residentSocket", snap.ResidentSocket, "services", len(snap.Demux))
	w.WriteHeader(http.StatusNoContent)
}

// Serve listens on a loopback TCP address (e.g. "127.0.0.1:2021") and serves the
// publish API until ctx is cancelled. The address MUST be loopback: this channel
// trusts its caller (whatever it publishes becomes the resident socket and demux
// the data plane routes to), so binding a network-reachable interface would let
// anyone redirect all workerd traffic. A non-loopback addr is rejected before
// binding.
func (s *Server) Serve(ctx context.Context, addr string) error {
	if !s.AllowNonLoopback {
		if err := validateLoopbackAddr(addr); err != nil {
			return err
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on workerd publish addr %s: %w", addr, err)
	}
	srv := &http.Server{Handler: s.Handler()}
	// Close on cancel; AfterFunc's stop() cancels the closer if Serve returns
	// first (e.g. a listener error), so nothing leaks.
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	slog.Info("Serving workerd private publish channel", "addr", addr)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serving workerd publish channel: %w", err)
	}
	return nil
}

// validateLoopbackAddr rejects a publish bind address that is not loopback. A
// literal IP must be loopback; a bare ":port"/0.0.0.0/:: (all interfaces) is
// refused; a hostname must resolve to loopback addresses only.
func validateLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parsing workerd publish addr %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("workerd publish addr %q binds all interfaces; use a loopback address", addr)
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return fmt.Errorf("workerd publish addr %q is not a loopback address", addr)
		}
		return nil
	}
	// A hostname (e.g. "localhost"): every resolved address must be loopback.
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolving workerd publish host %q: %w", host, err)
	}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return fmt.Errorf("workerd publish addr %q resolves to non-loopback %s", addr, ip)
		}
	}
	return nil
}
