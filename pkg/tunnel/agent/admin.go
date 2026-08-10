package agent

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// ConnectionTracker records the live relay sessions for one agent process.
// The required count is immutable so readiness uses the same target as the
// connection manager for the lifetime of the process.
type ConnectionTracker struct {
	active   atomic.Int32
	required int32
}

// NewConnectionTracker creates a tracker for the requested connection count.
func NewConnectionTracker(required int) *ConnectionTracker {
	if required < 1 {
		required = 1
	}
	return &ConnectionTracker{required: int32(required)}
}

// ActiveConnections returns the current number of live relay sessions.
func (t *ConnectionTracker) ActiveConnections() int {
	return int(t.active.Load())
}

// RequiredConnections returns the connection count required for readiness.
func (t *ConnectionTracker) RequiredConnections() int {
	return int(t.required)
}

// Ready reports whether the agent meets its configured connection target.
func (t *ConnectionTracker) Ready() bool {
	return t.active.Load() >= t.required
}

// ConnectionOpened records one live relay session.
func (t *ConnectionTracker) ConnectionOpened() {
	t.active.Add(1)
}

// ConnectionClosed records the end of one live relay session.
func (t *ConnectionTracker) ConnectionClosed() {
	t.active.Add(-1)
}

// LivenessHandler reports that the agent process and admin server are live.
// The server stops with the agent, so an active handler is sufficient for
// process liveness and does not depend on relay availability.
func LivenessHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, "OK - agent process is live")
}

// ReadinessHandler reports whether all requested relay sessions are live.
func (t *ConnectionTracker) ReadinessHandler(w http.ResponseWriter, _ *http.Request) {
	active := t.ActiveConnections()
	required := t.RequiredConnections()
	if active >= required {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "READY - %d/%d active connection(s)\n", active, required)
		return
	}

	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = fmt.Fprintf(w, "NOT READY - %d/%d active connection(s)\n", active, required)
}
