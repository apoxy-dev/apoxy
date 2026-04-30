package tunnel

import (
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/apoxy-dev/apoxy/pkg/diag"
	"github.com/apoxy-dev/apoxy/pkg/diag/protocol"
)

// handleDiagRPC services the long-lived bidi diag stream from an
// agent. The agent opens this on the same QUIC conn it uses for
// /connect; auth is inherited (we just need /connect to have run on
// this conn first so we know which TunnelNode is on the other end).
//
// Request body  (agent → server): nd-json Response frames.
// Response body (server → agent): nd-json Request frames.
func (t *TunnelServer) handleDiagRPC(w http.ResponseWriter, r *http.Request, connIDRef *atomic.Value) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	connID, ok := connIDRef.Load().(string)
	if !ok || connID == "" {
		// Diag stream arrived before /connect completed on this QUIC
		// conn. The agent's dispatcher waits 2s before opening, so
		// this should be rare; reply 412 and let it retry.
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}

	c, exists := t.conns.Get(connID)
	if !exists || c.obj == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	tunUID := string(c.obj.UID)
	if tunUID == "" {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		// Without Flush, the agent never observes our writes; that
		// makes the stream useless. Refuse rather than hang.
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", protocol.MimeType)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	sess := diag.NewSession(w, r.Body)
	sess.Start()
	t.diagSessions.Register(tunUID, sess)

	log := slog.With(
		slog.String("subsystem", "diag"),
		slog.String("tun_uid", tunUID),
		slog.String("conn_id", connID),
	)
	log.Info("Diag session opened")

	defer func() {
		t.diagSessions.Unregister(tunUID, sess)
		sess.Close()
		log.Info("Diag session closed")
	}()

	// Block until either the request context dies (QUIC stream gone)
	// or the session demux loop exits.
	select {
	case <-r.Context().Done():
	case <-sess.Done():
	}
}
