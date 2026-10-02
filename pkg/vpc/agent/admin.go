// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
)

// maxAdminBody limits the size of an admin API request body.
const maxAdminBody = 1 << 20

// Attacher adds and removes the extra attachments of an agent. Agent
// implements it.
type Attacher interface {
	Attach(ctx context.Context, s AttachmentSpec) (Attachment, error)
	Detach(ctx context.Context, name string) error
	Attachments() []Attachment
}

// AdminHandler serves the admin API of a, with JSON bodies:
//
//	GET    /v1/attachments         200 with all attachments.
//	POST   /v1/attachments         200 with the attachment of an AttachmentSpec.
//	DELETE /v1/attachments/{name}  204.
//
// The errors are 400 for a request that is not valid, 404 for an unknown
// name, 409 for a name in use or the attachment of Config, and 503 when the
// agent has no relay session or the relay fails.
func AdminHandler(a Attacher) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/attachments", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.Attachments())
	})
	mux.HandleFunc("POST /v1/attachments", func(w http.ResponseWriter, r *http.Request) {
		var s AttachmentSpec
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBody))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&s); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("request body: %w", err))
			return
		}
		at, err := a.Attach(r.Context(), s)
		if err != nil {
			writeError(w, adminStatus(err), err)
			return
		}
		writeJSON(w, http.StatusOK, at)
	})
	mux.HandleFunc("DELETE /v1/attachments/{name}", func(w http.ResponseWriter, r *http.Request) {
		if err := a.Detach(r.Context(), r.PathValue("name")); err != nil {
			writeError(w, adminStatus(err), err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func adminStatus(err error) int {
	switch {
	case errors.Is(err, ErrInvalidAttachment), rpc.CodeOf(err) == rpc.InvalidArgument:
		return http.StatusBadRequest
	case errors.Is(err, ErrNoAttachment):
		return http.StatusNotFound
	case errors.Is(err, ErrAttachmentExists), errors.Is(err, ErrBaseAttachment), rpc.CodeOf(err) == rpc.AlreadyExists:
		return http.StatusConflict
	}
	return http.StatusServiceUnavailable
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// ServeAdmin serves AdminHandler(a) on the unix socket at path until ctx
// ends, then removes the socket. Only this user and root can connect.
func ServeAdmin(ctx context.Context, path string, a Attacher) error {
	ln, err := listenAdmin(path)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: AdminHandler(a), ReadHeaderTimeout: 10 * time.Second}
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		_ = ln.Close()
		return err
	}
	return nil
}

// listenAdmin listens on the unix socket at path with mode 0600. It removes
// a socket that no process serves.
func listenAdmin(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("admin socket %s: the file exists and is not a socket", path)
		}
		if c, err := net.Dial("unix", path); err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("admin socket %s: another process serves it", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("admin socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("admin socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("admin socket: %w", err)
	}
	return adminListener{ln}, nil
}

// adminListener closes the connections from users other than this user and
// root.
type adminListener struct{ net.Listener }

func (l adminListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(c)
		if err == nil && !adminUID(uid) {
			err = fmt.Errorf("user %d is not this user or root", uid)
		}
		if err == nil {
			return c, nil
		}
		slog.Warn("Refused an admin API connection", "error", err)
		_ = c.Close()
	}
}

// adminUID reports whether the user uid can use the admin API.
func adminUID(uid int) bool { return uid == os.Getuid() || uid == 0 }
