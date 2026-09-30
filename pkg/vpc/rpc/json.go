// SPDX-License-Identifier: AGPL-3.0-only

package rpc

import (
	"encoding/json"
	"io"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// JSONHandler returns an HTTP handler that runs the calls of mux with
// protojson messages, for curl on a local debug port. POST the request
// messages to /package.Service/Method. The response has one message on each
// line. An error is {"error":{"code":...,"message":...}}: the body with an
// HTTP error status before the first message, else the last line.
// ConnFromContext returns nil in these handlers.
func JSONHandler(mux *Mux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		rc := http.NewResponseController(w)
		j := &jsonCall{dec: json.NewDecoder(r.Body), w: w, rc: rc}
		h := mux.handlers[r.URL.Path]
		if h == nil {
			j.writeError(Errorf(Unimplemented, "unknown method %s", r.URL.Path))
			return
		}
		// A streaming handler can read the body after it writes.
		_ = rc.EnableFullDuplex()
		if err := h(r.Context(), &ServerStream{ctx: r.Context(), method: r.URL.Path, json: j}); err != nil {
			j.writeError(err)
		}
	})
}

// jsonCall is the HTTP side of a call from JSONHandler.
type jsonCall struct {
	dec  *json.Decoder
	w    http.ResponseWriter
	rc   *http.ResponseController
	err  error // First read error.
	sent bool
}

func (j *jsonCall) recv(m proto.Message) error {
	if j.err != nil {
		return j.err
	}
	var raw json.RawMessage
	err := j.dec.Decode(&raw)
	if err == nil {
		err = protojson.Unmarshal(raw, m)
	}
	if err != nil && err != io.EOF {
		err = Errorf(InvalidArgument, "decode JSON message: %v", err)
	}
	j.err = err
	return err
}

func (j *jsonCall) send(m proto.Message) error {
	b, err := protojson.Marshal(m)
	if err != nil {
		return Errorf(Internal, "encode JSON message: %v", err)
	}
	j.sent = true
	if _, err := j.w.Write(append(b, '\n')); err != nil {
		return Errorf(Unavailable, "write JSON message: %v", err)
	}
	_ = j.rc.Flush()
	return nil
}

type jsonError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (j *jsonCall) writeError(err error) {
	c, msg := toStatus(err)
	var e jsonError
	e.Error.Code, e.Error.Message = c.String(), msg
	b, _ := json.Marshal(e)
	if !j.sent {
		j.w.WriteHeader(httpStatus(c))
	}
	_, _ = j.w.Write(append(b, '\n'))
}

// httpStatus maps c to an HTTP status, as grpc-gateway does.
func httpStatus(c Code) int {
	switch c {
	case InvalidArgument, FailedPrecondition, OutOfRange:
		return http.StatusBadRequest
	case Unauthenticated:
		return http.StatusUnauthorized
	case PermissionDenied:
		return http.StatusForbidden
	case NotFound:
		return http.StatusNotFound
	case AlreadyExists, Aborted:
		return http.StatusConflict
	case ResourceExhausted:
		return http.StatusTooManyRequests
	case Canceled:
		return 499 // Client closed request.
	case Unimplemented:
		return http.StatusNotImplemented
	case Unavailable:
		return http.StatusServiceUnavailable
	case DeadlineExceeded:
		return http.StatusGatewayTimeout
	}
	return http.StatusInternalServerError
}
