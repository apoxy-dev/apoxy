// Package watchmux serves multiple Kubernetes watch streams over one browser
// WebSocket connection.
package watchmux

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	authorizerfilter "k8s.io/apiserver/pkg/endpoints/filters"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

const (
	// Path is the browser WebSocket endpoint. It is a non-resource path so the
	// outer authorization layer can admit the handshake before each logical
	// resource watch is authorized.
	Path = "/console/watch"
	// Protocol is the negotiated WebSocket subprotocol.
	Protocol = "apoxy.watch.v1"

	maxClientMessageBytes = 64 << 10
)

// Config supplies the API server components needed to dispatch and authorize
// logical watch requests.
type Config struct {
	Delegate            http.Handler
	RequestInfoResolver apirequest.RequestInfoResolver
	Authorizer          authorizer.Authorizer
}

// Handler multiplexes watch requests over one WebSocket.
type Handler struct {
	delegate            http.Handler
	requestInfoResolver apirequest.RequestInfoResolver
	authorizer          authorizer.Authorizer
}

// New returns a watch multiplexer handler.
func New(cfg Config) (*Handler, error) {
	if cfg.Delegate == nil {
		return nil, errors.New("watch multiplexer delegate is required")
	}
	if cfg.RequestInfoResolver == nil {
		return nil, errors.New("watch multiplexer request info resolver is required")
	}
	return &Handler{
		delegate:            cfg.Delegate,
		requestInfoResolver: cfg.RequestInfoResolver,
		authorizer:          cfg.Authorizer,
	}, nil
}

type clientMessage struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Path string `json:"path,omitempty"`
}

type serverMessage struct {
	Type   string         `json:"type"`
	ID     string         `json:"id,omitempty"`
	Status int            `json:"status,omitempty"`
	Data   string         `json:"data,omitempty"`
	Error  *metav1.Status `json:"error,omitempty"`
}

type subscription struct {
	cancel context.CancelFunc
}

type session struct {
	handler *Handler
	conn    *websocket.Conn
	ctx     context.Context

	writeMu sync.Mutex
	mu      sync.Mutex
	subs    map[string]*subscription
}

// ServeHTTP upgrades one browser connection and manages its logical watches.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// The authentication token can arrive as a second requested subprotocol.
	// Keep only the public protocol before the upgrade response is negotiated.
	r.Header.Set("Sec-WebSocket-Protocol", Protocol)
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
		Subprotocols:   []string{Protocol},
	})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(maxClientMessageBytes)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	s := &session{
		handler: h,
		conn:    conn,
		ctx:     ctx,
		subs:    make(map[string]*subscription),
	}
	defer s.stopAll()

	for {
		var msg clientMessage
		if err := wsjson.Read(ctx, conn, &msg); err != nil {
			return
		}
		switch msg.Type {
		case "subscribe":
			s.subscribe(msg)
		case "unsubscribe":
			s.unsubscribe(msg.ID)
		default:
			_ = s.sendStatus(msg.ID, http.StatusBadRequest, "BadRequest", "unsupported watch multiplexer message")
		}
	}
}

func (s *session) subscribe(msg clientMessage) {
	if msg.ID == "" {
		_ = s.sendStatus("", http.StatusBadRequest, "BadRequest", "subscription ID is required")
		return
	}

	req, requestInfo, err := s.logicalRequest(msg.Path)
	if err != nil {
		_ = s.sendStatus(msg.ID, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	baseCtx := s.ctx
	if _, ok := apirequest.UserFrom(baseCtx); !ok {
		if s.handler.authorizer != nil {
			_ = s.sendStatus(msg.ID, http.StatusUnauthorized, "Unauthorized", "authentication is required")
			return
		}
		baseCtx = apirequest.WithUser(baseCtx, &authuser.DefaultInfo{
			Name:   authuser.Anonymous,
			Groups: []string{authuser.AllUnauthenticated},
		})
	}

	s.mu.Lock()
	if _, exists := s.subs[msg.ID]; exists {
		s.mu.Unlock()
		_ = s.sendStatus(msg.ID, http.StatusConflict, "AlreadyExists", "subscription ID is already active")
		return
	}
	ctx, cancel := context.WithCancel(baseCtx)
	sub := &subscription{cancel: cancel}
	s.subs[msg.ID] = sub
	s.mu.Unlock()

	ctx = apirequest.WithRequestInfo(ctx, requestInfo)
	req = req.WithContext(ctx)
	if err := s.authorize(req); err != nil {
		s.remove(msg.ID, sub)
		cancel()
		_ = s.sendStatus(msg.ID, http.StatusForbidden, "Forbidden", err.Error())
		return
	}

	go func() {
		writer := &streamResponseWriter{session: s, id: msg.ID, ctx: req.Context()}
		s.handler.delegate.ServeHTTP(writer, req)
		s.remove(msg.ID, sub)
		cancel()
		_ = s.send(serverMessage{Type: "complete", ID: msg.ID})
	}()
}

func (s *session) logicalRequest(rawPath string) (*http.Request, *apirequest.RequestInfo, error) {
	u, err := url.ParseRequestURI(rawPath)
	if err != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" {
		return nil, nil, errors.New("watch path must be a relative API URL")
	}
	if u.Path == Path || (!strings.HasPrefix(u.Path, "/api/") && !strings.HasPrefix(u.Path, "/apis/")) {
		return nil, nil, errors.New("watch path must select a Kubernetes API resource")
	}
	watch := strings.ToLower(u.Query().Get("watch"))
	if watch != "1" && watch != "true" {
		return nil, nil, errors.New("watch path must set watch=true")
	}

	req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, u.RequestURI(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create watch request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	requestInfo, err := s.handler.requestInfoResolver.NewRequestInfo(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve watch request: %w", err)
	}
	if !requestInfo.IsResourceRequest || requestInfo.Verb != "watch" || requestInfo.Resource == "" {
		return nil, nil, errors.New("watch path must select a watchable resource collection")
	}
	return req, requestInfo, nil
}

func (s *session) authorize(req *http.Request) error {
	if s.handler.authorizer == nil {
		return nil
	}
	attrs, err := authorizerfilter.GetAuthorizerAttributes(req.Context())
	if err != nil {
		return fmt.Errorf("failed to build authorization attributes: %w", err)
	}
	decision, reason, err := s.handler.authorizer.Authorize(req.Context(), attrs)
	if err != nil {
		return fmt.Errorf("watch authorization failed: %w", err)
	}
	if decision != authorizer.DecisionAllow {
		if reason == "" {
			reason = "watch access is not allowed"
		}
		return errors.New(reason)
	}
	return nil
}

func (s *session) unsubscribe(id string) {
	s.mu.Lock()
	sub := s.subs[id]
	if sub != nil {
		delete(s.subs, id)
	}
	s.mu.Unlock()
	if sub != nil {
		sub.cancel()
	}
}

func (s *session) remove(id string, sub *subscription) {
	s.mu.Lock()
	if s.subs[id] == sub {
		delete(s.subs, id)
	}
	s.mu.Unlock()
}

func (s *session) stopAll() {
	s.mu.Lock()
	subs := make([]*subscription, 0, len(s.subs))
	for id, sub := range s.subs {
		delete(s.subs, id)
		subs = append(subs, sub)
	}
	s.mu.Unlock()
	for _, sub := range subs {
		sub.cancel()
	}
}

func (s *session) sendStatus(id string, code int, reason, message string) error {
	return s.send(serverMessage{
		Type:   "error",
		ID:     id,
		Status: code,
		Error: &metav1.Status{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
			Status:   metav1.StatusFailure,
			Code:     int32(code),
			Reason:   metav1.StatusReason(reason),
			Message:  message,
		},
	})
}

func (s *session) send(msg serverMessage) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return wsjson.Write(s.ctx, s.conn, msg)
}

type streamResponseWriter struct {
	session *session
	id      string
	ctx     context.Context
	header  http.Header
	status  int
}

func (w *streamResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *streamResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	_ = w.session.send(serverMessage{Type: "start", ID: w.id, Status: status})
}

func (w *streamResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if err := w.session.send(serverMessage{
		Type: "data",
		ID:   w.id,
		Data: base64.StdEncoding.EncodeToString(p),
	}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *streamResponseWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
}

// CloseNotify lets Kubernetes preserve streaming interfaces when it wraps the
// writer for request metrics. The logical request context ends on unsubscribe
// or when the browser WebSocket closes.
func (w *streamResponseWriter) CloseNotify() <-chan bool {
	closed := make(chan bool, 1)
	go func() {
		<-w.ctx.Done()
		closed <- true
	}()
	return closed
}

var (
	_ http.Flusher       = (*streamResponseWriter)(nil)
	_ http.CloseNotifier = (*streamResponseWriter)(nil)
)
