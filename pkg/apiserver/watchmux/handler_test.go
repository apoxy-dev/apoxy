package watchmux

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

func newTestHandler(t *testing.T, delegate http.Handler, authz authorizer.Authorizer) *Handler {
	t.Helper()
	h, err := New(Config{
		Delegate: delegate,
		RequestInfoResolver: &apirequest.RequestInfoFactory{
			APIPrefixes:          sets.NewString("api", "apis"),
			GrouplessAPIPrefixes: sets.NewString("api"),
		},
		Authorizer: authz,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func serveTestHandler(t *testing.T, h *Handler) (*httptest.Server, *websocket.Conn) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := apirequest.WithUser(r.Context(), &user.DefaultInfo{
			Name:   "alice@example.com",
			Groups: []string{"project:test"},
		})
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + Path + "?watch=true"
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{Subprotocols: []string{Protocol}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	if got := conn.Subprotocol(); got != Protocol {
		t.Fatalf("subprotocol = %q, want %q", got, Protocol)
	}
	return srv, conn
}

func readServerMessage(t *testing.T, conn *websocket.Conn) serverMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var msg serverMessage
	if err := wsjson.Read(ctx, conn, &msg); err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestHandlerStreamsAuthorizedWatch(t *testing.T) {
	attributes := make(chan authorizer.Attributes, 1)
	authz := authorizer.AuthorizerFunc(func(_ context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
		attributes <- attrs
		return authorizer.DecisionAllow, "allowed by test", nil
	})
	delegate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(http.CloseNotifier); !ok {
			t.Error("delegate response writer has no CloseNotifier")
			return
		}
		info, ok := apirequest.RequestInfoFrom(r.Context())
		if !ok {
			t.Error("delegate request has no RequestInfo")
			return
		}
		if info.Verb != "watch" || info.APIGroup != "apps" || info.Resource != "deployments" {
			t.Errorf("request info = %+v", info)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"type":"ADDED",`)
		w.(http.Flusher).Flush()
		_, _ = fmt.Fprint(w, `"object":{"metadata":{"name":"one"}}}`+"\n")
	})
	_, conn := serveTestHandler(t, newTestHandler(t, delegate, authz))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := wsjson.Write(ctx, conn, clientMessage{
		Type: "subscribe",
		ID:   "watch-1",
		Path: "/apis/apps/v1/deployments?watch=true&resourceVersion=7",
	}); err != nil {
		t.Fatal(err)
	}

	var body strings.Builder
	for {
		msg := readServerMessage(t, conn)
		if msg.ID != "watch-1" {
			t.Fatalf("message ID = %q, want watch-1", msg.ID)
		}
		switch msg.Type {
		case "start":
			if msg.Status != http.StatusOK {
				t.Fatalf("start status = %d, want 200", msg.Status)
			}
		case "data":
			chunk, err := base64.StdEncoding.DecodeString(msg.Data)
			if err != nil {
				t.Fatal(err)
			}
			body.Write(chunk)
		case "complete":
			goto complete
		default:
			t.Fatalf("unexpected message: %+v", msg)
		}
	}

complete:
	if got := body.String(); got != `{"type":"ADDED","object":{"metadata":{"name":"one"}}}`+"\n" {
		t.Fatalf("watch body = %q", got)
	}
	attrs := <-attributes
	if attrs.GetUser().GetName() != "alice@example.com" || attrs.GetVerb() != "watch" || attrs.GetResource() != "deployments" {
		t.Fatalf("authorization attributes = user:%q verb:%q resource:%q", attrs.GetUser().GetName(), attrs.GetVerb(), attrs.GetResource())
	}
}

func TestHandlerUsesAnonymousUserWhenAuthorizationIsDisabled(t *testing.T) {
	delegate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, ok := apirequest.UserFrom(r.Context())
		if !ok {
			t.Error("delegate request has no user")
			return
		}
		if userInfo.GetName() != user.Anonymous {
			t.Errorf("user = %q, want %q", userInfo.GetName(), user.Anonymous)
		}
		w.WriteHeader(http.StatusOK)
	})
	h := newTestHandler(t, delegate, nil)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + Path + "?watch=true"
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{Subprotocols: []string{Protocol}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	if err := wsjson.Write(ctx, conn, clientMessage{Type: "subscribe", ID: "anonymous", Path: "/api/v1/pods?watch=true"}); err != nil {
		t.Fatal(err)
	}
	if msg := readServerMessage(t, conn); msg.Type != "start" || msg.Status != http.StatusOK {
		t.Fatalf("start message = %+v", msg)
	}
	if msg := readServerMessage(t, conn); msg.Type != "complete" {
		t.Fatalf("complete message = %+v", msg)
	}
}

func TestHandlerRejectsInvalidAndForbiddenWatches(t *testing.T) {
	authz := authorizer.AuthorizerFunc(func(_ context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
		if attrs.GetResource() == "secrets" {
			return authorizer.DecisionDeny, "secrets are denied", nil
		}
		return authorizer.DecisionAllow, "", nil
	})
	delegate := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("rejected watch reached the delegate")
	})
	_, conn := serveTestHandler(t, newTestHandler(t, delegate, authz))

	cases := []struct {
		name       string
		path       string
		wantStatus int
		wantReason string
	}{
		{name: "absolute URL", path: "https://other.test/apis/apps/v1/deployments?watch=true", wantStatus: 400, wantReason: "BadRequest"},
		{name: "missing watch", path: "/apis/apps/v1/deployments", wantStatus: 400, wantReason: "BadRequest"},
		{name: "forbidden resource", path: "/api/v1/secrets?watch=true", wantStatus: 403, wantReason: "Forbidden"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := fmt.Sprintf("case-%d", i)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := wsjson.Write(ctx, conn, clientMessage{Type: "subscribe", ID: id, Path: tc.path}); err != nil {
				t.Fatal(err)
			}
			msg := readServerMessage(t, conn)
			if msg.Type != "error" || msg.ID != id || msg.Status != tc.wantStatus || string(msg.Error.Reason) != tc.wantReason {
				t.Fatalf("error message = %+v", msg)
			}
		})
	}
}

func TestHandlerMultiplexesAndCancelsWatches(t *testing.T) {
	authz := authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
		return authorizer.DecisionAllow, "", nil
	})
	canceled := make(chan string, 2)
	started := make(chan string, 2)
	delegate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, _ := apirequest.RequestInfoFrom(r.Context())
		started <- info.Resource
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		canceled <- info.Resource
	})
	_, conn := serveTestHandler(t, newTestHandler(t, delegate, authz))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, msg := range []clientMessage{
		{Type: "subscribe", ID: "a", Path: "/api/v1/pods?watch=true"},
		{Type: "subscribe", ID: "b", Path: "/api/v1/services?watch=true"},
	} {
		if err := wsjson.Write(ctx, conn, msg); err != nil {
			t.Fatal(err)
		}
	}

	seen := map[string]bool{}
	for range 2 {
		select {
		case resource := <-started:
			seen[resource] = true
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if !seen["pods"] || !seen["services"] {
		t.Fatalf("started resources = %v", seen)
	}
	if err := wsjson.Write(ctx, conn, clientMessage{Type: "unsubscribe", ID: "a"}); err != nil {
		t.Fatal(err)
	}
	select {
	case resource := <-canceled:
		if resource != "pods" {
			t.Fatalf("canceled resource = %q, want pods", resource)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	conn.CloseNow()
	select {
	case resource := <-canceled:
		if resource != "services" {
			t.Fatalf("canceled resource = %q, want services", resource)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestLogicalRequestValidation(t *testing.T) {
	h := newTestHandler(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil)
	s := &session{handler: h, ctx: context.Background()}
	cases := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "group resource", path: "/apis/apps/v1/deployments?watch=true"},
		{name: "core resource", path: "/api/v1/pods?watch=1"},
		{name: "object is not a collection", path: "/api/v1/pods/one?watch=true", wantErr: true},
		{name: "proxy endpoint recursion", path: Path + "?watch=true", wantErr: true},
		{name: "non API path", path: "/metrics?watch=true", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := s.logicalRequest(tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("logicalRequest(%q) error = %v, wantErr %v", tc.path, err, tc.wantErr)
			}
		})
	}
}

func TestPathIsNonResource(t *testing.T) {
	factory := &apirequest.RequestInfoFactory{
		APIPrefixes:          sets.NewString("api", "apis"),
		GrouplessAPIPrefixes: sets.NewString("api"),
	}
	req := httptest.NewRequest(http.MethodGet, Path+"?watch=true", nil)
	info, err := factory.NewRequestInfo(req)
	if err != nil {
		t.Fatalf("NewRequestInfo() error = %v", err)
	}
	if info.IsResourceRequest {
		t.Fatalf("watch multiplexer path resolved as a resource request: %+v", info)
	}
}
