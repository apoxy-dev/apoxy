package tunnel

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alphadose/haxmap"
	"github.com/julienschmidt/httprouter"
)

// TestRelayTeardownIsIdentityAware pins the reconnect race: a stale
// session-close watcher for a replaced connection (same 4-tuple, same ID)
// must not tear down the replacement, or its addresses get released while the
// session is live and the next connect is handed a duplicate /96.
func TestRelayTeardownIsIdentityAware(t *testing.T) {
	var disconnects []string
	r := &Relay{
		conns:  haxmap.New[string, *connection](),
		agents: haxmap.New[string, string](),
	}
	r.SetOnDisconnect(func(ctx context.Context, agent, id string) error {
		disconnects = append(disconnects, id)
		return nil
	})

	old := &connection{id: "same-id"}
	replacement := &connection{id: "same-id"}
	r.conns.Set("same-id", replacement)

	// Stale teardown for the replaced session: must be a no-op.
	r.teardownConn(context.Background(), old)
	if got, ok := r.conns.Get("same-id"); !ok || got != replacement {
		t.Fatal("stale teardown removed the replacement connection")
	}
	if len(disconnects) != 0 {
		t.Fatalf("stale teardown fired onDisconnect: %v", disconnects)
	}

	// Teardown of the live connection still works, exactly once.
	r.teardownConn(context.Background(), replacement)
	if _, ok := r.conns.Get("same-id"); ok {
		t.Fatal("teardown did not remove the live connection")
	}
	r.teardownConn(context.Background(), replacement)
	if len(disconnects) != 1 {
		t.Fatalf("onDisconnect fired %d times, want 1", len(disconnects))
	}
}

func TestRelayConnectRequiresHTTP3SessionTracking(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/tunnel/default", bytes.NewBufferString(`{"agent":"agent-a"}`))
	resp := httptest.NewRecorder()

	(&Relay{}).handleConnect(resp, req, httprouter.Params{{Key: "name", Value: "default"}})

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusInternalServerError)
	}
}
