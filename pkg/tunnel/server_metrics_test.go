package tunnel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
)

// TestTunnelServerMetricsPush pins how the legacy server push route answers:
// the connection ID comes from the connect handler and never from the body, a
// push that arrives before connect is refused, a server that keeps no store
// says so, and an oversized body is refused with 413 rather than buffered. The
// size cap comes from the shared decoder the relay push route uses, so both
// paths hold the same limit and give the same answer.
func TestTunnelServerMetricsPush(t *testing.T) {
	const (
		connID      = "conn-legacy-1"
		metricsBody = "# TYPE tunnel_relay_rtt_seconds gauge\n" +
			"tunnel_relay_rtt_seconds{relay=\"relay-a\"} 0.012\n"
	)

	cases := []struct {
		name string
		// method is the request method; empty means POST.
		method string
		// withStore attaches a metrics store to the server.
		withStore bool
		// withConnID publishes the connection ID the connect handler records.
		withConnID bool
		body       string
		wantCode   int
		// wantBody is the response text the handler must write, if any.
		wantBody string
		// wantStored is the family name the store must hold afterward.
		wantStored string
	}{
		{
			name:       "a push from a connected agent is stored",
			withStore:  true,
			withConnID: true,
			body:       metricsBody,
			wantCode:   http.StatusOK,
			wantStored: metrics.RelayRTTMetric,
		},
		{
			name:      "a push before connect is refused",
			withStore: true,
			body:      metricsBody,
			wantCode:  http.StatusPreconditionFailed,
		},
		{
			name:       "a server with no store reports it cannot keep the push",
			withConnID: true,
			body:       metricsBody,
			wantCode:   http.StatusServiceUnavailable,
		},
		{
			name:       "a method other than POST is refused",
			method:     http.MethodGet,
			withStore:  true,
			withConnID: true,
			body:       metricsBody,
			wantCode:   http.StatusMethodNotAllowed,
		},
		{
			name:       "a malformed body is rejected",
			withStore:  true,
			withConnID: true,
			body:       "this is not the exposition format\n",
			wantCode:   http.StatusBadRequest,
		},
		{
			name:       "a body over the cap is refused as too large",
			withStore:  true,
			withConnID: true,
			body:       strings.Repeat("tunnel_relay_rtt_seconds{relay=\"relay-a\"} 0.012\n", metrics.MaxPushBytes/40),
			wantCode:   http.StatusRequestEntityTooLarge,
			wantBody:   "request too large",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var store *metrics.MetricsStore
			if tc.withStore {
				store = metrics.NewMetricsStore()
				store.Register(metrics.StoreTarget{ConnID: connID})
			}
			srv := &TunnelServer{options: &tunnelServerOptions{metricsStore: store}}

			connIDRef := &atomic.Value{}
			if tc.withConnID {
				connIDRef.Store(connID)
			}

			method := tc.method
			if method == "" {
				method = http.MethodPost
			}
			req := httptest.NewRequest(method, api.MetricsPushPath, strings.NewReader(tc.body))
			resp := httptest.NewRecorder()

			srv.handleMetricsPush(resp, req, connIDRef)

			if resp.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", resp.Code, tc.wantCode)
			}
			if tc.wantBody != "" {
				if got := strings.TrimSpace(resp.Body.String()); got != tc.wantBody {
					t.Fatalf("body = %q, want %q", got, tc.wantBody)
				}
			}
			if store == nil {
				return
			}
			families := store.Results()[connID].Families
			if tc.wantStored == "" {
				if len(families) != 0 {
					t.Fatalf("store holds %d families, want none", len(families))
				}
				return
			}
			mf, ok := families[tc.wantStored]
			if !ok {
				t.Fatalf("store holds %v, want %q", families, tc.wantStored)
			}
			if got := mf.GetMetric()[0].GetGauge().GetValue(); got != 0.012 {
				t.Errorf("%s = %v, want 0.012", tc.wantStored, got)
			}
		})
	}
}
