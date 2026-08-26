package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
)

// pushRecorder is a stand-in relay: it answers the connect and disconnect
// calls and records every metrics push.
type pushRecorder struct {
	mu     sync.Mutex
	bodies [][]byte
	pushed chan struct{}
	// status is the code the push route answers with.
	status int
}

func (p *pushRecorder) record(body []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.bodies = append(p.bodies, body)
	select {
	case p.pushed <- struct{}{}:
	default:
	}
}

func (p *pushRecorder) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.bodies)
}

func (p *pushRecorder) first() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.bodies) == 0 {
		return nil
	}
	return p.bodies[0]
}

// startPushRecorder runs a minimal HTTP/3 relay on loopback and returns it
// with its address.
func startPushRecorder(t *testing.T, status int) (*pushRecorder, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	rec := &pushRecorder{pushed: make(chan struct{}, 1), status: status}

	mux := http.NewServeMux()
	mux.HandleFunc(MetricsPushPath, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rec.record(body)
		w.WriteHeader(rec.status)
	})
	mux.HandleFunc("/v1/tunnel/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(ConnectResponse{ID: "conn-1", VNI: 42, MTU: 1392})
	})

	srv := &http3.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			NextProtos:   []string{http3.NextProtoH3},
		},
	}
	go srv.Serve(udpConn)
	t.Cleanup(func() {
		_ = srv.Close()
		_ = udpConn.Close()
	})

	return rec, udpConn.LocalAddr().String()
}

// compressPushCadence shortens the push timeline for a test.
func compressPushCadence(t *testing.T, settle, interval time.Duration) {
	t.Helper()

	oldSettle, oldInterval := metricsPushSettle, metricsPushInterval
	metricsPushSettle, metricsPushInterval = settle, interval
	t.Cleanup(func() { metricsPushSettle, metricsPushInterval = oldSettle, oldInterval })
}

func newTestClient(t *testing.T, addr string) *Client {
	t.Helper()

	c, err := NewClient(ClientOptions{
		BaseURL:    "https://" + addr,
		Agent:      "agent-a",
		TunnelName: "default",
		Token:      "token",
		TLSConfig:  &tls.Config{InsecureSkipVerify: true},
		Timeout:    5 * time.Second,
	})
	require.NoError(t, err)
	return c
}

// TestClientMetricsPushLoop pins the agent side of the push path: a connected
// client pushes its own metrics over the connection it already holds, keeps
// pushing on the interval, and stops when the connection is given up. The loop
// must outlive the connect request, whose context is bounded by the client
// timeout.
func TestClientMetricsPushLoop(t *testing.T) {
	const markerName = "tunnel_api_push_marker"

	marker := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: markerName,
		Help: "Set by the tunnel API client push test.",
	})
	marker.Set(1)
	require.NoError(t, crmetrics.Registry.Register(marker))
	t.Cleanup(func() { crmetrics.Registry.Unregister(marker) })

	compressPushCadence(t, 10*time.Millisecond, 20*time.Millisecond)

	rec, addr := startPushRecorder(t, http.StatusOK)
	c := newTestClient(t, addr)
	t.Cleanup(func() { _ = c.Close() })

	connectCtx, cancelConnect := context.WithTimeout(context.Background(), 5*time.Second)
	_, err := c.Connect(connectCtx)
	require.NoError(t, err)
	// The connect context is done, so a loop that inherited it would stop here.
	cancelConnect()

	for i := 0; i < 2; i++ {
		select {
		case <-rec.pushed:
		case <-time.After(5 * time.Second):
			t.Fatalf("push %d did not arrive", i+1)
		}
	}

	body := rec.first()
	require.NotEmpty(t, body)
	families := map[string]*dto.MetricFamily{}
	dec := expfmt.NewDecoder(bytes.NewReader(body), expfmt.NewFormat(expfmt.TypeTextPlain))
	for {
		mf := new(dto.MetricFamily)
		if err := dec.Decode(mf); err != nil {
			break
		}
		families[mf.GetName()] = mf
	}
	require.Contains(t, families, markerName)

	disconnectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, c.Disconnect(disconnectCtx, "conn-1"))

	// Disconnect waits for the loop to exit, so the count cannot grow after it.
	settled := rec.count()
	time.Sleep(5 * metricsPushInterval)
	require.Equal(t, settled, rec.count(), "the push loop kept running after disconnect")
}

// TestClientPushMetricsAcceptsNoContent pins that a relay keeping no store —
// which answers 204 rather than an error — is a successful push.
func TestClientPushMetricsAcceptsNoContent(t *testing.T) {
	compressPushCadence(t, time.Hour, time.Hour)

	rec, addr := startPushRecorder(t, http.StatusNoContent)
	c := newTestClient(t, addr)
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, c.PushMetrics(ctx))
	require.Equal(t, 1, rec.count())
}

// TestClientPushMetricsReportsRejection pins that a relay that does not know
// the connection is reported as a status error, so a caller can tell a
// rejected push from a delivered one.
func TestClientPushMetricsReportsRejection(t *testing.T) {
	compressPushCadence(t, time.Hour, time.Hour)

	_, addr := startPushRecorder(t, http.StatusNotFound)
	c := newTestClient(t, addr)
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := c.PushMetrics(ctx)
	require.Error(t, err)
	require.True(t, IsStatus(err, http.StatusNotFound), "error = %v", err)
}

// refusingRoundTripper fails the test if a request reaches it.
type refusingRoundTripper struct {
	t *testing.T
}

func (r *refusingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.t.Helper()
	r.t.Errorf("the client sent a request to %s, want no request at all", req.URL)
	return nil, errors.New("the round tripper must not be reached")
}

// TestClientPushMetricsRefusesOversizedBody pins that the agent stops an
// oversized push itself. The relay caps the body it reads, so sending it would
// only waste the connection and come back as 413, and trimming the families to
// fit would report a part of the registry as the whole of it. The failure must
// carry metrics.ErrPushTooLarge so the push loop can report it loudly: a
// registry this large stays this large on every tick.
func TestClientPushMetricsRefusesOversizedBody(t *testing.T) {
	const markerName = "tunnel_api_push_oversize_marker"

	oversize := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: markerName,
		Help: "Set by the tunnel API client oversize push test.",
	}, []string{"id"})
	require.NoError(t, crmetrics.Registry.Register(oversize))
	t.Cleanup(func() { crmetrics.Registry.Unregister(oversize) })

	// Every series writes a line of about 550 bytes, so this registry encodes
	// to well over the limit.
	filler := strings.Repeat("x", 500)
	for i := 0; i < 2200; i++ {
		oversize.WithLabelValues(fmt.Sprintf("%s-%04d", filler, i)).Set(1)
	}

	base, err := url.Parse("https://relay.invalid:6081")
	require.NoError(t, err)
	c := &Client{
		http:       &http.Client{Transport: &refusingRoundTripper{t: t}},
		baseURL:    base,
		tunnelName: "default",
		token:      "token",
		agent:      "agent-a",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = c.PushMetrics(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, metrics.ErrPushTooLarge)
	require.Contains(t, err.Error(), fmt.Sprintf("the limit is %d", metrics.MaxPushBytes))
}

// statusRoundTripper answers every request with a canned status and an empty
// body, so a test can drive the client's handling of a relay answer without a
// relay behind it.
type statusRoundTripper struct {
	status int
}

func (s *statusRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Read the request body so the client's encoder is exercised the way a
	// real transport exercises it.
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	return &http.Response{
		StatusCode: s.status,
		Status:     fmt.Sprintf("%d %s", s.status, http.StatusText(s.status)),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

// TestClientPushMetricsMapsRejectionStatus pins how a refused push is
// reported. A relay that answers 413 found the body too large after the local
// check let it through, which happens when the agent and the relay hold
// different limits. The cause and the remedy are the same as for the local
// check, so the failure must carry metrics.ErrPushTooLarge and reach the same
// loud report. Every other rejection stays a plain status error, which the
// push loop keeps quiet.
func TestClientPushMetricsMapsRejectionStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
		// wantTooLarge is true when the failure must wrap
		// metrics.ErrPushTooLarge.
		wantTooLarge bool
	}{
		{
			name:         "the relay refused the body as too large",
			status:       http.StatusRequestEntityTooLarge,
			wantTooLarge: true,
		},
		{
			name:   "the relay does not know the connection",
			status: http.StatusNotFound,
		},
		{
			name:   "the relay failed",
			status: http.StatusInternalServerError,
		},
	}

	base, err := url.Parse("https://relay.invalid:6081")
	require.NoError(t, err)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{
				http:       &http.Client{Transport: &statusRoundTripper{status: tc.status}},
				baseURL:    base,
				tunnelName: "default",
				token:      "token",
				agent:      "agent-a",
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := c.PushMetrics(ctx)
			require.Error(t, err)
			// The status stays readable whichever way the failure is wrapped.
			require.True(t, IsStatus(err, tc.status), "error = %v", err)
			require.Equal(t, tc.wantTooLarge, errors.Is(err, metrics.ErrPushTooLarge),
				"error = %v", err)
		})
	}
}
