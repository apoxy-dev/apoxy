package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Client struct {
	http             *http.Client
	h3               *http3.Transport
	baseURL          *url.URL
	tunnelName       string
	token            string
	agent            string
	metricsPort      int
	labels           map[string]string
	advertisedRoutes []string
	agentInstance    string

	// draining is closed when a control connection to the relay ends with a
	// graceful close (H3_NO_ERROR) — the relay sent GOAWAY, or closed the
	// connection cleanly. See Draining.
	draining  chan struct{}
	drainOnce sync.Once
	// lost is closed when the control connection ends without a graceful drain.
	lost     chan struct{}
	lostOnce sync.Once
	// closed marks a client-initiated Close so our own transport teardown
	// (which also closes gracefully) is not mistaken for a relay drain.
	closed atomic.Bool

	// rttNanos holds the control connection's latest smoothed RTT in
	// nanoseconds, recorded by the QUIC tracer on every metrics update. QUIC
	// measures RTT continuously as part of loss recovery, so this is a free,
	// always-fresh latency signal for the live session.
	rttNanos atomic.Int64
}

type ClientOptions struct {
	// BaseURL of the relay.
	BaseURL string
	// Agent is the agent name that will be sent in requests.
	Agent string
	// TunnelName is the name of the tunnel.
	TunnelName string
	// Token is the bearer token for authenticating to the relay.
	Token string
	// TLS config for HTTP/3. Provide RootCAs or InsecureSkipVerify if you're
	// talking to a dev relay with a self-signed cert (only for development).
	TLSConfig *tls.Config
	// Timeout for each request. Defaults to 10s if not set.
	Timeout time.Duration
	// PacketConn is an optional UDP PacketConn to use for QUIC connections.
	// If nil, a new UDP socket will be created for each connection.
	PacketConn net.PacketConn
	// MetricsPort is the port the agent's Prometheus metrics server listens on.
	// Advertised to the relay so it can scrape metrics through the overlay.
	MetricsPort int
	// Labels are agent-declared labels used for service selection.
	Labels map[string]string
	// AdvertisedRoutes are CIDRs reachable behind this agent.
	AdvertisedRoutes []string
	// AgentInstance is a stable per-process UUID identifying the agent instance.
	AgentInstance string
}

func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.BaseURL == "" {
		return nil, fmt.Errorf("BaseURL is required")
	}
	if opts.TunnelName == "" {
		return nil, fmt.Errorf("TunnelName is required")
	}
	if opts.Token == "" {
		return nil, fmt.Errorf("BearerToken is required")
	}
	if opts.Agent == "" {
		return nil, fmt.Errorf("Agent is required")
	}

	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid BaseURL: %w", err)
	}
	if u.Scheme != "https" {
		// http3 requires TLS.
		return nil, fmt.Errorf("BaseURL must be https (got %q)", u.Scheme)
	}

	c := &Client{
		baseURL:          u,
		tunnelName:       opts.TunnelName,
		token:            opts.Token,
		agent:            opts.Agent,
		metricsPort:      opts.MetricsPort,
		labels:           opts.Labels,
		advertisedRoutes: opts.AdvertisedRoutes,
		agentInstance:    opts.AgentInstance,
		draining:         make(chan struct{}),
		lost:             make(chan struct{}),
	}

	t := &http3.Transport{
		TLSClientConfig: opts.TLSConfig,
		QUICConfig: &quic.Config{
			Tracer:          c.newTracer,
			KeepAlivePeriod: 5 * time.Second,
			MaxIdleTimeout:  15 * time.Second,
		},
	}
	c.h3 = t
	c.http = &http.Client{
		Transport: t,
		Timeout:   opts.Timeout,
	}

	if opts.PacketConn != nil {
		quicTransport := &quic.Transport{
			Conn: opts.PacketConn,
		}
		t.Dial = func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			slog.Debug("Dialing QUIC", slog.String("addr", addr), slog.String("udp", udpAddr.String()))
			qc, err := quicTransport.DialEarly(ctx, udpAddr, tlsConf, quicConf)
			if err != nil {
				return nil, err
			}
			slog.Debug("Dialed QUIC", slog.String("addr", addr), slog.String("udp", udpAddr.String()))
			go c.watchControlConn(qc)
			return qc, nil
		}
	}

	return c, nil
}

// Draining is closed when the relay gracefully closes the control connection.
// The http3 client reacts to a relay GOAWAY on an idle control connection by
// closing it with H3_NO_ERROR, so from this side a drain announcement is
// observed as a graceful close — as opposed to an idle timeout, reset, or
// refused dial, which all mean the relay died. Only connections dialed via a
// caller-supplied PacketConn are watched (the transport's default dial path
// offers no hook), which covers every agent session.
func (c *Client) Draining() <-chan struct{} {
	return c.draining
}

// Lost is closed when the relay control connection ends without a graceful
// drain. The session must reconnect because its data-plane state can no longer
// be leased by that relay process.
func (c *Client) Lost() <-chan struct{} {
	return c.lost
}

// watchControlConn waits for a dialed control connection to end and flags a
// drain when the close was graceful and not our own doing.
func (c *Client) watchControlConn(qc quic.EarlyConnection) {
	<-qc.Context().Done()
	c.handleControlClose(context.Cause(qc.Context()))
}

func (c *Client) handleControlClose(cause error) {
	if c.closed.Load() {
		return
	}
	var appErr *quic.ApplicationError
	if errors.As(cause, &appErr) &&
		appErr.ErrorCode == quic.ApplicationErrorCode(http3.ErrCodeNoError) {
		c.drainOnce.Do(func() { close(c.draining) })
		return
	}
	c.lostOnce.Do(func() { close(c.lost) })
}

func (c *Client) Close() error {
	c.closed.Store(true)
	return c.h3.Close()
}

// Connect to the relay and establish a new tunnel connection.
func (c *Client) Connect(ctx context.Context) (*ConnectResponse, error) {
	reqBody := ConnectRequest{
		Agent:            c.agent,
		MetricsPort:      c.metricsPort,
		Labels:           c.labels,
		AdvertisedRoutes: c.advertisedRoutes,
		AgentInstance:    c.agentInstance,
	}
	var resp ConnectResponse
	if err := c.doJSON(ctx, http.MethodPost, c.path("/v1/tunnel/"+c.tunnelName), reqBody, &resp, http.StatusCreated); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Disconnect from the relay and close the tunnel connection.
func (c *Client) Disconnect(ctx context.Context, id string) error {
	reqBody := Request{Agent: c.agent, ID: id}
	return c.doJSON(ctx, http.MethodDelete, c.path("/v1/tunnel/"+c.tunnelName), reqBody, nil, http.StatusOK)
}

// UpdateKeys requests new encryption keys for the tunnel connection.
func (c *Client) UpdateKeys(ctx context.Context, id string) (*UpdateKeysResponse, error) {
	reqBody := Request{Agent: c.agent, ID: id}
	var resp UpdateKeysResponse
	if err := c.doJSON(ctx, http.MethodPut, c.path("/v1/tunnel/"+c.tunnelName+"/keys"), reqBody, &resp, http.StatusOK); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Routes fetches the connection's current route set from the relay.
func (c *Client) Routes(ctx context.Context, id string) (*RoutesResponse, error) {
	var resp RoutesResponse
	u := c.path("/v1/tunnel/"+c.tunnelName+"/routes") + "?id=" + url.QueryEscape(id)
	if err := c.doJSON(ctx, http.MethodGet, u, nil, &resp, http.StatusOK); err != nil {
		return nil, err
	}
	return &resp, nil
}

// StatusError is returned when the relay answers with an unexpected HTTP
// status. It carries the code so callers can distinguish a definitive
// rejection (e.g. 404: the relay does not know this connection, which no
// amount of retrying will fix) from a transient one.
type StatusError struct {
	Method string
	URL    string
	Code   int
	Status string
	Body   string
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("%s %s: unexpected status %s", e.Method, e.URL, e.Status)
	}
	return fmt.Sprintf("%s %s: unexpected status %s: %s", e.Method, e.URL, e.Status, e.Body)
}

// IsStatus reports whether err is a *StatusError with the given status code.
func IsStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == code
}

// ConnectionNotFoundMessage is the body the relay sends with 404 when it holds
// no connection under the requested ID. Callers must match on it rather than on
// the bare status: the relay's mux answers 404 for unregistered paths too, so a
// newer client talking to an older relay that lacks an endpoint would otherwise
// read "this route does not exist" as "my connection is gone".
const ConnectionNotFoundMessage = "Connection not found"

// IsConnectionUnknown reports whether err is the relay saying it does not know
// the connection the request named — a definitive rejection: the relay
// restarted or garbage-collected the connection, and no amount of retrying
// brings it back. The only remedy is a fresh Connect.
func IsConnectionUnknown(err error) bool {
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusNotFound {
		return false
	}
	return strings.Contains(se.Body, ConnectionNotFoundMessage)
}

// IsRelayDraining reports whether err is a request failing because the relay
// is gracefully shutting down: either the connection closed with H3_NO_ERROR,
// or the http3 client refused to open a stream past a received GOAWAY (its
// unexported errGoAway, matched by message as there is no exported value).
// Such failures are expected while a drain is in progress and carry no signal
// beyond the drain itself.
func IsRelayDraining(err error) bool {
	if err == nil {
		return false
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) && appErr.ErrorCode == quic.ApplicationErrorCode(http3.ErrCodeNoError) {
		return true
	}
	return strings.Contains(err.Error(), "connection in graceful shutdown")
}

func (c *Client) path(pth string) string {
	u := *c.baseURL
	u.Path = path.Join(c.baseURL.Path, pth)
	return u.String()
}

func (c *Client) doJSON(ctx context.Context, method, url string, in any, out any, want int) error {
	var body io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, url, err)
	}
	defer res.Body.Close()

	slurp, _ := io.ReadAll(res.Body) // best effort for richer errors

	if res.StatusCode != want {
		return &StatusError{
			Method: method,
			URL:    url,
			Code:   res.StatusCode,
			Status: res.Status,
			Body:   string(slurp),
		}
	}

	if out != nil {
		if err := json.Unmarshal(slurp, out); err != nil {
			return fmt.Errorf("decode response: %w (body: %s)", err, string(slurp))
		}
	}
	return nil
}
