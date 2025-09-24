package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Client struct {
	http       *http.Client
	h3         *http3.Transport
	baseURL    *url.URL
	tunnelName string
	token      string
	agent      string
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

	t := &http3.Transport{
		TLSClientConfig: opts.TLSConfig,
		QUICConfig: &quic.Config{
			Tracer: newConnectionTracer,
		},
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
			return qc, nil
		}
	}

	hc := &http.Client{
		Transport: t,
		Timeout:   opts.Timeout,
	}

	return &Client{
		http:       hc,
		h3:         t,
		baseURL:    u,
		tunnelName: opts.TunnelName,
		token:      opts.Token,
		agent:      opts.Agent,
	}, nil
}

func (c *Client) Close() error {
	return c.h3.Close()
}

// Connect to the relay and establish a new tunnel connection.
func (c *Client) Connect(ctx context.Context) (*ConnectResponse, error) {
	reqBody := ConnectRequest{Agent: c.agent}
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
		if len(slurp) == 0 {
			return fmt.Errorf("%s %s: unexpected status %s", method, url, res.Status)
		}
		return fmt.Errorf("%s %s: unexpected status %s: %s", method, url, res.Status, string(slurp))
	}

	if out != nil {
		if err := json.Unmarshal(slurp, out); err != nil {
			return fmt.Errorf("decode response: %w (body: %s)", err, string(slurp))
		}
	}
	return nil
}
