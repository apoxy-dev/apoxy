package kex

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Client struct {
	baseURL   string
	authToken string
	client    *http.Client
}

// NewClient creates an HTTP/3 client using quic-go.
// If pc is provided, it will be used for QUIC connections; otherwise, a new
// connection will be established.
func NewClient(baseURL, authToken string, tlsConf *tls.Config, pc net.PacketConn) *Client {
	rt := &http3.Transport{
		TLSClientConfig: tlsConf,
	}
	if pc != nil {
		rt.Dial = func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (quic.EarlyConnection, error) {
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			return quic.DialEarly(ctx, pc, udpAddr, tlsConf, conf)
		}
	}

	return &Client{
		baseURL:   baseURL,
		authToken: authToken,
		client:    &http.Client{Transport: rt, Timeout: 10 * time.Second},
	}
}

// Close releases underlying QUIC resources.
func (c *Client) Close() error {
	rt := c.client.Transport.(*http3.Transport)

	if err := rt.Close(); err != nil {
		return fmt.Errorf("failed to close transport: %w", err)
	}

	return nil
}

// Connect sends a POST to /network and returns the response.
// Optionally, you can provide a public address and port for data traffic.
// If not supplied, data traffic will use the same flow as the kex connection.
func (c *Client) Connect(ctx context.Context, publicAddressPort string) (*ConnectResponse, error) {
	reqBody := &ConnectRequest{Address: publicAddressPort}
	resp, err := c.doRequest(ctx, http.MethodPost, "/network", reqBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("connect failed: %s", resp.Status)
	}

	var result ConnectResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Disconnect sends a DELETE to /network/{vni}
func (c *Client) Disconnect(ctx context.Context, vni int) error {
	resp, err := c.doRequest(ctx, http.MethodDelete, fmt.Sprintf("/network/%d", vni), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("disconnect failed: %s - %s", resp.Status, string(body))
	}
	return nil
}

// RenewKeys sends a PUT to /network/{vni}/renewkeys
func (c *Client) RenewKeys(ctx context.Context, vni int) (*RenewKeysResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodPut, fmt.Sprintf("/network/%d/renewkeys", vni), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("renew keys failed: %s - %s", resp.Status, string(body))
	}

	var result RenewKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) doRequest(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.authToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.client.Do(req)
}
