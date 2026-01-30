//go:build linux

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"
)

const (
	// DefaultControlPort is the default port for the edge-runtime control API.
	DefaultControlPort = 9000

	// DefaultServicePort is the default port for serving requests.
	DefaultServicePort = 8080
)

// runtimeClientImpl implements RuntimeClient for communicating with edge-runtime.
type runtimeClientImpl struct {
	httpClient *http.Client
	baseURL    string
}

// NewRuntimeClient creates a new client for communicating with an edge-runtime instance.
func NewRuntimeClient(address netip.Addr, port int) RuntimeClient {
	return &runtimeClientImpl{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: fmt.Sprintf("http://%s:%d", address, port),
	}
}

// NewRuntimeClientWithURL creates a new client with a specific base URL.
func NewRuntimeClientWithURL(baseURL string) RuntimeClient {
	return &runtimeClientImpl{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: baseURL,
	}
}

// Upload registers a new function with the runtime via /_internal/upload.
func (c *runtimeClientImpl) Upload(ctx context.Context, req UploadRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal upload request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/_internal/upload", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create upload request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send upload request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// Ready bootstraps a worker for the function and returns readiness status via /_internal/ready.
func (c *runtimeClientImpl) Ready(ctx context.Context, functionID string) (*ReadyResponse, error) {
	reqBody := ReadyRequest{FunctionID: functionID}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ready request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/_internal/ready", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create ready request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send ready request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ready check failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var readyResp ReadyResponse
	if err := json.NewDecoder(resp.Body).Decode(&readyResp); err != nil {
		return nil, fmt.Errorf("failed to decode ready response: %w", err)
	}

	return &readyResp, nil
}

// Health returns the health status of all functions via /_internal/health.
func (c *runtimeClientImpl) Health(ctx context.Context) (*HealthResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/_internal/health", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create health request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send health request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("health check failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var healthResp HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&healthResp); err != nil {
		return nil, fmt.Errorf("failed to decode health response: %w", err)
	}

	return &healthResp, nil
}

// DeleteFunction unloads a function from the runtime via /_internal/functions/{id}.
func (c *runtimeClientImpl) DeleteFunction(ctx context.Context, functionID string) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/_internal/functions/"+functionID, nil)
	if err != nil {
		return fmt.Errorf("failed to create delete request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send delete request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
