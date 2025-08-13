package kex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	BaseURL   string
	AuthToken string
	Client    *http.Client
}

func NewClient(baseURL, authToken string) *Client {
	return &Client{
		BaseURL:   baseURL,
		AuthToken: authToken,
		Client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// Connect sends a POST to /network and returns the response
func (c *Client) Connect(publicAddressPort string) (*ConnectResponse, error) {
	reqBody := &ConnectRequest{Address: publicAddressPort}
	resp, err := c.doRequest(http.MethodPost, "/network", reqBody)
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
func (c *Client) Disconnect(vni int) error {
	resp, err := c.doRequest(http.MethodDelete, fmt.Sprintf("/network/%d", vni), nil)
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
func (c *Client) RenewKeys(vni int) (*RenewKeysResponse, error) {
	resp, err := c.doRequest(http.MethodPut, fmt.Sprintf("/network/%d/renewkeys", vni), nil)
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

func (c *Client) doRequest(method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, reader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.Client.Do(req)
}
