// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// PublishSnapshot is the routing state the manager pushes to the co-located
// backplane over the private node-local channel (APO-796). Its JSON shape is the
// wire contract shared with apoxy-cloud backplane/workerd.Snapshot; keep the
// field tags in sync.
type PublishSnapshot struct {
	// ResidentSocket is the host AF_UNIX path the resident dispatcher listens on
	// (host.ResidentInstance.InboundSocket). The backplane points one static
	// Envoy cluster at it.
	ResidentSocket string `json:"residentSocket"`
	// Demux maps a compute Service name to its live ServiceRevision name. The
	// backplane sets `x-apoxy-service: <service>:<rev>` from it.
	Demux map[string]string `json:"demux"`
}

// Publisher pushes a PublishSnapshot to the backplane. A seam so the publish
// reconciler is testable without a backplane.
type Publisher interface {
	Publish(ctx context.Context, snap PublishSnapshot) error
}

// httpPublisher POSTs snapshots to the backplane's private loopback publish
// endpoint.
type httpPublisher struct {
	endpoint string // e.g. "http://127.0.0.1:2021/publish"
	client   *http.Client
}

// NewHTTPPublisher returns a Publisher that POSTs to the backplane publish
// address (host:port of the backplane's --workerd_publish_addr).
func NewHTTPPublisher(addr string) Publisher {
	return &httpPublisher{
		endpoint: "http://" + addr + "/publish",
		client:   &http.Client{},
	}
}

func (p *httpPublisher) Publish(ctx context.Context, snap PublishSnapshot) error {
	body, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshaling snapshot: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building publish request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("posting snapshot to %s: %w", p.endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("backplane rejected snapshot: %s", resp.Status)
	}
	return nil
}
