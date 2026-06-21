// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// PublishSnapshot is THIS node's routing state the manager pushes to the apiserver
// (dev) / backplane (prod) over the private node-local channel (APO-796). Its JSON
// shape is the wire contract shared with apoxy-cloud backplane/workerd.Snapshot;
// keep the field tags in sync.
//
// It reports per-node readiness: the manager is 1:1 with a backplane, and what it
// advertises here is what THIS node can actually serve right now, sourced from
// node-local warm state — not a global, control-plane-gated Status.LiveRevision.
type PublishSnapshot struct {
	// NodeID identifies the backplane node this manager is co-located with (the
	// backplane's --replica / Proxy replica name). The receiver keys the published
	// routing state by node, so each backplane's resident readiness is tracked
	// independently and never collides with another node's.
	NodeID string `json:"nodeId"`
	// ResidentSocket is the host AF_UNIX path the resident dispatcher listens on
	// (host.ResidentInstance.InboundSocket). Envoy points one static cluster at it.
	ResidentSocket string `json:"residentSocket"`
	// Demux maps a project-qualified service key "<project>:<service>" to the
	// ServiceRevision THIS node currently serves for it — the newest revision this
	// node has warmed (honoring an explicit spec.liveRevision pin). The receiver
	// reads only presence-with-a-non-empty-value to gate routing and stamps
	// `x-apoxy-service: <project>:<service>` (the resident's dispatcher resolves the
	// revision via /resolve, so it never enters Envoy config). Because the value is
	// sourced from node-local warm state, a node keeps advertising the PREVIOUS
	// revision until it has pulled the new bundle (make-before-break), which the
	// dispatcher's /resolve then reflects.
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
