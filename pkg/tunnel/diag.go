package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	alog "github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/apoxy-dev/apoxy/pkg/diag"
	"github.com/apoxy-dev/apoxy/pkg/diag/protocol"
)

// startDiagDispatcher opens the long-lived /diag/rpc stream on the
// existing HTTP/3 connection and runs the dispatcher until ctx is
// cancelled. Auth is inherited from the QUIC TLS connection. The
// registry comes from c.diagRegistry, set via WithDiagRegistry.
func (c *Conn) startDiagDispatcher(ctx context.Context) {
	log := alog.FromContext(ctx).With(slog.String("subsystem", "diag"))

	// Brief warmup before opening the second stream — mirrors
	// /metrics/push. /connect has already completed by the time
	// c.run starts; this is purely defensive.
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
	}

	const (
		minBackoff = 2 * time.Second
		maxBackoff = 2 * time.Minute
	)
	backoff := minBackoff
	for {
		err := c.runDiagOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			backoff = minBackoff
		} else {
			log.Debug("Diag stream ended",
				slog.Any("error", err),
				slog.Duration("retry_in", backoff))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if err != nil {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func (c *Conn) runDiagOnce(ctx context.Context) error {
	// Pipe carrying agent → tunnelproxy responses. The dispatcher
	// writes nd-json frames to upW; http3 streams them out as the
	// request body.
	upR, upW := io.Pipe()
	defer upW.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://proxy"+protocol.Path, upR)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", protocol.MimeType)
	req.Header.Set("Accept", protocol.MimeType)

	// RoundTrip on the existing HTTP/3 client conn opens a single bidi
	// stream. Headers come back as soon as the server has written
	// them, after which both halves can interleave on the wire.
	resp, err := c.hConn.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("round trip: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return diag.New(c.diagRegistry).Run(ctx, resp.Body, upW)
}
