//go:build !stock

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

const quicBuild = "fork"

// releaseDatagram gives a received datagram back to quic-go.
func releaseDatagram(b []byte) { quic.ReleaseDatagram(b) }

// quicConfig returns the QUIC config of the tunnel (pkg/tunnel/quic.go).
func quicConfig(o options) *quic.Config {
	c := &quic.Config{
		EnableDatagrams:                true,
		DisableCongestionControl:       true,
		InitialPacketSize:              1350,
		InitialConnectionReceiveWindow: 5 * 1000 * 1000,
		MaxConnectionReceiveWindow:     100 * 1000 * 1000,
		KeepAlivePeriod:                5 * time.Second,
		MaxIdleTimeout:                 15 * time.Second,
	}
	if o.QlogDir != "" {
		c.Tracer = func(_ context.Context, p logging.Perspective, id quic.ConnectionID) *logging.ConnectionTracer {
			w, err := newQlogWriter(o.QlogDir, p == logging.PerspectiveClient, id, o.QlogMax)
			if err != nil {
				slog.Warn("Failed to create qlog file", "error", err)
				return nil
			}
			return qlog.NewConnectionTracer(w, p, id)
		}
	}
	return c
}
