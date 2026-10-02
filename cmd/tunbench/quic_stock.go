//go:build stock

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

const quicBuild = "stock"

// releaseDatagram does nothing. Stock quic-go has no buffer pool for datagrams.
func releaseDatagram([]byte) {}

// quicConfig returns the QUIC config of the tunnel (pkg/tunnel/quic.go).
// Stock quic-go has no DisableCongestionControl, so its congestion control stays on.
func quicConfig(o options) *quic.Config {
	c := &quic.Config{
		EnableDatagrams:                true,
		InitialPacketSize:              1350,
		InitialConnectionReceiveWindow: 5 * 1000 * 1000,
		MaxConnectionReceiveWindow:     100 * 1000 * 1000,
		KeepAlivePeriod:                5 * time.Second,
		MaxIdleTimeout:                 15 * time.Second,
	}
	if o.QlogDir != "" {
		c.Tracer = func(_ context.Context, isClient bool, id quic.ConnectionID) qlogwriter.Trace {
			w, err := newQlogWriter(o.QlogDir, isClient, id, o.QlogMax)
			if err != nil {
				slog.Warn("Failed to create qlog file", "error", err)
				return nil
			}
			t := qlogwriter.NewConnectionFileSeq(w, isClient, id, []string{qlog.EventSchema})
			go t.Run()
			return t
		}
	}
	return c
}
