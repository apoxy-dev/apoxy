package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
)

// newTracer is the client-bound QUIC tracer. It surfaces the transport's own
// path measurements — smoothed RTT (recorded on the client for status display),
// declared packet losses, and probe timeouts (exported as per-relay Prometheus
// counters) — all without any probe traffic. At debug level it also logs each
// QUIC event.
func (c *Client) newTracer(ctx context.Context, _ bool, odcid quic.ConnectionID) qlogwriter.Trace {
	return &tracer{
		c:     c,
		relay: c.baseURL.Host,
		odcid: odcid.String(),
		debug: slog.Default().Enabled(ctx, slog.LevelDebug),
	}
}

// tracer is the trace of one connection. QUIC records the events of a
// connection one at a time, and HTTP/3 does not record into it.
type tracer struct {
	c     *Client
	relay string
	odcid string
	debug bool

	// The transport reports its CURRENT consecutive-PTO count, which resets
	// to zero once anything is ACKed; count only the increments so the
	// exported value is a monotonic events-total.
	lastPTO uint32
}

func (t *tracer) AddProducer() qlogwriter.Recorder { return t }

// SupportsSchemas accepts only the QUIC events, so HTTP/3 keeps its own
// events out of the trace.
func (t *tracer) SupportsSchemas(schema string) bool { return schema == qlog.EventSchema }

func (t *tracer) Close() error { return nil }

func (t *tracer) RecordEvent(e qlogwriter.Event) {
	switch e := e.(type) {
	case qlog.MetricsUpdated:
		if e.SmoothedRTT > 0 {
			t.c.rttNanos.Store(int64(e.SmoothedRTT))
		}
	case qlog.PacketLost:
		metrics.TunnelRelayPacketsLost.WithLabelValues(t.relay, lossReason(e.Trigger)).Inc()
	case qlog.PTOCountUpdated:
		if e.PTOCount > t.lastPTO {
			metrics.TunnelRelayPTOs.WithLabelValues(t.relay).Add(float64(e.PTOCount - t.lastPTO))
		}
		t.lastPTO = e.PTOCount
	}
	if t.debug {
		slog.Debug("QUIC event", slog.String("odcid", t.odcid), slog.String("event", e.Name()))
	}
}

func lossReason(reason qlog.PacketLossReason) string {
	switch reason {
	case qlog.PacketLossTimeThreshold:
		return "timeout"
	case qlog.PacketLossReorderingThreshold:
		return "reordering"
	default:
		return "other"
	}
}

// RTT returns the smoothed round-trip time QUIC has measured on the control
// connection, or 0 before the first measurement.
func (c *Client) RTT() time.Duration {
	return time.Duration(c.rttNanos.Load())
}
