// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// reportInterval is the time between the reports of the QUIC loss to the
// breaker of the data frames. The breakers measure over 1 s.
const reportInterval = 500 * time.Millisecond

func fromReport(m *dp.RxReport) []psp.SACount {
	sas := make([]psp.SACount, len(m.GetSas()))
	for i, sa := range m.GetSas() {
		sas[i] = psp.SACount{SPI: sa.GetSpi(), Packets: sa.GetPackets(), Seq: sa.GetSeq()}
	}
	return sas
}

// traceLoss counts the 1-RTT packets that relay connections lose, for the
// breaker of the data frames.
func (a *Agent) traceLoss(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
	return &logging.ConnectionTracer{
		LostPacket: func(level logging.EncryptionLevel, _ logging.PacketNumber, _ logging.PacketLossReason) {
			if level == logging.Encryption1RTT {
				a.quicLost.Add(1)
			}
		},
	}
}

// traceSession is traceLoss for a relay session. It also keeps the smoothed
// RTT of the session in rtt and its lowest RTT in low.
func (a *Agent) traceSession(rtt, low *atomic.Int64) func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
	return func(ctx context.Context, p logging.Perspective, id quic.ConnectionID) *logging.ConnectionTracer {
		t := a.traceLoss(ctx, p, id)
		t.UpdatedMetrics = func(s *logging.RTTStats, _, _ logging.ByteCount, _ int) {
			rtt.Store(int64(s.SmoothedRTT()))
			low.Store(int64(s.MinRTT()))
		}
		return t
	}
}

// onTrip logs a change of a breaker limit. bp is nil for the data frames.
func onTrip(bp *psp.Peer, t psp.Trip) {
	to := "relay"
	if bp == nil {
		to = "relay (data frames)"
	}
	if t.Rate == 0 {
		slog.Info("Circuit breaker removed the send limit", "to", to)
		return
	}
	slog.Warn("Circuit breaker tripped; the send rate is limited", "to", to,
		"loss_percent", t.Loss, "limit_mbps", float64(t.Rate)*8/1e6)
}
