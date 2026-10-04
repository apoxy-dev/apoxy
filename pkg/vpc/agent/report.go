// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// reportInterval is the time between receive reports. The breakers measure
// over 1 s, so each interval with traffic gets at least one report.
const reportInterval = 500 * time.Millisecond

// sendReports sends the receive counters of the SAs of p to the peer when they
// change, until the session closes. The peer gives them to its breaker.
func (p *peer) sendReports() {
	if p.quic {
		return
	}
	ctx := p.qc.Context()
	t := time.NewTicker(reportInterval)
	defer t.Stop()
	var st rpc.ClientStreamClient[dp.RxReport, emptypb.Empty]
	var sent uint64 // Packets in the last report sent.
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		sas := p.bp.RxReport()
		var n uint64
		for _, c := range sas {
			n += c.Packets
		}
		// A report with no new packets has no data for the breaker. An idle
		// session sends no reports, so its QUIC connection stays quiet.
		if len(sas) == 0 || n == sent {
			continue
		}
		if st == nil {
			var err error
			if st, err = p.client.Reports(ctx); err != nil {
				continue
			}
		}
		if err := st.Send(toReport(sas)); err != nil {
			// A peer from before Reports answers Unimplemented. It gets no reports.
			if _, err := st.CloseAndRecv(); rpc.CodeOf(err) == rpc.Unimplemented {
				return
			}
			st = nil
			continue
		}
		sent = n
	}
}

// Reports gives the receive counters from the peer to the breaker of the
// packets to it.
func (s *peerService) Reports(ctx context.Context, st rpc.ClientStreamServer[dp.RxReport]) (*emptypb.Empty, error) {
	p := s.a.peerOf(ctx)
	if p == nil {
		return nil, rpc.Errorf(rpc.Unauthenticated, "no peer session")
	}
	select {
	case <-p.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if p.quic {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "data to this peer goes through the relay")
	}
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return &emptypb.Empty{}, nil
		}
		if err != nil {
			return nil, err
		}
		p.bp.Report(time.Now(), fromReport(m))
	}
}

func toReport(sas []psp.SACount) *dp.RxReport {
	m := &dp.RxReport{Sas: make([]*dp.SAStats, len(sas))}
	for i, sa := range sas {
		m.Sas[i] = &dp.SAStats{Spi: sa.SPI, Packets: sa.Packets, Seq: sa.Seq}
	}
	return m
}

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

// onTrip logs a change of a breaker limit. bp is nil for the data frames.
func (a *Agent) onTrip(bp *psp.Peer, t psp.Trip) {
	to := "relay"
	if bp == nil {
		to = "relay (data frames)"
	} else if p := a.peerOfBinding(bp); p != nil {
		to = p.subject
	}
	if t.Rate == 0 {
		slog.Info("Circuit breaker removed the send limit", "to", to)
		return
	}
	slog.Warn("Circuit breaker tripped; the send rate is limited", "to", to,
		"loss_percent", t.Loss, "limit_mbps", float64(t.Rate)*8/1e6)
}
