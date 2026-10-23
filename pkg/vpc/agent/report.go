// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"log/slog"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

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

// lossCount sums the packets that the relay connections of the agent lost. The
// sum keeps the loss of a closed connection.
type lossCount struct {
	mu    sync.Mutex
	conns map[*quic.Conn]uint64 // The last loss count of each open connection.
	sum   uint64
}

// add starts to count the loss of qc.
func (l *lossCount) add(qc *quic.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conns == nil {
		l.conns = make(map[*quic.Conn]uint64)
	}
	l.collect()
	l.conns[qc] = 0
}

// total returns the packets lost up to now.
func (l *lossCount) total() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.collect()
	return l.sum
}

// collect adds the new loss of each connection to the sum, and removes the
// closed connections. l.mu must be held.
func (l *lossCount) collect() {
	for qc, last := range l.conns {
		if n := qc.ConnectionStats().PacketsLost; n > last {
			l.sum += n - last
			l.conns[qc] = n
		}
		if qc.Context().Err() != nil {
			delete(l.conns, qc)
		}
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
