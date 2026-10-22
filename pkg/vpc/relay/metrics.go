// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"strconv"
	"sync"
	"time"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

var (
	sessionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "apoxy_vpc_relay_sessions_total",
		Help: "Agent Session calls, by data mode and the reason for QUIC mode.",
	}, []string{"mode", "reason"})
	sessionVersions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "apoxy_vpc_relay_session_versions_total",
		Help: "Agent Session calls, by protocol revision and build of the agent.",
	}, []string{"revision", "build"})
	modeChanges = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "apoxy_vpc_relay_mode_changes_total",
		Help: "Open agent connections that changed from QUIC mode to PSP mode.",
	})
	connectSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "apoxy_vpc_relay_connect_seconds",
		Help:    "Time to connect: from the start of the dial to the first Config, as the agent reports it.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"mode"})
)

func init() {
	metrics.Registry.MustRegister(sessionsTotal, sessionVersions, modeChanges, connectSeconds)
}

const (
	// maxBuildLabel is the most characters of a build label.
	maxBuildLabel = 40
	// maxVersionLabels is the most pairs of revision and build that the session metric keeps. The
	// other pairs count with the build otherLabel.
	maxVersionLabels = 64
	otherLabel       = "other"
	unknownLabel     = "unknown"
)

// versionLabelSet limits the label values of sessionVersions. The agent sets the revision and the
// build, so the relay keeps a fixed number of pairs.
type versionLabelSet struct {
	mu   sync.Mutex
	seen map[[2]string]struct{}
}

var versionLabels versionLabelSet

// of returns the revision and build labels of the agent version v.
func (l *versionLabelSet) of(v *dpv1.Version) []string {
	pair := [2]string{strconv.FormatUint(uint64(v.GetRevision()), 10), buildLabel(v.GetBuild())}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.seen[pair]; ok {
		return pair[:]
	}
	if len(l.seen) < maxVersionLabels {
		if l.seen == nil {
			l.seen = map[[2]string]struct{}{}
		}
		l.seen[pair] = struct{}{}
		return pair[:]
	}
	// The revisions that this relay knows are few, so they keep their label.
	if v.GetRevision() > dpv1.Revision {
		pair[0] = otherLabel
	}
	pair[1] = otherLabel
	return pair[:]
}

// buildLabel returns the build string of an agent as a label value. It keeps maxBuildLabel
// characters, and only letters, digits and "._+-" stay as they are.
func buildLabel(build string) string {
	if build == "" {
		return unknownLabel
	}
	b := []byte(build[:min(len(build), maxBuildLabel)])
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '+', c == '-':
		default:
			b[i] = '_'
		}
	}
	return string(b)
}

// dropLabels are the labels of the drop reasons of the data plane, by reason.
var dropLabels = map[uint8]string{
	dp.ReasonOldSession:    "old_session",
	dp.ReasonNoContext:     "no_context",
	dp.ReasonSource:        "source",
	dp.ReasonDemux:         "demux",
	dp.ReasonUnknownSPI:    "unknown_spi",
	dp.ReasonUnknownSource: "unknown_source",
	dp.ReasonMeter:         "meter",
	dp.ReasonNoRoute:       "no_route",
	dp.ReasonNoTarget:      "no_target",
	dp.ReasonTrunkToTrunk:  "trunk_to_trunk",
	dp.ReasonLocalOnly:     "local_only",
	dp.ReasonMTU:           "mtu",
	dp.ReasonNoKeys:        "no_keys",
	dp.ReasonDatagramFull:  "datagram_full",
	dp.ReasonNoNeighbor:    "no_neighbor",
	dp.ReasonPuntFull:      "punt_full",
	dp.ReasonMalformed:     "malformed",
	dp.ReasonOpen:          "open",
	dp.ReasonTXFull:        "tx_full",
	dp.ReasonQUICFull:      "quic_full",
}

var dropsDesc = prometheus.NewDesc("apoxy_vpc_relay_dropped_packets_total",
	"Packets that the relay data plane dropped, by reason.", []string{"reason"}, nil)

// stateLabel returns the label of an announcer state in logs and metrics.
func stateLabel(state dpv1.AnnouncerState) string {
	switch state {
	case stateNormal:
		return "normal"
	case stateDraining:
		return "draining"
	case stateSuspect:
		return "suspect"
	}
	return "unknown"
}

var stateChangesDesc = prometheus.NewDesc("apoxy_vpc_relay_announcer_state_changes_total",
	"State changes of the agent connections of this relay that have routes, by the new state.", []string{"state"}, nil)

var _ prometheus.Collector = (*Router)(nil)

// Describe implements prometheus.Collector.
func (r *Router) Describe(ch chan<- *prometheus.Desc) {
	ch <- dropsDesc
	ch <- stateChangesDesc
}

// Collect implements prometheus.Collector with the drop counters of the data plane and the state
// changes.
func (r *Router) Collect(ch chan<- prometheus.Metric) {
	drops := map[uint8]uint64{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = r.cfg.Target.Read(ctx, &p4.ReadRequest{Entities: []*p4.Entity{{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{
		CounterId: dp.CounterDrops,
	}}}}}, func(e *p4.Entity) {
		ce := e.GetCounterEntry()
		drops[uint8(ce.GetIndex().GetIndex())] = uint64(ce.GetData().GetPacketCount())
	})
	for reason, label := range dropLabels {
		ch <- prometheus.MustNewConstMetric(dropsDesc, prometheus.CounterValue, float64(drops[reason]), label)
	}
	for i := range r.stateChanges {
		ch <- prometheus.MustNewConstMetric(stateChangesDesc, prometheus.CounterValue, float64(r.stateChanges[i].Load()), stateLabel(dpv1.AnnouncerState(i)))
	}
}

func modeLabel(m dpv1.Mode) string {
	switch m {
	case dpv1.Mode_MODE_PSP:
		return "psp"
	case dpv1.Mode_MODE_QUIC:
		return "quic"
	}
	return "unknown"
}

func reasonLabel(h *dpv1.Hello) string {
	switch h.GetFallbackReason() {
	case dpv1.FallbackReason_FALLBACK_REASON_UNSPECIFIED:
		return "none"
	case dpv1.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT:
		return "probe_timeout"
	case dpv1.FallbackReason_FALLBACK_REASON_CONFIG:
		return "config"
	}
	return "unknown"
}
