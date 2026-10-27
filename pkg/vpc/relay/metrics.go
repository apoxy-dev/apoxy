// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
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
	dp.ReasonOldSession:      "old_session",
	dp.ReasonNoContext:       "no_context",
	dp.ReasonSource:          "source",
	dp.ReasonDemux:           "demux",
	dp.ReasonUnknownSPI:      "unknown_spi",
	dp.ReasonUnknownSource:   "unknown_source",
	dp.ReasonMeter:           "meter",
	dp.ReasonNoRoute:         "no_route",
	dp.ReasonNoTarget:        "no_target",
	dp.ReasonTrunkToTrunk:    "trunk_to_trunk",
	dp.ReasonLocalOnly:       "local_only",
	dp.ReasonMTU:             "mtu",
	dp.ReasonNoKeys:          "no_keys",
	dp.ReasonDatagramFull:    "datagram_full",
	dp.ReasonNoNeighbor:      "no_neighbor",
	dp.ReasonPuntFull:        "punt_full",
	dp.ReasonMalformed:       "malformed",
	dp.ReasonOpen:            "open",
	dp.ReasonTXFull:          "tx_full",
	dp.ReasonQUICFull:        "quic_full",
	dp.ReasonWorkerFull:      "worker_full",
	dp.ReasonWorkerAllowance: "worker_allowance",
}

var dropsDesc = prometheus.NewDesc("apoxy_vpc_relay_dropped_packets_total",
	"Packets that the relay data plane dropped, by reason.", []string{"reason"}, nil)

var busyDesc = prometheus.NewDesc("apoxy_vpc_relay_busy_seconds_total",
	"Busy time of each thread of the relay data plane: the elapsed time of its loop passes minus their idle waits, by thread kind (rx, worker, kick) and index.",
	[]string{"kind", "index"}, nil)

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

// The trunk metrics have the relay name and the last relay ID of each member of the mesh. Many
// members can have one ID.
var (
	trunkPacketsDesc = prometheus.NewDesc("apoxy_vpc_relay_trunk_packets_total",
		"Packets of agents that the relay sent to a mesh member (tx), or got from the member (rx).",
		[]string{"peer_relay", "peer_relay_id", "direction"}, nil)
	trunkBytesDesc = prometheus.NewDesc("apoxy_vpc_relay_trunk_bytes_total",
		"UDP payload bytes of the packets of agents that the relay sent to a mesh member (tx), or got from the member (rx).",
		[]string{"peer_relay", "peer_relay_id", "direction"}, nil)
	trunkDropsDesc = prometheus.NewDesc("apoxy_vpc_relay_trunk_dropped_packets_total",
		"Packets that the relay did not send to a mesh member (tx), and packets of the member that the relay dropped (rx), by reason.",
		[]string{"peer_relay", "peer_relay_id", "direction", "reason"}, nil)
	meshRTTDesc = prometheus.NewDesc("apoxy_vpc_relay_mesh_rtt_seconds",
		"Smoothed round-trip time of the mesh session with a member. A member with no session has no value.",
		[]string{"peer_relay", "peer_relay_id"}, nil)
)

// trunkDrops are the drop reasons that can count at a trunk port, with their direction: tx at the
// out port in send_out, rx at the in port. Each has a series from the start.
var trunkDrops = []struct {
	reason uint8
	dir    string
}{
	{dp.ReasonMTU, "tx"},
	{dp.ReasonNoKeys, "tx"},
	{dp.ReasonTrunkToTrunk, "tx"},
	{dp.ReasonLocalOnly, "tx"},
	{dp.ReasonMalformed, "rx"},
	{dp.ReasonOldSession, "rx"},
	{dp.ReasonUnknownSource, "rx"},
	{dp.ReasonNoContext, "rx"},
	{dp.ReasonSource, "rx"},
	{dp.ReasonNoRoute, "rx"},
	{dp.ReasonNoTarget, "rx"},
	{dp.ReasonPuntFull, "rx"},
}

// trunkStat is what the metrics read of one member: the trunk ports of its M and of each earlier
// M that did not end yet, and the final counts of the ended ones.
type trunkStat struct {
	name, id string
	ports    []trunkPort
	base     trunkCounts
	rtt      time.Duration // Zero with no session, or with no sample.
}

// trunkPort is the cell and the meter index of one trunk port.
type trunkPort struct{ cell, meter uint32 }

// read returns the counts of the member: base and the counts of each port.
func (st *trunkStat) read(ctx context.Context, t dp.Target) (trunkCounts, error) {
	n := st.base
	for _, p := range st.ports {
		c, err := readTrunk(ctx, t, p.cell, p.meter)
		if err != nil {
			return n, err
		}
		n.add(c)
	}
	return n, nil
}

// trunkAsk asks the root for the trunk stats of each member.
type trunkAsk struct{ reply chan []*trunkStat }

// trunkStats answers a trunkAsk with each member that the mesh has now.
func (r *Router) trunkStats(e trunkAsk) {
	byName := map[string]*trunkStat{}
	for c := range r.mall {
		cur := r.ms[c.name]
		if cur == nil {
			continue
		}
		st := byName[c.name]
		if st == nil {
			st = &trunkStat{name: c.name, id: cur.id}
			if cur.s != nil {
				st.rtt = cur.s.qc.ConnectionStats().SmoothedRTT
			}
			byName[c.name] = st
		}
		if st.id == "" {
			st.id = c.id
		}
		st.ports = append(st.ports, trunkPort{c.cell, c.meter})
		st.base.add(c.base)
	}
	e.reply <- slices.Collect(maps.Values(byName))
}

// collectTrunk gives the counts of the trunk ports of each member, and the RTT of its mesh
// session.
func (r *Router) collectTrunk(ctx context.Context, ch chan<- prometheus.Metric) {
	reply := make(chan []*trunkStat, 1)
	if r.mesh == nil || !r.box.send(trunkAsk{reply: reply}) {
		return
	}
	for _, st := range <-reply {
		n, err := st.read(ctx, r.cfg.Target)
		if err != nil {
			continue
		}
		for _, d := range trunkDrops {
			ch <- prometheus.MustNewConstMetric(trunkDropsDesc, prometheus.CounterValue, float64(n.drops[d.reason]), st.name, st.id, d.dir, dropLabels[d.reason])
		}
		for _, d := range []struct {
			label string
			n     tally
		}{{"tx", n.tx}, {"rx", n.rx}} {
			// The cell counts the inner packets. A trunk packet adds the PSP overhead to each.
			bytes := d.n.bytes + d.n.packets*pspwire.Overhead
			ch <- prometheus.MustNewConstMetric(trunkPacketsDesc, prometheus.CounterValue, float64(d.n.packets), st.name, st.id, d.label)
			ch <- prometheus.MustNewConstMetric(trunkBytesDesc, prometheus.CounterValue, float64(bytes), st.name, st.id, d.label)
		}
		if st.rtt > 0 {
			ch <- prometheus.MustNewConstMetric(meshRTTDesc, prometheus.GaugeValue, st.rtt.Seconds(), st.name, st.id)
		}
	}
}

// Describe implements prometheus.Collector.
func (r *Router) Describe(ch chan<- *prometheus.Desc) {
	ch <- dropsDesc
	ch <- busyDesc
	ch <- stateChangesDesc
	ch <- trunkPacketsDesc
	ch <- trunkBytesDesc
	ch <- trunkDropsDesc
	ch <- meshRTTDesc
}

// Collect implements prometheus.Collector with the drop counters and the busy times of the data
// plane, the state changes and the trunk metrics.
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
	if r.cfg.Busy != nil {
		for _, b := range r.cfg.Busy() {
			ch <- prometheus.MustNewConstMetric(busyDesc, prometheus.CounterValue, b.Busy.Seconds(), b.Kind, strconv.Itoa(b.Index))
		}
	}
	for i := range r.stateChanges {
		ch <- prometheus.MustNewConstMetric(stateChangesDesc, prometheus.CounterValue, float64(r.stateChanges[i].Load()), stateLabel(dpv1.AnnouncerState(i)))
	}
	r.collectTrunk(ctx, ch)
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
