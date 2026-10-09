// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

var (
	sessionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "apoxy_vpc_relay_sessions_total",
		Help: "Agent Session calls, by data mode and the reason for QUIC mode. Spare sessions have the reason spare.",
	}, []string{"mode", "reason"})
	sessionVersions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "apoxy_vpc_relay_session_versions_total",
		Help: "Agent Session calls, by protocol revision and build of the agent. A build from before revisions has revision 0 and the build unknown.",
	}, []string{"revision", "build"})
	connectSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "apoxy_vpc_relay_connect_seconds",
		Help:    "Time to connect: from the start of the dial to the first Config, as the agent reports it.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"mode"})
)

func init() {
	metrics.Registry.MustRegister(sessionsTotal, sessionVersions, connectSeconds)
}

const (
	// maxBuildLabel is the most characters of a build label.
	maxBuildLabel = 40
	// maxVersionLabels is the most pairs of revision and build that the session
	// metric keeps. The other pairs count with the build otherLabel.
	maxVersionLabels = 64
	otherLabel       = "other"
	unknownLabel     = "unknown"
)

// versionLabelSet limits the label values of sessionVersions. The agent sets
// the revision and the build, so the relay keeps a fixed number of pairs.
type versionLabelSet struct {
	mu   sync.Mutex
	seen map[[2]string]struct{}
}

var versionLabels versionLabelSet

// of returns the revision and build labels of the agent version v. Nil is
// revision 0.
func (l *versionLabelSet) of(v *dp.Version) []string {
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
	if v.GetRevision() > dp.Revision {
		pair[0] = otherLabel
	}
	pair[1] = otherLabel
	return pair[:]
}

// buildLabel returns the build string of an agent as a label value. It keeps
// maxBuildLabel characters, and only letters, digits and "._+-" stay as they are.
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

// dropReason is a reason that the relay drops a packet.
type dropReason int

const (
	dropMalformed dropReason = iota
	dropUnknownSource
	dropUnknownSPI
	dropLaneMeter
	dropTunnelLimit
	dropClosed    // The forward goroutines stopped.
	dropSendQueue // The forward goroutine of the destination is too slow.
	dropTrunkMTU  // The packet is too large for the trunk to another relay.
	dropTrunkKeys // The trunk to another relay has no SA for the packet.
	// The reasons below are for a peer frame to or from a mesh member.
	dropMeshNoSession  // The member of the destination has no open mesh session.
	dropMeshOldMember  // The member of the destination does not know the frame.
	dropMeshTooLarge   // The frame does not fit in a datagram of the mesh session.
	dropMeshMalformed  // The datagram of a member is short or has an unknown type.
	dropMeshUnknownTag // No entry of the member has the sender tag.
	dropMeshOldSession // Only entries from an older session of the member have the tag.
	dropMeshSource     // The sender does not have the route of the source address.
	dropMeshPermit     // Permit denies the destination.
	dropMeshNotLocal   // No session of this relay has the route of the destination.
	dropMeshNotSent    // The session of the destination did not take the frame.
	numDropReasons
)

// dropLabels are the reason labels of the drop metric.
var dropLabels = [numDropReasons]string{
	dropMalformed:      "malformed",
	dropUnknownSource:  "unknown_source",
	dropUnknownSPI:     "unknown_spi",
	dropLaneMeter:      "lane_meter",
	dropTunnelLimit:    "tunnel_limit",
	dropClosed:         "closed",
	dropSendQueue:      "send_queue",
	dropTrunkMTU:       "trunk_mtu",
	dropTrunkKeys:      "trunk_keys",
	dropMeshNoSession:  "mesh_no_session",
	dropMeshOldMember:  "mesh_old_member",
	dropMeshTooLarge:   "mesh_too_large",
	dropMeshMalformed:  "mesh_malformed",
	dropMeshUnknownTag: "mesh_unknown_tag",
	dropMeshOldSession: "mesh_old_session",
	dropMeshSource:     "mesh_source",
	dropMeshPermit:     "mesh_permit",
	dropMeshNotLocal:   "mesh_not_local",
	dropMeshNotSent:    "mesh_not_sent",
}

var dropsDesc = prometheus.NewDesc("apoxy_vpc_relay_dropped_packets_total",
	"Packets that the relay dropped before it forwarded them, by reason.", []string{"reason"}, nil)

var (
	xdpPacketsDesc = prometheus.NewDesc("apoxy_vpc_relay_xdp_packets_total",
		"PSP packets that the XDP program forwarded, or gave to the socket path, by result.", []string{"result"}, nil)
	xdpBytesDesc = prometheus.NewDesc("apoxy_vpc_relay_xdp_forwarded_bytes_total",
		"UDP payload bytes that the XDP program forwarded.", nil, nil)
)

var _ prometheus.Collector = (*Router)(nil)

// Describe implements prometheus.Collector.
func (r *Router) Describe(ch chan<- *prometheus.Desc) {
	ch <- dropsDesc
	ch <- xdpPacketsDesc
	ch <- xdpBytesDesc
}

// Collect implements prometheus.Collector. It gives the drop counters of the
// socket path and of the XDP program, and the XDP counters.
func (r *Router) Collect(ch chan<- prometheus.Metric) {
	x := r.xdpStatsNow()
	var drops [numDropReasons]uint64
	for i := range r.drops {
		drops[i] = r.drops[i].Load()
	}
	drops[dropLaneMeter] += x.laneDrops
	drops[dropTunnelLimit] += x.tunnelDrops
	for i, n := range drops {
		ch <- prometheus.MustNewConstMetric(dropsDesc, prometheus.CounterValue, float64(n), dropLabels[i])
	}
	for _, c := range []struct {
		result string
		n      uint64
	}{{"forwarded", x.packets}, {"no_row", x.noRow}, {"expired", x.expired}, {"no_route", x.noRoute}, {"malformed", x.malformed}, {"too_long", x.tooLong}} {
		ch <- prometheus.MustNewConstMetric(xdpPacketsDesc, prometheus.CounterValue, float64(c.n), c.result)
	}
	ch <- prometheus.MustNewConstMetric(xdpBytesDesc, prometheus.CounterValue, float64(x.bytes))
}

func modeLabel(m dp.Mode) string {
	switch m {
	case dp.Mode_MODE_PSP:
		return "psp"
	case dp.Mode_MODE_QUIC:
		return "quic"
	}
	return "unknown"
}

func reasonLabel(h *dp.Hello) string {
	if h.GetSpare() {
		return "spare"
	}
	switch h.GetFallbackReason() {
	case dp.FallbackReason_FALLBACK_REASON_UNSPECIFIED:
		return "none"
	case dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT:
		return "probe_timeout"
	case dp.FallbackReason_FALLBACK_REASON_CONFIG:
		return "config"
	}
	return "unknown"
}
