// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// trunkDir is the direction of a packet between this relay and a mesh member.
type trunkDir int

const (
	trunkTx trunkDir = iota // To the member.
	trunkRx                 // From the member.
	numTrunkDirs
)

var trunkDirLabels = [numTrunkDirs]string{trunkTx: "tx", trunkRx: "rx"}

// trunkDrops are the drop reasons that the relay counts for a member, with the
// direction of each. A reason that is not here has no series for a member.
var trunkDrops = []struct {
	why dropReason
	dir trunkDir
}{
	{dropTrunkMTU, trunkTx},
	{dropTrunkKeys, trunkTx},
	{dropMalformed, trunkRx},
	{dropTrunkPayload, trunkRx},
	{dropTrunkNoRow, trunkRx},
	{dropTrunkExpired, trunkRx},
	{dropTrunkSender, trunkRx},
	{dropTrunkPermit, trunkRx},
	{dropTrunkNotLocal, trunkRx},
	{dropTrunkReplay, trunkRx},
	{dropTrunkSource, trunkRx},
	{dropTrunkNotSent, trunkRx},
}

// The trunk metrics have the relay name and the relay ID of the member. Many
// members can have one ID.
var (
	trunkPacketsDesc = prometheus.NewDesc("apoxy_vpc_relay_trunk_packets_total",
		"Packets of agents that the relay sent to a mesh member (tx), or got from the member and sent on (rx).",
		[]string{"peer_relay", "peer_relay_id", "direction"}, nil)
	trunkBytesDesc = prometheus.NewDesc("apoxy_vpc_relay_trunk_bytes_total",
		"UDP payload bytes of the packets of agents that the relay sent to a mesh member (tx), or got from the member and sent on (rx).",
		[]string{"peer_relay", "peer_relay_id", "direction"}, nil)
	trunkDropsDesc = prometheus.NewDesc("apoxy_vpc_relay_trunk_dropped_packets_total",
		"Packets that the relay did not send to a mesh member (tx), and packets of the member that the relay dropped (rx), by reason.",
		[]string{"peer_relay", "peer_relay_id", "direction", "reason"}, nil)
	meshRTTDesc = prometheus.NewDesc("apoxy_vpc_relay_mesh_rtt_seconds",
		"Smoothed round-trip time of the mesh session with a member. A member with no session has no value.",
		[]string{"peer_relay", "peer_relay_id"}, nil)
)

// peerStats are the counters of the packets between this relay and one mesh member.
// All senders count in them, so the series follow the members and not the agents.
type peerStats struct {
	packets, bytes [numTrunkDirs]atomic.Uint64
	drops          [numDropReasons]atomic.Uint64
	// id is the last relay ID that the member gave, for the time with no session.
	id atomic.Pointer[string]
}

// add counts one packet with n bytes of UDP payload.
func (p *peerStats) add(dir trunkDir, n int) {
	p.packets[dir].Add(1)
	p.bytes[dir].Add(uint64(n))
}

// relayID returns id, or the last ID of the member if id is empty: the mesh forgets
// the ID of a member that stops, and the series of the member must not change then.
func (p *peerStats) relayID(id string) string {
	last := p.id.Load()
	switch {
	case id == "" && last != nil:
		return *last
	case id != "" && (last == nil || *last != id):
		p.id.Store(&id)
	}
	return id
}

// peerTable has the counters of the members by relay name.
type peerTable struct {
	byName atomic.Pointer[map[string]*peerStats] // The packet path reads it with no lock.
	mu     sync.Mutex                            // Guards a change of byName.
}

func (t *peerTable) load() map[string]*peerStats {
	if m := t.byName.Load(); m != nil {
		return *m
	}
	return nil
}

// of returns the counters of member name. The first call for a name makes them.
func (t *peerTable) of(name string) *peerStats {
	if p := t.load()[name]; p != nil {
		return p
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	old := t.load()
	if p := old[name]; p != nil {
		return p
	}
	next := make(map[string]*peerStats, len(old)+1)
	maps.Copy(next, old)
	p := &peerStats{}
	next[name] = p
	t.byName.Store(&next)
	return p
}

// keep removes the counters of each name that is not in names.
func (t *peerTable) keep(names map[string]struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	old := t.load()
	next := make(map[string]*peerStats, len(old))
	for name, p := range old {
		if _, ok := names[name]; ok {
			next[name] = p
		}
	}
	if len(next) != len(old) {
		t.byName.Store(&next)
	}
}

// meshPeer is what the metrics read of one member.
type meshPeer struct {
	name string
	id   string       // Relay ID from the last session. Empty if the mesh does not have it.
	sess *MeshSession // Open session, or nil.
}

// peers returns the members that the mesh has now.
func (m *Mesh) peers() []meshPeer {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]meshPeer, 0, len(m.members))
	for name, mem := range m.members {
		out = append(out, meshPeer{name: name, id: mem.relay.GetId(), sess: mem.sess})
	}
	return out
}

// sweepPeers removes the counters of the relays that are not members now. A
// late packet can make the counters of such a relay again.
func (r *Router) sweepPeers() {
	t := r.trunk.Load()
	if t == nil || len(r.peers.load()) == 0 {
		return
	}
	names := map[string]struct{}{}
	for _, m := range t.m.peers() {
		names[m.name] = struct{}{}
	}
	r.peers.keep(names)
}

// xdpToMembers returns the live counts of the XDP rows that send to each member.
// Router.mu must be held.
func (r *Router) xdpToMembers() map[*peerStats]xdpCounters {
	x := r.xdp
	if x == nil {
		return nil
	}
	out := map[*peerStats]xdpCounters{}
	for a, rows := range x.rows {
		for spi, e := range rows {
			if e.peer == nil {
				continue
			}
			c, err := x.t.counters(xdpKey{a, spi})
			if err != nil {
				continue
			}
			sum := out[e.peer]
			sum.packets += c.packets
			sum.bytes += c.bytes
			out[e.peer] = sum
		}
	}
	return out
}

// collectTrunk gives the counters of each member that the mesh has now, and the
// RTT of its mesh session.
func (r *Router) collectTrunk(ch chan<- prometheus.Metric) {
	t := r.trunk.Load()
	if t == nil {
		return
	}
	peers := t.m.peers()
	stats := make([]*peerStats, len(peers))
	sent := make([]xdpCounters, len(peers))
	// A removed XDP row gives its counts to the member with the lock held for
	// writing, so the sums of one read with the lock do not go down.
	r.mu.RLock()
	live := r.xdpToMembers()
	for i, m := range peers {
		st := r.peers.of(m.name)
		c := live[st]
		c.packets += st.packets[trunkTx].Load()
		c.bytes += st.bytes[trunkTx].Load()
		stats[i], sent[i] = st, c
	}
	r.mu.RUnlock()
	for i, m := range peers {
		st, id := stats[i], stats[i].relayID(m.id)
		packets := [numTrunkDirs]uint64{trunkTx: sent[i].packets, trunkRx: st.packets[trunkRx].Load()}
		bytes := [numTrunkDirs]uint64{trunkTx: sent[i].bytes, trunkRx: st.bytes[trunkRx].Load()}
		for dir, label := range trunkDirLabels {
			ch <- prometheus.MustNewConstMetric(trunkPacketsDesc, prometheus.CounterValue, float64(packets[dir]), m.name, id, label)
			ch <- prometheus.MustNewConstMetric(trunkBytesDesc, prometheus.CounterValue, float64(bytes[dir]), m.name, id, label)
		}
		for _, d := range trunkDrops {
			ch <- prometheus.MustNewConstMetric(trunkDropsDesc, prometheus.CounterValue, float64(st.drops[d.why].Load()),
				m.name, id, trunkDirLabels[d.dir], dropLabels[d.why])
		}
		if rtt := meshRTT(m.sess); rtt > 0 {
			ch <- prometheus.MustNewConstMetric(meshRTTDesc, prometheus.GaugeValue, rtt.Seconds(), m.name, id)
		}
	}
}

// meshRTT returns the smoothed RTT of the connection of s. It is zero with no
// session, with no sample, and for a connection that has no place for its RTT.
func meshRTT(s *MeshSession) time.Duration {
	if s == nil {
		return 0
	}
	rtt := rttOf(s.Context())
	if rtt == nil {
		return 0
	}
	return time.Duration(rtt.Load())
}
