// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/quic-go/quic-go"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// gatherInterval is the time between two gathers of the candidates when the sessions do not change.
	gatherInterval = time.Minute
	// maxRound is the most addresses in one Candidates round to a peer.
	maxRound = 8
)

// HostAddrs lists the addresses of the host for the host candidates of the agent.
type HostAddrs interface {
	// HostAddrs returns the unicast addresses of the host interfaces that are up
	// and not loopback. The agent removes the addresses that a peer cannot use.
	// The agent can call it from more than one goroutine at the same time.
	HostAddrs() ([]netip.Addr, error)
}

// CandidateKind tells where a candidate comes from.
type CandidateKind string

const (
	// CandidateReflexive is the address of the agent socket as a relay saw it at the attach.
	CandidateReflexive CandidateKind = "reflexive"
	// CandidateHost is a host address at the port of the agent socket.
	CandidateHost CandidateKind = "host"
)

// Candidate is an address where a peer agent can try to reach the agent socket.
type Candidate struct {
	Address netip.AddrPort
	Kind    CandidateKind
}

// candidates are the own candidates of the agent. The root makes a new value
// at each change, and a value does not change after that.
type candidates struct {
	reflexive []netip.AddrPort // Of the live sessions in rank order, each one time.
	host      []netip.AddrPort // Global IPv6 first, then the other IPv6, then IPv4.
}

func (c candidates) equal(o candidates) bool {
	return slices.Equal(c.reflexive, o.reflexive) && slices.Equal(c.host, o.host)
}

// list returns the candidates for Status: the reflexive ones, then the host ones.
func (c candidates) list() []Candidate {
	var out []Candidate
	for _, a := range c.reflexive {
		out = append(out, Candidate{Address: a, Kind: CandidateReflexive})
	}
	for _, a := range c.host {
		out = append(out, Candidate{Address: a, Kind: CandidateHost})
	}
	return out
}

// round returns the addresses of a Candidates round to a peer: the reflexive
// addresses and observed, then the host addresses, each one time, at most maxRound.
func (c candidates) round(observed netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, maxRound)
	add := func(a netip.AddrPort) {
		if a.IsValid() && len(out) < maxRound && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	for _, a := range c.reflexive {
		add(a)
	}
	add(observed)
	for _, a := range c.host {
		add(a)
	}
	return out
}

// reflexiveAddr returns the reflexive address of a Welcome. An address that is
// not valid gives no candidate; the session works without it.
func reflexiveAddr(w *dp.Welcome) netip.AddrPort {
	a, err := netip.ParseAddrPort(w.GetReflexiveAddress())
	if err != nil {
		return netip.AddrPort{}
	}
	ip := a.Addr().Unmap().WithZone("")
	if !usable(ip) || a.Port() == 0 {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip, a.Port())
}

// usable reports whether a peer can send to ip: a unicast address that is not link-local.
func usable(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() && ip != broadcast4
}

var broadcast4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// hostRank orders the host candidates: global IPv6, the other IPv6, IPv4.
func hostRank(ip netip.Addr) int {
	switch {
	case ip.Is4():
		return 2
	case ip.IsGlobalUnicast() && !ip.IsPrivate():
		return 0
	}
	return 1
}

// hostsListed is the result of the task that lists the host addresses.
type hostsListed struct {
	addrs []netip.Addr
	err   error
}

// gather makes the candidates from the live sessions and the last host list,
// and starts a new host list.
func (r *root) gather() {
	r.setCandidates()
	lister := r.a.cfg.Addresses
	switch {
	case lister == nil || r.ending:
		return
	case r.listing:
		r.listAgain = true
		return
	}
	r.listing = true
	r.task(func() any {
		addrs, err := lister.HostAddrs()
		// The root keeps a copy, so the lister can use its slice again.
		return hostsListed{slices.Clone(addrs), err}
	})
}

// hostsListed takes a new host list. After an error the last list stays.
func (r *root) hostsListed(m hostsListed) {
	r.listing = false
	switch {
	case m.err != nil && !r.listFailed:
		r.listFailed = true
		slog.Warn("Failed to list the host addresses; the host candidates stay as they are", "error", m.err)
	case m.err != nil:
		slog.Debug("Failed to list the host addresses again", "error", m.err)
	default:
		r.listFailed = false
		r.hostAddrs = m.addrs
	}
	r.setCandidates()
	if r.listAgain {
		r.listAgain = false
		r.gather()
	}
}

// setCandidates makes the candidates from the live sessions and the host list.
func (r *root) setCandidates() {
	var c candidates
	for _, h := range r.live() {
		if a := h.reflexive; a.IsValid() && !slices.Contains(c.reflexive, a) {
			c.reflexive = append(c.reflexive, a)
		}
	}
	c.host = hostCandidates(r.a.cfg.Transport, r.hostAddrs)
	if c.equal(r.cands) {
		return
	}
	r.cands = c
	slog.Info("Direct path candidates changed", "reflexive", c.reflexive, "host", c.host)
}

// hostCandidates returns the addresses of hosts that a peer can use, at the
// port of the agent socket of t. A socket on one address has only that address.
// The overlay addresses of all VPCs are not host candidates.
func hostCandidates(t *quic.Transport, hosts []netip.Addr) []netip.AddrPort {
	if t == nil || t.Conn == nil {
		return nil
	}
	ua, ok := t.Conn.LocalAddr().(*net.UDPAddr)
	if !ok || ua.Port == 0 {
		return nil
	}
	local := ua.AddrPort().Addr().Unmap()
	anyAddr := !local.IsValid() || local.IsUnspecified()
	var ips []netip.Addr
	for _, ip := range hosts {
		ip = ip.Unmap().WithZone("")
		switch {
		case !usable(ip), tunnet.ULAPrefix().Contains(ip), slices.Contains(ips, ip):
		case anyAddr && local.Is4() && !ip.Is4():
		case !anyAddr && ip != local:
		default:
			ips = append(ips, ip)
		}
	}
	slices.SortStableFunc(ips, func(x, y netip.Addr) int { return cmp.Compare(hostRank(x), hostRank(y)) })
	out := make([]netip.AddrPort, len(ips))
	for i, ip := range ips {
		out[i] = netip.AddrPortFrom(ip, uint16(ua.Port))
	}
	return out
}
