// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
)

// hostList is a HostAddrs with a fixed list.
type hostList []netip.Addr

func (l hostList) HostAddrs() ([]netip.Addr, error) { return slices.Clone(l), nil }

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// localAddrPort returns the address of a socket, unmapped.
func localAddrPort(c net.PacketConn) netip.AddrPort {
	return unmap(c.LocalAddr().(*net.UDPAddr).AddrPort())
}

// loopback6 opens a UDP socket on ::1, or skips the test.
func loopback6(t *testing.T) *net.UDPConn {
	t.Helper()
	udp, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	return udp
}

// listen opens a UDP socket on the unspecified address of network, or skips the test.
func listen(t *testing.T, network string) *net.UDPConn {
	t.Helper()
	ip := net.IPv4zero
	if network == "udp" {
		ip = net.IPv6unspecified
	}
	udp, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		t.Skipf("no %s socket: %v", network, err)
	}
	return udp
}

// waitCandidates waits until Status of a has the candidates want.
func waitCandidates(t *testing.T, a *testAgent, want []Candidate, msg string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, want, a.a.Status().Candidates)
	}, 5*time.Second, 10*time.Millisecond, msg)
}

// TestCandidates checks the candidates in Status: the reflexive address from
// the Welcome of the relay, then the host addresses that a peer can use.
func TestCandidates(t *testing.T) {
	// One address of each kind that the agent removes or orders.
	all := hostList(addrs(
		"192.0.2.10", "fd00::10", "127.0.0.1", "fe80::1",
		"fd61:706f:7879:12:3400::99", // In the VPC network.
		"fd61:706f:7879:99:9900::1",  // In another VPC network.
		"2001:db8::10", "::1", "224.0.0.1", "192.0.2.10", "::ffff:198.51.100.7",
	))
	cases := []struct {
		name    string
		network string // Network of the agent socket. Empty means a socket on 127.0.0.1.
		hosts   HostAddrs
		want    []string // Host candidates, at the port of the agent socket.
	}{
		{name: "no host list"},
		{name: "socket on one address", hosts: all, want: []string{"127.0.0.1"}},
		{name: "IPv4 socket on all addresses", network: "udp4", hosts: all, want: []string{"192.0.2.10", "127.0.0.1", "198.51.100.7"}},
		{
			name: "dual-stack socket", network: "udp", hosts: all,
			want: []string{"2001:db8::10", "fd00::10", "::1", "192.0.2.10", "127.0.0.1", "198.51.100.7"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var udp *net.UDPConn
			if tc.network == "" {
				udp = loopback(t)
			} else {
				udp = listen(t, tc.network)
			}
			port := localAddrPort(udp).Port()
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			a := w.agent(t, "a", r, agentOptions{udp: udp, hosts: tc.hosts})
			a.attached(t)

			want := []Candidate{{Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), Kind: CandidateReflexive}}
			for _, s := range tc.want {
				want = append(want, Candidate{Address: netip.AddrPortFrom(netip.MustParseAddr(s), port), Kind: CandidateHost})
			}
			waitCandidates(t, a, want, "candidates after the attach")

			a.stop()
			assert.Empty(t, a.a.Status().Candidates, "candidates after Run")
		})
	}
}

// TestReflexiveCandidates checks that each relay session gives its reflexive
// address one time, and that the address goes when its session ends.
func TestReflexiveCandidates(t *testing.T) {
	cases := []struct {
		name string
		ipv6 bool // The second relay is on ::1, so it sees another address.
	}{
		{name: "one address on two relays"},
		{name: "two addresses", ipv6: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r1 := w.relay(t, "relay-1")
			var r2 *testRelay
			var udp *net.UDPConn
			if tc.ipv6 {
				r2, udp = w.relayOn(t, "relay-2", loopback6(t), loopback6(t)), listen(t, "udp")
			} else {
				r2, udp = w.relay(t, "relay-2"), loopback(t)
			}
			port := localAddrPort(udp).Port()
			a := w.agent(t, "a", r1, agentOptions{udp: udp, sessions: 2, relays: []identity.Relay{r1.ref(), r2.ref()}})
			require.Eventually(t, func() bool { return len(a.a.Status().Connections) == 2 }, 5*time.Second, 10*time.Millisecond)

			v4 := Candidate{Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), Kind: CandidateReflexive}
			if !tc.ipv6 {
				waitCandidates(t, a, []Candidate{v4}, "equal reflexive addresses count one time")
				return
			}
			v6 := Candidate{Address: netip.AddrPortFrom(netip.IPv6Loopback(), port), Kind: CandidateReflexive}
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.ElementsMatch(c, []Candidate{v4, v6}, a.a.Status().Candidates)
			}, 5*time.Second, 10*time.Millisecond, "a reflexive address for each session")

			// The session on r2 ends, and r2 opens no new one.
			r2.stopAccept()
			for _, qc := range r2.agentConns(udp.LocalAddr(), true) {
				_ = qc.CloseWithError(0, "session ends")
			}
			waitCandidates(t, a, []Candidate{v4}, "the reflexive address of the ended session goes")
		})
	}
}

// TestReflexiveAfterRebind checks that a new source address of the agent socket
// does not change the reflexive candidate until the session attaches again.
func TestReflexiveAfterRebind(t *testing.T) {
	first, next := loopback(t), loopback(t)
	t.Cleanup(func() { _ = next.Close() })
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	mc := &moveConn{next: next, hide: true}
	a := w.agent(t, "a", r, agentOptions{udp: first, move: mc})
	a.attached(t)
	old := []Candidate{{Address: localAddrPort(first), Kind: CandidateReflexive}}
	waitCandidates(t, a, old, "reflexive address at the attach")

	mc.move()
	require.Eventually(t, func() bool { return len(r.agentConns(next.LocalAddr(), true)) > 0 }, 5*time.Second, 10*time.Millisecond,
		"the relay sees the new source")
	require.Never(t, func() bool { return !slices.Equal(old, a.a.Status().Candidates) }, checkTx+time.Second, 20*time.Millisecond,
		"the reflexive address changed before the next attach")

	a.reconnect()
	a.attached(t)
	waitCandidates(t, a, []Candidate{{Address: localAddrPort(next), Kind: CandidateReflexive}}, "reflexive address at the next attach")
}

// TestCandidateRound checks the addresses of a Candidates round: each reflexive
// address and the observed one stay when the host addresses are more than the limit.
func TestCandidateRound(t *testing.T) {
	ap := func(ss ...string) []netip.AddrPort {
		out := make([]netip.AddrPort, len(ss))
		for i, s := range ss {
			out[i] = netip.MustParseAddrPort(s)
		}
		return out
	}
	hosts := ap("[2001:db8::1]:9", "[2001:db8::2]:9", "[2001:db8::3]:9", "[fd00::1]:9", "[fd00::2]:9",
		"192.0.2.1:9", "192.0.2.2:9", "192.0.2.3:9", "192.0.2.4:9", "192.0.2.5:9")
	cases := []struct {
		name      string
		reflexive []netip.AddrPort
		observed  string
		want      []netip.AddrPort
	}{
		{name: "host addresses only", want: hosts[:maxRound]},
		{
			name: "reflexive and observed first", reflexive: ap("203.0.113.1:40000", "203.0.113.2:40000"), observed: "203.0.113.9:41000",
			want: append(ap("203.0.113.1:40000", "203.0.113.2:40000", "203.0.113.9:41000"), hosts[:5]...),
		},
		{
			name: "observed equal to a reflexive address", reflexive: ap("203.0.113.1:40000"), observed: "203.0.113.1:40000",
			want: append(ap("203.0.113.1:40000"), hosts[:7]...),
		},
		{
			name: "host equal to a reflexive address", reflexive: ap("[2001:db8::1]:9"),
			want: hosts[:maxRound],
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var obs netip.AddrPort
			if tc.observed != "" {
				obs = netip.MustParseAddrPort(tc.observed)
			}
			c := candidates{reflexive: tc.reflexive, host: hosts}
			assert.Equal(t, tc.want, c.round(obs))
		})
	}
}
