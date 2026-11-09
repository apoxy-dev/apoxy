// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
)

// fakeResolver answers each name with its addresses, or each lookup with err when it is set.
type fakeResolver struct {
	mu      sync.Mutex
	addrs   map[string][]netip.Addr
	err     error
	network string                 // Of the last lookup.
	slow    map[string]*slowLookup // The next lookup of a name is slow.
}

// slowLookup is a lookup that started before a change of its name: it gives old after release.
type slowLookup struct {
	old                    []netip.Addr
	started, release, done chan struct{}
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	if s := f.slow[host]; s != nil {
		delete(f.slow, host)
		f.mu.Unlock()
		close(s.started)
		defer close(s.done)
		<-s.release
		return s.old, nil
	}
	defer f.mu.Unlock()
	f.network = network
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	addrs, ok := f.addrs[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return addrs, nil
}

// set makes the lookups of host answer addrs, or makes all lookups fail with err.
func (f *fakeResolver) set(host string, err error, addrs ...netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addrs == nil {
		f.addrs = map[string][]netip.Addr{}
	}
	f.err = err
	if err == nil {
		f.addrs[host] = addrs
	}
}

// TestResolveRelay checks the address that the agent dials for a relay
// address, and the answers that it keeps for the next dial.
func TestResolveRelay(t *testing.T) {
	v4a, v4b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	v6 := netip.MustParseAddr("2001:db8::1")
	mapped := netip.MustParseAddr("::ffff:192.0.2.3")
	errLookup := errors.New("no DNS server")
	cases := []struct {
		name     string
		addr     string
		network  string
		answers  []netip.Addr // Of the lookup of localhost.
		err      error        // Of the lookup.
		canceled bool         // The context of the dial ended.
		last     []netip.Addr
		want     []netip.Addr // The address to dial is one of these.
		kept     []netip.Addr
		wantErr  bool
	}{
		{name: "an IP needs no lookup", addr: "192.0.2.9:443", network: "ip", want: []netip.Addr{netip.MustParseAddr("192.0.2.9")}},
		{name: "an IPv6 address needs no lookup", addr: "[2001:db8::9]:443", network: "ip", want: []netip.Addr{netip.MustParseAddr("2001:db8::9")}},
		{name: "a name with one address", addr: "localhost:443", network: "ip", answers: []netip.Addr{v4a}, want: []netip.Addr{v4a}, kept: []netip.Addr{v4a}},
		{name: "IPv4 first", addr: "localhost:443", network: "ip", answers: []netip.Addr{v6, v4a}, want: []netip.Addr{v4a}, kept: []netip.Addr{v6, v4a}},
		{name: "only IPv6", addr: "localhost:443", network: "ip", answers: []netip.Addr{v6}, want: []netip.Addr{v6}, kept: []netip.Addr{v6}},
		{name: "an IPv4 socket takes no IPv6 address", addr: "localhost:443", network: "ip4", answers: []netip.Addr{v6, v4a}, want: []netip.Addr{v4a}, kept: []netip.Addr{v4a}},
		{name: "an IPv4-mapped answer is IPv4", addr: "localhost:443", network: "ip4", answers: []netip.Addr{mapped}, want: []netip.Addr{mapped.Unmap()}, kept: []netip.Addr{mapped.Unmap()}},
		{name: "an IPv6 socket takes no IPv4 address", addr: "localhost:443", network: "ip6", answers: []netip.Addr{v4a, v6}, want: []netip.Addr{v6}, kept: []netip.Addr{v6}},
		{name: "an IPv6 socket takes no IPv4-mapped answer", addr: "localhost:443", network: "ip6", answers: []netip.Addr{mapped, v6}, want: []netip.Addr{v6}, kept: []netip.Addr{v6}},
		{name: "an IPv6 socket with only IPv4 answers uses the last answers", addr: "localhost:443", network: "ip6", answers: []netip.Addr{v4a}, last: []netip.Addr{v6}, want: []netip.Addr{v6}},
		{name: "an IPv6 socket with only IPv4 answers", addr: "localhost:443", network: "ip6", answers: []netip.Addr{v4a}, wantErr: true},
		{name: "many relays", addr: "localhost:443", network: "ip", answers: []netip.Addr{v4a, v4b}, want: []netip.Addr{v4a, v4b}, kept: []netip.Addr{v4a, v4b}},
		{name: "a failed lookup uses the last answers and keeps none", addr: "localhost:443", network: "ip", err: errLookup, last: []netip.Addr{v4b}, want: []netip.Addr{v4b}},
		{name: "a lookup with no address for the socket uses the last answers", addr: "localhost:443", network: "ip4", answers: []netip.Addr{v6}, last: []netip.Addr{v4b}, want: []netip.Addr{v4b}},
		{name: "a failed lookup with no last answers", addr: "localhost:443", network: "ip", err: errLookup, wantErr: true},
		{name: "a lookup with no address for the socket", addr: "localhost:443", network: "ip4", answers: []netip.Addr{v6}, wantErr: true},
		{name: "an ended dial does not use the last answers", addr: "localhost:443", network: "ip", canceled: true, last: []netip.Addr{v4b}, wantErr: true},
		{name: "a good lookup replaces the last answers", addr: "localhost:443", network: "ip", answers: []netip.Addr{v4a}, last: []netip.Addr{v4b}, want: []netip.Addr{v4a}, kept: []netip.Addr{v4a}},
		{name: "no port", addr: "localhost", network: "ip", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := &fakeResolver{}
			res.set("localhost", tc.err, tc.answers...)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			got := map[netip.Addr]bool{}
			// Many dials, so that each relay of a name gets picked.
			for range 64 {
				ap, kept, err := resolveRelay(ctx, res, tc.network, tc.addr, tc.last)
				if tc.wantErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				require.Equal(t, uint16(443), ap.Port())
				require.Contains(t, tc.want, ap.Addr())
				require.Equal(t, tc.kept, kept)
				got[ap.Addr()] = true
			}
			assert.Len(t, got, len(tc.want), "each address gets picked")
			if tc.answers != nil || tc.err != nil {
				assert.Equal(t, tc.network, res.network, "network of the lookup")
			}
		})
	}
}

// TestLookupNetwork checks the lookup network of the agent socket: the network of Config, else the local address.
func TestLookupNetwork(t *testing.T) {
	cases := []struct {
		name    string
		family  string // Config.Network.
		listen  string // The network and the address of the socket.
		laddr   string
		network string
	}{
		{name: "udp4", family: "udp4", listen: "udp4", laddr: "0.0.0.0:0", network: "ip4"},
		{name: "udp6", family: "udp6", listen: "udp6", laddr: "[::]:0", network: "ip6"},
		{name: "dual-stack", family: "udp", listen: "udp", laddr: "[::]:0", network: "ip"},
		{name: "no network and an IPv4 address", listen: "udp4", laddr: "127.0.0.1:0", network: "ip4"},
		{name: "no network and an IPv6 address", listen: "udp6", laddr: "[::1]:0", network: "ip6"},
		{name: "no network and a wildcard IPv6 address", listen: "udp6", laddr: "[::]:0", network: "ip"},
		{name: "no network and a dual-stack socket", listen: "udp", laddr: "[::]:0", network: "ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := net.ListenPacket(tc.listen, tc.laddr)
			if err != nil {
				t.Skipf("no %s socket: %v", tc.listen, err)
			}
			defer pc.Close()
			require.Equal(t, tc.network, lookupNetwork(tc.family, pc))
		})
	}
}

// TestRelayByName checks an identity file entry that names a relay group by its DNS name. The agent checks the
// relay cert with the group name, dials the answer of each lookup, and dials the last answer when a lookup fails.
func TestRelayByName(t *testing.T) {
	const group = "us-west-2-0.relay.test"
	v4, v6 := netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()
	type step struct {
		answer netip.Addr // The answer of the name for the next session. Not valid means that the lookups fail.
		relay  int        // The relay of the next session: 0 on 127.0.0.1, 1 on ::1.
	}
	cases := []struct {
		name  string
		steps []step // After the first session on relay 0, the relay closes each session.
	}{
		{name: "the name answers a moved relay", steps: []step{{answer: v6, relay: 1}}},
		{name: "a failed lookup dials the last answer", steps: []step{{relay: 0}}},
		{name: "a failed lookup after a move dials the moved relay", steps: []step{{answer: v6, relay: 1}, {relay: 1}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			udp := listen(t, "udp") // A dual-stack socket takes the IPv4 and the IPv6 answers.
			w := newWorld(t)
			// As at a real relay, the cert has a wildcard name and the Welcome has the relay ID.
			w.certNames = map[string]string{"r0.relay.test": "*.relay.test", "r1.relay.test": "*.relay.test"}
			r0 := w.relay(t, "r0.relay.test")
			port := netip.MustParseAddrPort(r0.addr).Port()
			sock6, err := net.ListenUDP("udp6", net.UDPAddrFromAddrPort(netip.AddrPortFrom(v6, port)))
			if err != nil {
				t.Skipf("no IPv6 loopback: %v", err)
			}
			relays := []*testRelay{r0, w.relayOn(t, "r1.relay.test", sock6, loopback6(t))}
			res := &fakeResolver{}
			res.set("localhost", nil, v4)
			// The TLS name is the ID of the entry, not the host of its address.
			entry := identity.Relay{ID: group, Addresses: []string{net.JoinHostPort("localhost", strconv.Itoa(int(port)))}}
			a := w.agent(t, "a", r0, agentOptions{udp: udp, identityFile: true, relays: []identity.Relay{entry}, resolver: res})
			a.attached(t)
			want, at := []int{1, 0}, 0
			require.Equal(t, want, []int{a.dials(r0), a.dials(relays[1])}, "sessions on each relay")

			for _, s := range tc.steps {
				if s.answer.IsValid() {
					res.set("localhost", nil, s.answer)
				} else {
					res.set("localhost", errors.New("no DNS server"))
				}
				for _, qc := range relays[at].agentConns(udp.LocalAddr(), true) {
					_ = qc.CloseWithError(0, "relay closed the session")
				}
				a.attached(t)
				at = s.relay
				want[at]++
				require.Eventually(t, func() bool { return a.dials(relays[at]) == want[at] }, 5*time.Second, 10*time.Millisecond,
					"session on relay %d", at)
				assert.Equal(t, want, []int{a.dials(r0), a.dials(relays[1])}, "sessions on each relay")
			}
		})
	}
}

// TestRelayLateLookup checks that a lookup that ends after its dial round closed does not replace the answers of a
// newer lookup: when the lookups fail later, the agent dials the newer answer.
func TestRelayLateLookup(t *testing.T) {
	udp := listen(t, "udp") // A dual-stack socket takes the IPv4 and the IPv6 answers.
	w := newWorld(t)
	w.certNames = map[string]string{"a.relay.test": "*.relay.test", "old.relay.test": "*.relay.test", "new.relay.test": "*.relay.test"}
	ra, old := w.relay(t, "a.relay.test"), w.relay(t, "old.relay.test")
	port := netip.MustParseAddrPort(old.addr).Port()
	sock6, err := net.ListenUDP("udp6", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Loopback(), port)))
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	moved := w.relayOn(t, "new.relay.test", sock6, loopback6(t))

	// The first lookup of group b gives the old relay after the round closed. The next lookup gives the moved relay.
	slow := &slowLookup{old: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, started: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{})}
	release := sync.OnceFunc(func() { close(slow.release) })
	defer release() // Before the cleanups: the agent stops only after the slow lookup ends.
	res := &fakeResolver{slow: map[string]*slowLookup{"b.localhost": slow}}
	res.set("a.localhost", nil, netip.MustParseAddr("127.0.0.1"))
	res.set("b.localhost", nil, netip.IPv6Loopback())
	entries := []identity.Relay{
		{ID: "a-group.relay.test", Addresses: []string{net.JoinHostPort("a.localhost", strconv.Itoa(int(netip.MustParseAddrPort(ra.addr).Port())))}},
		{ID: "b-group.relay.test", Addresses: []string{net.JoinHostPort("b.localhost", strconv.Itoa(int(port)))}},
	}
	a := w.agent(t, "a", ra, agentOptions{udp: udp, sessions: 2, identityFile: true, relays: entries, resolver: res})
	waitClosed(t, slow.started, "the first lookup of group b")
	a.attached(t)
	a.attached(t)
	sessions := func() []int { return []int{a.dials(ra), a.dials(old), a.dials(moved)} }
	require.Equal(t, []int{1, 0, 1}, sessions(), "sessions on relay a, the old relay and the moved relay")

	release()
	waitClosed(t, slow.done, "the end of the first lookup of group b")
	// The root takes the late result of the closed round; no event shows it.
	time.Sleep(200 * time.Millisecond)
	res.set("", errors.New("no DNS server"))
	for _, qc := range moved.agentConns(udp.LocalAddr(), true) {
		_ = qc.CloseWithError(0, "relay closed the session")
	}
	a.attached(t)
	require.Eventually(t, func() bool { return a.dials(moved) == 2 }, 5*time.Second, 10*time.Millisecond, "session on the moved relay")
	assert.Equal(t, []int{1, 0, 2}, sessions(), "sessions on relay a, the old relay and the moved relay")
}

// waitClosed waits up to 10 s for the close of ch.
func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("no %s in 10 s", what)
	}
}
