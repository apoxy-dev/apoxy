package agent

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
)

// fakeRouteTable is a routeTable that records what the reconciler asked for.
type fakeRouteTable struct {
	routes  sets.Set[netip.Prefix]
	adds    []netip.Prefix
	dels    []netip.Prefix
	addErr  map[netip.Prefix]error
	delErr  map[netip.Prefix]error
	addSeen int
}

func newFakeRouteTable() *fakeRouteTable {
	return &fakeRouteTable{
		routes: sets.New[netip.Prefix](),
		addErr: map[netip.Prefix]error{},
		delErr: map[netip.Prefix]error{},
	}
}

func (f *fakeRouteTable) AddRoute(dst netip.Prefix) error {
	f.addSeen++
	if err := f.addErr[dst]; err != nil {
		return err
	}
	f.adds = append(f.adds, dst)
	f.routes.Insert(dst)
	return nil
}

func (f *fakeRouteTable) DelRoute(dst netip.Prefix) error {
	f.dels = append(f.dels, dst)
	f.routes.Delete(dst)
	return f.delErr[dst]
}

func p(t *testing.T, s string) netip.Prefix {
	t.Helper()
	pfx, err := netip.ParsePrefix(s)
	require.NoError(t, err)
	return pfx
}

func set(t *testing.T, ss ...string) sets.Set[netip.Prefix] {
	t.Helper()
	out := sets.New[netip.Prefix]()
	for _, s := range ss {
		out.Insert(p(t, s))
	}
	return out
}

// rr builds a reconciler over a fake table. The fake is returned so tests can
// assert on the resulting table rather than on the reconciler's bookkeeping.
func rr(t *testing.T, installed sets.Set[netip.Prefix]) (*routeReconciler, *fakeRouteTable) {
	t.Helper()
	f := newFakeRouteTable()
	preinstalled := make(map[netip.Prefix]netip.Addr, installed.Len())
	for dst := range installed {
		f.routes.Insert(dst)
		preinstalled[dst] = netip.Addr{}
	}
	return newRouteReconciler(f, nil, preinstalled), f
}

func TestRouteReconciler(t *testing.T) {
	cases := []struct {
		name string
		// preinstalled is what the router already carries before any claim,
		// standing in for the bootstrap routes initRouter installs.
		preinstalled []string
		// steps mutate claims in order; empty desired means Release.
		steps []struct {
			owner   string
			desired []string
			release bool
		}
		wantRoutes []string
	}{
		{
			name: "single owner installs its claim",
			steps: []struct {
				owner   string
				desired []string
				release bool
			}{
				{owner: "relay-a", desired: []string{"10.0.0.0/24", "10.0.1.0/24"}},
			},
			wantRoutes: []string{"10.0.0.0/24", "10.0.1.0/24"},
		},
		{
			name: "re-claim withdraws dropped prefixes",
			steps: []struct {
				owner   string
				desired []string
				release bool
			}{
				{owner: "relay-a", desired: []string{"10.0.0.0/24", "10.0.1.0/24"}},
				{owner: "relay-a", desired: []string{"10.0.0.0/24"}},
			},
			wantRoutes: []string{"10.0.0.0/24"},
		},
		{
			name: "release withdraws everything the owner held",
			steps: []struct {
				owner   string
				desired []string
				release bool
			}{
				{owner: "relay-a", desired: []string{"10.0.0.0/24"}},
				{owner: "relay-a", release: true},
			},
			wantRoutes: nil,
		},
		{
			// The leak this whole type exists for: session 1 advertises a
			// prefix, dies, and session 2 never sees it. Before the reconciler
			// the prefix stayed installed for the agent's lifetime.
			name: "prefix from a dead session does not survive the next one",
			steps: []struct {
				owner   string
				desired []string
				release bool
			}{
				{owner: "relay-a", desired: []string{"10.0.0.0/24", "192.168.5.0/24"}},
				{owner: "relay-a", release: true},
				{owner: "relay-a", desired: []string{"10.0.0.0/24"}},
			},
			wantRoutes: []string{"10.0.0.0/24"},
		},
		{
			// MinConns > 1: two sessions share the router. Neither may withdraw
			// a prefix the other still claims.
			name: "concurrent owners keep overlapping prefixes",
			steps: []struct {
				owner   string
				desired []string
				release bool
			}{
				{owner: "relay-a", desired: []string{"10.0.0.0/24", "10.0.1.0/24"}},
				{owner: "relay-b", desired: []string{"10.0.1.0/24", "10.0.2.0/24"}},
				{owner: "relay-a", release: true},
			},
			wantRoutes: []string{"10.0.1.0/24", "10.0.2.0/24"},
		},
		{
			name: "last claim released removes the shared prefix",
			steps: []struct {
				owner   string
				desired []string
				release bool
			}{
				{owner: "relay-a", desired: []string{"10.0.1.0/24"}},
				{owner: "relay-b", desired: []string{"10.0.1.0/24"}},
				{owner: "relay-a", release: true},
				{owner: "relay-b", release: true},
			},
			wantRoutes: nil,
		},
		{
			// Bootstrap routes are installed before any session exists. The
			// first claim is authoritative, so an unclaimed leftover goes away.
			name:         "unclaimed bootstrap route is withdrawn on first claim",
			preinstalled: []string{"172.16.0.0/24"},
			steps: []struct {
				owner   string
				desired []string
				release bool
			}{
				{owner: "relay-a", desired: []string{"10.0.0.0/24"}},
			},
			wantRoutes: []string{"10.0.0.0/24"},
		},
		{
			name:         "bootstrap route the session also wants is kept",
			preinstalled: []string{"172.16.0.0/24"},
			steps: []struct {
				owner   string
				desired []string
				release bool
			}{
				{owner: "relay-a", desired: []string{"172.16.0.0/24", "10.0.0.0/24"}},
			},
			wantRoutes: []string{"172.16.0.0/24", "10.0.0.0/24"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, f := rr(t, set(t, tc.preinstalled...))
			for _, st := range tc.steps {
				if st.release {
					r.Release(routeOwner(st.owner))
					continue
				}
				r.Claim(routeOwner(st.owner), routeSource{}, set(t, st.desired...))
			}
			require.Equal(t, set(t, tc.wantRoutes...), f.routes)
		})
	}
}

// TestRouteReconciler_KeepsAlreadyInstalledStable guards against churn: a
// re-claim of an unchanged set must not touch the router at all, since every
// AddRoute/DelRoute on a live datapath is a real kernel operation.
func TestRouteReconciler_KeepsAlreadyInstalledStable(t *testing.T) {
	r, f := rr(t, nil)
	want := set(t, "10.0.0.0/24", "10.0.1.0/24")

	r.Claim("relay-a", routeSource{}, want)
	require.Len(t, f.adds, 2)
	require.Empty(t, f.dels)

	r.Claim("relay-a", routeSource{}, want.Clone())
	require.Len(t, f.adds, 2, "re-claiming an identical set must not re-add")
	require.Empty(t, f.dels, "re-claiming an identical set must not delete")
}

// TestRouteReconciler_FailedAddIsRetried pins that a route the router rejected
// is not recorded as installed — otherwise a transient failure would leave the
// prefix permanently missing while the reconciler believed it was present.
func TestRouteReconciler_FailedAddIsRetried(t *testing.T) {
	r, f := rr(t, nil)
	boom := p(t, "10.0.0.0/24")
	f.addErr[boom] = fmt.Errorf("kernel said no")

	r.Claim("relay-a", routeSource{}, set(t, "10.0.0.0/24"))
	require.Empty(t, f.routes)
	require.Equal(t, 1, f.addSeen)

	// Same claim again: because the failure was not recorded as installed, the
	// reconciler tries once more. Now it succeeds.
	delete(f.addErr, boom)
	r.Claim("relay-b", routeSource{}, set(t, "10.0.0.0/24"))
	require.Equal(t, 2, f.addSeen)
	require.Equal(t, set(t, "10.0.0.0/24"), f.routes)
}

// TestRouteReconciler_Installable pins the TUN-mode filter: a default route is
// never handed to a kernel TUN device, where it would shadow the netns default
// and capture the embedding process's egress.
func TestRouteReconciler_Installable(t *testing.T) {
	cases := []struct {
		name    string
		tunMode bool
		want    []string
	}{
		{name: "netstack carries the default route", tunMode: false, want: []string{"0.0.0.0/0", "10.0.0.0/24"}},
		{name: "tun mode drops the default route", tunMode: true, want: []string{"10.0.0.0/24"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRouteTable()
			r := newRouteReconciler(f, installableRoute(tc.tunMode), nil)
			r.Claim("relay-a", routeSource{}, set(t, "0.0.0.0/0", "10.0.0.0/24"))
			require.Equal(t, set(t, tc.want...), f.routes)
		})
	}
}

// fakeSourcedRouteTable is a routeTable whose datapath can pin source
// addresses, recording what it was asked to program.
type fakeSourcedRouteTable struct {
	*fakeRouteTable
	srcs map[netip.Prefix]netip.Addr
	// unsourced counts fallbacks to plain AddRoute, so a test can tell "no
	// source was pinned" apart from "a source was pinned to the zero Addr".
	unsourced int
}

func newFakeSourcedRouteTable() *fakeSourcedRouteTable {
	return &fakeSourcedRouteTable{
		fakeRouteTable: newFakeRouteTable(),
		srcs:           map[netip.Prefix]netip.Addr{},
	}
}

func (f *fakeSourcedRouteTable) AddRoute(dst netip.Prefix) error {
	f.unsourced++
	// Reprogramming without a source clears any source a previous program set,
	// so srcs always reflects what the datapath currently carries.
	delete(f.srcs, dst)
	return f.fakeRouteTable.AddRoute(dst)
}

func (f *fakeSourcedRouteTable) AddRouteSrc(dst netip.Prefix, src netip.Addr) error {
	if err := f.fakeRouteTable.AddRoute(dst); err != nil {
		return err
	}
	f.srcs[dst] = src
	return nil
}

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	require.NoError(t, err)
	return a
}

// TestRouteReconciler_SourcePinning covers the property the whole src path
// exists for: traffic to a prefix a relay advertised must leave with this
// agent's address ON THAT RELAY. Relays do not federate, so a packet sourced
// from the address a different relay leased has no return path, which is
// invisible until an agent holds addresses on more than one relay at once.
func TestRouteReconciler_SourcePinning(t *testing.T) {
	westAddr := "fd61:706f:7879:0:100:903::"
	eastAddr := "fd61:706f:7879:0:100:a04::"
	westAddrV4 := "100.64.0.3"
	eastAddrV4 := "100.64.0.4"
	westSlot := "fd61:706f:7879:0:100:900::/88"
	eastSlot := "fd61:706f:7879:0:100:a00::/88"
	// A transit CIDR behind a private network, reachable through either relay
	// when an agent is connected to it from both.
	transit := "fd00:9::/64"
	transitV4 := "192.168.7.0/24"

	type step struct {
		owner   string
		src     string
		srcV4   string
		desired []string
	}
	cases := []struct {
		name    string
		steps   []step
		wantSrc map[string]string
		// wantUnpinned are prefixes the datapath must end up carrying with no
		// preferred source at all.
		wantUnpinned []string
		// wantUnsourced is how many routes went in without a pinned source.
		wantUnsourced int
	}{
		{
			name: "each relay's slot is sourced from this agent's address on it",
			steps: []step{
				{owner: "relay-west", src: westAddr, desired: []string{westSlot}},
				{owner: "relay-east", src: eastAddr, desired: []string{eastSlot}},
			},
			wantSrc: map[string]string{westSlot: westAddr, eastSlot: eastAddr},
		},
		{
			// A session re-dials onto a new connection index; the prefix is
			// unchanged but the address it must be sourced from is not.
			name: "a changed source reprograms the route",
			steps: []step{
				{owner: "relay-west", src: westAddr, desired: []string{westSlot}},
				{owner: "relay-west", src: eastAddr, desired: []string{westSlot}},
			},
			wantSrc: map[string]string{westSlot: eastAddr},
		},
		{
			// A transit CIDR reachable behind exactly one relay is still that
			// relay's to source, even though it is nowhere near its slot.
			name: "a transit CIDR behind a single relay keeps that relay's source",
			steps: []step{
				{owner: "relay-west", src: westAddr, desired: []string{transit}},
			},
			wantSrc: map[string]string{transit: westAddr},
		},
		{
			// The same CIDR advertised by both relays has no one right source:
			// pinning west's address would send traffic that the kernel routed
			// out the east session home from an address east never leased.
			// Unsourced, the kernel's own longest-match pick stands.
			name: "a CIDR both relays advertise goes unsourced",
			steps: []step{
				{owner: "relay-west", src: westAddr, desired: []string{transit}},
				{owner: "relay-east", src: eastAddr, desired: []string{transit}},
			},
			wantUnpinned:  []string{transit},
			wantUnsourced: 1,
		},
		{
			// Order must not decide it: east first reaches the same state.
			name: "a contested prefix goes unsourced regardless of claim order",
			steps: []step{
				{owner: "relay-east", src: eastAddr, desired: []string{transit}},
				{owner: "relay-west", src: westAddr, desired: []string{transit}},
			},
			wantUnpinned:  []string{transit},
			wantUnsourced: 1,
		},
		{
			// Each family is pinned from the session's address in that family.
			// The agent holds a 100.64/10 address on every relay it is connected
			// to, so an unsourced IPv4 route is as free to pick the wrong relay's
			// v4 address as an IPv6 one is to pick the wrong relay's ULA.
			name: "each family is pinned from the session's address in that family",
			steps: []step{
				{owner: "relay-west", src: westAddr, srcV4: westAddrV4, desired: []string{transitV4, westSlot}},
			},
			wantSrc: map[string]string{westSlot: westAddr, transitV4: westAddrV4},
		},
		{
			// A v4 CIDR both relays advertise is contested exactly like a v6 one.
			name: "an IPv4 CIDR both relays advertise goes unsourced",
			steps: []step{
				{owner: "relay-west", src: westAddr, srcV4: westAddrV4, desired: []string{transitV4}},
				{owner: "relay-east", src: eastAddr, srcV4: eastAddrV4, desired: []string{transitV4}},
			},
			wantUnpinned:  []string{transitV4},
			wantUnsourced: 1,
		},
		{
			// A session that never got a v4 address cannot source v4 routes; the
			// v6 address is not a substitute, since the kernel carries the
			// preferred source in the route's own family.
			name: "an IPv4 destination is never pinned to the IPv6 source",
			steps: []step{
				{owner: "relay-west", src: westAddr, desired: []string{"100.65.0.1/32", westSlot}},
			},
			wantSrc:       map[string]string{westSlot: westAddr},
			wantUnpinned:  []string{"100.65.0.1/32"},
			wantUnsourced: 1,
		},
		{
			// initRouter's bootstrap routes have no session behind them yet.
			name: "a claim with no source falls back to an unsourced route",
			steps: []step{
				{owner: "relay-west", desired: []string{westSlot}},
			},
			wantUnsourced: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSourcedRouteTable()
			r := newRouteReconciler(f, nil, nil)
			for _, st := range tc.steps {
				var src routeSource
				if st.src != "" {
					src.v6 = addr(t, st.src)
				}
				if st.srcV4 != "" {
					src.v4 = addr(t, st.srcV4)
				}
				r.Claim(routeOwner(st.owner), src, set(t, st.desired...))
			}
			for dst, want := range tc.wantSrc {
				require.Equal(t, addr(t, want), f.srcs[p(t, dst)],
					"source pinned for %s", dst)
			}
			for _, dst := range tc.wantUnpinned {
				require.NotContains(t, f.srcs, p(t, dst),
					"%s must carry no preferred source", dst)
			}
			require.Equal(t, tc.wantUnsourced, f.unsourced)
		})
	}
}

// TestOverlaySources pins the extraction the whole per-family pinning rests on:
// a session's claim must carry an address in each family it holds, since a route
// is only ever pinned to a source of its own family.
func TestOverlaySources(t *testing.T) {
	cases := []struct {
		name   string
		addrs  []string
		wantV4 string
		wantV6 string
	}{
		{
			name:   "dual stack takes one address of each family",
			addrs:  []string{"fd61:706f:7879:0:100:903::/96", "100.64.0.3/32"},
			wantV4: "100.64.0.3",
			wantV6: "fd61:706f:7879:0:100:903::",
		},
		{
			// Order is the relay's, not ours: v4 first must land the same way.
			name:   "family order does not matter",
			addrs:  []string{"100.64.0.3/32", "fd61:706f:7879:0:100:903::/96"},
			wantV4: "100.64.0.3",
			wantV6: "fd61:706f:7879:0:100:903::",
		},
		{
			name:   "a v6-only session leaves the v4 source unset",
			addrs:  []string{"fd61:706f:7879:0:100:903::/96"},
			wantV6: "fd61:706f:7879:0:100:903::",
		},
		{
			// A 4-in-6 address is an IPv4 address; unmapped, the kernel takes it
			// as the 4-byte preferred source an IPv4 route needs.
			name:   "a 4-in-6 address is unmapped into the v4 slot",
			addrs:  []string{"::ffff:100.64.0.3/128"},
			wantV4: "100.64.0.3",
		},
		{
			// Extra addresses in a family the session already has are ignored:
			// only one can be the preferred source.
			name:   "the first address in each family wins",
			addrs:  []string{"100.64.0.3/32", "100.64.0.9/32"},
			wantV4: "100.64.0.3",
		},
		{name: "no addresses leaves both unset"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addrs := make([]netip.Prefix, 0, len(tc.addrs))
			for _, a := range tc.addrs {
				addrs = append(addrs, p(t, a))
			}
			got := overlaySources(addrs)

			var wantV4, wantV6 netip.Addr
			if tc.wantV4 != "" {
				wantV4 = addr(t, tc.wantV4)
			}
			if tc.wantV6 != "" {
				wantV6 = addr(t, tc.wantV6)
			}
			require.Equal(t, wantV4, got.v4)
			require.Equal(t, wantV6, got.v6)
		})
	}
}

func TestRouteReconciler_ClaimedPrefixesOnlyInstalled(t *testing.T) {
	reconciler, f := rr(t, nil)
	good := p(t, "fd00:1::/64")
	bad := p(t, "fd00:2::/64")
	f.addErr[bad] = fmt.Errorf("netlink: no such device")

	reconciler.Claim("relay-a", routeSource{}, sets.New(good, bad))

	// Only the installed prefix may appear in the report. Consumers rank
	// relay reachability by this set. A claimed prefix with a failed route
	// would advertise a path that drops traffic.
	require.Equal(t, []netip.Prefix{good}, reconciler.ClaimedPrefixes("relay-a"))
	require.Nil(t, reconciler.ClaimedPrefixes("relay-b"))

	// When the failure clears, a periodic Reconcile from the status ticker
	// picks the route up. No claim change is necessary.
	delete(f.addErr, bad)
	reconciler.Reconcile()
	require.ElementsMatch(t, []netip.Prefix{good, bad}, reconciler.ClaimedPrefixes("relay-a"))
}
