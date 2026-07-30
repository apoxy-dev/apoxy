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
	for dst := range installed {
		f.routes.Insert(dst)
	}
	return newRouteReconciler(f, nil, installed.Clone()), f
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
				r.Claim(routeOwner(st.owner), set(t, st.desired...))
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

	r.Claim("relay-a", want)
	require.Len(t, f.adds, 2)
	require.Empty(t, f.dels)

	r.Claim("relay-a", want.Clone())
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

	r.Claim("relay-a", set(t, "10.0.0.0/24"))
	require.Empty(t, f.routes)
	require.Equal(t, 1, f.addSeen)

	// Same claim again: because the failure was not recorded as installed, the
	// reconciler tries once more. Now it succeeds.
	delete(f.addErr, boom)
	r.Claim("relay-b", set(t, "10.0.0.0/24"))
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
			r.Claim("relay-a", set(t, "0.0.0.0/0", "10.0.0.0/24"))
			require.Equal(t, set(t, tc.want...), f.routes)
		})
	}
}
