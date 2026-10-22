// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
)

// meshRelays returns a new world with two relays of one mesh.
func meshRelays(t *testing.T) (w *world, r1, r2 *testRelay) {
	t.Helper()
	w = newWorld(t)
	w.mesh = true
	r1, r2 = w.relay(t, "relay-1"), w.relay(t, "relay-2")
	joinMesh(t, r1, r2)
	return w, r1, r2
}

// hasRoutes waits until OnRoutes of ta has each prefix of want.
func (ta *testAgent) hasRoutes(t *testing.T, want ...netip.Prefix) {
	t.Helper()
	require.Eventually(t, func() bool {
		got := ta.routeSet()
		return !slices.ContainsFunc(want, func(p netip.Prefix) bool { return !slices.Contains(got, p) })
	}, 5*time.Second, 10*time.Millisecond, "routes %v", want)
}

// relayDrops returns the packets that r dropped, by reason.
func relayDrops(t *testing.T, r *testRelay) map[string]uint64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(r.r))
	families, err := reg.Gather()
	require.NoError(t, err)
	out := map[string]uint64{}
	for _, f := range families {
		if f.GetName() != "apoxy_vpc_relay_dropped_packets_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			if n := uint64(m.GetCounter().GetValue()); n > 0 {
				out[m.GetLabel()[0].GetValue()] = n
			}
		}
	}
	return out
}

// meshDrops returns the drops of relayDrops on the paths between two relays.
// It leaves out trunk_no_row: a first packet can come before its row.
func meshDrops(t *testing.T, relays ...*testRelay) []string {
	t.Helper()
	var out []string
	for _, r := range relays {
		for reason, n := range relayDrops(t, r) {
			if reason != "trunk_no_row" && (strings.HasPrefix(reason, "trunk_") || strings.HasPrefix(reason, "mesh_")) {
				out = append(out, fmt.Sprintf("%s %s %d", r.id, reason, n))
			}
		}
	}
	return out
}

// TestAttachPrefixLimit checks that the agent gets the error of a relay with a
// mesh for an attachment with too many prefixes, and keeps its session.
func TestAttachPrefixLimit(t *testing.T) {
	// The attachment has one address prefix more than its routes.
	const limit = 64
	cases := []struct {
		name    string
		mesh    bool
		routes  int
		refused bool
	}{
		{name: "relay with a mesh, at the limit", mesh: true, routes: limit - 1},
		{name: "relay with a mesh, above the limit", mesh: true, routes: limit, refused: true},
		{name: "relay with no mesh, above the limit", routes: limit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.mesh = tc.mesh
			r := w.relay(t, "relay-1")
			a := w.agent(t, "a", r, agentOptions{})
			a.attached(t)
			spec := AttachmentSpec{Name: "big"}
			for i := range tc.routes {
				spec.Routes = append(spec.Routes, netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", i)))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			rc := a.current()
			_, err := a.a.Attach(ctx, spec)
			if !tc.refused {
				require.NoError(t, err)
				assert.Len(t, a.a.Attachments(), 2)
				return
			}
			require.Equal(t, rpc.InvalidArgument, rpc.CodeOf(err), "error %v", err)
			assert.ErrorContains(t, err, fmt.Sprintf("attachment has %d addresses and routes, and a relay with a mesh takes at most %d", limit+1, limit))
			assert.Len(t, a.a.Attachments(), 1, "the agent keeps no attachment that the relay refused")
			assert.Equal(t, 1, w.addrs.LiveOf(a.ids.Current().ID.String()), "only the base attachment keeps its addresses")
			// The session stays, and takes an attachment that fits.
			spec.Routes = spec.Routes[:1]
			_, err = a.a.Attach(ctx, spec)
			require.NoError(t, err)
			sameSession(t, rc, a.current())
		})
	}
}
