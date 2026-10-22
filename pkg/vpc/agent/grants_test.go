// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtraAttachments sends UDP to and from another attachment of agent a.
func TestExtraAttachments(t *testing.T) {
	cases := []struct {
		name   string
		mode   TransportMode
		before bool // a attaches the extra before the first packet.
	}{
		{name: "PSP, extra after the first packet"},
		{name: "PSP, extra before the first packet", before: true},
		{name: "QUIC, extra after the first packet", mode: TransportQUIC},
		{name: "QUIC, extra before the first packet", mode: TransportQUIC, before: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			a, b := w.agent(t, "a", r, agentOptions{mode: tc.mode}), w.agent(t, "b", r, agentOptions{})
			ea, eb := a.attached(t), b.attached(t)
			echo(t, a.stack, ea.addr, 9000)
			echo(t, b.stack, eb.addr, 9001)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var x Attachment
			attach := func() {
				var err error
				x, err = a.a.Attach(ctx, AttachmentSpec{Name: "a-2"})
				require.NoError(t, err)
				echo(t, a.stack, x.Address, 9002)
			}
			if tc.before {
				attach()
			}
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to a")
			if !tc.before {
				attach()
			}
			ping(t, b.stack, eb.addr, x.Address, 9002, "to a-2")
			ping(t, a.stack, x.Address, eb.addr, 9001, "from a-2")
			// The route of a-2 comes from the relay and can come later.
			require.Eventually(t, func() bool { return slices.Contains(b.routeSet(), x.Prefixes[0]) },
				5*time.Second, 10*time.Millisecond, "OnRoutes of b has the routes of a")
			assert.NotContains(t, a.routeSet(), x.Prefixes[0], "OnRoutes of a has no routes of a")

			// After a detaches the extra, b drops its routes, and the base stays.
			require.NoError(t, a.a.Detach(ctx, "a-2"))
			assert.Equal(t, []string{"attach a-2 " + x.Address.String(), "detach a-2 " + x.Address.String()}, a.events("a-2"))
			require.Eventually(t, func() bool { return !slices.Contains(b.routeSet(), x.Prefixes[0]) },
				5*time.Second, 10*time.Millisecond, "the relay removes the route of a-2")
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to a again")
		})
	}
}
