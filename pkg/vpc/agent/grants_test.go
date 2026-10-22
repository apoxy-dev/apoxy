// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"context"
	"crypto/tls"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// extraGrant returns a grant on relay-1 of attachment id for the agent called name.
func extraGrant(t *testing.T, cert *tls.Certificate, name, id, prefix string, change func(*dp.GrantClaims)) *dp.AttachmentGrant {
	t.Helper()
	c := &dp.GrantClaims{
		Vpc:          &dp.VPCRef{ProjectId: testProject, VpcUid: testVPC, NetworkId: testVNI},
		AttachmentId: id,
		Subject:      identity.ID{Project: testProject, VPC: testVPC, Agent: name}.String(),
		Addresses:    []string{prefix},
		RelayId:      "relay-1",
		NotAfter:     timestamppb.New(time.Now().Add(time.Hour)),
	}
	if change != nil {
		change(c)
	}
	g, err := relay.SignGrant(cert, c)
	require.NoError(t, err)
	return g
}

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

// grantClient is a relay client that answers Grant with a new grant.
type grantClient struct {
	dp.RelayClient
	t     *testing.T
	cert  *tls.Certificate
	calls atomic.Int32
}

func (c *grantClient) Grant(_ context.Context, in *dp.GrantRequest) (*dp.GrantResponse, error) {
	c.calls.Add(1)
	return &dp.GrantResponse{Grant: extraGrant(c.t, c.cert, "a", in.GetAttachmentId(), "fd00:a::/96", nil)}, nil
}

// TestOwnGrant checks that the agent asks its relay for a new grant only at the
// refresh age, by its own elapsed time.
func TestOwnGrant(t *testing.T) {
	cases := []struct {
		name    string
		age     time.Duration // Time since the agent got the stored grant.
		left    time.Duration // If set, the stored grant ends this long after the time of the host.
		wantNew bool
	}{
		{name: "new grant"},
		{name: "below the refresh age", age: grantRefreshAge - 10*time.Second},
		{name: "above the refresh age", age: grantRefreshAge + time.Second, wantNew: true},
		// The end time of a new grant is 3 minutes nearer on a host with such a clock.
		{name: "host clock 3 minutes ahead of the relay", left: grantRefreshAge},
		{name: "host clock ahead, above the refresh age", age: grantRefreshAge + time.Second, left: time.Minute, wantNew: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			cert := w.relayCA.relayCert(t, "relay-1")
			left := cmp.Or(tc.left, time.Hour)
			stored := extraGrant(t, cert, "a", "attachment-a", "fd00:a::/96",
				func(c *dp.GrantClaims) { c.NotAfter = timestamppb.New(time.Now().Add(left)) })
			g := ownGrant{id: "attachment-a", cur: stored, got: time.Now().Add(-tc.age)}
			c := &grantClient{t: t, cert: cert}
			got, err := g.get(context.Background(), c, "192.0.2.1:443", w.relayCA.Pool())
			require.NoError(t, err)
			if !tc.wantNew {
				assert.Same(t, stored, got, "the agent made a Grant call below the refresh age")
				assert.Zero(t, c.calls.Load())
				return
			}
			assert.NotSame(t, stored, got, "the agent made no Grant call")
			assert.Equal(t, int32(1), c.calls.Load())
			claims, err := relay.VerifyGrant(got, w.relayCA.Pool(), time.Now())
			require.NoError(t, err)
			assert.Equal(t, "attachment-a", claims.GetAttachmentId())
		})
	}
}
