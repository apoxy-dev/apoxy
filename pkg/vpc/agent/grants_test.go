// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
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

// routedIn reports whether the binding of a routes pfx to a peer.
func routedIn(t *testing.T, a *Agent, pfx string) bool {
	t.Helper()
	other, err := a.bind.AddPeer(netip.MustParseAddrPort("127.0.0.1:445"))
	require.NoError(t, err)
	defer a.bind.RemovePeer(other)
	p := netip.MustParsePrefix(pfx)
	err = a.bind.AddRoute(p, other)
	if err == nil {
		a.bind.RemoveRoute(p, other)
	}
	return errors.Is(err, engine.ErrRouteTaken)
}

func TestAddGrants(t *testing.T) {
	w := newWorld(t)
	cert := w.relayCA.relayCert(t, "relay-1")
	const b2 = "fd00:b2::/96"
	cases := []struct {
		name     string
		mode     dp.Mode // Of the peer session.
		grants   func(t *testing.T) []*dp.AttachmentGrant
		taken    bool // Another peer routes b2.
		wantText string
		want     []string // Attachment IDs in p.extra.
	}{
		{
			name: "good",
			grants: func(t *testing.T) []*dp.AttachmentGrant {
				return []*dp.AttachmentGrant{extraGrant(t, cert, "b", "b-2", b2, nil)}
			},
			want: []string{"b-2"},
		},
		{
			name: "QUIC pair",
			mode: dp.Mode_MODE_QUIC,
			grants: func(t *testing.T) []*dp.AttachmentGrant {
				return []*dp.AttachmentGrant{extraGrant(t, cert, "b", "b-2", b2, nil)}
			},
			want: []string{"b-2"},
		},
		{
			name: "same grant twice",
			grants: func(t *testing.T) []*dp.AttachmentGrant {
				g := extraGrant(t, cert, "b", "b-2", b2, nil)
				return []*dp.AttachmentGrant{g, g}
			},
			want: []string{"b-2"},
		},
		{
			name: "grant of the attachment of Open",
			grants: func(t *testing.T) []*dp.AttachmentGrant {
				return []*dp.AttachmentGrant{signGrant(t, cert, "b", "fd00:b::/96")}
			},
		},
		{
			name: "other subject",
			grants: func(t *testing.T) []*dp.AttachmentGrant {
				return []*dp.AttachmentGrant{extraGrant(t, cert, "c", "c-2", b2, nil), extraGrant(t, cert, "b", "b-3", "fd00:b3::/96", nil)}
			},
			wantText: "not for the peer cert",
			want:     []string{"b-3"},
		},
		{
			name: "other VPC",
			grants: func(t *testing.T) []*dp.AttachmentGrant {
				return []*dp.AttachmentGrant{extraGrant(t, cert, "b", "b-2", b2, func(c *dp.GrantClaims) { c.Vpc.VpcUid = "vpc-2" })}
			},
			wantText: "another VPC",
		},
		{
			name: "route taken",
			grants: func(t *testing.T) []*dp.AttachmentGrant {
				return []*dp.AttachmentGrant{extraGrant(t, cert, "b", "b-2", b2, nil)}
			},
			taken:    true,
			wantText: engine.ErrRouteTaken.Error(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := w.stubAgent(t, "a")
			if tc.taken {
				bp, err := a.bind.AddPeer(netip.MustParseAddrPort("127.0.0.1:446"))
				require.NoError(t, err)
				require.NoError(t, a.bind.AddRoute(netip.MustParsePrefix(b2), bp))
			}
			p, _ := stubPeer(a, "b", true)
			mode := dp.Mode_MODE_PSP
			if tc.mode != dp.Mode_MODE_UNSPECIFIED {
				mode = tc.mode
			}
			require.NoError(t, a.admit(p, nil, signGrant(t, cert, "b", "fd00:b::/96"), 7, mode, 1))

			err := a.addGrants(p, tc.grants(t))
			if tc.wantText != "" {
				assert.ErrorContains(t, err, tc.wantText)
			} else {
				assert.NoError(t, err)
			}
			a.mu.Lock()
			got := slices.Sorted(maps.Keys(p.extra))
			a.mu.Unlock()
			assert.Equal(t, tc.want, got)
			if slices.Contains(tc.want, "b-2") {
				assert.True(t, routedIn(t, a, b2))
				assert.True(t, p.routes(netip.MustParseAddr("fd00:b2::1")))
				assert.True(t, p.origin("b-2"))
			}

			// A remove of an ID that p does not hold does nothing.
			a.removeGrants(p, append(slices.Clone(tc.want), "unknown"))
			assert.Empty(t, p.extra)
			assert.Equal(t, tc.taken, routedIn(t, a, b2), "only the other peer keeps the route")
			assert.True(t, routedIn(t, a, "fd00:b::/96"), "the grant of Open stays")
		})
	}
}

func TestWaitGrant(t *testing.T) {
	w := newWorld(t)
	cert := w.relayCA.relayCert(t, "relay-1")
	dst := netip.MustParseAddr("fd00:b2::1")
	// The open session with b has the attachment "attachment-b".
	cases := []struct {
		name    string
		relay   func() *dp.Version // Nil means a relay of this build.
		subject string             // From ResolvePeer.
		ids     []string           // Attachment IDs from ResolvePeer. A relay of revision 1 gives none.
		grant   bool               // The grant of b-2 comes after 50 ms.
		want    bool               // waitGrant returns the session with b.
	}{
		{name: "grant comes late", subject: "b", ids: []string{"attachment-b", "b-2"}, grant: true, want: true},
		{name: "grant does not come", subject: "b", ids: []string{"attachment-b", "b-2"}},
		{name: "no session with the subject", subject: "c", ids: []string{"attachment-c"}, grant: true},
		{name: "no subject", grant: true},
		// Another agent with the subject of b has the address. Its grant never comes on the session with b.
		{name: "other agent of the subject", subject: "b", ids: []string{"attachment-b9"}, grant: true},
		{name: "no attachments in the answer", subject: "b", grant: true},
		// A relay of revision 1 gives only the subject, so the agent waits as before.
		{name: "relay of revision 1, grant comes late", relay: revision1, subject: "b", grant: true, want: true},
		{name: "relay of revision 1, grant does not come", relay: revision1, subject: "b"},
		{name: "relay of revision 1, no session with the subject", relay: revision1, subject: "c", grant: true},
		{name: "relay from before revisions, grant comes late", relay: beforeRevisions, subject: "b", grant: true, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := w.stubAgent(t, "a")
			a.rc.version = dp.LocalVersion("relay")
			if tc.relay != nil {
				a.rc.version = tc.relay()
			}
			p, _ := stubPeer(a, "b", true)
			require.NoError(t, a.admit(p, nil, signGrant(t, cert, "b", "fd00:b::/96"), 7, dp.Mode_MODE_PSP, 1))
			if tc.grant {
				g := extraGrant(t, cert, "b", "b-2", "fd00:b2::/96", nil)
				added := make(chan error, 1)
				time.AfterFunc(50*time.Millisecond, func() { added <- a.addGrants(p, []*dp.AttachmentGrant{g}) })
				t.Cleanup(func() { assert.NoError(t, <-added) })
			}
			res := &dp.ResolvePeerResponse{Reach: dp.Reach_REACH_LOCAL, AttachmentIds: tc.ids}
			if tc.subject != "" {
				res.Subject = identity.ID{Project: testProject, VPC: testVPC, Agent: tc.subject}.String()
			}
			// The context ends the wait of the case with no grant before duplicateWait.
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			start := time.Now()
			got := a.waitGrant(ctx, a.rc, dst, res)
			if tc.want {
				assert.Same(t, p, got)
			} else {
				assert.Nil(t, got)
			}
			if !tc.grant || tc.want {
				return
			}
			assert.Less(t, time.Since(start), 50*time.Millisecond, "no wait with no session to wait on")
		})
	}
}

func TestQueueGrants(t *testing.T) {
	x := func(id string) *extra { return &extra{id: id, grant: &dp.AttachmentGrant{Signature: []byte(id)}} }
	type op struct {
		add    string
		remove string
	}
	cases := []struct {
		name       string
		noGrants   bool // The peer does not serve Grants.
		ops        []op
		wantAdd    []string
		wantRemove []string
	}{
		{name: "add", ops: []op{{add: "x"}, {add: "y"}}, wantAdd: []string{"x", "y"}},
		{name: "remove", ops: []op{{remove: "x"}}, wantRemove: []string{"x"}},
		// The peer can have x from Open.
		{name: "add then remove", ops: []op{{add: "x"}, {remove: "x"}}, wantRemove: []string{"x"}},
		{name: "remove then add", ops: []op{{remove: "x"}, {add: "x"}}, wantAdd: []string{"x"}},
		{name: "peer with no Grants call", noGrants: true, ops: []op{{add: "x"}, {remove: "y"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &peer{sending: true, noGrants: tc.noGrants} // No sender starts.
			for _, o := range tc.ops {
				if o.add != "" {
					p.queueGrants(x(o.add), "")
				} else {
					p.queueGrants(nil, o.remove)
				}
			}
			assert.Equal(t, tc.wantAdd, sortedKeys(p.sendAdd))
			assert.Equal(t, tc.wantRemove, sortedKeys(p.sendRemove))
		})
	}
}

func sortedKeys[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(m))
}

// TestRemoveRoutesOfExtra checks that a peer session stays when another
// attachment of the peer leaves, and closes when the attachment of Open leaves.
func TestRemoveRoutesOfExtra(t *testing.T) {
	w := newWorld(t)
	cert := w.relayCA.relayCert(t, "relay-1")
	a := w.stubAgent(t, "a")
	p, qc := stubPeer(a, "b", true)
	require.NoError(t, a.admit(p, nil, signGrant(t, cert, "b", "fd00:b::/96"), 7, dp.Mode_MODE_PSP, 1))
	require.NoError(t, a.addGrants(p, []*dp.AttachmentGrant{extraGrant(t, cert, "b", "b-2", "fd00:b2::/96", nil)}))

	// Another origin that takes a prefix does not end the grant.
	a.removeRoutes(a.rc, []*dp.Route{{Prefix: "10.0.0.0/8", Origin: "b-2"}})
	assert.True(t, p.origin("b-2"))
	a.removeRoutes(a.rc, []*dp.Route{{Prefix: "fd00:b2::/96", Origin: "b-2"}})
	assert.False(t, p.origin("b-2"))
	assert.False(t, routedIn(t, a, "fd00:b2::/96"))
	assert.False(t, qc.closed())

	a.removeRoutes(a.rc, []*dp.Route{{Prefix: "fd00:b::/96", Origin: "attachment-b"}})
	assert.True(t, qc.closed())
}

// TestExtraAttachments sends UDP to and from another attachment of agent a,
// on the peer session of the attachment of Config.
func TestExtraAttachments(t *testing.T) {
	cases := []struct {
		name   string
		mode   TransportMode
		before bool // a attaches the extra before the peer session opens.
		aDials bool // a dials the peer session, else b.
	}{
		{name: "PSP, extra after Open"},
		{name: "PSP, extra in the Open answer", before: true},
		{name: "PSP, extra in the Open call", before: true, aDials: true},
		{name: "QUIC, extra after Open", mode: TransportQUIC},
		{name: "QUIC, extra in the Open answer", mode: TransportQUIC, before: true},
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
			if tc.aDials {
				ping(t, a.stack, ea.addr, eb.addr, 9001, "to b")
			} else {
				ping(t, b.stack, eb.addr, ea.addr, 9000, "to a")
			}
			pa, pb := onlyPeer(t, a.a), onlyPeer(t, b.a)
			if !tc.before {
				attach()
			}
			ping(t, b.stack, eb.addr, x.Address, 9002, "to a-2")
			ping(t, a.stack, x.Address, eb.addr, 9001, "from a-2")
			assert.Same(t, pa, onlyPeer(t, a.a), "a keeps its peer session")
			assert.Same(t, pb, onlyPeer(t, b.a), "b keeps its peer session")
			assert.Contains(t, b.routeSet(), x.Prefixes[0], "OnRoutes of b has the routes of a")
			assert.NotContains(t, a.routeSet(), x.Prefixes[0], "OnRoutes of a has no routes of a")

			// After a detaches the extra, b drops its routes and keeps the session.
			require.NoError(t, a.a.Detach(ctx, "a-2"))
			assert.Equal(t, []string{"attach a-2 " + x.Address.String(), "detach a-2 " + x.Address.String()}, a.events("a-2"))
			require.Eventually(t, func() bool { return !slices.Contains(b.routeSet(), x.Prefixes[0]) },
				5*time.Second, 10*time.Millisecond, "the relay removes the route of a-2")
			require.Eventually(t, func() bool {
				b.a.mu.Lock()
				defer b.a.mu.Unlock()
				return !pb.origin(x.ID)
			}, 5*time.Second, 10*time.Millisecond, "b removes the grant of a-2")
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to a again")
			assert.Same(t, pb, onlyPeer(t, b.a), "b keeps its peer session")
		})
	}
}

// onlyPeer returns the one peer session of a.
func onlyPeer(t *testing.T, a *Agent) *peer {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	require.Len(t, a.peers, 1)
	for _, p := range a.peers {
		return p
	}
	return nil
}
