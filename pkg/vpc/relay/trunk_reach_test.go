// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// The reach tests have a caller on the relay of the test, and server on
// relay-a, which the test plays, with the attachment x and the tag inTag.
const (
	reachSocket = "192.0.2.31:1"
	reachNet    = "fd00:31::/96"
)

// reachCaller is the caller of a reach test.
type reachCaller struct {
	rev    uint32 // Revision in its Hello. Zero is an agent from before revisions.
	mode   dp.Mode
	local  bool // Its Hello has local_routes_only.
	noSync bool // It has no Session call.
	spare  bool // It has no attachment, and so no sender tag.
}

// caller adds the session of c to the relay.
func (g *rowRig) caller(c reachCaller) *Session {
	g.t.Helper()
	ap := netip.MustParseAddrPort(reachSocket)
	s := newSession(Identity{VPC: vpcA, ID: agentID(vpcA, "caller")}, func() netip.AddrPort { return ap })
	if c.rev > 0 {
		s.version = &dp.Version{Revision: c.rev}
	}
	g.r.addSession(s, time.Now())
	if !c.noSync {
		require.NoError(g.t, g.r.openSync(s, c.mode, ref(vpcA), &dp.Hello{LocalRoutesOnly: c.local}))
	}
	if !c.spare {
		require.NoError(g.t, g.r.attach(s, attachment("att-caller", reachNet)))
	}
	return s
}

// resolve returns the ResolvePeer answer of the relay to s for dst.
func (g *rowRig) resolve(s *Session, dst string) (*dp.ResolvePeerResponse, error) {
	return g.r.resolvePeer(s, &dp.ResolvePeerRequest{Vpc: ref(vpcA), Address: dst})
}

// TestResolvePeerTrunk checks the ResolvePeer answer for an address of server on
// relay-a, by the state of the caller, of relay-a and of the trunk to it.
func TestResolvePeerTrunk(t *testing.T) {
	// The numbers are those of the README: an agent gets the answer from revision 10.
	this := reachCaller{rev: 10, mode: dp.Mode_MODE_PSP}
	quicMode := reachCaller{rev: 10, mode: dp.Mode_MODE_QUIC}
	// at returns a link at revision rev with keys in both directions.
	at := func(rev uint32) func(*testing.T, *rowRig) {
		return func(_ *testing.T, g *rowRig) { g.link(rev) }
	}
	cases := []struct {
		name   string
		caller reachCaller
		link   func(t *testing.T, g *rowRig) // Nil is a link at the revision of this build.
		setup  func(t *testing.T, g *rowRig) // Runs after the link.
		first  bool                          // Before the setup, the answer is REACH_TRUNK.
		dst    string                        // Empty is the address of server.
		want   dp.Reach                      // Zero is no answer.
		code   rpc.Code                      // Error code with no answer. Zero is NotFound.
		ids    []string                      // Attachments in the answer. Nil is x.
	}{
		{name: "PSP-mode agent", caller: this, want: dp.Reach_REACH_TRUNK},
		{name: "QUIC-mode agent", caller: quicMode, want: dp.Reach_REACH_TRUNK},
		{name: "IPv4 address in a route of server", caller: this, dst: brServer4, want: dp.Reach_REACH_TRUNK},
		{name: "agent of a later revision", caller: reachCaller{rev: 11, mode: dp.Mode_MODE_PSP}, want: dp.Reach_REACH_TRUNK},

		{name: "agent one revision before", caller: reachCaller{rev: 9, mode: dp.Mode_MODE_PSP}},
		{name: "QUIC-mode agent one revision before", caller: reachCaller{rev: 9, mode: dp.Mode_MODE_QUIC}},
		{name: "agent from before revisions", caller: reachCaller{mode: dp.Mode_MODE_PSP}},
		{name: "agent with local routes only", caller: reachCaller{rev: 10, mode: dp.Mode_MODE_PSP, local: true}},
		{name: "agent with no Session call", caller: reachCaller{rev: 10, noSync: true}},
		{name: "session with no attachment", caller: reachCaller{rev: 10, mode: dp.Mode_MODE_PSP, spare: true}},

		{name: "relay at the bridge revision, PSP-mode agent", caller: this, link: at(trunkBridgeRevision), want: dp.Reach_REACH_TRUNK},
		{name: "relay at the bridge revision, QUIC-mode agent", caller: quicMode, link: at(trunkBridgeRevision), want: dp.Reach_REACH_TRUNK},
		{name: "relay at the row revision, PSP-mode agent", caller: this, link: at(trunkRowsRevision)},
		{name: "relay at the row revision, QUIC-mode agent", caller: quicMode, link: at(trunkRowsRevision)},
		{name: "relay at the frame revision", caller: this, link: at(meshFramesRevision)},

		{
			name: "no keys of relay-a", caller: this,
			link: func(_ *testing.T, g *rowRig) {
				g.join(dp.Revision)
				g.tellServer(10)
			},
		},
		{
			name: "relay-a did not take the keys of this relay", caller: this,
			link: func(t *testing.T, g *rowRig) {
				g.before = func(int, keys.Request) error { return errors.New("not now") }
				_, err := g.offer(g.join(dp.Revision))
				require.NoError(t, err)
				g.tellServer(10)
			},
		},
		{
			name: "keys and no answer to the probe", caller: this, want: dp.Reach_REACH_TRUNK,
			link: func(t *testing.T, g *rowRig) {
				_, err := g.offer(g.join(dp.Revision))
				require.NoError(t, err)
				g.tellServer(10)
			},
		},
		{
			name: "limited path", caller: this, want: dp.Reach_REACH_TRUNK,
			link: func(t *testing.T, g *rowRig) {
				_, err := g.offer(g.join(dp.Revision))
				require.NoError(t, err)
				g.tellServer(10)
				time.Sleep(trunkProbeWait)
				synctest.Wait()
				require.Equal(t, trunkPathLimited, trunkPath(g.pair.path.Load()))
			},
		},
		{name: "relay-a revoked its lane 0 SA", caller: this, first: true, setup: func(_ *testing.T, g *rowRig) { g.revoke(trunkLanePSP) }},
		{name: "relay-a revoked its lane 1 SA", caller: this, first: true, setup: func(_ *testing.T, g *rowRig) { g.revoke(trunkLaneInner) }},
		{
			name: "session of relay-a ended, and relay-a is still up", caller: this, first: true,
			setup: func(t *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				require.True(t, g.m.Up("relay-a"))
				require.NotNil(t, g.pair.tx.SA(trunkLaneInner), "the keys stay")
			},
		},
		{
			// The trunk can see the end a moment later than the connection.
			name: "connection of relay-a closed just now", caller: this, first: true,
			setup: func(_ *testing.T, g *rowRig) { g.stubs[g.sess].cancel(meshLost) },
		},
		{
			name: "relay-a is lost", caller: this, first: true,
			setup: func(t *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				time.Sleep(meshDownAfter)
				g.deliver()
				require.False(t, g.m.Up("relay-a"))
				// The address of server keeps its route.
				g.r.mu.RLock()
				defer g.r.mu.RUnlock()
				require.Equal(t, "relay-a", g.r.lookup(vpcA, netip.MustParseAddr(brServer)).home)
			},
		},
		{
			name: "new session of relay-a with no keys", caller: this, first: true,
			setup: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				g.join(dp.Revision)
			},
		},
		{
			name: "new session of relay-a with keys", caller: this, first: true, want: dp.Reach_REACH_TRUNK,
			setup: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				g.keyed(g.join(dp.Revision))
				g.tellServer(10)
			},
		},
		{
			name: "new session of relay-a at the row revision", caller: this, first: true,
			setup: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				g.keyed(g.join(trunkRowsRevision))
				g.tellServer(10)
			},
		},

		{
			name: "Permit denies the address", caller: this, first: true, code: rpc.PermissionDenied,
			setup: func(_ *testing.T, g *rowRig) { g.r.SetPermit(denyAll) },
		},
		{name: "address with no route", caller: this, dst: "fd00:f::1"},
		{name: "address of an agent of this relay", caller: this, dst: "fd00:1::1", want: dp.Reach_REACH_LOCAL, ids: []string{"att-" + rowSrc}},
		{name: "address of an agent of this relay, agent one revision before", caller: reachCaller{rev: 9, mode: dp.Mode_MODE_PSP}, dst: "fd00:1::1", want: dp.Reach_REACH_LOCAL, ids: []string{"att-" + rowSrc}},
		{
			// The entries y and z come first, and the answer has the order of the generations.
			name: "server has three attachments", caller: this, ids: []string{"x", "y", "z"}, want: dp.Reach_REACH_TRUNK,
			setup: func(_ *testing.T, g *rowRig) {
				g.announce(atGen(liveEntry("z", server, "", inTag, "fd00:b2::/96"), 12), atGen(liveEntry("y", server, "", inTag, "fd00:b1::/96"), 11))
			},
		},
		{
			name: "address of the second attachment of server", caller: this, dst: "fd00:b1::1", ids: []string{"x", "y"}, want: dp.Reach_REACH_TRUNK,
			setup: func(_ *testing.T, g *rowRig) {
				g.announce(atGen(liveEntry("y", server, "", inTag, "fd00:b1::/96"), 11))
			},
		},
		{
			name: "other sessions on relay-a", caller: this, want: dp.Reach_REACH_TRUNK,
			setup: func(_ *testing.T, g *rowRig) {
				g.announce(
					// Another session of the subject, a named agent of the subject, and another subject.
					atGen(liveEntry("s2", server, "", inTag+1, "fd00:b1::/96"), 11),
					atGen(liveEntry("named", server, "base", inTag, "fd00:b2::/96"), 12),
					atGen(liveEntry("other", agentID(vpcA, "other"), "", inTag, "fd00:b3::/96"), 13),
				)
			},
		},
		{
			name: "address of a named agent with the subject of server", caller: this, dst: "fd00:b2::1", ids: []string{"named"}, want: dp.Reach_REACH_TRUNK,
			setup: func(_ *testing.T, g *rowRig) {
				g.announce(atGen(liveEntry("named", server, "base", inTag, "fd00:b2::/96"), 12))
			},
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				c := g.caller(tc.caller)
				dst := tc.dst
				if dst == "" {
					dst = brServer
				}
				if tc.link == nil {
					g.link(dp.Revision)
				} else {
					tc.link(t, g)
				}
				if tc.first {
					res, err := g.resolve(c, dst)
					require.NoError(t, err)
					require.Equal(t, dp.Reach_REACH_TRUNK, res.GetReach())
				}
				if tc.setup != nil {
					tc.setup(t, g)
				}
				res, err := g.resolve(c, dst)
				if tc.want == dp.Reach_REACH_UNSPECIFIED {
					code := tc.code
					if code == 0 {
						code = rpc.NotFound
					}
					require.Equal(t, code, rpc.CodeOf(err), "answer %v, error %v", res, err)
					if code == rpc.NotFound {
						// The error is the same as for an address with no route.
						assert.ErrorContains(t, err, "no route to "+dst)
					}
					assert.Nil(t, res)
					assert.Empty(t, noRoutes(g.r, c), "NoRoute messages of the caller")
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tc.want, res.GetReach())
				ids := tc.ids
				if ids == nil {
					ids = []string{"x"}
				}
				assert.Equal(t, ids, res.GetAttachmentIds())
				assert.Nil(t, res.GetHomeRelay())
				if tc.want == dp.Reach_REACH_LOCAL {
					assert.Equal(t, laptop, res.GetSubject())
					assert.True(t, res.GetP2P())
					return
				}
				assert.Equal(t, server, res.GetSubject())
				assert.False(t, res.GetP2P(), "a peer on another relay has no direct path")
				// The agent registers its SPIs for the address that it asked for.
				g.laptop = c
				require.NoError(t, g.register(dst, rowTTL, 5))
			})
		})
	}
}

// TestRouteOfOtherRelayNoRoute checks that Route gives no session and sends no
// NoRoute for an address with a route of another relay.
func TestRouteOfOtherRelayNoRoute(t *testing.T) {
	cases := []struct {
		name    string
		dst     string
		noRoute bool
	}{
		{name: "address of server on relay-a", dst: brServer},
		{name: "address with no route", dst: "fd00:f::1", noRoute: true},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				g.link(dp.Revision)
				g.r.takeSync(g.laptop)
				assert.Nil(t, g.r.Route(g.laptop, netip.MustParseAddr(tc.dst), time.Now()))
				var want []string
				if tc.noRoute {
					want = []string{tc.dst}
				}
				assert.Equal(t, want, noRoutes(g.r, g.laptop))
			})
		})
	}
}

// TestAttachPrefixLimit checks that a relay with a mesh refuses an attachment
// with more prefixes than the other relays keep of one entry.
func TestAttachPrefixLimit(t *testing.T) {
	cases := []struct {
		name      string
		mesh      bool
		addresses int
		routes    int
		refused   bool
	}{
		{name: "mesh, at the limit", mesh: true, addresses: 1, routes: maxEntryPrefixes - 1},
		{name: "mesh, one route above the limit", mesh: true, addresses: 1, routes: maxEntryPrefixes, refused: true},
		{name: "mesh, one address above the limit", mesh: true, addresses: 2, routes: maxEntryPrefixes - 1, refused: true},
		{name: "mesh, only addresses above the limit", mesh: true, addresses: maxEntryPrefixes + 1, refused: true},
		{name: "no mesh, above the limit", addresses: 1, routes: maxEntryPrefixes},
		{name: "no mesh, far above the limit", addresses: 2, routes: 4 * maxEntryPrefixes},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := localRouter(t)
			var sent []*dp.Presence
			if tc.mesh {
				m, err := NewMesh("relay-m", cfg)
				require.NoError(t, err)
				m.SetRouter(r)
				// The test reads the entries that the mesh gets.
				r.mu.Lock()
				announce := r.presence
				r.presence = func(e *dp.Presence) {
					sent = append(sent, e)
					announce(e)
				}
				r.mu.Unlock()
			}
			ap := netip.MustParseAddrPort(reachSocket)
			s := newSession(Identity{VPC: vpcA, ID: laptop}, func() netip.AddrPort { return ap })
			r.addSession(s, time.Now())
			require.NoError(t, r.openSync(s, dp.Mode_MODE_PSP, ref(vpcA), nil))
			a := attachment("big")
			for i := range tc.addresses {
				a.Addresses = append(a.Addresses, netip.MustParsePrefix(fmt.Sprintf("fd00:31:%x::/96", i)))
			}
			for i := range tc.routes {
				a.Routes = append(a.Routes, netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", i)))
			}
			err := r.attach(s, a)
			r.mu.RLock()
			defer r.mu.RUnlock()
			if !tc.refused {
				require.NoError(t, err)
				assert.Len(t, s.routes, tc.addresses+tc.routes)
				if tc.mesh {
					require.Len(t, sent, 1)
					// The other relays take the entry.
					_, err := checkPresence(sent[0])
					assert.NoError(t, err)
				}
				return
			}
			require.Equal(t, rpc.InvalidArgument, rpc.CodeOf(err), "error %v", err)
			assert.ErrorContains(t, err, fmt.Sprintf("attachment has %d addresses and routes, and a relay with a mesh takes at most %d", tc.addresses+tc.routes, maxEntryPrefixes))
			// A refused attach changes nothing.
			assert.Empty(t, s.attachments)
			assert.Empty(t, s.routes)
			assert.Zero(t, s.tag)
			assert.Empty(t, sent)
		})
	}
}
