// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// The visit tests use the rig of the reach tests: a caller on the relay of the
// test, relay-m, and server on relay-a, which gives visitRefA in Open.
const (
	visitCallerAddr = "fd00:31::1" // Address of the caller, in reachNet.
	visitNoRoute    = "fd00:f::1"  // Address with no route.
)

var (
	visitRefA = &dp.RelayRef{Id: "relay-a.example", Addresses: []string{"192.0.2.1:443"}}
	visitRefB = &dp.RelayRef{Id: "relay-b.example", Addresses: []string{"192.0.2.2:443"}}
	visitAddr = netip.MustParseAddrPort("192.0.2.2:6081") // Mesh address of relay-b.
)

// member adds relay-b with a session that gives ref in Open. relay-b takes no keys.
func (g *rowRig) member(ref *dp.RelayRef) *MeshSession {
	g.t.Helper()
	g.m.SetMembers([]MeshMember{{Name: "relay-a", Addr: trunkRigAddr}, {Name: "relay-b", Addr: visitAddr}})
	conn := newStubConn()
	s := g.m.newSession(movedConn{conn, visitAddr}, false)
	g.stubs[s] = conn
	s.client = trunkClient{
		keys: func(*dp.KeysRequest) (*dp.KeysResponse, error) { return nil, rpc.Errorf(rpc.Unavailable, "not now") },
		rows: func() (rowStream, error) { return nil, rpc.Errorf(rpc.Unimplemented, "no SPIRows call") },
	}
	require.True(g.t, g.m.track(s))
	require.NoError(g.t, g.m.admit(s, "relay-b", nil, &dp.Version{Revision: dp.Revision}, ref))
	g.deliver()
	return s
}

// pspSender adds a PSP-mode agent at revision rev, with an attachment that has
// brPNet. It takes the relay SAs, and gives no SA.
func (g *rowRig) pspSender(rev uint32) *bridgeEnd {
	g.t.Helper()
	e := &bridgeEnd{socket: netip.MustParseAddrPort(brPSocket)}
	e.s = newSession(Identity{VPC: vpcA, ID: agentID(vpcA, "p")}, func() netip.AddrPort { return e.socket })
	e.s.version = &dp.Version{Revision: rev}
	g.r.addSession(e.s, time.Now())
	require.NoError(g.t, g.r.openSync(e.s, dp.Mode_MODE_PSP, ref(vpcA), nil))
	require.NoError(g.t, g.r.attach(e.s, attachment("att-p", brPNet)))
	offer, err := g.r.offer(e.s, Network{ID: testVNI, MTU: 1280}, time.Now())
	require.NoError(g.t, err)
	e.psp = newPSPAgent(g.t, offer.GetRekey(), time.Now())
	return e
}

// lose ends the session s with cause, and waits for d on the fake clock.
func (g *rowRig) lose(s *MeshSession, cause error, d time.Duration) {
	g.end(s, cause)
	time.Sleep(d)
	g.deliver()
}

// noRouteMsgs returns the NoRoute messages that wait for s.
func noRouteMsgs(r *Router, s *Session) []*dp.NoRoute {
	var out []*dp.NoRoute
	for _, m := range r.takeSync(s) {
		if nr := m.GetNoRoute(); nr != nil {
			out = append(out, nr)
		}
	}
	return out
}

// homeAsk is one call of the host lookup.
type homeAsk struct {
	vpc  VPCKey
	addr netip.Addr
}

// visitCase is one state of the caller, of the members and of the host. The
// ResolvePeer answer and the NoRoute of Route come from the same rule.
type visitCase struct {
	name   string
	caller *reachCaller // Nil is a PSP-mode agent at the revision of the answer.
	ref    *dp.RelayRef // What relay-a gives of itself in Open.
	self   string       // Relay ID of the relay of the test.
	home   string       // Answer of the host lookup for each address.
	noHost bool         // The host gives no lookup.
	dst    string       // Empty is the address of server.
	setup  func(t *testing.T, g *rowRig)
	want   dp.Reach // Zero is no answer.
	code   rpc.Code // Error code with no answer. Zero is NotFound.
	asked  bool     // The relay asks the host for the home of dst.
	// plain tells that Route gives a NoRoute with no home relay. With the want
	// REACH_VISIT, the NoRoute has the home relay. Else Route gives no NoRoute.
	plain bool
}

func visitCases() []visitCase {
	lost := func(d time.Duration) func(*testing.T, *rowRig) {
		return func(_ *testing.T, g *rowRig) { g.lose(g.sess, meshLost, d) }
	}
	down := lost(meshDownAfter)
	// then runs the steps in order.
	then := func(steps ...func(*testing.T, *rowRig)) func(*testing.T, *rowRig) {
		return func(t *testing.T, g *rowRig) {
			for _, step := range steps {
				step(t, g)
			}
		}
	}
	restart := func(_ *testing.T, g *rowRig) { g.lose(g.sess, meshRestart, meshDownAfter) }
	leave := func(_ *testing.T, g *rowRig) {
		g.m.SetMembers(nil)
		g.deliver()
	}
	deny := func(_ *testing.T, g *rowRig) { g.r.SetPermit(denyAll) }
	// withB adds relay-b before relay-a is down. after runs on its session.
	withB := func(ref *dp.RelayRef, after func(g *rowRig, b *MeshSession)) func(*testing.T, *rowRig) {
		return func(t *testing.T, g *rowRig) {
			b := g.member(ref)
			down(t, g)
			if after != nil {
				after(g, b)
			}
		}
	}
	at := func(c reachCaller) *reachCaller { return &c }
	psp := dp.Mode_MODE_PSP
	return []visitCase{
		// The member is up: the trunk, or no answer. Never the visit.
		{name: "relay-a is up", ref: visitRefA, want: dp.Reach_REACH_TRUNK},
		{name: "relay-a is up, address with no route that the host knows", ref: visitRefA, dst: visitNoRoute, home: "relay-a", plain: true},
		{name: "session of relay-a ended, one moment before the down time", ref: visitRefA, setup: lost(meshDownAfter - time.Nanosecond)},

		// The member is down, and it has its own ID.
		{name: "relay-a is down for the down time", ref: visitRefA, setup: down, want: dp.Reach_REACH_VISIT},
		{name: "relay-a is down for one hour", ref: visitRefA, setup: lost(time.Hour), want: dp.Reach_REACH_VISIT},
		{name: "IPv4 address in a route of server", ref: visitRefA, dst: brServer4, setup: down, want: dp.Reach_REACH_VISIT},
		{name: "QUIC-mode agent", caller: at(reachCaller{rev: visitReachRevision, mode: dp.Mode_MODE_QUIC}), ref: visitRefA, setup: down, want: dp.Reach_REACH_VISIT},
		{name: "relay with an ID of its own", ref: visitRefA, self: "relay-m.example", setup: down, want: dp.Reach_REACH_VISIT},
		{name: "relay-b is up with another ID", ref: visitRefA, setup: withB(visitRefB, nil), want: dp.Reach_REACH_VISIT},
		{name: "relay-b is down with another ID", ref: visitRefA, want: dp.Reach_REACH_VISIT,
			setup: withB(visitRefB, func(g *rowRig, b *MeshSession) { g.lose(b, meshLost, meshDownAfter) })},
		{name: "relay-b gave no RelayRef", ref: visitRefA, setup: withB(nil, nil), want: dp.Reach_REACH_VISIT},

		// The member stopped on purpose.
		{name: "relay-a closed with RESTART", ref: visitRefA, setup: restart, plain: true},
		{name: "relay-a closed with RESTART, and the host knows the home", ref: visitRefA, home: "relay-a", setup: restart, plain: true},
		{name: "relay-a closed with RESTART, address with no route that the host knows", ref: visitRefA, dst: visitNoRoute, home: "relay-a", setup: restart, plain: true},

		// The member has no ID of its own.
		{name: "relay-a gave no RelayRef", setup: down},
		{name: "relay-a gave no ID", ref: &dp.RelayRef{Addresses: visitRefA.Addresses}, setup: down},
		{name: "relay-a gave no ID, relay with an ID of its own", ref: &dp.RelayRef{Addresses: visitRefA.Addresses}, self: "relay-m.example", setup: down},
		{name: "relay-a has the ID of this relay", ref: visitRefA, self: visitRefA.Id, setup: down},
		{name: "relay-b is up with the same ID", ref: visitRefA, setup: withB(visitRefA, nil)},
		{name: "relay-b is down with the same ID", ref: visitRefA,
			setup: withB(visitRefA, func(g *rowRig, b *MeshSession) { g.lose(b, meshLost, meshDownAfter) })},
		{name: "relay-b had the same ID and closed with RESTART", ref: visitRefA, want: dp.Reach_REACH_VISIT,
			setup: withB(visitRefA, func(g *rowRig, b *MeshSession) { g.lose(b, meshRestart, 0) })},

		// The member is up again.
		{name: "new session of relay-a with no keys", ref: visitRefA, setup: then(down, func(_ *testing.T, g *rowRig) { g.join(dp.Revision) })},
		{name: "new session of relay-a with keys", ref: visitRefA, want: dp.Reach_REACH_TRUNK,
			setup: then(down, func(_ *testing.T, g *rowRig) {
				g.keyed(g.join(dp.Revision))
				g.tellServer(10)
			})},
		{name: "relay-a is down again after a new session", ref: visitRefA, want: dp.Reach_REACH_VISIT,
			setup: then(down, func(_ *testing.T, g *rowRig) { g.join(dp.Revision) }, down)},
		{name: "new session of relay-a with no ID, then down", ref: visitRefA,
			setup: then(down, func(_ *testing.T, g *rowRig) {
				g.ref = nil
				g.join(dp.Revision)
			}, down)},

		// The member is gone.
		{name: "relay-a left the members", ref: visitRefA, setup: then(down, leave), plain: true},
		{name: "relay-a left the members, and the host knows the home", ref: visitRefA, home: "relay-a", setup: then(down, leave), plain: true},
		{name: "relay-a has a new address", ref: visitRefA, home: "relay-a", plain: true,
			setup: then(down, func(_ *testing.T, g *rowRig) {
				g.m.SetMembers([]MeshMember{{Name: "relay-a", Addr: netip.MustParseAddrPort("192.0.2.9:6081")}})
				g.deliver()
			})},

		// The caller cannot use the answer.
		{name: "agent one revision before", caller: at(reachCaller{rev: visitReachRevision - 1, mode: psp}), ref: visitRefA, setup: down},
		{name: "agent from before revisions", caller: at(reachCaller{mode: psp}), ref: visitRefA, setup: down},
		{name: "agent with local routes only", caller: at(reachCaller{rev: visitReachRevision, mode: psp, local: true}), ref: visitRefA, setup: down},
		{name: "session with no attachment", caller: at(reachCaller{rev: visitReachRevision, mode: psp, spare: true}), ref: visitRefA, setup: down},
		{name: "agent one revision before, address with no route", caller: at(reachCaller{rev: visitReachRevision - 1, mode: psp}),
			ref: visitRefA, dst: visitNoRoute, home: "relay-a", setup: down, plain: true},
		{name: "Permit denies the address", ref: visitRefA, setup: then(down, deny), code: rpc.PermissionDenied, plain: true},
		{name: "Permit denies an address with no route that the host knows", ref: visitRefA, dst: visitNoRoute, home: "relay-a",
			setup: then(down, deny), code: rpc.PermissionDenied, plain: true},

		// No entry has the address, so the host tells its home.
		{name: "address with no route, home relay-a", ref: visitRefA, dst: visitNoRoute, home: "relay-a", setup: down, want: dp.Reach_REACH_VISIT, asked: true},
		{name: "address with no route, the host knows no home", ref: visitRefA, dst: visitNoRoute, setup: down, asked: true, plain: true},
		{name: "address with no route, no host lookup", ref: visitRefA, dst: visitNoRoute, noHost: true, setup: down, plain: true},
		{name: "address with no route, home is this relay", ref: visitRefA, dst: visitNoRoute, home: "relay-m", setup: down, asked: true, plain: true},
		{name: "address with no route, home is not a member", ref: visitRefA, dst: visitNoRoute, home: "relay-x", setup: down, asked: true, plain: true},
		{name: "address with no route, home relay-b is up", ref: visitRefA, dst: visitNoRoute, home: "relay-b", setup: withB(visitRefB, nil), asked: true, plain: true},
		{name: "address with no route, home relay-b is down", ref: visitRefA, dst: visitNoRoute, home: "relay-b", want: dp.Reach_REACH_VISIT, asked: true,
			setup: func(_ *testing.T, g *rowRig) { g.lose(g.member(visitRefB), meshLost, meshDownAfter) }},
	}
}

// TestVisitAnswer checks, for each state of the caller, of the members and of
// the host, the ResolvePeer answer and the NoRoute that Route gives the caller.
func TestVisitAnswer(t *testing.T) {
	base := trunkRigConfig(t)
	for _, tc := range visitCases() {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var asks []homeAsk
				cfg := base
				if tc.self != "" {
					cfg.Relay = &dp.RelayRef{Id: tc.self}
				}
				if !tc.noHost {
					cfg.Home = func(vpc VPCKey, addr netip.Addr) string {
						asks = append(asks, homeAsk{vpc, addr})
						return tc.home
					}
				}
				g := newRowRig(t, cfg)
				defer g.stop()
				caller := reachCaller{rev: visitReachRevision, mode: dp.Mode_MODE_PSP}
				if tc.caller != nil {
					caller = *tc.caller
				}
				c := g.caller(caller)
				dst := tc.dst
				if dst == "" {
					dst = brServer
				}
				addr := netip.MustParseAddr(dst)
				g.ref = tc.ref
				g.link(dp.Revision)
				if tc.setup != nil {
					tc.setup(t, g)
				}
				// The home relay of each visit answer is what the last session of the member gave.
				home := tc.ref
				if tc.home == "relay-b" {
					home = visitRefB
				}
				var askWant []homeAsk
				if tc.asked {
					askWant = []homeAsk{{vpcA, addr}}
				}

				res, err := g.resolve(c, dst)
				switch tc.want {
				case dp.Reach_REACH_UNSPECIFIED:
					code := tc.code
					if code == 0 {
						code = rpc.NotFound
						assert.ErrorContains(t, err, "no route to "+dst)
					}
					require.Equal(t, code, rpc.CodeOf(err), "answer %v, error %v", res, err)
					assert.Nil(t, res)
				case dp.Reach_REACH_VISIT:
					require.NoError(t, err)
					want := &dp.ResolvePeerResponse{Reach: dp.Reach_REACH_VISIT, HomeRelay: home}
					assert.Empty(t, cmp.Diff(want, res, protocmp.Transform()))
				default:
					require.NoError(t, err)
					assert.Equal(t, tc.want, res.GetReach())
					assert.Nil(t, res.GetHomeRelay(), "the trunk answer has no home relay")
				}
				if tc.code == rpc.PermissionDenied {
					assert.Empty(t, asks, "a denied caller learns nothing of the home")
				} else {
					assert.Equal(t, askWant, asks, "host lookups of ResolvePeer")
				}
				assert.Empty(t, noRouteMsgs(g.r, c), "ResolvePeer sends no NoRoute")

				asks = nil
				assert.Nil(t, g.r.Route(c, addr, time.Now()), "the relay has no session for the address")
				var want []*dp.NoRoute
				switch {
				case tc.want == dp.Reach_REACH_VISIT:
					want = []*dp.NoRoute{{Vpc: ref(vpcA), Address: dst, HomeRelay: home}}
				case tc.plain:
					want = []*dp.NoRoute{{Vpc: ref(vpcA), Address: dst}}
				}
				assert.Empty(t, cmp.Diff(want, noRouteMsgs(g.r, c), protocmp.Transform()))
				if tc.code == rpc.PermissionDenied {
					assert.Empty(t, asks, "a denied sender learns nothing of the home")
				} else {
					assert.Equal(t, askWant, asks, "host lookups of Route")
				}
			})
		})
	}
}

// TestVisitNoRouteSenders checks which traffic of an agent for an address of
// relay-a gives the agent a NoRoute with the home relay, and how often.
func TestVisitNoRouteSenders(t *testing.T) {
	server := netip.MustParseAddr(brServer)
	frame := func(g *rowRig, c *Session) bool {
		return g.r.forwardDatagram(c, peerconn.EncodeToRelay(nil, server, netip.MustParseAddr(visitCallerAddr), []byte("hi")), time.Now())
	}
	data := func(g *rowRig, c *Session) bool {
		inner := innerOf(visitCallerAddr, brServer, 100)
		return g.r.forwardData(c, peerconn.EncodeData(nil, testVNI, inner), make([]byte, maxUDP), time.Now())
	}
	cases := []struct {
		name string
		rev  uint32 // Zero is the revision of the answer.
		mode dp.Mode
		psp  bool // The sender is a PSP-mode agent that sends a packet with the relay SA.
		row  bool // The sender is a PSP-mode agent that sends the PSP packet of an SPI row.
		send func(g *rowRig, c *Session) bool
		down time.Duration // Time since the session of relay-a ended. Zero is an open session.
		sent bool          // The relay sends the traffic to relay-a.
		want bool          // The sender gets the NoRoute.
	}{
		{name: "peer frame, relay-a is up", mode: dp.Mode_MODE_PSP, send: frame, sent: true},
		{name: "peer frame, session ended a moment ago", mode: dp.Mode_MODE_PSP, send: frame, down: time.Second},
		{name: "peer frame, relay-a is down", mode: dp.Mode_MODE_PSP, send: frame, down: meshDownAfter, want: true},
		{name: "peer frame of a QUIC-mode agent, relay-a is down", mode: dp.Mode_MODE_QUIC, send: frame, down: meshDownAfter, want: true},
		{name: "peer frame of an agent one revision before, relay-a is down", rev: visitReachRevision - 1, mode: dp.Mode_MODE_PSP, send: frame, down: meshDownAfter},
		{name: "data frame, relay-a is up", mode: dp.Mode_MODE_QUIC, send: data, sent: true},
		{name: "data frame, session ended a moment ago", mode: dp.Mode_MODE_QUIC, send: data, down: time.Second, sent: true},
		{name: "data frame, relay-a is down", mode: dp.Mode_MODE_QUIC, send: data, down: meshDownAfter, want: true},
		{name: "data frame of an agent one revision before, relay-a is down", rev: visitReachRevision - 1, mode: dp.Mode_MODE_QUIC, send: data, down: meshDownAfter},
		{name: "PSP packet with the relay SA, relay-a is up", psp: true, sent: true},
		{name: "PSP packet with the relay SA, relay-a is down", psp: true, down: meshDownAfter, want: true},
		{name: "PSP packet of an agent one revision before, relay-a is down", rev: visitReachRevision - 1, psp: true, down: meshDownAfter},
		// The relay does not open the packet of a row: the address is the destination of the row.
		{name: "PSP packet of an SPI row, relay-a is up", row: true, sent: true},
		{name: "PSP packet of an SPI row, session ended a moment ago", row: true, down: time.Second, sent: true},
		{name: "PSP packet of an SPI row, relay-a is down", row: true, down: meshDownAfter, want: true},
		{name: "PSP packet of an SPI row of an agent one revision before, relay-a is down", rev: visitReachRevision - 1, row: true, down: meshDownAfter},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				rev := tc.rev
				if rev == 0 {
					rev = visitReachRevision
				}
				var c *Session
				send := tc.send
				switch {
				case tc.psp:
					e := g.pspSender(rev)
					c = e.s
					send = func(g *rowRig, _ *Session) bool { return len(g.bridgeSend(e, innerOf(brP, brServer, 100))) > 0 }
				case tc.row:
					c = g.caller(reachCaller{rev: rev, mode: dp.Mode_MODE_PSP})
					send = func(g *rowRig, _ *Session) bool { return g.rowPacket(5, 100) }
				default:
					c = g.caller(reachCaller{rev: rev, mode: tc.mode})
				}
				g.ref = visitRefA
				g.link(dp.Revision)
				if tc.row {
					require.NoError(t, g.r.registerSPI(c, register(vpcA, brServer, rowTTL, 5), time.Now()))
				}
				if tc.down > 0 {
					g.lose(g.sess, meshLost, tc.down)
				}
				g.r.takeSync(c)
				g.packets()

				assert.Equal(t, tc.sent, send(g, c), "the relay sent the traffic")
				var want []*dp.NoRoute
				if tc.want {
					want = []*dp.NoRoute{{Vpc: ref(vpcA), Address: brServer, HomeRelay: visitRefA}}
				}
				assert.Empty(t, cmp.Diff(want, noRouteMsgs(g.r, c), protocmp.Transform()))

				// The relay sends at most one NoRoute each second for an address.
				time.Sleep(noRouteInterval - time.Nanosecond)
				send(g, c)
				assert.Empty(t, noRouteMsgs(g.r, c), "second NoRoute in one second")
				time.Sleep(time.Nanosecond)
				send(g, c)
				assert.Empty(t, cmp.Diff(want, noRouteMsgs(g.r, c), protocmp.Transform()), "NoRoute after one second")
			})
		})
	}
}

// rowPacket gives the relay a PSP packet with spi and an inner packet of n bytes from
// the socket of the caller. It reports whether relay-a got the packet with no change.
func (g *rowRig) rowPacket(spi uint32, n int) bool {
	g.t.Helper()
	pkt := pspOfSize(g.t, spi, n)
	pkts := g.arrive(slices.Clone(pkt), netip.MustParseAddrPort(reachSocket))
	if len(pkts) == 0 {
		return false
	}
	assert.Equal(g.t, []keptPacket{{pkt, g.addr}}, pkts, "relay-a gets the packet of the agent with no change")
	return true
}

// TestVisitNoRouteRow checks when the PSP packet of an SPI row to server on relay-a
// gives its sender a NoRoute with the home relay, by the state of relay-a.
func TestVisitNoRouteRow(t *testing.T) {
	lost := func(d time.Duration) func(*rowRig) {
		return func(g *rowRig) { g.lose(g.sess, meshLost, d) }
	}
	down := lost(meshDownAfter)
	then := func(steps ...func(*rowRig)) func(*rowRig) {
		return func(g *rowRig) {
			for _, step := range steps {
				step(g)
			}
		}
	}
	noID := &dp.RelayRef{Addresses: visitRefA.Addresses}
	cases := []struct {
		name  string
		rev   uint32        // Revision of the sender. Zero is the revision of the visit answer.
		ref   *dp.RelayRef  // What relay-a gives of itself in Open. Nil is visitRefA.
		self  string        // Relay ID of the relay of the test.
		setup func(*rowRig) // Runs when the row is there. Nil leaves relay-a up.
		size  int           // Bytes of the inner packet. Zero is 100.
		sent  bool          // relay-a gets the packet.
		drop  string        // Reason label of the drop, if the packet drops.
		want  bool          // The sender gets a NoRoute with the home relay.
	}{
		{name: "relay-a is up", sent: true},
		{name: "packet too long for the path, relay-a is up", size: trunkMTU + 1, drop: "trunk_mtu"},
		{name: "session of relay-a ended, one moment before the down time", setup: lost(meshDownAfter - time.Nanosecond), sent: true},
		{name: "relay-a is down for the down time", setup: down, drop: "trunk_keys", want: true},
		{name: "relay-a is down for one minute", setup: lost(time.Minute), drop: "trunk_keys", want: true},
		{name: "packet too long for the path, relay-a is down", size: trunkMTU + 1, setup: down, drop: "trunk_keys", want: true},
		{name: "relay with an ID of its own", self: "relay-m.example", setup: down, drop: "trunk_keys", want: true},
		{name: "relay-b is up with another ID", drop: "trunk_keys", want: true,
			setup: func(g *rowRig) {
				g.member(visitRefB)
				down(g)
			}},

		// The other cases of the visit rule: the address has a route, so the sender gets no NoRoute.
		{name: "relay-a closed with RESTART", setup: func(g *rowRig) { g.lose(g.sess, meshRestart, meshDownAfter) }, drop: "unknown_spi"},
		// The relay has an ID here: with none, the empty ID of relay-a is also the ID of this relay.
		{name: "relay-a gave no relay ID", ref: noID, self: "relay-m.example", setup: down, drop: "trunk_keys"},
		{name: "relay-a has the relay ID of this relay", self: visitRefA.Id, setup: down, drop: "trunk_keys"},
		{name: "relay-b is up with the same relay ID", drop: "trunk_keys",
			setup: func(g *rowRig) {
				g.member(visitRefA)
				down(g)
			}},
		{name: "relay-b is down with the same relay ID", drop: "trunk_keys",
			setup: func(g *rowRig) {
				b := g.member(visitRefA)
				down(g)
				g.lose(b, meshLost, meshDownAfter)
			}},
		{name: "agent one revision before the visit answer", rev: visitReachRevision - 1, setup: down, drop: "trunk_keys"},
		{name: "agent from before revisions", rev: 1, setup: down, drop: "trunk_keys"},

		// The member has a session again.
		{name: "relay-a came back one revision before the trunk", drop: "trunk_keys",
			setup: then(down, func(g *rowRig) { g.join(trunkRevision - 1) })},
		{name: "relay-a came back with no SA", setup: then(down, func(g *rowRig) { g.join(trunkRevision) }), sent: true},
		{name: "relay-a came back and is down again", drop: "trunk_keys", want: true,
			setup: then(down, func(g *rowRig) { g.join(trunkRevision) }, down)},
	}
	base := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := base
				if tc.self != "" {
					cfg.Relay = &dp.RelayRef{Id: tc.self}
				}
				g := newRowRig(t, cfg)
				defer g.stop()
				rev, size, home := tc.rev, tc.size, tc.ref
				if rev == 0 {
					rev = visitReachRevision
				}
				if size == 0 {
					size = 100
				}
				if home == nil {
					home = visitRefA
				}
				c := g.caller(reachCaller{rev: rev, mode: dp.Mode_MODE_PSP})
				g.ref = home
				g.link(dp.Revision)
				require.NoError(t, g.r.registerSPI(c, register(vpcA, brServer, rowTTL, 5), time.Now()))
				if tc.setup != nil {
					tc.setup(g)
				}
				g.r.takeSync(c)
				before := dropsOf(g.r)

				assert.Equal(t, tc.sent, g.rowPacket(5, size), "relay-a got the packet")
				if tc.drop != "" {
					before[tc.drop]++
				}
				assert.Equal(t, before, dropsOf(g.r), "drop counters")
				var want []*dp.NoRoute
				if tc.want {
					// The inner packet has another destination: the address is from the row.
					want = []*dp.NoRoute{{Vpc: ref(vpcA), Address: brServer, HomeRelay: home}}
				}
				assert.Empty(t, cmp.Diff(want, noRouteMsgs(g.r, c), protocmp.Transform()))
			})
		})
	}
}

// TestVisitNoRouteRowLimit checks that the packets of the rows of a sender give at
// most one NoRoute each second for each address, also with two rows to one address.
func TestVisitNoRouteRowLimit(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		c := g.caller(reachCaller{rev: visitReachRevision, mode: dp.Mode_MODE_PSP})
		g.ref = visitRefA
		g.link(dp.Revision)
		// The rows 5 and 6 are to one address of server, and the row 7 to its IPv4 address.
		require.NoError(t, g.r.registerSPI(c, register(vpcA, brServer, rowTTL, 5, 6), time.Now()))
		require.NoError(t, g.r.registerSPI(c, register(vpcA, brServer4, rowTTL, 7), time.Now()))
		g.lose(g.sess, meshLost, meshDownAfter)
		g.r.takeSync(c)
		steps := []struct {
			name string
			wait time.Duration // Time before the packet.
			spi  uint32
			want string // Address of the NoRoute. Empty is no NoRoute.
		}{
			{name: "first packet of row 5", spi: 5, want: brServer},
			{name: "second packet of row 5", spi: 5},
			{name: "packet of row 6 to the same address", spi: 6},
			{name: "packet of row 7 to another address", spi: 7, want: brServer4},
			// The second is that of the README, so the steps do not use the constant of the relay.
			{name: "one moment before the end of the second", wait: time.Second - time.Nanosecond, spi: 6},
			{name: "one second after the first NoRoute", wait: time.Nanosecond, spi: 6, want: brServer},
			{name: "the other address, one second after its NoRoute", spi: 7, want: brServer4},
			{name: "row 5 after the NoRoute of row 6", spi: 5},
		}
		for _, st := range steps {
			time.Sleep(st.wait)
			assert.False(t, g.rowPacket(st.spi, 100), st.name)
			var want []*dp.NoRoute
			if st.want != "" {
				want = []*dp.NoRoute{{Vpc: ref(vpcA), Address: st.want, HomeRelay: visitRefA}}
			}
			assert.Empty(t, cmp.Diff(want, noRouteMsgs(g.r, c), protocmp.Transform()), st.name)
		}
		assert.EqualValues(t, len(steps), g.r.drops[dropTrunkKeys].Load(), "each packet drops")
	})
}
