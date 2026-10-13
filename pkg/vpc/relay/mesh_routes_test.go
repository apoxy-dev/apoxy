// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// The prefixes of the route tests: two attachment addresses and an advertised
// route.
const (
	prefixA = "fd00:a::/96"
	prefixB = "fd00:b::/96"
	prefixR = "10.9.0.0/16"
)

// thisRevision is the Hello of an agent of this build.
func thisRevision() *dp.Hello { return &dp.Hello{Version: dp.LocalVersion("test")} }

// namedHello is thisRevision with the agent name.
func namedHello(name string) *dp.Hello {
	h := thisRevision()
	h.Name = name
	return h
}

var routeMembers = []MeshMember{
	{Name: "relay-a", Addr: netip.MustParseAddrPort("192.0.2.1:6081")},
	{Name: "relay-b", Addr: netip.MustParseAddrPort("192.0.2.2:6081")},
}

// routeWorld is relay-m with a router and a mesh. The test plays its members
// relay-a and relay-b, and the agents of relay-m.
type routeWorld struct {
	t     *testing.T
	m     *Mesh
	r     *Router
	sess  map[string]*Session
	mesh  map[string]*MeshSession
	conns map[string]*stubConn
}

// newRouteWorld gives relay-m the router r, and opens the mesh sessions of
// relay-a and relay-b with a Presence call on each.
func newRouteWorld(t *testing.T, r *Router) *routeWorld {
	t.Helper()
	// At revision 3 a member gets no Presence call, which the stub cannot carry.
	return newRouteWorldAt(t, r, 3)
}

// newRouteWorldAt is newRouteWorld with members at revision rev. From revision
// 4, the test must not call deliver, which starts a Presence call to a member.
func newRouteWorldAt(t *testing.T, r *Router, rev uint32) *routeWorld {
	t.Helper()
	ca := newCA(t)
	m, err := NewMesh("relay-m", MeshConfig{TLS: meshTLS(ca.meshCert(t, "relay-m")), Verify: ca.verifyName})
	require.NoError(t, err)
	w := &routeWorld{t: t, m: m, r: r, sess: map[string]*Session{}, mesh: map[string]*MeshSession{}, conns: map[string]*stubConn{}}
	m.SetRouter(r)
	m.SetMembers(routeMembers)
	w.openAt("relay-a", rev)
	w.openAt("relay-b", rev)
	return w
}

// open opens a new mesh session of member and its Presence call.
func (w *routeWorld) open(member string) {
	w.t.Helper()
	w.openAt(member, 3)
}

// openAt is open for a member at revision rev.
func (w *routeWorld) openAt(member string, rev uint32) {
	w.t.Helper()
	w.dial(member, rev)
	require.NoError(w.t, w.m.pres.accept(w.mesh[member]))
}

// dial opens a new mesh session of member at revision rev, with no Presence call.
func (w *routeWorld) dial(member string, rev uint32) {
	w.t.Helper()
	conn := newStubConn()
	s := w.m.newSession(conn, false)
	require.True(w.t, w.m.track(s))
	require.NoError(w.t, w.m.admit(s, member, nil, &dp.Version{Revision: rev}, nil))
	w.mesh[member], w.conns[member] = s, conn
}

// send gives entries to relay-m in one message of the Presence call of member.
func (w *routeWorld) send(member string, entries ...*dp.Presence) {
	w.t.Helper()
	require.NoError(w.t, w.m.pres.apply(w.mesh[member], &dp.PresenceUpdate{Entries: entries}))
}

// full is send for the last message of the full set of member.
func (w *routeWorld) full(member string, entries ...*dp.Presence) {
	w.t.Helper()
	require.NoError(w.t, w.m.pres.apply(w.mesh[member], &dp.PresenceUpdate{Entries: entries, EndOfFullSet: true}))
}

// pass lets d pass on the fake clock, with the hooks of the mesh as Run calls them.
func (w *routeWorld) pass(d time.Duration) {
	w.m.deliver()
	time.Sleep(d)
	synctest.Wait()
	w.m.deliver()
}

// restart closes the session of member with RESTART, as when the member stops.
// It needs the fake clock.
func (w *routeWorld) restart(member string) {
	w.conns[member].cancel(&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART)})
	synctest.Wait()
	w.m.deliver()
}

// lose ends the session of member with an idle timeout and waits a minute. It
// needs the fake clock.
func (w *routeWorld) lose(member string) {
	w.conns[member].cancel(&quic.IdleTimeoutError{})
	time.Sleep(time.Minute)
	synctest.Wait()
	w.m.deliver()
}

// leave takes member out of the member set. It needs the fake clock.
func (w *routeWorld) leave(member string) {
	w.m.SetMembers(slices.DeleteFunc(slices.Clone(routeMembers), func(m MeshMember) bool { return m.Name == member }))
	synctest.Wait()
	w.m.deliver()
}

// remoteEntry is the entry of attachment id of laptop in vpcA at generation
// gen. laptop has the agent name "base" and the tag 7 on its relay.
func remoteEntry(id string, gen uint64, prefixes ...string) *dp.Presence {
	e := liveEntry(id, laptop, "base", 7, prefixes...)
	e.Generation = gen
	return e
}

// draining returns e in the draining state, so each normal announcer of its
// prefixes comes before it.
func draining(e *dp.Presence) *dp.Presence {
	e.State = dp.AnnouncerState_ANNOUNCER_STATE_DRAINING
	return e
}

// ranked returns e with the rank that its agent gives to the connection.
func ranked(e *dp.Presence, rank uint32) *dp.Presence {
	e.Rank = rank
	return e
}

// goneAt is the entry of attachment id that ended at generation gen.
func goneAt(id string, gen uint64) *dp.Presence {
	return &dp.Presence{AttachmentId: id, Generation: gen, Gone: true}
}

// session adds a session of subject in vpc to relay-m. Its Session call
// starts with h.
func (w *routeWorld) session(name string, vpc VPCKey, subject string, h *dp.Hello) *Session {
	w.t.Helper()
	s := w.join(name, vpc, subject)
	require.NoError(w.t, w.r.checkRevision(s, h.GetVersion()))
	require.NoError(w.t, w.r.openSync(s, dp.Mode_MODE_QUIC, ref(vpc), h))
	return s
}

// join adds a session of subject in vpc to relay-m, with no Session call.
func (w *routeWorld) join(name string, vpc VPCKey, subject string) *Session {
	w.t.Helper()
	s := addSession(w.t, w.r, vpc, subject, fmt.Sprintf("192.0.2.9:%d", 1000+len(w.sess))).Session
	w.sess[name] = s
	return s
}

// attach gives the session name the attachment id with the address prefix
// addr and the advertised routes.
func (w *routeWorld) attach(name, id, addr string, routes ...string) {
	w.t.Helper()
	a := attachment(id, addr)
	for _, p := range routes {
		a.Routes = append(a.Routes, netip.MustParsePrefix(p))
	}
	require.NoError(w.t, w.r.attach(w.sess[name], a))
}

func (w *routeWorld) detach(name, id string) {
	w.t.Helper()
	_, _, err := w.r.detach(w.sess[name], id)
	require.NoError(w.t, err)
}

// routeChanges returns the route changes that wait for s, as "-origin prefix"
// and "+origin prefix", with " standby=a,b" after a route that has standby
// announcers.
func routeChanges(r *Router, s *Session) []string {
	var out []string
	for _, m := range r.takeSync(s) {
		for _, rt := range m.GetRouteDelta().GetRemove() {
			out = append(out, "-"+rt.GetOrigin()+" "+rt.GetPrefix())
		}
		for _, rt := range m.GetRouteDelta().GetAdd() {
			line := "+" + rt.GetOrigin() + " " + rt.GetPrefix()
			if sb := rt.GetStandby(); len(sb) > 0 {
				line += " standby=" + strings.Join(sb, ",")
			}
			out = append(out, line)
		}
	}
	return out
}

func (w *routeWorld) changes(name string) []string { return routeChanges(w.r, w.sess[name]) }

func (w *routeWorld) drain() {
	for name := range w.sess {
		w.changes(name)
	}
}

// routeTable returns the active announcer of each prefix of vpc in r: "origin"
// for an attachment of r, and "origin@relay" for an attachment of another relay.
func routeTable(r *Router, vpc VPCKey) map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := map[string]string{}
	d := r.domains[vpc]
	if d == nil {
		return out
	}
	for p, set := range d.routes {
		out[p.String()] = entryName(set.active())
	}
	return out
}

// entryName returns "origin" for an entry of an attachment of this relay, and
// "origin@relay" for an attachment of another relay.
func entryName(e *announcer) string {
	if e.s.home != "" {
		return e.origin + "@" + e.s.home
	}
	return e.origin
}

func (w *routeWorld) table(vpc VPCKey) map[string]string { return routeTable(w.r, vpc) }

// check checks that the router has a record for each session of another relay
// that has a route, and no other record.
func (w *routeWorld) check() {
	w.t.Helper()
	w.r.mu.RLock()
	defer w.r.mu.RUnlock()
	owned := map[*Session][]netip.Prefix{}
	for vpc, d := range w.r.domains {
		for p, set := range d.routes {
			assert.NotEmpty(w.t, set.entries, "entries of %s", p)
			assert.Equal(w.t, selectOrder(set.entries, time.Now()), set.order, "selection of %s", p)
			for _, o := range set.entries {
				if o.s.home == "" {
					continue
				}
				owned[o.s] = append(owned[o.s], p)
				assert.Equal(w.t, vpc, o.s.id.VPC, "VPC of the record of %s", p)
				assert.Nil(w.t, o.att, "attachment of the route %s", p)
				assert.Same(w.t, o.s, w.r.remotes[o.s.remoteKey()], "record of %s", p)
				_, member := d.members[o.s]
				assert.False(w.t, member, "the record of %s is a member of its domain", p)
			}
		}
		assert.False(w.t, len(d.routes) == 0 && len(d.members) == 0 && len(d.claims) == 0, "empty domain of %v stays", vpc)
	}
	assert.Len(w.t, w.r.remotes, len(owned), "records")
	for s, prefixes := range owned {
		assert.ElementsMatch(w.t, prefixes, s.routes, "routes of the record of %s on %s", s.id.ID, s.home)
		assert.NotContains(w.t, w.r.sessions, s, "the record is a session of this relay")
	}
	checkEntries(w.t, w.m)
}

// TestMeshRoutes gives the entries of two other relays to a relay. Each prefix
// of an entry gets a route, which the agents of the relay get and lose.
func TestMeshRoutes(t *testing.T) {
	cases := []struct {
		name  string
		steps func(w *routeWorld)
		// routes are the routes of vpcA at the end, as routeTable gives them.
		routes map[string]string
		// delta are the changes of the watcher after the last drain.
		delta []string
		// records is the number of sessions of other relays that have routes.
		records int
	}{
		{
			name:    "attachment of another relay",
			steps:   func(w *routeWorld) { w.send("relay-a", remoteEntry("x", 10, prefixA, prefixR)) },
			routes:  map[string]string{prefixA: "x@relay-a", prefixR: "x@relay-a"},
			delta:   []string{"+x " + prefixR, "+x " + prefixA},
			records: 1,
		},
		{
			name: "attachment of another relay ends",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA, prefixR))
				w.drain()
				w.send("relay-a", goneAt("x", 11))
			},
			delta: []string{"-x " + prefixR, "-x " + prefixA},
		},
		{
			name: "end with a lower generation changes nothing",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA))
				w.drain()
				w.send("relay-a", goneAt("x", 9))
			},
			routes: map[string]string{prefixA: "x@relay-a"}, records: 1,
		},
		{
			name: "attachment comes again with other prefixes",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA))
				w.drain()
				w.send("relay-a", remoteEntry("x", 12, prefixB))
			},
			routes: map[string]string{prefixB: "x@relay-a"},
			delta:  []string{"-x " + prefixA, "+x " + prefixB}, records: 1,
		},
		{
			name: "member sends the entry again on a new session",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA))
				w.drain()
				w.open("relay-a")
				w.send("relay-a", remoteEntry("x", 10, prefixA))
			},
			routes: map[string]string{prefixA: "x@relay-a"}, records: 1,
		},
		{
			name: "two attachments of one session",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA), remoteEntry("x2", 11, prefixB))
				w.drain()
				w.send("relay-a", goneAt("x", 12))
			},
			routes: map[string]string{prefixB: "x2@relay-a"},
			delta:  []string{"-x " + prefixA}, records: 1,
		},
		{
			name: "two sessions of one agent on one relay",
			steps: func(w *routeWorld) {
				second := remoteEntry("x2", 11, prefixB)
				second.SenderTag = 8
				w.send("relay-a", remoteEntry("x", 10, prefixA), second)
			},
			routes: map[string]string{prefixA: "x@relay-a", prefixB: "x2@relay-a"},
			delta:  []string{"+x " + prefixA, "+x2 " + prefixB}, records: 2,
		},
		{
			// The generation has no effect between two relays.
			// A session at this revision gets the route again with the new standby list.
			name: "one agent on two relays: the lower relay name is active",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixR))
				w.drain()
				w.send("relay-b", remoteEntry("y", 20, prefixR))
			},
			routes: map[string]string{prefixR: "x@relay-a"},
			delta:  []string{"+x " + prefixR + " standby=y"}, records: 2,
		},
		{
			name: "one agent on two relays: the lower relay name comes later",
			steps: func(w *routeWorld) {
				w.send("relay-b", remoteEntry("y", 20, prefixR))
				w.drain()
				w.send("relay-a", remoteEntry("x", 10, prefixR))
			},
			routes: map[string]string{prefixR: "x@relay-a"},
			delta:  []string{"-y " + prefixR, "+x " + prefixR + " standby=y"}, records: 2,
		},
		{
			name: "one agent on two relays: the other connection is active at the end of the first",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixR))
				w.send("relay-b", remoteEntry("y", 20, prefixR))
				w.drain()
				w.send("relay-a", goneAt("x", 21))
			},
			routes: map[string]string{prefixR: "y@relay-b"},
			delta:  []string{"-x " + prefixR, "+y " + prefixR}, records: 1,
		},
		{
			name: "one agent on two relays: the end of the standby connection changes only the standby list",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixR))
				w.send("relay-b", remoteEntry("y", 20, prefixR))
				w.drain()
				w.send("relay-b", goneAt("y", 21))
			},
			routes: map[string]string{prefixR: "x@relay-a"},
			delta:  []string{"+x " + prefixR}, records: 1,
		},
		{
			name: "one agent on two relays: the lower rank is active",
			steps: func(w *routeWorld) {
				w.send("relay-a", ranked(remoteEntry("x", 10, prefixR), 1))
				w.drain()
				w.send("relay-b", remoteEntry("y", 20, prefixR))
			},
			routes: map[string]string{prefixR: "y@relay-b"},
			delta:  []string{"-x " + prefixR, "+y " + prefixR + " standby=x"}, records: 2,
		},
		{
			name: "two agents: the normal one is active, and the draining one is standby",
			steps: func(w *routeWorld) {
				second := liveEntry("y", agentID(vpcA, "tablet"), "base", 9, prefixR)
				second.Generation = 20
				w.send("relay-a", draining(remoteEntry("x", 10, prefixR)))
				w.drain()
				w.send("relay-b", second)
			},
			routes: map[string]string{prefixR: "y@relay-b"},
			delta:  []string{"-x " + prefixR, "+y " + prefixR + " standby=x"}, records: 2,
		},
		{
			name: "equal generations on one relay: the lower attachment ID gets the prefix",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("y", 10, prefixR))
				w.drain()
				w.send("relay-a", remoteEntry("x", 10, prefixR))
			},
			routes: map[string]string{prefixR: "x@relay-a"},
			delta:  []string{"-y " + prefixR, "+x " + prefixR}, records: 1,
		},
		{
			name: "attachment of this relay and a draining entry",
			steps: func(w *routeWorld) {
				w.attach("local", "y", prefixA)
				w.drain()
				w.send("relay-a", draining(remoteEntry("x", 10, prefixA, prefixB)))
			},
			routes: map[string]string{prefixA: "y", prefixB: "x@relay-a"},
			delta:  []string{"+y " + prefixA + " standby=x", "+x " + prefixB}, records: 1,
		},
		{
			// The relay does not take the address from the entry: the two are in the set.
			name: "attachment of this relay gets an address that an entry of another relay has",
			steps: func(w *routeWorld) {
				w.send("relay-a", draining(remoteEntry("x", 10, prefixA)))
				w.drain()
				w.attach("local", "y", prefixA)
			},
			routes: map[string]string{prefixA: "y"},
			delta:  []string{"-x " + prefixA, "+y " + prefixA + " standby=x"}, records: 1,
		},
		{
			// The agent has a connection to each relay. With equal ranks, the lower relay name comes first.
			name: "attachment of this relay and an entry of the same agent on another relay",
			steps: func(w *routeWorld) {
				w.session("moved", vpcA, laptop, namedHello("base"))
				w.send("relay-a", remoteEntry("x", 10, prefixA, prefixR))
				w.drain()
				w.attach("moved", "y", prefixB, prefixR)
			},
			routes: map[string]string{prefixA: "x@relay-a", prefixB: "y", prefixR: "x@relay-a"},
			delta:  []string{"+x " + prefixR + " standby=y", "+y " + prefixB}, records: 1,
		},
		{
			name: "route of a session of this relay and an entry of the same agent on another relay",
			steps: func(w *routeWorld) {
				w.session("moved", vpcA, laptop, namedHello("base"))
				w.send("relay-a", remoteEntry("x", 10, prefixR))
				w.drain()
				require.NoError(w.t, w.r.AddRoute(w.sess["moved"], netip.MustParsePrefix(prefixR), "y"))
			},
			routes: map[string]string{prefixR: "x@relay-a"},
			delta:  []string{"+x " + prefixR + " standby=y"}, records: 1,
		},
		{
			name: "prefix goes to the other relay at the detach on this relay",
			steps: func(w *routeWorld) {
				w.attach("local", "y", prefixA, prefixR)
				w.send("relay-a", draining(remoteEntry("x", 10, prefixA, prefixR)))
				w.drain()
				w.detach("local", "y")
			},
			routes: map[string]string{prefixA: "x@relay-a", prefixR: "x@relay-a"},
			delta:  []string{"-y " + prefixR, "-y " + prefixA, "+x " + prefixR, "+x " + prefixA}, records: 1,
		},
		{
			name: "prefix goes to the other relay when the session of this relay closes",
			steps: func(w *routeWorld) {
				w.attach("local", "y", prefixA)
				w.send("relay-a", draining(remoteEntry("x", 10, prefixA)))
				w.drain()
				w.r.removeSession(w.sess["local"])
			},
			routes: map[string]string{prefixA: "x@relay-a"},
			delta:  []string{"-y " + prefixA, "+x " + prefixA}, records: 1,
		},
		{
			name: "prefix goes to the other relay when the route of this relay goes",
			steps: func(w *routeWorld) {
				require.NoError(w.t, w.r.AddRoute(w.sess["local"], netip.MustParsePrefix(prefixR), "y"))
				w.send("relay-a", draining(remoteEntry("x", 10, prefixR)))
				w.drain()
				w.r.RemoveRoute(w.sess["local"], netip.MustParsePrefix(prefixR))
			},
			routes: map[string]string{prefixR: "x@relay-a"},
			delta:  []string{"-y " + prefixR, "+x " + prefixR}, records: 1,
		},
		{
			name: "advertised route stays on this relay while an attachment of the agent lists it",
			steps: func(w *routeWorld) {
				w.attach("local", "y", prefixA, prefixR)
				w.attach("local", "y2", prefixB, prefixR)
				w.send("relay-a", draining(remoteEntry("x", 10, prefixR)))
				w.drain()
				w.detach("local", "y2")
			},
			routes: map[string]string{prefixA: "y", prefixR: "y"},
			delta:  []string{"-y2 " + prefixR, "-y2 " + prefixB, "+y " + prefixR + " standby=x"}, records: 1,
		},
		{
			name:  "entry with no prefix",
			steps: func(w *routeWorld) { w.send("relay-a", remoteEntry("x", 10)) },
		},
		{
			name:    "entry with one prefix two times",
			steps:   func(w *routeWorld) { w.send("relay-a", remoteEntry("x", 10, prefixA, prefixA)) },
			routes:  map[string]string{prefixA: "x@relay-a"},
			delta:   []string{"+x " + prefixA},
			records: 1,
		},
		{
			name: "member stops",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA, prefixR))
				w.send("relay-b", remoteEntry("y", 11, prefixB))
				w.drain()
				w.restart("relay-a")
			},
			routes: map[string]string{prefixB: "y@relay-b"},
			delta:  []string{"-x " + prefixR, "-x " + prefixA}, records: 1,
		},
		{
			name: "member leaves the member set",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA, prefixR))
				w.send("relay-b", remoteEntry("y", 11, prefixB))
				w.drain()
				w.leave("relay-a")
			},
			routes: map[string]string{prefixB: "y@relay-b"},
			delta:  []string{"-x " + prefixR, "-x " + prefixA}, records: 1,
		},
		{
			name: "member stops, and the other relay gets its prefix",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 20, prefixR))
				w.send("relay-b", remoteEntry("y", 10, prefixR))
				w.drain()
				w.restart("relay-a")
			},
			routes: map[string]string{prefixR: "y@relay-b"},
			delta:  []string{"-x " + prefixR, "+y " + prefixR}, records: 1,
		},
		{
			name: "member stops, and its new session sent an attachment before the change",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA))
				w.drain()
				w.conns["relay-a"].cancel(&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART)})
				synctest.Wait()
				w.open("relay-a")
				w.send("relay-a", remoteEntry("z", 30, prefixB))
				w.m.deliver()
			},
			routes: map[string]string{prefixB: "z@relay-a"},
			delta:  []string{"-x " + prefixA, "+z " + prefixB}, records: 1,
		},
		{
			// The routes of a lost member stay for memberLostTime. TestMemberLost has the end.
			name: "session of a member is lost",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA))
				w.drain()
				w.lose("relay-a")
				w.pass(memberLostTime - 2*time.Minute)
			},
			routes: map[string]string{prefixA: "x@relay-a"}, records: 1,
		},
		{
			name: "lost member leaves the member set",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA, prefixR))
				w.send("relay-b", remoteEntry("y", 11, prefixB))
				w.drain()
				w.lose("relay-a")
				w.leave("relay-a")
			},
			routes: map[string]string{prefixB: "y@relay-b"},
			delta:  []string{"-x " + prefixR, "-x " + prefixA}, records: 1,
		},
		{
			// The entry of the lost relay stays in the set as a suspect one.
			name: "attachment comes on another relay while its first relay is lost",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA))
				w.drain()
				w.lose("relay-a")
				w.send("relay-b", remoteEntry("y", 20, prefixA))
			},
			routes: map[string]string{prefixA: "y@relay-b"},
			delta:  []string{"-x " + prefixA, "+y " + prefixA + " standby=x"}, records: 2,
		},
		{
			name: "new session of a lost member: the routes stay before the end of the full set",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA), remoteEntry("x2", 11, prefixB))
				w.drain()
				w.lose("relay-a")
				w.open("relay-a")
				w.send("relay-a", remoteEntry("x2", 11, prefixB))
				w.pass(10*time.Second - time.Nanosecond)
			},
			routes: map[string]string{prefixA: "x@relay-a", prefixB: "x2@relay-a"}, records: 1,
		},
		{
			name: "new session of a lost member ends its full set",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA, prefixR), remoteEntry("x2", 11, prefixB))
				w.drain()
				w.lose("relay-a")
				w.open("relay-a")
				w.full("relay-a", remoteEntry("x2", 11, prefixB))
			},
			routes: map[string]string{prefixB: "x2@relay-a"},
			delta:  []string{"-x " + prefixR, "-x " + prefixA}, records: 1,
		},
		{
			name: "new session of a lost member has the same attachments",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA, prefixR), remoteEntry("x2", 11, prefixB))
				w.drain()
				w.lose("relay-a")
				w.open("relay-a")
				w.full("relay-a", remoteEntry("x", 10, prefixA, prefixR), remoteEntry("x2", 11, prefixB))
				w.pass(time.Minute)
			},
			routes: map[string]string{prefixA: "x@relay-a", prefixR: "x@relay-a", prefixB: "x2@relay-a"}, records: 1,
		},
		{
			name: "new session of a lost member has no full set in time",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA, prefixR), remoteEntry("x2", 11, prefixB))
				w.drain()
				w.lose("relay-a")
				w.open("relay-a")
				w.send("relay-a", remoteEntry("x2", 11, prefixB))
				w.pass(10 * time.Second)
			},
			routes: map[string]string{prefixB: "x2@relay-a"},
			delta:  []string{"-x " + prefixR, "-x " + prefixA}, records: 1,
		},
		{
			name: "new session of a lost member has no Presence call in time",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA, prefixR))
				w.send("relay-b", remoteEntry("y", 11, prefixB))
				w.drain()
				w.lose("relay-a")
				w.dial("relay-a", 3)
				w.pass(10 * time.Second)
			},
			routes: map[string]string{prefixB: "y@relay-b"},
			delta:  []string{"-x " + prefixR, "-x " + prefixA}, records: 1,
		},
		{
			name: "new session of a lost member ends before its full set",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA), remoteEntry("x2", 11, prefixB))
				w.drain()
				w.lose("relay-a")
				w.open("relay-a")
				w.send("relay-a", remoteEntry("x2", 11, prefixB))
				w.pass(5 * time.Second)
				w.lose("relay-a")
				w.pass(time.Minute)
			},
			routes: map[string]string{prefixA: "x@relay-a", prefixB: "x2@relay-a"}, records: 1,
		},
		{
			name: "full set of a new session with no attachment: the other relay gets the prefix",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 20, prefixR))
				w.send("relay-b", remoteEntry("y", 10, prefixR))
				w.drain()
				w.lose("relay-a")
				w.open("relay-a")
				w.full("relay-a")
			},
			routes: map[string]string{prefixR: "y@relay-b"},
			delta:  []string{"-x " + prefixR, "+y " + prefixR}, records: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newRouteWorld(t, NewRouter(nil, Config{}))
				w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
				w.session("local", vpcA, server, thisRevision())
				w.drain()

				tc.steps(w)
				if tc.routes == nil {
					tc.routes = map[string]string{}
				}
				assert.Equal(t, tc.routes, w.table(vpcA))
				assert.Equal(t, tc.delta, w.changes("watcher"))
				w.r.mu.RLock()
				assert.Len(t, w.r.remotes, tc.records, "records of sessions of other relays")
				w.r.mu.RUnlock()
				w.check()
			})
		})
	}
}

// TestMeshRouteSameActive checks that an entry that does not change the active
// announcer of a prefix makes no work for a session of an agent from before
// the standby list: no route change and no wake.
func TestMeshRouteSameActive(t *testing.T) {
	loser := func(w *routeWorld) { w.send("relay-b", remoteEntry("y", 10, prefixA)) }
	cases := []struct {
		name   string
		before func(w *routeWorld) // Runs after the entry x of relay-a has prefixA.
		step   func(w *routeWorld)
	}{
		{name: "standby entry comes", step: loser},
		{name: "standby entry ends", before: loser, step: func(w *routeWorld) { w.send("relay-b", goneAt("y", 11)) }},
		{name: "member with the other entry stops", before: loser, step: func(w *routeWorld) { w.restart("relay-b") }},
		{
			name: "entry comes again on a new session of its member",
			step: func(w *routeWorld) {
				w.open("relay-a")
				w.send("relay-a", remoteEntry("x", 20, prefixA))
			},
		},
		{
			name: "entry comes again in the full set of a new session of its member",
			step: func(w *routeWorld) {
				w.lose("relay-a")
				w.open("relay-a")
				w.full("relay-a", remoteEntry("x", 20, prefixA))
				w.pass(time.Minute)
			},
		},
		{
			name:   "entry for a prefix of an attachment of this relay",
			before: func(w *routeWorld) { w.attach("local", "l", prefixB) },
			step:   func(w *routeWorld) { w.send("relay-b", draining(remoteEntry("y", 30, prefixB))) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newRouteWorld(t, NewRouter(nil, Config{}))
				s := w.session("watcher", vpcA, agentID(vpcA, "watcher"), &dp.Hello{Version: &dp.Version{Revision: announcerRevision - 1}})
				w.session("local", vpcA, server, thisRevision())
				w.send("relay-a", remoteEntry("x", 20, prefixA))
				if tc.before != nil {
					tc.before(w)
				}
				w.drain()
				woken := func() bool {
					select {
					case <-s.wake:
						return true
					default:
						return false
					}
				}
				woken()
				routes := w.table(vpcA)

				tc.step(w)
				assert.False(t, woken(), "the session got a wake")
				assert.Empty(t, w.changes("watcher"))
				assert.Equal(t, routes, w.table(vpcA))
				w.check()
			})
		})
	}
}

// TestMeshRouteVPC checks that an entry gets routes only in a VPC that this
// relay knows from a Hello, and only with the network ID of that VPC.
func TestMeshRouteVPC(t *testing.T) {
	const other = testVNI + 1
	// in returns the entry x of relay-a with the network ID id.
	in := func(id uint32, prefixes ...string) *dp.Presence {
		e := remoteEntry("x", 10, prefixes...)
		e.Vpc.NetworkId = id
		return e
	}
	routed := map[string]string{prefixA: "x@relay-a"}
	type step struct {
		// One of: send is an entry of relay-a, hello is the network ID in the
		// Config of a new session, and join adds a session with no Hello.
		send  *dp.Presence
		hello uint32
		join  bool
		// refused is the number of attachments that the Hello refuses.
		refused int
		// delta are the route changes of the new session of a hello step.
		delta []string
	}
	cases := []struct {
		name   string
		steps  []step
		routes map[string]string
	}{
		{name: "no session of the VPC on this relay", steps: []step{{send: in(testVNI, prefixA)}}},
		{name: "session with no Hello", steps: []step{{join: true}, {send: in(testVNI, prefixA)}}},
		// A VPC with no Hello has no network ID, and that is not the ID 0.
		{name: "network ID 0 and no session of the VPC", steps: []step{{send: in(0, prefixA)}}},
		{name: "network ID 0 and a session with no Hello", steps: []step{{join: true}, {send: in(0, prefixA)}}},
		{
			name:   "network ID 0 in the entry and in the Hello",
			steps:  []step{{send: in(0, prefixA)}, {hello: 0, delta: []string{"+x " + prefixA}}},
			routes: routed,
		},
		{
			name:   "Hello after the entry",
			steps:  []step{{send: in(testVNI, prefixA)}, {hello: testVNI, delta: []string{"+x " + prefixA}}},
			routes: routed,
		},
		{
			name:   "Hello before the entry",
			steps:  []step{{hello: testVNI}, {send: in(testVNI, prefixA)}},
			routes: routed,
		},
		{
			name:   "second Hello",
			steps:  []step{{send: in(testVNI, prefixA)}, {hello: testVNI, delta: []string{"+x " + prefixA}}, {hello: testVNI, delta: []string{"+x " + prefixA}}},
			routes: routed,
		},
		{
			name:  "another network ID before the Hello",
			steps: []step{{send: in(other, prefixA, prefixR)}, {hello: testVNI, refused: 1}, {hello: testVNI}},
		},
		{name: "another network ID after the Hello", steps: []step{{hello: testVNI}, {send: in(other, prefixA)}}},
		{
			name: "entry with the network ID comes again after one with another ID",
			steps: []step{
				{hello: testVNI}, {send: in(other, prefixA)},
				{send: func() *dp.Presence { e := in(testVNI, prefixA); e.Generation = 11; return e }()},
			},
			routes: routed,
		},
		{
			name: "network ID of the VPC changes",
			steps: []step{
				{send: in(testVNI, prefixA)}, {hello: testVNI, delta: []string{"+x " + prefixA}},
				{hello: other, refused: 1},
			},
		},
		{
			name: "network ID of the VPC changes to the ID of the entry",
			steps: []step{
				{send: in(other, prefixA)}, {hello: testVNI, refused: 1},
				{hello: other, delta: []string{"+x " + prefixA}},
			},
			routes: routed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newRouteWorld(t, NewRouter(nil, Config{}))
			for i, st := range tc.steps {
				name := fmt.Sprintf("agent-%d", i)
				switch {
				case st.send != nil:
					w.send("relay-a", st.send)
				case st.join:
					w.join(name, vpcA, agentID(vpcA, name))
				default:
					s := w.join(name, vpcA, agentID(vpcA, name))
					h := thisRevision()
					require.NoError(t, w.r.checkRevision(s, h.GetVersion()))
					vpc := ref(vpcA)
					vpc.NetworkId = st.hello
					refused, err := w.r.startSync(s, dp.Mode_MODE_QUIC, vpc, h)
					require.NoError(t, err)
					assert.Equal(t, st.refused, refused, "attachments that step %d refuses", i)
					assert.Equal(t, st.delta, w.changes(name), "routes of the session of step %d", i)
				}
			}
			if tc.routes == nil {
				tc.routes = map[string]string{}
			}
			assert.Equal(t, tc.routes, w.table(vpcA))
			w.check()
		})
	}
}

// TestMeshRouteRefused checks which entries of a message make no route, and
// that each of them is refused one time.
func TestMeshRouteRefused(t *testing.T) {
	// with returns the entry x of relay-a after change.
	with := func(change func(e *dp.Presence)) *dp.Presence {
		e := remoteEntry("x", 10, prefixA)
		change(e)
		return e
	}
	cases := []struct {
		name  string
		entry *dp.Presence
		// known is false when no agent of the VPC sent Hello to this relay.
		known   bool
		refused string // Reason, or empty when the relay does not refuse the entry.
		route   bool
	}{
		{name: "good entry", entry: with(func(*dp.Presence) {}), known: true, route: true},
		{name: "VPC that this relay does not know", entry: with(func(*dp.Presence) {})},
		{
			name: "another network ID", known: true,
			entry:   with(func(e *dp.Presence) { e.Vpc.NetworkId = testVNI + 1 }),
			refused: fmt.Sprintf("network ID %d is not the ID %d of the VPC on this relay", testVNI+1, testVNI),
		},
		{
			name:  "another network ID in a VPC that this relay does not know",
			entry: with(func(e *dp.Presence) { e.Vpc.NetworkId = testVNI + 1 }),
		},
		{
			name: "subject of another VPC", known: true,
			entry:   with(func(e *dp.Presence) { e.Subject = agentID(VPCKey{Project: vpcA.Project, UID: "vpc-2"}, "laptop") }),
			refused: "is not in VPC project-a/vpc-1",
		},
		{
			name: "subject of another project", known: true,
			entry:   with(func(e *dp.Presence) { e.Subject = agentID(vpcB, "laptop") }),
			refused: "is not in VPC project-a/vpc-1",
		},
		{
			name: "subject that is not an agent ID", known: true,
			entry:   with(func(e *dp.Presence) { e.Subject = "laptop" }),
			refused: "subject",
		},
		{
			name: "VPC of another project with the subject of this one", known: true,
			entry:   with(func(e *dp.Presence) { e.Vpc = ref(vpcB) }),
			refused: "is not in VPC project-b/vpc-1",
		},
		{
			name: "more prefixes than the limit", known: true,
			entry: with(func(e *dp.Presence) {
				for i := range 64 {
					e.Prefixes = append(e.Prefixes, fmt.Sprintf("fd00:f:%x::/96", i))
				}
			}),
			refused: "65 prefixes, which is more than the limit 64",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newRouteWorld(t, NewRouter(nil, Config{}))
			if tc.known {
				w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
				w.session("b", vpcB, agentID(vpcB, "b"), thisRevision())
				w.drain()
			}
			// The message has the entry and a good entry of another attachment.
			var reasons []string
			refuse := func(id string, err error) { reasons = append(reasons, id+": "+err.Error()) }
			var changes []presenceChange
			for _, e := range []*dp.Presence{tc.entry, remoteEntry("good", 10, prefixB)} {
				pe, err := checkPresence(e)
				if err != nil {
					refuse(e.GetAttachmentId(), err)
					continue
				}
				pe.sess = w.mesh["relay-a"]
				changes = append(changes, presenceChange{pe, false})
			}
			require.NoError(t, w.m.pres.keep(w.mesh["relay-a"], changes, false, refuse))

			if tc.refused == "" {
				assert.Empty(t, reasons)
			} else if assert.Len(t, reasons, 1) {
				assert.Contains(t, reasons[0], "x: ")
				assert.Contains(t, reasons[0], tc.refused)
			}
			want := map[string]string{}
			if tc.known {
				want[prefixB] = "good@relay-a"
			}
			if tc.route {
				want[prefixA] = "x@relay-a"
			}
			assert.Equal(t, want, w.table(vpcA))
			assert.Empty(t, w.table(vpcB))
			if tc.known {
				assert.Empty(t, w.changes("b"), "routes of the agent of the other project")
			}
			w.check()
		})
	}
}

// TestMeshRouteDomains checks that the relay keeps nothing for a VPC after
// the entries of the other relays and its own sessions are gone.
func TestMeshRouteDomains(t *testing.T) {
	cases := []struct {
		name  string
		steps func(w *routeWorld)
		kept  bool // The relay keeps the VPC at the end.
	}{
		{name: "entry", steps: func(w *routeWorld) { w.send("relay-a", remoteEntry("x", 10, prefixA)) }, kept: true},
		{
			name: "entry ends",
			steps: func(w *routeWorld) {
				w.send("relay-a", remoteEntry("x", 10, prefixA, prefixR))
				w.send("relay-a", goneAt("x", 11))
			},
		},
		{name: "entry with no prefix", steps: func(w *routeWorld) { w.send("relay-a", remoteEntry("x", 10)) }},
		{
			name: "entry ends after the last session of the VPC",
			steps: func(w *routeWorld) {
				s := w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
				w.send("relay-a", remoteEntry("x", 10, prefixA))
				w.r.removeSession(s)
				w.send("relay-a", goneAt("x", 11))
			},
		},
		{
			name: "last session of the VPC closes after the entry ends",
			steps: func(w *routeWorld) {
				s := w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
				w.send("relay-a", remoteEntry("x", 10, prefixA))
				w.send("relay-a", goneAt("x", 11))
				w.r.removeSession(s)
			},
		},
		{
			name: "last session of the VPC closes and the entry stays",
			steps: func(w *routeWorld) {
				s := w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
				w.send("relay-a", remoteEntry("x", 10, prefixA))
				w.r.removeSession(s)
			},
			kept: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newRouteWorld(t, NewRouter(nil, Config{}))
			tc.steps(w)
			w.r.mu.RLock()
			_, kept := w.r.domains[vpcA]
			records := len(w.r.remotes)
			w.r.mu.RUnlock()
			assert.Equal(t, tc.kept, kept, "the relay keeps the VPC")
			if !tc.kept {
				assert.Zero(t, records, "records of sessions of other relays")
			}
			w.check()
		})
	}
}

// TestMeshRouteSessions checks which sessions get the route of an attachment
// of another relay, by the revision, the Hello option and the agent.
func TestMeshRouteSessions(t *testing.T) {
	this := dp.LocalVersion("test")
	watcher := agentID(vpcA, "watcher")
	cases := []struct {
		name    string
		subject string // SPIFFE ID of the session.
		hello   *dp.Hello
		agent   string // Agent name in the entry of the other relay.
		gets    bool   // The session gets the route of the other relay.
	}{
		{name: "this revision", subject: watcher, hello: &dp.Hello{Version: this}, agent: "base", gets: true},
		{name: "later revision", subject: watcher, hello: &dp.Hello{Version: &dp.Version{Revision: dp.Revision + 1}}, agent: "base", gets: true},
		{name: "first revision with the routes", subject: watcher, hello: &dp.Hello{Version: &dp.Version{Revision: 6}}, agent: "base", gets: true},
		{name: "revision 5", subject: watcher, hello: &dp.Hello{Version: &dp.Version{Revision: 5}}, agent: "base"},
		{name: "before revisions", subject: watcher, hello: &dp.Hello{}, agent: "base"},
		{name: "local routes only", subject: watcher, hello: &dp.Hello{Version: this, LocalRoutesOnly: true}, agent: "base"},
		{name: "local routes only at revision 5", subject: watcher, hello: &dp.Hello{Version: &dp.Version{Revision: 5}, LocalRoutesOnly: true}, agent: "base"},
		{name: "same agent", subject: laptop, hello: &dp.Hello{Version: this, Name: "base"}, agent: "base"},
		{name: "another agent of the subject", subject: laptop, hello: &dp.Hello{Version: this, Name: "second"}, agent: "base", gets: true},
		{name: "same agent with another instance", subject: laptop, hello: &dp.Hello{Version: this, Name: "base", Instance: 7}, agent: "base", gets: true},
		{name: "session of the subject with no name", subject: laptop, hello: &dp.Hello{Version: this}, agent: "base", gets: true},
		{name: "entry of the subject with no name", subject: laptop, hello: &dp.Hello{Version: this, Name: "base"}, agent: "", gets: true},
		{name: "same name with another subject", subject: watcher, hello: &dp.Hello{Version: this, Name: "base"}, agent: "base", gets: true},
		{name: "another agent of the subject with local routes only", subject: laptop, hello: &dp.Hello{Version: this, Name: "second", LocalRoutesOnly: true}, agent: "base"},
	}
	for _, tc := range cases {
		for _, first := range []string{"session", "entry"} {
			t.Run(tc.name+"/"+first+" first", func(t *testing.T) {
				w := newRouteWorld(t, NewRouter(nil, Config{}))
				w.session("local", vpcA, server, thisRevision())
				w.attach("local", "y", prefixB)
				entry := remoteEntry("x", 10, prefixA)
				entry.AgentName = tc.agent
				far, near := "+x "+prefixA, "+y "+prefixB

				var got []string
				if first == "entry" {
					w.send("relay-a", entry)
					w.session("s", vpcA, tc.subject, tc.hello)
					got = w.changes("s")
				} else {
					w.session("s", vpcA, tc.subject, tc.hello)
					require.Equal(t, []string{near}, w.changes("s"), "routes at the Hello")
					w.send("relay-a", entry)
					got = append([]string{near}, w.changes("s")...)
					slices.Sort(got)
				}
				want := []string{near}
				if tc.gets {
					want = []string{far, near}
				}
				assert.Equal(t, want, got, "routes of the session")

				// The route goes only from a session that has it.
				w.send("relay-a", goneAt("x", 11))
				var gone []string
				if tc.gets {
					gone = []string{"-x " + prefixA}
				}
				assert.Equal(t, gone, w.changes("s"), "changes at the end of the attachment")

				// Only an announcer of a prefix can send from it, not each session of its subject.
				w.send("relay-a", func() *dp.Presence { e := remoteEntry("x", 12, prefixA); e.AgentName = tc.agent; return e }())
				src := netip.MustParsePrefix(prefixA).Addr().Next()
				assert.False(t, w.sess["s"].sources(src), "the session can send from the prefix")
				w.check()
			})
		}
	}
}

// TestMeshRouteNotReachable sends to an address of another relay: each call gets
// "no route", and each packet drops. That relay is too old to get a packet.
func TestMeshRouteNotReachable(t *testing.T) {
	const (
		quicAddr = "fd00:1::1" // Address of the sender in QUIC mode.
		pspAddr  = "fd00:2::1" // Address of the sender in PSP mode.
	)
	cases := []struct {
		name   string
		dst    string
		local  bool // An attachment of this relay has dst.
		member bool // An attachment of relay-a has dst.
	}{
		{name: "address on this relay", dst: "fd00:3::1", local: true},
		{name: "address on another relay", dst: "fd00:a::1", member: true},
		{name: "advertised route of another relay", dst: "fd00:8::1", member: true},
		{name: "route of another relay in a route of this relay", dst: "fd00:9:0:7::1", member: true},
		{name: "route of this relay around a route of another relay", dst: "fd00:9:0:8::1", local: true},
		{name: "address with no route", dst: "fd00:f::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, handle := localRouter(t)
			w := newRouteWorld(t, r)
			q := localSession(t, r, "q", "192.0.2.1:1", "fd00:1::/96", dp.Mode_MODE_QUIC)
			p := localSession(t, r, "p", "192.0.2.2:1", "fd00:2::/96", dp.Mode_MODE_PSP)
			l := localSession(t, r, "l", "192.0.2.3:1", "fd00:3::/96", dp.Mode_MODE_QUIC)
			require.NoError(t, r.AddRoute(l, netip.MustParsePrefix("fd00:9::/48"), "att-l"))
			w.send("relay-a", remoteEntry("x", 10, prefixA, "fd00:8::/64", "fd00:9:0:7::/64"))
			var got [][]byte
			l.sendDatagram = func(b []byte) error {
				got = append(got, slices.Clone(b))
				return nil
			}
			now := time.Now()
			offer, err := r.offer(p, Network{ID: testVNI, MTU: 1280}, now)
			require.NoError(t, err)
			pspSender := newPSPAgent(t, offer.GetRekey(), now)
			for _, s := range []*Session{q, p, l} {
				r.takeSync(s)
			}
			dst := netip.MustParseAddr(tc.dst)
			// noRoutes returns the addresses of the NoRoute messages that wait for s.
			noRoutes := func(s *Session) []string {
				var out []string
				for _, m := range r.takeSync(s) {
					if nr := m.GetNoRoute(); nr != nil {
						out = append(out, nr.GetAddress())
					}
				}
				return out
			}
			// tells checks that s got one NoRoute for dst if want is true, or else none.
			tells := func(want bool, s *Session, path string) {
				t.Helper()
				var addrs []string
				if want {
					addrs = []string{tc.dst}
				}
				assert.Equal(t, addrs, noRoutes(s), "NoRoute after %s", path)
				r.mu.Lock()
				clear(s.sync.noRoute)
				r.mu.Unlock()
			}
			res, err := r.resolvePeer(q, &dp.ResolvePeerRequest{Vpc: ref(vpcA), Address: tc.dst})
			if tc.local {
				require.NoError(t, err)
				assert.Equal(t, dp.Reach_REACH_LOCAL, res.GetReach())
				assert.Equal(t, "l", res.GetSubject())
			} else {
				assert.Equal(t, rpc.NotFound, rpc.CodeOf(err), "ResolvePeer: %v, %v", res, err)
				assert.ErrorContains(t, err, "no route to "+tc.dst)
			}

			err = r.registerSPI(q, register(vpcA, tc.dst, time.Minute, 7), t0)
			r.mu.RLock()
			row := q.rows[7]
			r.mu.RUnlock()
			if tc.local {
				require.NoError(t, err)
				require.NotNil(t, row)
				assert.Same(t, l, row.receiver)
				to, verdict := r.Forward(netip.MustParseAddrPort("192.0.2.1:1"), 7, 100, t0)
				assert.Equal(t, Pass, verdict)
				assert.Equal(t, netip.MustParseAddrPort("192.0.2.3:1"), to)
			} else {
				assert.Equal(t, rpc.NotFound, rpc.CodeOf(err), "RegisterSPI: %v", err)
				assert.ErrorContains(t, err, "no route to "+tc.dst)
				assert.Nil(t, row, "row to the address")
				_, verdict := r.Forward(netip.MustParseAddrPort("192.0.2.1:1"), 7, 100, t0)
				assert.Equal(t, DropUnknownSPI, verdict)
			}

			next := r.Route(q, dst, t0)
			if tc.local {
				assert.Same(t, l, next)
			} else {
				assert.Nil(t, next, "session for the address")
			}
			tells(!tc.local && !tc.member, q, "Route")

			// A peer frame, a data frame and a PSP packet to the relay. The address
			// of each one for relay-a has a route, so the sender gets no NoRoute.
			sent := r.forwardDatagram(q, peerFrame(dst, netip.MustParseAddr(quicAddr), "hi"), t0)
			assert.Equal(t, tc.local, sent, "peer frame")
			tells(!tc.local && !tc.member, q, "a peer frame")
			assert.Equal(t, tc.member, r.drops[dropMeshOldMember].Load() == 1, "the peer frame was for relay-a")

			inner := ipPacket(netip.MustParseAddr(quicAddr), dst, []byte("data"))
			sent = r.forwardData(q, peerconn.EncodeData(nil, testVNI, inner), make([]byte, maxUDP), t0)
			assert.Equal(t, tc.local, sent, "data frame")
			tells(!tc.local && !tc.member, q, "a data frame")

			inner = ipPacket(netip.MustParseAddr(pspAddr), dst, []byte("data"))
			handle(pspSender.seal(t, inner), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.2:1")))
			tells(!tc.local && !tc.member, p, "a PSP packet")

			if tc.local {
				assert.Len(t, got, 3, "frames that the session of this relay gets")
				assert.Zero(t, q.dataDrops.Load()+p.dataDrops.Load(), "drops")
			} else {
				assert.Empty(t, got, "frames that the session of this relay gets")
				assert.Equal(t, uint64(1), q.dataDrops.Load(), "drops of the data frames")
				assert.Equal(t, uint64(1), p.dataDrops.Load(), "drops of the PSP packets")
			}
			r.mu.RLock()
			h := r.nextHop(q, inner)
			r.mu.RUnlock()
			if tc.local {
				assert.Same(t, l, h.next)
			} else {
				assert.Nil(t, h.next, "next hop")
			}
			w.check()
		})
	}
}

// routeRelay is a relay of the tests with two relays: a mesh node, its router,
// and the routes that each of its sessions has from Sync.
type routeRelay struct {
	n *meshNode
	r *Router

	mu sync.Mutex
	// seen has the routes of each session: "origin prefix" to its standby list.
	seen map[*Session]map[string]string
}

func newRouteRelay(t *testing.T, ca *testCA, name string) *routeRelay {
	t.Helper()
	rr := &routeRelay{n: newMeshNode(t, ca, name), r: NewRouter(nil, Config{}), seen: map[*Session]map[string]string{}}
	rr.n.m.SetRouter(rr.r)
	return rr
}

// session opens a session of agent in vpcA with a Session call that starts with h.
func (rr *routeRelay) session(t *testing.T, agent, addr string, h *dp.Hello) *Session {
	t.Helper()
	s, err := rr.open(t, agent, addr, h)
	require.NoError(t, err)
	return s
}

// open is session with the error of the Session call, for a goroutine that is
// not the one of the test.
func (rr *routeRelay) open(t *testing.T, agent, addr string, h *dp.Hello) (*Session, error) {
	s := addSession(t, rr.r, vpcA, agentID(vpcA, agent), addr).Session
	if err := rr.r.checkRevision(s, h.GetVersion()); err != nil {
		return nil, err
	}
	return s, rr.r.openSync(s, dp.Mode_MODE_QUIC, ref(vpcA), h)
}

// routes applies the route changes that wait for s, and returns the routes
// that s has: "origin prefix", sorted.
func (rr *routeRelay) routes(t *testing.T, s *Session) []string {
	t.Helper()
	rr.mu.Lock()
	defer rr.mu.Unlock()
	have := rr.seen[s]
	if have == nil {
		have = map[string]string{}
		rr.seen[s] = have
	}
	for _, c := range routeChanges(rr.r, s) {
		rt, standby, _ := strings.Cut(c[1:], " standby=")
		old, had := have[rt]
		if c[0] == '+' {
			// A route that the session has comes again only with a new standby list.
			assert.False(t, had && old == standby, "the route %q comes two times", c[1:])
			have[rt] = standby
		} else {
			assert.True(t, had, "the route %q goes, and the session does not have it", rt)
			delete(have, rt)
		}
	}
	return slices.Sorted(maps.Keys(have))
}

// has waits until s has the routes want.
func (rr *routeRelay) has(t *testing.T, s *Session, want ...string) {
	t.Helper()
	slices.Sort(want)
	var got []string
	if !assert.Eventually(t, func() bool {
		got = rr.routes(t, s)
		return slices.Equal(want, got)
	}, 10*time.Second, 5*time.Millisecond) {
		require.Equal(t, want, got, "routes of the session of %s on %s", s.id.ID, rr.n.name)
	}
}

// TestMeshRoutesBetweenRelays runs two relays with agent sessions. A session
// gets the routes of the other relay, and loses them at a detach and a stop.
func TestMeshRoutesBetweenRelays(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	a, b := newRouteRelay(t, ca, "relay-a"), newRouteRelay(t, ca, "relay-b")
	sa := a.session(t, "laptop", "192.0.2.1:1000", &dp.Hello{Version: dp.LocalVersion("test"), Name: "base"})
	sb := b.session(t, "server", "192.0.2.2:1000", thisRevision())
	// These sessions of relay-b get no route of relay-a: an agent with one
	// session for each relay, an agent from before the routes, and laptop.
	each := b.session(t, "vtep", "192.0.2.3:1000", &dp.Hello{Version: dp.LocalVersion("test"), LocalRoutesOnly: true})
	old := b.session(t, "old", "192.0.2.4:1000", &dp.Hello{Version: &dp.Version{Revision: 5}})
	second := b.session(t, "laptop", "192.0.2.5:1000", &dp.Hello{Version: dp.LocalVersion("test"), Name: "base"})
	att := func(id, addr string, routes ...string) *Attachment {
		at := attachment(id, addr)
		for _, p := range routes {
			at.Routes = append(at.Routes, netip.MustParsePrefix(p))
		}
		return at
	}

	// An attachment from before the mesh session is in the full set.
	require.NoError(t, a.r.attach(sa, att("x", "fd00:1::/96", prefixR)))
	a.n.m.SetMembers([]MeshMember{b.n.member()})
	b.n.m.SetMembers([]MeshMember{a.n.member()})
	b.n.start(t)
	a.n.start(t)
	b.has(t, sb, "x fd00:1::/96", "x "+prefixR)
	a.has(t, sa)
	require.NoError(t, b.r.attach(sb, att("y", "fd00:2::/96")))
	a.has(t, sa, "y fd00:2::/96")
	local := []string{"y fd00:2::/96"}
	b.has(t, each, local...)
	b.has(t, old, local...)
	b.has(t, second, local...)
	assert.Equal(t, map[string]string{"fd00:1::/96": "x@relay-a", prefixR: "x@relay-a", "fd00:2::/96": "y"}, routeTable(b.r, vpcA))
	assert.Equal(t, map[string]string{"fd00:1::/96": "x", prefixR: "x", "fd00:2::/96": "y@relay-b"}, routeTable(a.r, vpcA))

	// The advertised route moves to a new attachment of the agent on relay-a.
	require.NoError(t, a.r.attach(sa, att("x2", "fd00:3::/96", prefixR)))
	b.has(t, sb, "x fd00:1::/96", "x2 fd00:3::/96", "x2 "+prefixR)
	_, _, err := a.r.detach(sa, "x")
	require.NoError(t, err)
	b.has(t, sb, "x2 fd00:3::/96", "x2 "+prefixR)
	_, _, err = b.r.detach(sb, "y")
	require.NoError(t, err)
	a.has(t, sa)

	// relay-a stops. The agents of relay-b lose its routes at once.
	a.n.cancel()
	b.has(t, sb)
	assert.Empty(t, routeTable(b.r, vpcA))
	for _, s := range []*Session{each, old, second} {
		assert.Empty(t, b.routes(t, s), "routes of the session of %s", s.id.ID)
	}
}

// TestMeshRoutesConverge changes the attachments of two relays from many
// goroutines. At the end the relays and the sessions have the same routes.
func TestMeshRoutesConverge(t *testing.T) {
	t.Parallel()
	const (
		writers  = 4
		attaches = 30
	)
	ca := newCA(t)
	relays := []*routeRelay{newRouteRelay(t, ca, "relay-a"), newRouteRelay(t, ca, "relay-b")}
	relays[0].n.m.SetMembers([]MeshMember{relays[1].n.member()})
	relays[1].n.m.SetMembers([]MeshMember{relays[0].n.member()})
	relays[1].n.start(t)
	relays[0].n.start(t)

	// writer is an agent that attaches on its relay. Its attachment IDs start
	// with own, and it keeps each second attachment.
	type writer struct {
		s   *Session
		own string
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	kept := make([]map[string]string, len(relays)) // Attachment ID of each prefix that stays.
	agents := make([][]writer, len(relays))
	for i, rr := range relays {
		kept[i] = map[string]string{}
		for n := range writers {
			wr := writer{
				s:   rr.session(t, fmt.Sprintf("agent-%d-%d", i, n), fmt.Sprintf("192.0.%d.%d:1000", 2+i, 1+n), thisRevision()),
				own: fmt.Sprintf("%s-%d-", rr.n.name, n),
			}
			agents[i] = append(agents[i], wr)
			wg.Go(func() {
				for k := range attaches {
					id := fmt.Sprintf("%s%d", wr.own, k)
					prefix := netip.MustParsePrefix(fmt.Sprintf("fd00:%x:%x:%x::/96", i+1, n+1, k+1)).String()
					if !assert.NoError(t, rr.r.attach(wr.s, attachment(id, prefix))) {
						return
					}
					if k%2 == 1 {
						if _, _, err := rr.r.detach(wr.s, id); !assert.NoError(t, err) {
							return
						}
						continue
					}
					mu.Lock()
					kept[i][prefix] = id
					mu.Unlock()
				}
			})
		}
		// Sessions open and close during the changes.
		wg.Go(func() {
			for k := range attaches {
				s, err := rr.open(t, fmt.Sprintf("short-%d-%d", i, k), fmt.Sprintf("192.0.%d.200:%d", 2+i, 1000+k), thisRevision())
				if !assert.NoError(t, err) {
					return
				}
				rr.routes(t, s)
				rr.r.removeSession(s)
			}
		})
	}
	wg.Wait()

	for i, rr := range relays {
		other := relays[1-i]
		table := map[string]string{}
		var all []string
		for p, id := range kept[i] {
			table[p] = id
			all = append(all, id+" "+p)
		}
		for p, id := range kept[1-i] {
			table[p] = id + "@" + other.n.name
			all = append(all, id+" "+p)
		}
		var got map[string]string
		if !assert.Eventually(t, func() bool {
			got = routeTable(rr.r, vpcA)
			return maps.Equal(table, got)
		}, 20*time.Second, 10*time.Millisecond) {
			require.Equal(t, table, got, "routes of %s", rr.n.name)
		}
		// Each agent has each route but the routes of its own attachments.
		for _, wr := range agents[i] {
			rr.has(t, wr.s, slices.DeleteFunc(slices.Clone(all), func(rt string) bool { return strings.HasPrefix(rt, wr.own) })...)
		}
		// A session that opens now gets each route in its first RouteDelta.
		rr.has(t, rr.session(t, "late", fmt.Sprintf("192.0.%d.250:1000", 2+i), thisRevision()), all...)
	}
}

// TestMeshRouteRowsNewSession gives relay-a a new session while an SPI row goes
// to its agent. The row stays only if the attachment comes again in time.
func TestMeshRouteRowsNewSession(t *testing.T) {
	const fullSetTime = 10 * time.Second
	cases := []struct {
		name  string
		call  bool          // The new session has a Presence call.
		again bool          // It sends the attachment of the receiver again.
		end   bool          // It ends its full set.
		wait  time.Duration // Time after the new session opened.
		stays bool          // The relay has the row at the end.
	}{
		{name: "full set has the attachment", call: true, again: true, end: true, wait: time.Minute, stays: true},
		{name: "attachment comes again, and the full set does not end", call: true, again: true, wait: time.Minute, stays: true},
		{name: "full set does not have the attachment", call: true, end: true},
		{name: "full set does not end: before the time limit", call: true, wait: fullSetTime - time.Nanosecond, stays: true},
		{name: "full set does not end in time", call: true, wait: fullSetTime},
		{name: "no Presence call: before the time limit", wait: fullSetTime - time.Nanosecond, stays: true},
		{name: "no Presence call in time", wait: fullSetTime},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				g.start()
				require.NoError(t, g.register(rowDst, rowTTL, 5))

				// The next session opens before relay-a is down, so its keys stay.
				g.end(g.sess, &quic.IdleTimeoutError{})
				time.Sleep(time.Second)
				if tc.call {
					g.join(trunkRevision)
				} else {
					g.sess = g.open(trunkRevision)
					g.deliver()
				}
				g.a.take()
				_, v := g.verdict(5)
				require.Equal(t, Pass, v, "the row works before the full set of the new session")

				if tc.again {
					g.announce(entryOf("x", server, 7, 10))
				}
				if tc.end {
					require.NoError(t, g.m.pres.apply(g.sess, &dp.PresenceUpdate{EndOfFullSet: true}))
				}
				time.Sleep(tc.wait)
				synctest.Wait()

				_, ok := g.row(5)
				_, v = g.verdict(5)
				var told [][]*dp.SPIRow
				if tc.stays {
					assert.True(t, ok, "row")
					assert.Equal(t, Pass, v)
					assert.Equal(t, 1, g.inbound(), "rows to the sessions of other relays")
				} else {
					assert.False(t, ok, "row")
					assert.Equal(t, DropUnknownSPI, v)
					assert.Zero(t, g.inbound(), "rows to the sessions of other relays")
					told = [][]*dp.SPIRow{{goneRow(5)}}
				}
				assert.Empty(t, diffRows(told, g.a.take()), "rows that relay-a gets")
			})
		})
	}
}

// TestMeshLostMemberLeaves changes the member set after relay-a was lost. The
// relay drops the attachments of relay-a and the SPI rows that relay-a gave.
func TestMeshLostMemberLeaves(t *testing.T) {
	cases := []struct {
		name    string
		members []MeshMember // Member set after the loss.
	}{
		{name: "member leaves the member set"},
		{name: "member gets a new address", members: []MeshMember{{Name: "relay-a", Addr: netip.MustParseAddrPort("198.51.100.7:6081")}}},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				g.serve()
				g.give(serverRow(5, inTTL))
				g.passes(5, rowSrc, "packet before the loss")

				// A lost member keeps its attachments and its rows.
				g.end(g.sess, meshLost)
				time.Sleep(10 * time.Second)
				g.deliver()
				rows, _ := g.kept()
				require.Equal(t, 1, rows, "rows of relay-a")
				require.Equal(t, []string{"x"}, presenceIDs(g.m, "relay-a"))
				require.Equal(t, "x@relay-a", routeTable(g.r, vpcA)[prefixA])

				g.m.SetMembers(tc.members)
				g.deliver()
				_, ok := g.kept()
				assert.False(t, ok, "the relay keeps a row set of relay-a")
				assert.Empty(t, presenceIDs(g.m, "relay-a"))
				assert.NotContains(t, routeTable(g.r, vpcA), prefixA)
				checkEntries(t, g.m)
			})
		})
	}
}

// TestMeshRowSenderFullSetTime checks a row of the session before, when the
// time for the full set of a new session ends and no route changes.
func TestMeshRowSenderFullSetTime(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		g.connect()
		require.NoError(t, g.tk.rowsFrom(g.sess))
		// The entry of the sender has no prefix, so it gives no route.
		g.announce(atGen(liveEntry("x", server, "", inTag), 10))
		g.give(serverRow(5, inTTL))
		g.end(g.sess, meshLost)
		// The hooks of the new session do not run, so the row and the keys stay.
		s := g.open(trunkRevision)
		g.passes(5, rowSrc, "packet before the time limit")
		g.m.pres.expire(s)
		g.drops(5, "trunk_sender", "packet after the time limit")
		assert.Empty(t, presenceIDs(g.m, "relay-a"))
	})
}

// TestMeshRoutesAfterLoss ends the mesh session of two relays that run. The
// routes stay, and the next full set removes those of attachments that ended.
func TestMeshRoutesAfterLoss(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	a, b := newRouteRelay(t, ca, "relay-a"), newRouteRelay(t, ca, "relay-b")
	sa := a.session(t, "laptop", "192.0.2.1:1000", thisRevision())
	sb := b.session(t, "server", "192.0.2.2:1000", thisRevision())
	require.NoError(t, a.r.attach(sa, attachment("x", "fd00:1::/96")))
	require.NoError(t, a.r.attach(sa, attachment("x2", "fd00:2::/96")))
	a.n.m.SetMembers([]MeshMember{b.n.member()})
	b.n.m.SetMembers([]MeshMember{a.n.member()})
	b.n.start(t)
	a.n.start(t)
	require.Equal(t, MeshChange{Name: "relay-a", Up: true}, b.n.change(t, 10*time.Second))
	b.has(t, sb, "x fd00:1::/96", "x2 fd00:2::/96")

	// relay-a closes the session and does not dial: it has no member now.
	// relay-b has relay-a as down 3 s later.
	a.n.m.SetMembers(nil)
	require.Equal(t, MeshChange{Name: "relay-a", Down: MeshLost}, b.n.change(t, 10*time.Second))
	assert.Empty(t, routeChanges(b.r, sb), "route changes for a relay that is down")
	assert.Equal(t, map[string]string{"fd00:1::/96": "x@relay-a", "fd00:2::/96": "x2@relay-a"}, routeTable(b.r, vpcA))

	// One attachment of relay-a ends and one comes while it has no session.
	_, _, err := a.r.detach(sa, "x2")
	require.NoError(t, err)
	require.NoError(t, a.r.attach(sa, attachment("x3", "fd00:3::/96")))
	a.n.m.SetMembers([]MeshMember{b.n.member()})
	want := map[string]string{"fd00:1::/96": "x@relay-a", "fd00:3::/96": "x3@relay-a"}
	require.Eventually(t, func() bool { return maps.Equal(want, routeTable(b.r, vpcA)) }, 10*time.Second, 5*time.Millisecond)
	// The route of x did not go and come again.
	assert.ElementsMatch(t, []string{"+x3 fd00:3::/96", "-x2 fd00:2::/96"}, routeChanges(b.r, sb))
	entries, full := presenceEntries(b.n.m, "relay-a")
	assert.True(t, full, "the full set of the new session is complete")
	assert.Len(t, entries, 2)
	checkEntries(t, b.n.m)
}

// entryState returns the state of the entry of the attachment origin for
// prefix in vpcA of r. ok is false with no such entry.
func entryState(r *Router, prefix, origin string) (state dp.AnnouncerState, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d := r.domains[vpcA]
	if d == nil || d.routes[netip.MustParsePrefix(prefix)] == nil {
		return 0, false
	}
	for _, e := range d.routes[netip.MustParsePrefix(prefix)].entries {
		if e.origin == origin {
			return e.state, true
		}
	}
	return 0, false
}

// TestMemberLost checks the entries of a member that is lost: they are suspect
// on this relay from the down change, normal again when a new session of the
// member sends them, and gone when the member is still down after
// memberLostTime or leaves the member set. The agent laptop has the attachment
// x on relay-a, with the lower rank, and the attachment y on relay-b. lose
// gives the relay the down change one minute after the session ended.
func TestMemberLost(t *testing.T) {
	x := func(gen uint64) *dp.Presence { return remoteEntry("x", gen, prefixA, prefixR) }
	lostOrder, normalOrder := []string{"y@relay-b", "x@relay-a"}, []string{"x@relay-a", "y@relay-b"}
	toStandby := []string{"-x " + prefixR, "+y " + prefixR + " standby=x"}
	cases := []struct {
		name  string
		steps func(w *routeWorld)
		order []string // Announcers of prefixR at the end, in the order of selection.
		state dp.AnnouncerState
		gone  bool     // The entries of relay-a are gone at the end.
		delta []string // Changes that the watcher gets in steps.
	}{
		{
			name:  "lost member: its entries are suspect",
			steps: func(w *routeWorld) { w.lose("relay-a") },
			order: lostOrder, state: stateSuspect, delta: toStandby,
		},
		{
			name: "session that ends is not a lost member before the down change",
			steps: func(w *routeWorld) {
				w.conns["relay-a"].cancel(&quic.IdleTimeoutError{})
				w.pass(meshDownAfter - time.Nanosecond)
			},
			order: normalOrder,
		},
		{
			name: "new session sends the entry again: normal",
			steps: func(w *routeWorld) {
				w.lose("relay-a")
				w.open("relay-a")
				w.full("relay-a", x(10))
			},
			order: normalOrder,
		},
		{
			name: "new session sends the entry with a new generation: normal",
			steps: func(w *routeWorld) {
				w.lose("relay-a")
				w.open("relay-a")
				e := x(30)
				e.Attached = 10
				w.send("relay-a", e)
			},
			order: normalOrder,
		},
		{
			name: "new session sends the entry in the draining state: draining",
			steps: func(w *routeWorld) {
				w.lose("relay-a")
				w.open("relay-a")
				e := draining(x(30))
				e.Attached = 10
				w.send("relay-a", e)
			},
			order: lostOrder, state: stateDraining, delta: toStandby,
		},
		{
			name: "new session did not send the entry yet: suspect",
			steps: func(w *routeWorld) {
				w.lose("relay-a")
				w.open("relay-a")
				w.pass(presenceFullSetTime - time.Nanosecond)
			},
			order: lostOrder, state: stateSuspect, delta: toStandby,
		},
		{
			name: "member is down for less than memberLostTime: the entries stay",
			steps: func(w *routeWorld) {
				w.lose("relay-a")
				w.pass(memberLostTime - time.Nanosecond)
			},
			order: lostOrder, state: stateSuspect, delta: toStandby,
		},
		{
			name: "member is down for memberLostTime: the entries go",
			steps: func(w *routeWorld) {
				w.lose("relay-a")
				w.pass(memberLostTime)
			},
			order: []string{"y@relay-b"}, gone: true,
			delta: []string{"-x " + prefixR, "+y " + prefixR, "-x " + prefixA},
		},
		{
			name: "member came back and is lost again: the time starts again",
			steps: func(w *routeWorld) {
				w.lose("relay-a")
				w.open("relay-a")
				w.full("relay-a", x(10))
				w.pass(time.Minute)
				w.lose("relay-a")
				// The time of the first loss ends now.
				w.pass(memberLostTime - 2*time.Minute)
			},
			order: lostOrder, state: stateSuspect, delta: toStandby,
		},
		{
			name: "member came back and is down again for memberLostTime: the entries go",
			steps: func(w *routeWorld) {
				w.lose("relay-a")
				w.open("relay-a")
				w.full("relay-a", x(10))
				w.pass(time.Minute)
				w.lose("relay-a")
				w.pass(memberLostTime)
			},
			order: []string{"y@relay-b"}, gone: true,
			delta: []string{"-x " + prefixR, "+y " + prefixR, "-x " + prefixA},
		},
		{
			name: "lost member leaves the member set: the entries go at once",
			steps: func(w *routeWorld) {
				w.lose("relay-a")
				w.leave("relay-a")
			},
			order: []string{"y@relay-b"}, gone: true,
			delta: []string{"-x " + prefixR, "+y " + prefixR, "-x " + prefixA},
		},
		{
			name: "lost member comes back as a new relay process: the entries go at once",
			steps: func(w *routeWorld) {
				w.lose("relay-a")
				w.open("relay-a")
				w.restart("relay-a")
			},
			order: []string{"y@relay-b"}, gone: true,
			delta: []string{"-x " + prefixR, "+y " + prefixR, "-x " + prefixA},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newRouteWorld(t, NewRouter(nil, Config{}))
				w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
				// No other relay gets the state that this relay gives to the entries.
				var sent []*dp.Presence
				w.r.mu.Lock()
				w.r.presence = func(e *dp.Presence) { sent = append(sent, e) }
				w.r.mu.Unlock()
				w.send("relay-a", x(10))
				w.send("relay-b", ranked(remoteEntry("y", 10, prefixR), 1))
				require.Equal(t, normalOrder, entriesOf(w.r, prefixR))
				w.drain()

				tc.steps(w)
				assert.Equal(t, tc.order, entriesOf(w.r, prefixR))
				assert.ElementsMatch(t, tc.delta, w.changes("watcher"))
				assert.Empty(t, sent, "entries that the relay sent")
				for _, p := range []string{prefixA, prefixR} {
					state, ok := entryState(w.r, p, "x")
					assert.Equal(t, !tc.gone, ok, "entry of x for %s", p)
					assert.Equal(t, tc.state, state, "state of x for %s", p)
				}
				// The address of x has one announcer: its route stays while the entry stays.
				_, has := w.table(vpcA)[prefixA]
				assert.Equal(t, !tc.gone, has, "route of the address of x")
				w.check()
			})
		})
	}
}

// TestMemberLostTimer checks the timer of memberLostTime of a member: only the
// one of its last loss runs, and none runs after the member is back or gone.
func TestMemberLostTimer(t *testing.T) {
	lose := func(w *routeWorld) { w.lose("relay-a") }
	back := func(w *routeWorld) {
		w.open("relay-a")
		w.pass(0)
	}
	leave := func(w *routeWorld) { w.leave("relay-a") }
	cases := []struct {
		name  string
		steps []func(w *routeWorld)
		runs  bool // A timer runs at the end.
	}{
		{name: "lost member", steps: []func(w *routeWorld){lose}, runs: true},
		{name: "member came back", steps: []func(w *routeWorld){lose, back}},
		{name: "member came back and is lost again", steps: []func(w *routeWorld){lose, back, lose}, runs: true},
		{name: "lost member leaves the member set", steps: []func(w *routeWorld){lose, leave}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newRouteWorld(t, NewRouter(nil, Config{}))
				timer := func() *time.Timer {
					w.m.pres.mu.Lock()
					defer w.m.pres.mu.Unlock()
					if in := w.m.pres.in["relay-a"]; in != nil {
						return in.lostTimer
					}
					return nil
				}
				var cur *time.Timer
				var before []*time.Timer
				for _, step := range tc.steps {
					step(w)
					if next := timer(); next != cur {
						if cur != nil {
							before = append(before, cur)
						}
						cur = next
					}
				}
				assert.Equal(t, tc.runs, cur != nil, "timer of the last loss")
				for _, tm := range before {
					assert.False(t, tm.Stop(), "a timer from before runs")
				}
			})
		})
	}
}

// TestPresenceStateChange checks an entry of a member that comes again with a
// higher generation. With only a new state it changes in place: the relay
// keeps the entry and its routes. With other new data it is a new entry.
func TestPresenceStateChange(t *testing.T) {
	next := func(gen uint64, change func(e *dp.Presence)) *dp.Presence {
		e := remoteEntry("x", gen, prefixA, prefixR)
		e.Attached = 10
		change(e)
		return e
	}
	cases := []struct {
		name    string
		entry   *dp.Presence
		inPlace bool
		state   dp.AnnouncerState
		gen     uint64
	}{
		{
			name:    "new state",
			entry:   next(30, func(e *dp.Presence) { e.State = stateSuspect }),
			inPlace: true, state: stateSuspect, gen: 30,
		},
		{
			name:    "new hold time",
			entry:   next(30, func(e *dp.Presence) { e.ActiveFrom = timestamppb.New(time.Unix(1, 0)) }),
			inPlace: true, gen: 30,
		},
		{
			name:    "state of a later revision",
			entry:   next(30, func(e *dp.Presence) { e.State = 7 }),
			inPlace: true, state: 7, gen: 30,
		},
		{
			name:    "new state with a lower generation: ignored",
			entry:   next(9, func(e *dp.Presence) { e.State, e.Attached = stateSuspect, 9 }),
			inPlace: true, gen: 10,
		},
		{
			name:    "new state with the same generation: ignored",
			entry:   next(10, func(e *dp.Presence) { e.State = stateSuspect }),
			inPlace: true, gen: 10,
		},
		{
			name:  "new state and new prefixes",
			entry: next(30, func(e *dp.Presence) { e.State, e.Prefixes = stateSuspect, []string{prefixA} }),
			state: stateSuspect, gen: 30,
		},
		{
			name:  "new state and a new sender tag",
			entry: next(30, func(e *dp.Presence) { e.State, e.SenderTag = stateSuspect, 8 }),
			state: stateSuspect, gen: 30,
		},
		{
			name:  "new state and a new rank",
			entry: next(30, func(e *dp.Presence) { e.State, e.Rank = stateSuspect, 4 }),
			state: stateSuspect, gen: 30,
		},
		{
			name:  "new state from a member that sends no generation of the attach",
			entry: next(30, func(e *dp.Presence) { e.State, e.Attached = stateSuspect, 0 }),
			state: stateSuspect, gen: 30,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newRouteWorld(t, NewRouter(nil, Config{}))
				w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
				w.send("relay-a", remoteEntry("x", 10, prefixA, prefixR))
				w.drain()
				kept := func() (*presenceEntry, *announcer) {
					w.m.pres.mu.Lock()
					defer w.m.pres.mu.Unlock()
					w.r.mu.RLock()
					defer w.r.mu.RUnlock()
					return w.m.pres.in["relay-a"].entries["x"], w.r.domains[vpcA].routes[netip.MustParsePrefix(prefixA)].active()
				}
				entry, route := kept()

				w.send("relay-a", tc.entry)
				gotEntry, gotRoute := kept()
				assert.Equal(t, tc.gen, gotEntry.gen)
				assert.Equal(t, tc.state, gotRoute.state)
				if tc.inPlace {
					assert.Same(t, entry, gotEntry, "entry of the member")
					assert.Same(t, route, gotRoute, "entry of the route table")
					// The attachment is the one announcer of its prefixes.
					assert.Empty(t, w.changes("watcher"))
				} else {
					assert.NotSame(t, entry, gotEntry, "entry of the member")
					assert.NotSame(t, route, gotRoute, "entry of the route table")
				}
				assert.Equal(t, "x@relay-a", w.table(vpcA)[prefixA])
				w.check()
			})
		})
	}
}
