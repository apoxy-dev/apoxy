// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// The agents of the presence tests. laptop sends the name "base" in Hello,
// and server sends no name.
var (
	laptop = agentID(vpcA, "laptop")
	server = agentID(vpcA, "server")
)

// presenceSink is a mesh member that the test controls. It dials a relay and
// keeps each Presence call that the relay opens.
type presenceSink struct {
	dp.UnimplementedMeshServer
	qc     quic.Connection
	calls  chan *sinkCall
	refuse error // If set, the sink ends each Presence call with it.
}

// sinkCall is one Presence call to a sink.
type sinkCall struct {
	updates chan *dp.PresenceUpdate
	done    chan error // The error that ended the call.
}

func (f *presenceSink) Presence(_ context.Context, st rpc.ClientStreamServer[dp.PresenceUpdate]) (*emptypb.Empty, error) {
	c := &sinkCall{updates: make(chan *dp.PresenceUpdate, 4096), done: make(chan error, 1)}
	f.calls <- c
	if f.refuse != nil {
		return nil, f.refuse
	}
	for {
		u, err := st.Recv()
		if err != nil {
			c.done <- err
			return &emptypb.Empty{}, nil
		}
		c.updates <- u
	}
}

// dialSink opens a mesh session to n as member name at revision rev. n has
// the higher name, so that it dials no member itself.
func dialSink(t *testing.T, n *meshNode, ca *testCA, name string, rev uint32) *presenceSink {
	t.Helper()
	return dialSinkErr(t, n, ca, name, rev, nil)
}

// dialSinkErr is dialSink for a member that ends each Presence call with refuse.
func dialSinkErr(t *testing.T, n *meshNode, ca *testCA, name string, rev uint32, refuse error) *presenceSink {
	t.Helper()
	f := &presenceSink{qc: n.rawDial(t, ca.meshCert(t, name)), calls: make(chan *sinkCall, 16), refuse: refuse}
	mux := rpc.NewMux()
	dp.RegisterMeshServer(mux, f)
	conn := rpc.NewConn(f.qc, mux)
	go func() { _ = conn.Serve(context.Background()) }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := dp.NewMeshClient(conn).Open(ctx, &dp.MeshOpenRequest{Version: &dp.Version{Revision: rev}, Name: name})
	require.NoError(t, err)
	return f
}

// call returns the next Presence call to the sink.
func (f *presenceSink) call(t *testing.T) *sinkCall {
	t.Helper()
	select {
	case c := <-f.calls:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("no Presence call in 10 s")
		return nil
	}
}

// next returns the next message of the call.
func (c *sinkCall) next(t *testing.T) *dp.PresenceUpdate {
	t.Helper()
	select {
	case u := <-c.updates:
		return u
	case <-time.After(10 * time.Second):
		t.Fatal("no presence message in 10 s")
		return nil
	}
}

// fullSet reads the messages of the call up to the end of the full set. It
// returns the entries and the number of entries of each message.
func (c *sinkCall) fullSet(t *testing.T) (entries []*dp.Presence, sizes []int) {
	t.Helper()
	for {
		u := c.next(t)
		entries = append(entries, u.GetEntries()...)
		sizes = append(sizes, len(u.GetEntries()))
		if u.GetEndOfFullSet() {
			return entries, sizes
		}
	}
}

// changes returns the next n entries of the call, after its full set. They
// come in one message or in more.
func (c *sinkCall) changes(t *testing.T, n int) []*dp.Presence {
	t.Helper()
	var out []*dp.Presence
	for len(out) < n {
		u := c.next(t)
		require.False(t, u.GetEndOfFullSet(), "a call has one end of the full set")
		require.NotEmpty(t, u.GetEntries(), "a message after the full set has entries")
		out = append(out, u.GetEntries()...)
	}
	require.Len(t, out, n)
	return out
}

// quiet checks that the call gets no message for a short time.
func (c *sinkCall) quiet(t *testing.T) {
	t.Helper()
	select {
	case u := <-c.updates:
		t.Fatalf("the member got a message that no change made: %v", u)
	case <-time.After(150 * time.Millisecond):
	}
}

// liveEntry is the entry of a live attachment of vpcA, with no generation.
func liveEntry(id, subject, agent string, tag uint32, prefixes ...string) *dp.Presence {
	return &dp.Presence{Vpc: ref(vpcA), AttachmentId: id, Prefixes: prefixes, Subject: subject, AgentName: agent, SenderTag: tag}
}

// goneEntry is the entry of an attachment of vpcA that ended, with no
// generation.
func goneEntry(id string) *dp.Presence {
	return &dp.Presence{Vpc: ref(vpcA), AttachmentId: id, Gone: true}
}

// diffPresence compares entries without the generation, which is a time.
func diffPresence(want, got []*dp.Presence) string {
	return cmp.Diff(want, got, protocmp.Transform(), protocmp.IgnoreFields(&dp.Presence{}, "generation"))
}

// growing checks that each generation is above the one before it, from last.
// It returns the last generation.
func growing(t *testing.T, last uint64, entries []*dp.Presence) uint64 {
	t.Helper()
	for _, e := range entries {
		require.Greater(t, e.GetGeneration(), last, "generation of %s", e.GetAttachmentId())
		last = e.GetGeneration()
	}
	return last
}

// presenceWorld is a relay with a mesh and the sessions of two agents.
type presenceWorld struct {
	t    *testing.T
	n    *meshNode
	r    *Router
	sess map[string]*Session
}

// newPresenceWorld starts relay-m, which sends its attachments to its
// members relay-a and relay-b. They have lower names, so relay-m dials none.
func newPresenceWorld(t *testing.T, ca *testCA) *presenceWorld {
	t.Helper()
	w := &presenceWorld{t: t, n: newMeshNode(t, ca, "relay-m"), r: NewRouter(nil, Config{}), sess: map[string]*Session{}}
	w.sess["laptop"] = addSession(t, w.r, vpcA, laptop, "192.0.2.1:1000").Session
	w.sess["server"] = addSession(t, w.r, vpcA, server, "192.0.2.2:1000").Session
	w.r.mu.Lock()
	w.sess["laptop"].name = "base"
	w.r.mu.Unlock()
	w.n.m.SetRouter(w.r)
	w.n.m.SetMembers([]MeshMember{
		{Name: "relay-a", Addr: netip.MustParseAddrPort("127.0.0.1:1")},
		{Name: "relay-b", Addr: netip.MustParseAddrPort("127.0.0.1:2")},
	})
	w.n.start(t)
	return w
}

// attach adds attachment id with one address and the advertised routes to the
// session of agent.
func (w *presenceWorld) attach(agent, id, addr string, routes ...string) error {
	a := attachment(id, addr)
	for _, p := range routes {
		a.Routes = append(a.Routes, netip.MustParsePrefix(p))
	}
	return w.r.attach(w.sess[agent], a)
}

func (w *presenceWorld) mustAttach(agent, id, addr string, routes ...string) {
	w.t.Helper()
	require.NoError(w.t, w.attach(agent, id, addr, routes...))
}

func (w *presenceWorld) detach(agent, id string) {
	w.t.Helper()
	_, _, err := w.r.detach(w.sess[agent], id)
	require.NoError(w.t, err)
}

// TestPresenceFullSet opens a session to a relay with attachments. The member
// gets all of them, oldest first, and the last message ends the full set.
func TestPresenceFullSet(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		count int   // Attachments of the relay when the session opens.
		sizes []int // Entries of each message of the full set.
	}{
		{name: "no attachment", count: 0, sizes: []int{0}},
		{name: "one attachment", count: 1, sizes: []int{1}},
		{name: "as many attachments as one message has", count: 256, sizes: []int{256}},
		{name: "one attachment more than one message has", count: 257, sizes: []int{256, 1}},
		{name: "attachments for three messages", count: 600, sizes: []int{256, 256, 88}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ca := newCA(t)
			w := newPresenceWorld(t, ca)
			var want []*dp.Presence
			for i := range tc.count {
				id, addr, route := fmt.Sprintf("att-%04d", i), fmt.Sprintf("fd00:%x::/96", i+1), fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
				if i%2 == 0 {
					w.mustAttach("laptop", id, addr, route)
					want = append(want, liveEntry(id, laptop, "base", 1, addr, route))
				} else {
					w.mustAttach("server", id, addr, route)
					want = append(want, liveEntry(id, server, "", 2, addr, route))
				}
			}
			start := uint64(time.Now().UnixMilli())

			call := dialSink(t, w.n, ca, "relay-a", dp.Revision).call(t)
			got, sizes := call.fullSet(t)
			assert.Equal(t, tc.sizes, sizes, "entries of each message")
			assert.Empty(t, diffPresence(want, got))
			if last := growing(t, 0, got); tc.count > 0 {
				// The generation is the attach time, which is before the session.
				assert.LessOrEqual(t, last, start+uint64(tc.count))
				assert.Greater(t, got[0].GetGeneration(), start-uint64(time.Minute.Milliseconds()))
			}
			call.quiet(t)
		})
	}
}

// TestPresenceChanges changes the attachments of a relay after the full set.
// The member gets an entry for each new attachment and for each one that ended.
func TestPresenceChanges(t *testing.T) {
	t.Parallel()
	type step struct {
		act  func(w *presenceWorld)
		want []*dp.Presence // Entries that the member gets, with no generation.
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{"new attachment", []step{
			// The address is not the base of its prefix. The member gets the prefix.
			{func(w *presenceWorld) { w.mustAttach("laptop", "x", "fd00:1::5/96", "10.9.0.0/16", "192.168.7.0/24") },
				[]*dp.Presence{liveEntry("x", laptop, "base", 1, "fd00:1::/96", "10.9.0.0/16", "192.168.7.0/24")}},
		}},
		{"attachment of an agent with no name", []step{
			{func(w *presenceWorld) { w.mustAttach("server", "y", "fd00:2::/96") },
				[]*dp.Presence{liveEntry("y", server, "", 1, "fd00:2::/96")}},
		}},
		{"detach", []step{
			{func(w *presenceWorld) { w.mustAttach("laptop", "x", "fd00:1::/96") },
				[]*dp.Presence{liveEntry("x", laptop, "base", 1, "fd00:1::/96")}},
			{func(w *presenceWorld) { w.detach("laptop", "x") }, []*dp.Presence{goneEntry("x")}},
		}},
		{"session closes", []step{
			{func(w *presenceWorld) { w.mustAttach("laptop", "x1", "fd00:1::/96") },
				[]*dp.Presence{liveEntry("x1", laptop, "base", 1, "fd00:1::/96")}},
			{func(w *presenceWorld) { w.mustAttach("server", "y", "fd00:2::/96") },
				[]*dp.Presence{liveEntry("y", server, "", 2, "fd00:2::/96")}},
			// The second attachment of a session has the tag of the session.
			{func(w *presenceWorld) { w.mustAttach("laptop", "x2", "fd00:3::/96") },
				[]*dp.Presence{liveEntry("x2", laptop, "base", 1, "fd00:3::/96")}},
			// The attachments of the other session stay.
			{func(w *presenceWorld) { w.r.removeSession(w.sess["laptop"]) }, []*dp.Presence{goneEntry("x1"), goneEntry("x2")}},
		}},
		{"detach and last counters after the session closed", []step{
			{func(w *presenceWorld) { w.mustAttach("laptop", "x", "fd00:1::/96") },
				[]*dp.Presence{liveEntry("x", laptop, "base", 1, "fd00:1::/96")}},
			{func(w *presenceWorld) { w.r.removeSession(w.sess["laptop"]) }, []*dp.Presence{goneEntry("x")}},
			// The attachment ended one time.
			{func(w *presenceWorld) { w.r.removeSession(w.sess["laptop"]) }, nil},
			{func(w *presenceWorld) { w.detach("laptop", "x") }, nil},
			{func(w *presenceWorld) { w.r.endAttachments(w.sess["laptop"]) }, nil},
		}},
		{"one attachment ID two times", []step{
			{func(w *presenceWorld) { w.mustAttach("laptop", "x", "fd00:1::/96") },
				[]*dp.Presence{liveEntry("x", laptop, "base", 1, "fd00:1::/96")}},
			{func(w *presenceWorld) { w.detach("laptop", "x") }, []*dp.Presence{goneEntry("x")}},
			// The session keeps its tag when its last attachment ends.
			{func(w *presenceWorld) { w.mustAttach("laptop", "x", "fd00:1::/96") },
				[]*dp.Presence{liveEntry("x", laptop, "base", 1, "fd00:1::/96")}},
			{func(w *presenceWorld) { w.detach("laptop", "x") }, []*dp.Presence{goneEntry("x")}},
		}},
		{"attach that fails", []step{
			{func(w *presenceWorld) { w.mustAttach("laptop", "x", "fd00:1::/96") },
				[]*dp.Presence{liveEntry("x", laptop, "base", 1, "fd00:1::/96")}},
			// The address has another owner, so the attach fails.
			{func(w *presenceWorld) {
				assert.Equal(w.t, rpc.AlreadyExists, rpc.CodeOf(w.attach("server", "y", "fd00:1::/96")))
			}, nil},
			{func(w *presenceWorld) { w.mustAttach("server", "y", "fd00:2::/96") },
				[]*dp.Presence{liveEntry("y", server, "", 2, "fd00:2::/96")}},
		}},
		{"advertised route of two attachments of one agent", []step{
			{func(w *presenceWorld) { w.mustAttach("laptop", "x1", "fd00:1::/96", "10.9.0.0/16") },
				[]*dp.Presence{liveEntry("x1", laptop, "base", 1, "fd00:1::/96", "10.9.0.0/16")}},
			// The route moves to x2 in the relay, and the entry of x1 does not change.
			{func(w *presenceWorld) { w.mustAttach("laptop", "x2", "fd00:2::/96", "10.9.0.0/16") },
				[]*dp.Presence{liveEntry("x2", laptop, "base", 1, "fd00:2::/96", "10.9.0.0/16")}},
			// The route moves back to x1.
			{func(w *presenceWorld) { w.detach("laptop", "x2") }, []*dp.Presence{goneEntry("x2")}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ca := newCA(t)
			w := newPresenceWorld(t, ca)
			call := dialSink(t, w.n, ca, "relay-a", dp.Revision).call(t)
			got, _ := call.fullSet(t)
			require.Empty(t, got, "the relay has no attachment at the start")

			var last uint64
			for i, st := range tc.steps {
				before := uint64(time.Now().UnixMilli())
				st.act(w)
				if st.want == nil {
					call.quiet(t)
					continue
				}
				got := call.changes(t, len(st.want))
				assert.Empty(t, diffPresence(st.want, got), "step %d", i)
				last = growing(t, last, got)
				// The generation is the time of the change.
				assert.GreaterOrEqual(t, got[0].GetGeneration(), before, "step %d", i)
				// Changes in one ms put the generation a few ms after the time.
				assert.LessOrEqual(t, last, uint64(time.Now().UnixMilli())+100, "step %d", i)
			}
			call.quiet(t)
		})
	}
}

// TestPresenceEachMember changes the attachments fast with two members. Each
// member has the attachments of the relay when it uses the higher generation.
func TestPresenceEachMember(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	w := newPresenceWorld(t, ca)
	calls := []*sinkCall{
		dialSink(t, w.n, ca, "relay-a", dp.Revision).call(t),
		dialSink(t, w.n, ca, "relay-b", dp.Revision).call(t),
	}
	for _, c := range calls {
		c.fullSet(t)
	}
	want := map[string]string{}
	for i := range 300 {
		id, addr := fmt.Sprintf("att-%d", i%40), fmt.Sprintf("fd00:%x::/96", i%40+1)
		if _, live := want[id]; live {
			w.detach("laptop", id)
			delete(want, id)
		} else if i%7 != 0 {
			w.mustAttach("laptop", id, addr)
			want[id] = addr
		}
	}
	w.mustAttach("server", "last", "fd00:ffff::/96")
	want["last"] = "fd00:ffff::/96"

	for i, c := range calls {
		got, gens := map[string]string{}, map[string]uint64{}
		for got["last"] == "" {
			for _, e := range c.next(t).GetEntries() {
				id := e.GetAttachmentId()
				if e.GetGeneration() < gens[id] {
					continue
				}
				gens[id] = e.GetGeneration()
				if delete(got, id); !e.GetGone() {
					got[id] = e.GetPrefixes()[0]
				}
			}
		}
		assert.Equal(t, want, got, "attachments that member %d has", i)
	}
}

// TestPresenceReplacedSession opens a second session of a member. The new
// session gets the full set again, with the attachments that the relay has then.
func TestPresenceReplacedSession(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	w := newPresenceWorld(t, ca)
	w.mustAttach("laptop", "x", "fd00:1::/96")
	w.mustAttach("server", "y", "fd00:2::/96")
	x, y := liveEntry("x", laptop, "base", 1, "fd00:1::/96"), liveEntry("y", server, "", 2, "fd00:2::/96")

	first := dialSink(t, w.n, ca, "relay-a", dp.Revision)
	call := first.call(t)
	got, _ := call.fullSet(t)
	require.Empty(t, diffPresence([]*dp.Presence{x, y}, got))
	old := map[string]uint64{"x": got[0].GetGeneration(), "y": got[1].GetGeneration()}
	w.mustAttach("laptop", "z", "fd00:3::/96")
	w.detach("laptop", "x")
	z := liveEntry("z", laptop, "base", 1, "fd00:3::/96")
	require.Empty(t, diffPresence([]*dp.Presence{z, goneEntry("x")}, call.changes(t, 2)))

	for i := range 2 {
		next := dialSink(t, w.n, ca, "relay-a", dp.Revision)
		call := next.call(t)
		got, _ := call.fullSet(t)
		require.Empty(t, diffPresence([]*dp.Presence{y, z}, got), "full set of session %d", i+2)
		// An attachment that did not change has the generation that it had.
		assert.Equal(t, old["y"], got[0].GetGeneration())
		// The new session gets the changes, and the old one is closed.
		w.mustAttach("server", fmt.Sprintf("more-%d", i), fmt.Sprintf("fd00:%x::/96", 10+i))
		more := liveEntry(fmt.Sprintf("more-%d", i), server, "", 2, fmt.Sprintf("fd00:%x::/96", 10+i))
		require.Empty(t, diffPresence([]*dp.Presence{more}, call.changes(t, 1)))
		w.detach("server", fmt.Sprintf("more-%d", i))
		require.Empty(t, diffPresence([]*dp.Presence{goneEntry(fmt.Sprintf("more-%d", i))}, call.changes(t, 1)))
		select {
		case <-first.qc.Context().Done():
		case <-time.After(5 * time.Second):
			t.Fatal("the relay did not close the replaced session in 5 s")
		}
		first = next
	}
	// The relay keeps no state of the calls that ended.
	require.Eventually(t, func() bool {
		w.n.m.pres.mu.Lock()
		defer w.n.m.pres.mu.Unlock()
		return len(w.n.m.pres.outs) == 1
	}, 5*time.Second, 5*time.Millisecond)
}

// TestPresenceCallRefused has a member that ends the Presence call with an
// error. The relay sends no more on that session, and the session stays open.
func TestPresenceCallRefused(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	w := newPresenceWorld(t, ca)
	w.mustAttach("laptop", "x", "fd00:1::/96")
	sink := dialSinkErr(t, w.n, ca, "relay-a", dp.Revision, rpc.Errorf(rpc.Unavailable, "no presence"))
	sink.call(t)
	sess := w.n.session(t)
	calls := func() int {
		w.n.m.pres.mu.Lock()
		defer w.n.m.pres.mu.Unlock()
		return len(w.n.m.pres.outs)
	}

	// The relay sees the end of the call when it sends a change.
	more := 0
	for start := time.Now(); calls() > 0; more++ {
		require.Less(t, time.Since(start), 5*time.Second, "the relay keeps the call that ended")
		w.mustAttach("server", fmt.Sprintf("y-%d", more), fmt.Sprintf("fd00:%x::/96", more+2))
		time.Sleep(10 * time.Millisecond)
	}
	w.mustAttach("server", "z", "fd00:ffff::/96")
	select {
	case <-sink.calls:
		t.Fatal("the relay opened a second Presence call on the session")
	case <-time.After(300 * time.Millisecond):
	}
	assert.NoError(t, sess.Context().Err())
	assert.Same(t, sess, w.n.m.Session("relay-a"))
	assert.Equal(t, 0, calls())

	// The next session of the member gets the full set.
	got, _ := dialSink(t, w.n, ca, "relay-a", dp.Revision).call(t).fullSet(t)
	assert.Len(t, got, more+2)
}

// TestPresenceRevision opens sessions of members at different revisions. Only
// a member at revision 4 or later gets a Presence call, and each session stays.
func TestPresenceRevision(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		revision uint32
		call     bool // The relay opens a Presence call.
	}{
		{name: "revision 3, from before the call", revision: 3},
		{name: "revision 4, the first with the call", revision: 4, call: true},
		{name: "later revision", revision: 9, call: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ca := newCA(t)
			w := newPresenceWorld(t, ca)
			w.mustAttach("laptop", "x", "fd00:1::/96")
			sink := dialSink(t, w.n, ca, "relay-a", tc.revision)
			require.Equal(t, MeshChange{Name: "relay-a", Up: true}, w.n.change(t, 10*time.Second))
			sess := w.n.session(t)
			assert.Equal(t, tc.revision, sess.Version().GetRevision())

			if tc.call {
				call := sink.call(t)
				got, _ := call.fullSet(t)
				assert.Empty(t, diffPresence([]*dp.Presence{liveEntry("x", laptop, "base", 1, "fd00:1::/96")}, got))
				w.mustAttach("server", "y", "fd00:2::/96")
				assert.Empty(t, diffPresence([]*dp.Presence{liveEntry("y", server, "", 2, "fd00:2::/96")}, call.changes(t, 1)))
			} else {
				// No call at the start, and none for a change.
				w.mustAttach("server", "y", "fd00:2::/96")
				w.detach("laptop", "x")
				select {
				case <-sink.calls:
					t.Fatal("the relay opened a Presence call to a member at revision 3")
				case <-time.After(500 * time.Millisecond):
				}
			}
			// The member stays in the mesh with its session.
			assert.NoError(t, sink.qc.Context().Err())
			assert.NoError(t, sess.Context().Err())
			assert.Same(t, sess, w.n.m.Session("relay-a"))
			assert.True(t, w.n.m.Up("relay-a"))
			stays(t, w.n)
		})
	}
}

// TestPresenceGeneration attaches and detaches on the fake clock. The
// generation is the time of the change in ms, and no two changes have one.
func TestPresenceGeneration(t *testing.T) {
	type step struct {
		after time.Duration // Time that passes before act.
		act   string        // "attach <id>", "detach <id>" or "close".
		want  []string      // "<id> <ms after the start>", with "-" in front of a gone entry.
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{"changes at different times", []step{
			{0, "attach x", []string{"x 0"}},
			{5 * time.Millisecond, "attach y", []string{"y 5"}},
			{time.Second, "attach z", []string{"z 1005"}},
			{7 * time.Millisecond, "detach y", []string{"-y 1012"}},
		}},
		{"two attaches in one millisecond", []step{
			{0, "attach x", []string{"x 0"}},
			{0, "attach y", []string{"y 1"}},
		}},
		{"two attaches of one attachment ID in one millisecond", []step{
			{0, "attach x", []string{"x 0"}},
			{0, "detach x", []string{"-x 1"}},
			{0, "attach x", []string{"x 2"}},
			{0, "detach x", []string{"-x 3"}},
		}},
		{"attaches in the same and in the next millisecond", []step{
			{0, "attach x", []string{"x 0"}},
			{400 * time.Microsecond, "attach y", []string{"y 1"}},
			// The time is 1.1 ms: 1 is not above the last generation.
			{700 * time.Microsecond, "attach z", []string{"z 2"}},
		}},
		{"the time passes the generation again", []step{
			{0, "attach a", []string{"a 0"}},
			{0, "attach b", []string{"b 1"}},
			{0, "attach c", []string{"c 2"}},
			{time.Millisecond, "attach d", []string{"d 3"}},
			{time.Millisecond, "attach e", []string{"e 4"}},
			{10 * time.Millisecond, "attach f", []string{"f 12"}},
		}},
		{"session closes", []step{
			{0, "attach x", []string{"x 0"}},
			{0, "attach y", []string{"y 1"}},
			{3 * time.Millisecond, "close", []string{"-x 3", "-y 4"}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := NewRouter(nil, Config{})
				s := addSession(t, r, vpcA, laptop, "192.0.2.1:1000").Session
				var got []string
				start := time.Now().UnixMilli()
				r.presence = func(e *dp.Presence) {
					text := fmt.Sprintf("%s %d", e.GetAttachmentId(), int64(e.GetGeneration())-start)
					if e.GetGone() {
						text = "-" + text
					}
					got = append(got, text)
				}
				addrs := 0
				for i, st := range tc.steps {
					time.Sleep(st.after)
					got = nil
					switch act, id, _ := strings.Cut(st.act, " "); act {
					case "attach":
						addrs++
						require.NoError(t, r.attach(s, attachment(id, fmt.Sprintf("fd00:%x::/96", addrs))))
					case "detach":
						_, _, err := r.detach(s, id)
						require.NoError(t, err)
					case "close":
						r.removeSession(s)
					}
					assert.Equal(t, st.want, got, "step %d (%s)", i, st.act)
				}
			})
		})
	}
}

// TestPresenceGenerationClock gives the times of changes on a clock that
// stops and goes back. Each generation is above the one before it.
func TestPresenceGenerationClock(t *testing.T) {
	cases := []struct {
		name  string
		times []int64 // Unix ms of each change.
		want  []uint64
	}{
		{"clock goes on", []int64{1000, 1001, 1500}, []uint64{1000, 1001, 1500}},
		{"clock stops", []int64{1000, 1000, 1000, 1001, 1004}, []uint64{1000, 1001, 1002, 1003, 1004}},
		{"clock goes back", []int64{1000, 400, 401, 1000, 1001, 1003}, []uint64{1000, 1001, 1002, 1003, 1004, 1005}},
		{"clock goes back and passes the generation", []int64{1000, 400, 2000}, []uint64{1000, 1001, 2000}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			var got []uint64
			for _, ms := range tc.times {
				got = append(got, r.nextGen(time.UnixMilli(ms)))
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestTrunkTag checks the tag of each session: a session gets it at its first
// attach and has it to its end, and a free tag comes again after all the others.
func TestTrunkTag(t *testing.T) {
	cases := []struct {
		name string
		last uint32 // Last tag that the router gave before the test.
		// acts are "attach", "fail" (an attach that fails) and "detach" with
		// "<session> <id>", "close" and "end" with "<session>", and "last <tag>".
		acts []string
		want map[string]uint32 // Tag of each session that has one at the end.
	}{
		{name: "session with no attachment", want: map[string]uint32{}},
		{name: "two attachments of one session", acts: []string{"attach s1 a", "attach s1 b"}, want: map[string]uint32{"s1": 1}},
		{
			name: "two sessions",
			acts: []string{"attach s1 a", "attach s2 b", "attach s1 c", "attach s3 d"},
			want: map[string]uint32{"s1": 1, "s2": 2, "s3": 3},
		},
		{
			name: "detach while a second attachment lives",
			acts: []string{"attach s1 a", "attach s1 b", "detach s1 a", "last 16777215", "attach s2 c"},
			want: map[string]uint32{"s1": 1, "s2": 2},
		},
		{
			name: "detach of the last attachment, then a new attachment",
			acts: []string{"attach s1 a", "detach s1 a", "last 16777215", "attach s2 b", "attach s1 c"},
			want: map[string]uint32{"s1": 1, "s2": 2},
		},
		{
			// "end" gives the last counters of the closed session.
			name: "closed session frees its tag",
			acts: []string{"attach s1 a", "attach s1 b", "attach s2 c", "close s1", "detach s1 a", "end s1", "last 16777215", "attach s3 d"},
			want: map[string]uint32{"s2": 2, "s3": 1},
		},
		{
			name: "free tag is not the next tag",
			acts: []string{"attach s1 a", "attach s2 b", "close s1", "attach s3 c", "close s2", "attach s4 d"},
			want: map[string]uint32{"s3": 3, "s4": 4},
		},
		{
			name: "highest tag, then the first again", last: 1<<24 - 2,
			acts: []string{"attach s1 a", "attach s2 b", "attach s3 c"},
			want: map[string]uint32{"s1": 1<<24 - 1, "s2": 1, "s3": 2},
		},
		{
			name: "tags in use are not given again",
			acts: []string{"attach s1 a", "attach s2 b", "attach s3 c", "close s2", "last 16777215", "attach s4 d", "attach s5 e"},
			want: map[string]uint32{"s1": 1, "s3": 3, "s4": 2, "s5": 4},
		},
		{
			name: "failed first attach takes no tag",
			acts: []string{"attach s1 a", "fail s2 a", "attach s3 b"},
			want: map[string]uint32{"s1": 1, "s3": 2},
		},
		{
			name: "failed second attach keeps the tag",
			acts: []string{"attach s1 a", "attach s2 b", "fail s2 a", "attach s3 c"},
			want: map[string]uint32{"s1": 1, "s2": 2, "s3": 3},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			sess := map[string]*Session{}
			for i := range 5 {
				name := fmt.Sprintf("s%d", i+1)
				sess[name] = addSession(t, r, vpcA, agentID(vpcA, name), fmt.Sprintf("192.0.2.%d:1000", i+1)).Session
			}
			r.tag = tc.last
			for _, text := range tc.acts {
				f := strings.Fields(text)
				switch f[0] {
				case "attach", "fail":
					// Each ID has one address, so an ID that another session has fails.
					err := r.attach(sess[f[1]], attachment(f[2], fmt.Sprintf("fd00:%x::/96", f[2][0])))
					if f[0] == "fail" {
						require.Equal(t, rpc.AlreadyExists, rpc.CodeOf(err), text)
					} else {
						require.NoError(t, err, text)
					}
				case "detach":
					_, _, err := r.detach(sess[f[1]], f[2])
					require.NoError(t, err, text)
				case "close":
					r.removeSession(sess[f[1]])
				case "end":
					r.endAttachments(sess[f[1]])
				case "last":
					var n uint32
					_, err := fmt.Sscan(f[1], &n)
					require.NoError(t, err)
					r.tag = n
				}
			}
			got, tags := map[string]uint32{}, map[uint32]struct{}{}
			for name, s := range sess {
				if s.tag != 0 {
					got[name], tags[s.tag] = s.tag, struct{}{}
				}
			}
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tags, r.tags, "tags that the router has as in use")
		})
	}
}

// presenceEntries returns the attachments that m has of member name, by ID
// with no session, and whether the full set of its last call is complete.
func presenceEntries(m *Mesh, name string) (map[string]presenceEntry, bool) {
	m.pres.mu.Lock()
	defer m.pres.mu.Unlock()
	in := m.pres.in[name]
	if in == nil {
		return nil, false
	}
	out := map[string]presenceEntry{}
	for id, e := range in.entries {
		c := *e
		c.sess = nil
		out[id] = c
	}
	return out, in.full
}

// presenceIDs returns the IDs of the attachments that m has of member name.
func presenceIDs(m *Mesh, name string) []string {
	entries, _ := presenceEntries(m, name)
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// memberEntry is an entry that a member sends for its attachment id of laptop.
func memberEntry(id string, generation uint64) *dp.Presence {
	e := liveEntry(id, laptop, "base", 7, "fd00:1::/96")
	e.Generation = generation
	return e
}

// openStub opens a session of relay-a to m on a connection that only closes.
func openStub(t *testing.T, m *Mesh) (*MeshSession, *stubConn) {
	t.Helper()
	conn := newStubConn()
	s := m.newSession(conn, false)
	require.True(t, m.track(s))
	require.NoError(t, m.admit(s, "relay-a", nil, m.ver, nil))
	return s, conn
}

// stubMesh returns the mesh of relay-m with the member relay-a, which dials.
func stubMesh(t *testing.T) *Mesh {
	t.Helper()
	ca := newCA(t)
	m, err := NewMesh("relay-m", MeshConfig{TLS: meshTLS(ca.meshCert(t, "relay-m")), Verify: ca.verifyName})
	require.NoError(t, err)
	m.SetMembers([]MeshMember{{Name: "relay-a", Addr: netip.MustParseAddrPort("192.0.2.1:6081")}})
	return m
}

// TestPresenceEntries gives the entries of a member to a relay. The relay
// keeps the good ones and the higher generation, and refuses the bad ones.
func TestPresenceEntries(t *testing.T) {
	good := presenceEntry{
		vpc: vpcA, networkID: testVNI, id: "x", gen: 10, subject: laptop, agent: "base", tag: 7,
		prefixes: []netip.Prefix{netip.MustParsePrefix("fd00:1::/96")},
	}
	// with returns the good entry after change.
	with := func(change func(e *dp.Presence)) []*dp.Presence {
		e := memberEntry("x", 10)
		change(e)
		return []*dp.Presence{e}
	}
	// kept returns the good entry after change, as the relay keeps it.
	kept := func(change func(e *presenceEntry)) map[string]presenceEntry {
		e := good
		change(&e)
		return map[string]presenceEntry{e.id: e}
	}
	longID := strings.Repeat("a", 128)
	// nets returns n prefixes, as a member sends them and as the relay keeps them.
	nets := func(n int) (sent []string, kept []netip.Prefix) {
		for i := range n {
			p := netip.MustParsePrefix(fmt.Sprintf("fd00:%x::/96", i+1))
			sent, kept = append(sent, p.String()), append(kept, p)
		}
		return sent, kept
	}
	most, mostKept := nets(64)
	tooMany, _ := nets(65)
	cases := []struct {
		name string
		// msgs are the messages of one Presence call. A message with no entry
		// ends the full set.
		msgs [][]*dp.Presence
		want map[string]presenceEntry
		full bool
	}{
		{name: "entry with each field", msgs: [][]*dp.Presence{{memberEntry("x", 10)}}, want: kept(func(*presenceEntry) {})},
		{name: "end of the full set", msgs: [][]*dp.Presence{{memberEntry("x", 10)}, {}}, want: kept(func(*presenceEntry) {}), full: true},
		{name: "full set with no attachment", msgs: [][]*dp.Presence{{}}, full: true},
		{
			name: "prefixes: address in a prefix, IPv4 route",
			msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Prefixes = []string{"fd00:1::5/96", "10.9.3.7/16"} })},
			want: kept(func(e *presenceEntry) {
				e.prefixes = []netip.Prefix{netip.MustParsePrefix("fd00:1::/96"), netip.MustParsePrefix("10.9.0.0/16")}
			}),
		},
		{name: "no prefix", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Prefixes = nil })}, want: kept(func(e *presenceEntry) { e.prefixes = nil })},
		{name: "no agent name", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.AgentName = "" })}, want: kept(func(e *presenceEntry) { e.agent = "" })},
		{name: "lowest tag", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.SenderTag = 1 })}, want: kept(func(e *presenceEntry) { e.tag = 1 })},
		{name: "highest tag", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.SenderTag = 1<<24 - 1 })}, want: kept(func(e *presenceEntry) { e.tag = 1<<24 - 1 })},
		{
			name: "highest network ID",
			msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Vpc.NetworkId = 1<<24 - 1 })},
			want: kept(func(e *presenceEntry) { e.networkID = 1<<24 - 1 }),
		},
		{name: "longest attachment ID", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.AttachmentId = longID })}, want: kept(func(e *presenceEntry) { e.id = longID })},
		{
			name: "most prefixes",
			msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Prefixes = most })},
			want: kept(func(e *presenceEntry) { e.prefixes = mostKept }),
		},

		{name: "no attachment ID", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.AttachmentId = "" })}},
		{name: "attachment ID too long", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.AttachmentId = longID + "a" })}},
		{name: "no generation", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Generation = 0 })}},
		{name: "no VPC", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Vpc = nil })}},
		{name: "no project", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Vpc.ProjectId = "" })}},
		{name: "no VPC UID", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Vpc.VpcUid = "" })}},
		{name: "network ID above 24 bits", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Vpc.NetworkId = 1 << 24 })}},
		{name: "no subject", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Subject = "" })}},
		{name: "subject is not an agent ID", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Subject = "laptop" })}},
		{name: "subject of another project", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Subject = agentID(vpcB, "laptop") })}},
		{
			name: "subject of another VPC",
			msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Subject = agentID(VPCKey{Project: vpcA.Project, UID: "vpc-2"}, "laptop") })},
		},
		{name: "no tag", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.SenderTag = 0 })}},
		{name: "tag above 24 bits", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.SenderTag = 1 << 24 })}},
		{name: "prefix with no length", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Prefixes = []string{"fd00:1::"} })}},
		{name: "one bad prefix of two", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Prefixes = []string{"fd00:1::/96", "10.0.0.0/33"} })}},
		{name: "one prefix too many", msgs: [][]*dp.Presence{with(func(e *dp.Presence) { e.Prefixes = tooMany })}},
		{
			name: "entry with too many prefixes does not replace the entry that the relay has",
			msgs: [][]*dp.Presence{{memberEntry("x", 10)}, with(func(e *dp.Presence) { e.Generation, e.Prefixes = 11, tooMany })},
			want: kept(func(*presenceEntry) {}),
		},
		{
			name: "bad entry between good entries",
			msgs: [][]*dp.Presence{{memberEntry("w", 9), with(func(e *dp.Presence) { e.SenderTag = 0 })[0], memberEntry("y", 11)}, {memberEntry("z", 12)}},
			want: map[string]presenceEntry{
				"w": kept(func(e *presenceEntry) { e.id, e.gen = "w", 9 })["w"],
				"y": kept(func(e *presenceEntry) { e.id, e.gen = "y", 11 })["y"],
				"z": kept(func(e *presenceEntry) { e.id, e.gen = "z", 12 })["z"],
			},
		},
		{
			name: "bad entry does not replace the entry that the relay has",
			msgs: [][]*dp.Presence{{memberEntry("x", 10)}, with(func(e *dp.Presence) { e.Generation, e.Subject = 11, "" })},
			want: kept(func(*presenceEntry) {}),
		},

		{
			name: "higher generation replaces",
			msgs: [][]*dp.Presence{{memberEntry("x", 10)}, with(func(e *dp.Presence) { e.Generation, e.SenderTag = 11, 8 })},
			want: kept(func(e *presenceEntry) { e.gen, e.tag = 11, 8 }),
		},
		{
			name: "lower generation is ignored",
			msgs: [][]*dp.Presence{{memberEntry("x", 10)}, with(func(e *dp.Presence) { e.Generation, e.SenderTag = 9, 8 })},
			want: kept(func(*presenceEntry) {}),
		},
		{
			name: "same generation keeps the entry",
			msgs: [][]*dp.Presence{{memberEntry("x", 10)}, with(func(e *dp.Presence) { e.SenderTag = 8 })},
			want: kept(func(*presenceEntry) {}),
		},
		{name: "gone with a higher generation", msgs: [][]*dp.Presence{{memberEntry("x", 10)}, {{AttachmentId: "x", Generation: 11, Gone: true}}}},
		{name: "gone with the same generation", msgs: [][]*dp.Presence{{memberEntry("x", 10)}, {{AttachmentId: "x", Generation: 10, Gone: true}}}},
		{
			// A gone entry has only the attachment ID and the generation.
			name: "gone with too many prefixes",
			msgs: [][]*dp.Presence{{memberEntry("x", 10)}, {{AttachmentId: "x", Generation: 11, Gone: true, Prefixes: tooMany}}},
		},
		{
			name: "gone with a lower generation is ignored",
			msgs: [][]*dp.Presence{{memberEntry("x", 10)}, {{AttachmentId: "x", Generation: 9, Gone: true}}},
			want: kept(func(*presenceEntry) {}),
		},
		{
			name: "gone for another attachment",
			msgs: [][]*dp.Presence{{memberEntry("x", 10), {AttachmentId: "y", Generation: 11, Gone: true}}},
			want: kept(func(*presenceEntry) {}),
		},
		{
			name: "gone with no generation is refused",
			msgs: [][]*dp.Presence{{memberEntry("x", 10)}, {{AttachmentId: "x", Gone: true}}},
			want: kept(func(*presenceEntry) {}),
		},
		{
			name: "attachment comes again after it is gone",
			msgs: [][]*dp.Presence{{memberEntry("x", 8), {AttachmentId: "x", Generation: 9, Gone: true}, memberEntry("x", 10)}},
			want: kept(func(*presenceEntry) {}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := stubMesh(t)
			s, _ := openStub(t, m)
			require.NoError(t, m.pres.accept(s))
			for _, entries := range tc.msgs {
				require.NoError(t, m.pres.apply(s, &dp.PresenceUpdate{Entries: entries, EndOfFullSet: len(entries) == 0}))
			}
			got, full := presenceEntries(m, "relay-a")
			if tc.want == nil {
				tc.want = map[string]presenceEntry{}
			}
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.full, full, "the full set is complete")
		})
	}
}

// TestPresenceMemberLimit gives a relay the most entries that it keeps of one
// member. Then it refuses a new entry, after it drops those of older sessions.
func TestPresenceMemberLimit(t *testing.T) {
	t.Parallel()
	// The number of the protocol. The test does not read it from the code.
	const limit = 65536
	full := "the member has 65536 attachments, which is the limit"
	cases := []struct {
		name string
		have int  // Entries "e0", "e1", ... at generation 1 that the relay has of relay-a.
		next bool // send comes on a new session of relay-a.
		send []*dp.Presence
		// refused are the entries that the relay refuses, as "<ID>: <reason>".
		refused []string
		count   int               // Entries of relay-a after send.
		want    map[string]uint64 // Generation of some entries after send. 0 is no entry.
	}{
		{
			name: "one below the limit", have: limit - 1, send: []*dp.Presence{memberEntry("n", 2)},
			count: limit, want: map[string]uint64{"n": 2, "e0": 1},
		},
		{
			name: "at the limit", have: limit, send: []*dp.Presence{memberEntry("n", 2)},
			refused: []string{"n: " + full}, count: limit, want: map[string]uint64{"n": 0, "e0": 1},
		},
		{
			name: "room for one of two", have: limit - 1, send: []*dp.Presence{memberEntry("n", 2), memberEntry("o", 3)},
			refused: []string{"o: " + full}, count: limit, want: map[string]uint64{"n": 2, "o": 0},
		},
		{
			name: "end of an attachment gives room", have: limit, send: []*dp.Presence{goneAt("e0", 2), memberEntry("n", 3)},
			count: limit, want: map[string]uint64{"e0": 0, "n": 3},
		},
		{
			name: "end of an attachment after the new entry", have: limit, send: []*dp.Presence{memberEntry("n", 2), goneAt("e0", 3)},
			refused: []string{"n: " + full}, count: limit - 1, want: map[string]uint64{"e0": 0, "n": 0},
		},
		{
			name: "new generation of an attachment", have: limit, send: []*dp.Presence{memberEntry("e0", 2)},
			count: limit, want: map[string]uint64{"e0": 2, "e1": 1},
		},
		{
			name: "same entry again", have: limit, send: []*dp.Presence{memberEntry("e0", 1)},
			count: limit, want: map[string]uint64{"e0": 1},
		},
		{
			name: "new session sends entries again", have: limit, next: true,
			send:  []*dp.Presence{memberEntry("e0", 1), memberEntry("e1", 1)},
			count: limit, want: map[string]uint64{"e0": 1, "e1": 1, "e2": 1},
		},
		{
			// The entries that the new session did not send go: e1 comes after that.
			name: "new session sends a new entry", have: limit, next: true,
			send:  []*dp.Presence{memberEntry("e0", 1), memberEntry("n", 2), memberEntry("e1", 1)},
			count: 3, want: map[string]uint64{"e0": 1, "n": 2, "e1": 1, "e2": 0},
		},
		{
			name: "new session sends only new entries", have: limit, next: true,
			send:  []*dp.Presence{memberEntry("n", 2), memberEntry("o", 3)},
			count: 2, want: map[string]uint64{"n": 2, "o": 3, "e0": 0},
		},
		{
			name: "new session below the limit sends a new entry", have: limit - 1, next: true,
			send:  []*dp.Presence{memberEntry("n", 2)},
			count: limit, want: map[string]uint64{"n": 2, "e0": 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := stubMesh(t)
			s, _ := openStub(t, m)
			require.NoError(t, m.pres.accept(s))
			m.pres.mu.Lock()
			in := m.pres.in["relay-a"]
			for i := range tc.have {
				// Each entry has its own tag, as the entries of different agents have.
				in.add(&presenceEntry{vpc: vpcA, networkID: testVNI, id: fmt.Sprintf("e%d", i), gen: 1, subject: laptop, tag: uint32(i + 1), sess: s})
			}
			m.pres.mu.Unlock()
			if tc.next {
				s, _ = openStub(t, m)
				require.NoError(t, m.pres.accept(s))
			}

			var refused []string
			var changes []presenceChange
			for _, e := range tc.send {
				pe, err := checkPresence(e)
				require.NoError(t, err)
				pe.sess = s
				changes = append(changes, presenceChange{pe, e.GetGone()})
			}
			require.NoError(t, m.pres.keep(s, changes, false, func(id string, err error) { refused = append(refused, id+": "+err.Error()) }))

			assert.Equal(t, tc.refused, refused)
			got, _ := presenceEntries(m, "relay-a")
			assert.Len(t, got, tc.count)
			for id, gen := range tc.want {
				assert.Equal(t, gen, got[id].gen, "generation of %s", id)
			}
			checkEntries(t, m)
		})
	}
}

// TestPresenceHandler calls Presence on a relay. The relay keeps the entries
// of the one call of an open mesh session, and refuses each other call.
func TestPresenceHandler(t *testing.T) {
	t.Parallel()
	update := func(ids ...string) *dp.PresenceUpdate {
		u := &dp.PresenceUpdate{}
		for i, id := range ids {
			u.Entries = append(u.Entries, memberEntry(id, uint64(10+i)))
		}
		return u
	}
	cases := []struct {
		name string
		// open is the session of the caller: "no" (the call is not on a mesh
		// session), "before" (no Open call yet) or "yes".
		open  string
		first []string // Attachments of a first Presence call, which stays open.
		send  []string // Attachments of the call of the test.
		// codes are the results that the caller can get. A call that waits for
		// Open ends at its deadline, which the caller or the relay sees first.
		codes  []rpc.Code
		reason string
		want   []string // Attachments that the relay has after the call.
	}{
		{
			name: "call with no mesh session", open: "no", send: []string{"x"},
			codes: []rpc.Code{rpc.FailedPrecondition}, reason: "call is not on a mesh session",
		},
		{name: "call before Open", open: "before", send: []string{"x"}, codes: []rpc.Code{rpc.DeadlineExceeded, rpc.FailedPrecondition}},
		{name: "call on an open session", open: "yes", send: []string{"x", "y"}, codes: []rpc.Code{rpc.OK}, want: []string{"x", "y"}},
		{
			name: "second call on an open session", open: "yes", first: []string{"w"}, send: []string{"x"},
			codes: []rpc.Code{rpc.FailedPrecondition}, reason: "session already has a Presence call", want: []string{"w"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ca := newCA(t)
			n := newMeshNode(t, ca, "relay-m")
			n.m.SetMembers([]MeshMember{{Name: "relay-a", Addr: netip.MustParseAddrPort("127.0.0.1:1")}})
			n.start(t)
			if tc.open == "no" {
				_, err := n.m.Presence(context.Background(), nil)
				assert.Contains(t, tc.codes, rpc.CodeOf(err))
				assert.ErrorContains(t, err, tc.reason)
				assert.Empty(t, presenceIDs(n.m, "relay-a"))
				return
			}
			c := dp.NewMeshClient(rpc.NewConn(n.rawDial(t, ca.meshCert(t, "relay-a")), nil))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if tc.open == "yes" {
				_, err := c.Open(ctx, &dp.MeshOpenRequest{Version: dp.LocalVersion("test"), Name: "relay-a"})
				require.NoError(t, err)
			}
			if tc.first != nil {
				st, err := c.Presence(ctx)
				require.NoError(t, err)
				require.NoError(t, st.Send(update(tc.first...)))
				require.Eventually(t, func() bool { return len(presenceIDs(n.m, "relay-a")) == len(tc.first) }, 5*time.Second, 5*time.Millisecond)
			}

			callCtx := ctx
			if tc.open == "before" {
				// The relay waits for Open, so the call ends at its deadline.
				var stop context.CancelFunc
				callCtx, stop = context.WithTimeout(ctx, 500*time.Millisecond)
				defer stop()
			}
			st, err := c.Presence(callCtx)
			require.NoError(t, err)
			if err := st.Send(update(tc.send...)); err != nil {
				require.ErrorIs(t, err, io.EOF, "the relay ended the call")
			}
			_, err = st.CloseAndRecv()
			assert.Contains(t, tc.codes, rpc.CodeOf(err), "error: %v", err)
			if tc.reason != "" {
				assert.ErrorContains(t, err, tc.reason)
			}
			if tc.want == nil {
				tc.want = []string{}
			}
			assert.Equal(t, tc.want, presenceIDs(n.m, "relay-a"))
			_, full := presenceEntries(n.m, "relay-a")
			assert.False(t, full, "no call ended a full set")
		})
	}
}

// TestPresenceOldSession uses a session after a new session of the member
// opened. The relay refuses its new call, and its entries after the new call.
func TestPresenceOldSession(t *testing.T) {
	ended := func(t *testing.T, err error) {
		t.Helper()
		assert.Equal(t, rpc.FailedPrecondition, rpc.CodeOf(err))
		assert.ErrorContains(t, err, "mesh session ended")
	}
	isFull := func(m *Mesh) bool {
		_, full := presenceEntries(m, "relay-a")
		return full
	}
	cases := []struct {
		name string
		call bool     // The old session has a Presence call with a complete full set.
		want []string // Attachments of relay-a that the relay has at the end.
	}{
		// y, which only the old session sent, goes at the end of the new full set.
		{name: "old session with a call", call: true, want: []string{"x"}},
		{name: "old session with no call", want: []string{"x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := stubMesh(t)
			old, _ := openStub(t, m)
			if tc.call {
				require.NoError(t, m.pres.accept(old))
				require.NoError(t, m.pres.apply(old, &dp.PresenceUpdate{Entries: []*dp.Presence{memberEntry("x", 10)}, EndOfFullSet: true}))
			}
			require.Equal(t, tc.call, isFull(m))

			next, _ := openStub(t, m)
			// The new session is the session of the member, also before its call.
			ended(t, m.pres.accept(old))
			if tc.call {
				// The call that the old session has can add entries until the new call.
				require.NoError(t, m.pres.apply(old, &dp.PresenceUpdate{Entries: []*dp.Presence{memberEntry("y", 11)}}))
			}
			require.NoError(t, m.pres.accept(next))
			assert.False(t, isFull(m), "the new call has no full set yet")
			ended(t, m.pres.apply(old, &dp.PresenceUpdate{Entries: []*dp.Presence{memberEntry("z", 12)}, EndOfFullSet: true}))
			assert.False(t, isFull(m), "the old session cannot end the full set")

			// The entries of the old session stay until the new call ends its full set.
			if tc.call {
				require.Equal(t, []string{"x", "y"}, presenceIDs(m, "relay-a"))
			}
			require.NoError(t, m.pres.apply(next, &dp.PresenceUpdate{Entries: []*dp.Presence{memberEntry("x", 10)}, EndOfFullSet: true}))
			assert.Equal(t, tc.want, presenceIDs(m, "relay-a"))
			assert.True(t, isFull(m))
		})
	}
}

// checkEntries checks the data that m keeps with the entries of each member:
// the entries by tag, and the count of the entries of older sessions.
func checkEntries(t *testing.T, m *Mesh) {
	t.Helper()
	m.pres.mu.Lock()
	defer m.pres.mu.Unlock()
	for member, in := range m.pres.in {
		stale := 0
		for _, e := range in.entries {
			if e.sess != in.sess {
				stale++
			}
		}
		assert.Equal(t, stale, in.stale, "entries of older sessions of %s", member)
		// Each entry is one time in the list of its tag.
		seen := map[*presenceEntry]bool{}
		for tag, entries := range in.tags {
			assert.NotEmpty(t, entries, "list of the tag %d of %s", tag, member)
			for _, e := range entries {
				if seen[e] || e.tag != tag || in.entries[e.id] != e {
					t.Errorf("%s: the list of the tag %d has %q, which has the tag %d, is not an entry or is there two times", member, tag, e.id, e.tag)
				}
				seen[e] = true
			}
		}
		assert.Len(t, seen, len(in.entries), "entries of %s by tag", member)
	}
}

// TestPresenceDown ends the session of a member in different ways. The relay
// keeps its attachments until a new full set, a stop or a leave of the member.
func TestPresenceDown(t *testing.T) {
	const fullSetTime = 10 * time.Second
	type step struct {
		// act is "open", an end of the session ("lose", "restart", "close"), a
		// member set change ("remove", "add", "move"), or "send <ids>" on the last session.
		act  string
		wait time.Duration // Time that passes after act.
		// hold keeps the changes of the mesh from the hooks until a later step,
		// as when the calls of a new session run first.
		hold bool
		want []string // Attachments of relay-a that the relay has after the step.
		full bool     // The relay has a complete full set of relay-a after the step.
	}
	ab, bc, abc := []string{"a", "b"}, []string{"b", "c"}, []string{"a", "b", "c"}
	cases := []struct {
		name  string
		steps []step
	}{
		{"session lost", []step{
			{act: "open"}, {act: "send a b", want: ab},
			// The attachments stay while the member has no new session.
			{act: "lose", wait: 24 * time.Hour, want: ab},
		}},
		{"member closes with the normal code", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "close", wait: 24 * time.Hour, want: ab},
		}},
		{"new session ends its full set", []step{
			{act: "open"}, {act: "send a b end", want: ab, full: true},
			{act: "lose", wait: time.Minute, want: ab, full: true},
			{act: "open", want: ab, full: true},
			// The attachments of the session before stay until the end of the full set.
			{act: "send b", want: ab},
			{act: "send c", wait: fullSetTime - time.Nanosecond, want: abc},
			{act: "send end", want: bc, full: true},
			{act: "", wait: time.Minute, want: bc, full: true},
		}},
		{"new session in the down time ends its full set", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "lose", wait: time.Second, want: ab},
			{act: "open", want: ab},
			{act: "send b c end", want: bc, full: true},
		}},
		{"new session sends an attachment that ended", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "lose", wait: time.Minute, want: ab},
			{act: "open", want: ab},
			{act: "send b -a", want: []string{"b"}},
			{act: "send end", want: []string{"b"}, full: true},
		}},
		{"full set with no attachment", []step{
			{act: "open"}, {act: "send a b end", want: ab, full: true},
			{act: "lose", wait: time.Minute, want: ab, full: true},
			{act: "open", want: ab, full: true},
			{act: "send end", full: true},
		}},
		{"full set does not end in time", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "lose", wait: time.Second, want: ab},
			{act: "open", want: ab},
			{act: "send b c", wait: fullSetTime - time.Nanosecond, want: abc},
			// Only the attachments that the new session sent stay.
			{act: "", wait: time.Nanosecond, want: bc},
			// The full set can end later, and the new session can send a again.
			{act: "send a end", want: abc, full: true},
		}},
		{"new session with no Presence call", []step{
			{act: "open"}, {act: "send a b end", want: ab, full: true},
			{act: "lose", wait: time.Minute, want: ab, full: true},
			{act: "open", want: ab, full: true},
			{act: "", wait: fullSetTime - time.Nanosecond, want: ab, full: true},
			{act: "", wait: time.Nanosecond},
			{act: "send c", wait: time.Minute, want: []string{"c"}},
		}},
		{"new session replaces an open session", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "open", want: ab},
			{act: "send c", wait: fullSetTime - time.Nanosecond, want: abc},
			{act: "", wait: time.Nanosecond, want: []string{"c"}},
		}},
		{"new session ends before its full set", []step{
			{act: "open"}, {act: "send a b end", want: ab, full: true},
			{act: "lose", wait: time.Second, want: ab, full: true},
			{act: "open", want: ab, full: true},
			{act: "send b c", wait: 5 * time.Second, want: abc},
			// The attachments stay, also after the time for the full set of that session.
			{act: "lose", wait: time.Hour, want: abc},
			{act: "open", want: abc},
			// For the next session, the attachments of each session before can go.
			{act: "send a end", want: []string{"a"}, full: true},
		}},
		{"time for the full set starts again at the next session", []step{
			{act: "open"}, {act: "send a b end", want: ab, full: true},
			{act: "lose", wait: time.Second, want: ab, full: true},
			{act: "open", want: ab, full: true},
			{act: "", wait: 4 * time.Second, want: ab, full: true},
			{act: "lose", wait: time.Second, want: ab, full: true},
			{act: "open", want: ab, full: true},
			// The time of the session that ended is over now, and it removes nothing.
			{act: "", wait: 5 * time.Second, want: ab, full: true},
			{act: "", wait: 5*time.Second - time.Nanosecond, want: ab, full: true},
			{act: "", wait: time.Nanosecond},
		}},
		{"full set ends two times", []step{
			{act: "open"}, {act: "send a b end", want: ab, full: true},
			{act: "send c end", wait: time.Minute, want: abc, full: true},
		}},
		{"member stops", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "restart"},
			{act: "", wait: time.Minute},
		}},
		{"member stops with attachments of two sessions", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "lose", wait: time.Second, want: ab},
			{act: "open", want: ab},
			{act: "send b c", want: abc},
			{act: "restart"},
		}},
		{"member leaves the set", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "remove"},
			{act: "add", wait: time.Minute},
		}},
		{"member leaves the set in the down time", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "lose", wait: time.Second, want: ab},
			{act: "remove"},
		}},
		{"member leaves the set after it was lost", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "lose", wait: time.Minute, want: ab},
			{act: "remove"},
			{act: "add", wait: time.Minute},
		}},
		{"member gets a new address after it was lost", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "lose", wait: time.Minute, want: ab},
			// A new address is a new relay process, which has none of the attachments.
			{act: "move", wait: time.Minute},
		}},
		{"member leaves the set after it was lost, and the two changes come later", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "lose", wait: time.Minute, hold: true, want: ab},
			{act: "remove", hold: true, want: ab},
			{act: ""},
		}},
		{"member leaves the set with attachments of two sessions", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "lose", wait: time.Second, want: ab},
			{act: "open", want: ab},
			{act: "send b c", want: abc},
			{act: "remove"},
		}},
		{"member comes back after it left the set", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "lose", wait: time.Minute, want: ab},
			{act: "remove"},
			{act: "add"},
			{act: "open"},
			{act: "send b end", wait: time.Minute, want: []string{"b"}, full: true},
		}},
		{"member stops and comes back", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "restart"},
			{act: "open"},
			{act: "send c", want: []string{"c"}},
		}},
		{"member stops, and its new session sends before the change", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "restart", hold: true, want: ab},
			{act: "open", hold: true, want: ab},
			{act: "send c d", hold: true, want: []string{"a", "b", "c", "d"}},
			// Only the attachments of the session before the stop go.
			{act: "", want: []string{"c", "d"}},
			{act: "send e", want: []string{"c", "d", "e"}},
		}},
		{"member stops, and its new session opens before the change", []step{
			{act: "open"}, {act: "send a b end", want: ab, full: true},
			{act: "restart", hold: true, want: ab, full: true},
			{act: "open", hold: true, want: ab, full: true},
			// The full set of the session before the stop goes with its attachments.
			{act: ""},
			{act: "send c", want: []string{"c"}},
			{act: "send end", want: []string{"c"}, full: true},
		}},
		{"member leaves the set, and its new session sends before the change", []step{
			{act: "open"}, {act: "send a b", want: ab},
			{act: "remove", hold: true, want: ab},
			{act: "add", hold: true, want: ab},
			{act: "open", hold: true, want: ab},
			{act: "send c", hold: true, want: abc},
			{act: "", want: []string{"c"}},
		}},
		{"member leaves the set, and its new session sends an attachment again before the change", []step{
			{act: "open"}, {act: "send a b end", want: ab, full: true},
			{act: "remove", hold: true, want: ab, full: true},
			{act: "add", hold: true, want: ab, full: true},
			{act: "open", hold: true, want: ab, full: true},
			{act: "send b c", hold: true, want: abc},
			// The new session sent b again, so b stays.
			{act: "", want: bc},
		}},
	}
	member := []MeshMember{{Name: "relay-a", Addr: netip.MustParseAddrPort("192.0.2.1:6081")}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// The test calls the hooks in place of Run, so that it can hold them.
				m := stubMesh(t)
				var sess *MeshSession
				var conn *stubConn
				gens, last, called := map[string]uint64{}, uint64(0), false
				for i, st := range tc.steps {
					switch act, ids, _ := strings.Cut(st.act, " "); act {
					case "open":
						sess, conn = openStub(t, m)
						called = false
					case "send":
						if !called {
							require.NoError(t, m.pres.accept(sess))
							called = true
						}
						// An ID keeps its generation, as in the full set of a new
						// session. "-<id>" is a gone entry, and "end" ends the full set.
						u := &dp.PresenceUpdate{}
						for _, id := range strings.Fields(ids) {
							if id == "end" {
								u.EndOfFullSet = true
								continue
							}
							id, isGone := strings.CutPrefix(id, "-")
							if gens[id] == 0 || isGone {
								last++
								gens[id] = last
							}
							e := memberEntry(id, gens[id])
							if isGone {
								e = &dp.Presence{AttachmentId: id, Generation: gens[id], Gone: true}
							}
							u.Entries = append(u.Entries, e)
						}
						require.NoError(t, m.pres.apply(sess, u))
					case "lose":
						conn.cancel(&quic.IdleTimeoutError{})
					case "restart":
						conn.cancel(&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART)})
					case "close":
						conn.cancel(&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(dp.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED)})
					case "remove":
						m.SetMembers(nil)
					case "add":
						m.SetMembers(member)
					case "move":
						m.SetMembers([]MeshMember{{Name: "relay-a", Addr: netip.MustParseAddrPort("192.0.2.7:6081")}})
					}
					time.Sleep(st.wait)
					synctest.Wait()
					if !st.hold {
						m.deliver()
					}
					if st.want == nil {
						st.want = []string{}
					}
					assert.Equal(t, st.want, presenceIDs(m, "relay-a"), "step %d (%s)", i, st.act)
					_, full := presenceEntries(m, "relay-a")
					assert.Equal(t, st.full, full, "full set at step %d (%s)", i, st.act)
					checkEntries(t, m)
				}
			})
		})
	}
}

// TestPresenceTimeLimitChanges ends the time for the full set of a session
// while its Presence call sends entries. The entries of that session stay.
func TestPresenceTimeLimitChanges(t *testing.T) {
	const rounds, entries = 50, 20
	m := stubMesh(t)
	var wg sync.WaitGroup
	for round := range rounds {
		// The entries of the session before are of an older session now.
		s, _ := openStub(t, m)
		require.NoError(t, m.pres.accept(s))
		wg.Go(func() { m.pres.expire(s) })
		var want []string
		for i := range entries {
			id := fmt.Sprintf("x%02d", i)
			want = append(want, id)
			require.NoError(t, m.pres.apply(s, &dp.PresenceUpdate{Entries: []*dp.Presence{memberEntry(id, uint64(round*entries+i+1))}}))
		}
		wg.Wait()
		require.Equal(t, want, presenceIDs(m, "relay-a"), "round %d", round)
		checkEntries(t, m)
	}
}

// TestPresenceBetweenRelays runs two relays with attachments. Each relay has
// the attachments of the other, and drops them when the other stops.
func TestPresenceBetweenRelays(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	a, b := newMeshNode(t, ca, "relay-a"), newMeshNode(t, ca, "relay-b")
	ra, rb := NewRouter(nil, Config{}), NewRouter(nil, Config{})
	a.m.SetRouter(ra)
	b.m.SetRouter(rb)
	sa := addSession(t, ra, vpcA, laptop, "192.0.2.1:1000").Session
	sb := addSession(t, rb, vpcA, server, "192.0.2.2:1000").Session
	require.NoError(t, ra.attach(sa, attachment("x", "fd00:1::/96")))
	a.m.SetMembers([]MeshMember{b.member()})
	b.m.SetMembers([]MeshMember{a.member()})
	b.start(t)
	a.start(t)

	// has waits until relay n has the attachments ids of relay from, after a full set.
	has := func(n *meshNode, from string, ids ...string) {
		t.Helper()
		require.Eventually(t, func() bool {
			_, full := presenceEntries(n.m, from)
			return full && slices.Equal(ids, presenceIDs(n.m, from))
		}, 10*time.Second, 5*time.Millisecond, "%s has the attachments %v of %s", n.name, ids, from)
	}
	has(b, "relay-a", "x")
	has(a, "relay-b")
	got, _ := presenceEntries(b.m, "relay-a")
	assert.Equal(t, presenceEntry{
		vpc: vpcA, networkID: testVNI, id: "x", gen: got["x"].gen, subject: laptop, tag: 1,
		prefixes: []netip.Prefix{netip.MustParsePrefix("fd00:1::/96")},
	}, got["x"])
	assert.InDelta(t, time.Now().UnixMilli(), got["x"].gen, 60_000, "the generation is the attach time")

	require.NoError(t, rb.attach(sb, attachment("y", "fd00:2::/96")))
	require.NoError(t, ra.attach(sa, attachment("z", "fd00:3::/96")))
	has(a, "relay-b", "y")
	has(b, "relay-a", "x", "z")
	_, _, err := ra.detach(sa, "x")
	require.NoError(t, err)
	has(b, "relay-a", "z")

	// relay-a stops. relay-b drops its attachments at once.
	a.cancel()
	require.Eventually(t, func() bool {
		entries, _ := presenceEntries(b.m, "relay-a")
		return entries == nil
	}, 2*time.Second, 5*time.Millisecond)
	assert.False(t, b.m.Up("relay-a"))
}
