// SPDX-License-Identifier: AGPL-3.0-only

package relay_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// writeLog is the data plane target of a test relay. It keeps each Write, refuses a Write whose
// updates bad matches, and holds a Read of keys entries for hold.
type writeLog struct {
	*vpctest.SocketTarget
	bad  func([]*p4.Update) bool // Set it before the relay starts.
	hold atomic.Pointer[readHold]

	mu     sync.Mutex
	writes []loggedWrite
}

// readHold holds the first Read of keys entries that starts at from or later: it closes held, and
// the Read continues after free.
type readHold struct {
	from     time.Time
	held     chan struct{}
	release  chan struct{}
	once     sync.Once
	freeOnce sync.Once
}

func newReadHold(from time.Time) *readHold {
	return &readHold{from: from, held: make(chan struct{}), release: make(chan struct{})}
}

// free lets the held Read continue.
func (h *readHold) free() { h.freeOnce.Do(func() { close(h.release) }) }

func (w *writeLog) Read(ctx context.Context, req *p4.ReadRequest, each func(*p4.Entity)) error {
	h := w.hold.Load()
	if h != nil && !time.Now().Before(h.from) && slices.ContainsFunc(req.GetEntities(), func(e *p4.Entity) bool { return e.GetExternEntry() != nil }) {
		h.once.Do(func() {
			close(h.held)
			<-h.release
		})
	}
	return w.SocketTarget.Read(ctx, req, each)
}

// loggedWrite is one Write of the relay.
type loggedWrite struct {
	start, end time.Time
	updates    []*p4.Update
	err        error
}

func (w *writeLog) Write(ctx context.Context, req *p4.WriteRequest) error {
	start := time.Now()
	var err error
	if w.bad != nil && w.bad(req.GetUpdates()) {
		err = status.Error(codes.InvalidArgument, "the test refuses an update of the batch")
	} else {
		err = w.SocketTarget.Write(ctx, req)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, loggedWrite{start: start, end: time.Now(), updates: slices.Clone(req.GetUpdates()), err: err})
	return err
}

// all returns the Writes until now.
func (w *writeLog) all() []loggedWrite {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.writes)
}

// with returns the Writes with an update that f matches.
func (w *writeLog) with(f func(*p4.Update) bool) []loggedWrite {
	var out []loggedWrite
	for _, lw := range w.all() {
		if lw.count(f) > 0 {
			out = append(out, lw)
		}
	}
	return out
}

// firstAfter waits for the first Write that starts at t0 or later and has an update that f matches.
func (w *writeLog) firstAfter(t *testing.T, t0 time.Time, f func(*p4.Update) bool) loggedWrite {
	t.Helper()
	var got loggedWrite
	require.Eventually(t, func() bool {
		for _, lw := range w.with(f) {
			if !lw.start.Before(t0) {
				got = lw
				return true
			}
		}
		return false
	}, wait, 10*time.Millisecond)
	return got
}

// count returns the number of updates of the Write that f matches.
func (lw loggedWrite) count(f func(*p4.Update) bool) int {
	n := 0
	for _, u := range lw.updates {
		if f(u) {
			n++
		}
	}
	return n
}

// isTable matches an update of type typ of an entry of table.
func isTable(typ p4.Update_Type, table uint32) func(*p4.Update) bool {
	return func(u *p4.Update) bool {
		return u.GetType() == typ && u.GetEntity().GetTableEntry().GetTableId() == table
	}
}

// isKeys matches an update of type typ of a keys entry.
func isKeys(typ p4.Update_Type) func(*p4.Update) bool {
	return func(u *p4.Update) bool { return u.GetType() == typ && u.GetEntity().GetExternEntry() != nil }
}

// isKeysIn matches an update of type typ of a keys entry in direction dir.
func isKeysIn(typ p4.Update_Type, dir dpv1.PspSaDirection) func(*p4.Update) bool {
	return func(u *p4.Update) bool {
		se := &dpv1.PspSaEntry{}
		return u.GetType() == typ && u.GetEntity().GetExternEntry().GetEntry().UnmarshalTo(se) == nil && se.GetDirection() == dir
	}
}

var (
	portsInsert = isTable(p4.Update_INSERT, dp.TablePorts)
	portsDelete = isTable(p4.Update_DELETE, dp.TablePorts)
)

// anyOf matches the updates of a Write when f matches one of them.
func anyOf(f func(*p4.Update) bool) func([]*p4.Update) bool {
	return func(us []*p4.Update) bool { return slices.ContainsFunc(us, f) }
}

// entries returns the number of table entries and of keys entries in the data plane.
func (w *writeLog) entries(t *testing.T) (tables, keys int) {
	t.Helper()
	req := &p4.ReadRequest{Entities: []*p4.Entity{
		{Entity: &p4.Entity_TableEntry{TableEntry: &p4.TableEntry{}}},
		{Entity: &p4.Entity_ExternEntry{ExternEntry: &p4.ExternEntry{}}},
	}}
	require.NoError(t, w.SocketTarget.Read(t.Context(), req, func(e *p4.Entity) {
		if e.GetTableEntry() != nil {
			tables++
		} else {
			keys++
		}
	}))
	return tables, keys
}

// firstOf waits for the first message of a Session call that begin started.
func firstOf(t *testing.T, c <-chan first) first {
	t.Helper()
	select {
	case f := <-c:
		return f
	case <-time.After(wait):
		t.Fatal("no first message of the relay")
		return first{}
	}
}

// arrival waits for a message of the relay after the first one that matches f, and returns its
// arrival time.
func (a *agent) arrival(f func(*dpv1.SessionResponse) bool) time.Time {
	a.t.Helper()
	var at time.Time
	require.Eventually(a.t, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		if i := slices.IndexFunc(a.msgs, f); i >= 0 {
			at = a.at[i]
			return true
		}
		return false
	}, wait, 10*time.Millisecond)
	return at
}

// TestTableWriteBatches checks the write rate of the root for events that no chain waits for, the
// ends of connections: one Write in each table write interval at most, and that Write has the
// changes of the interval. A change after a quiet interval writes at once.
func TestTableWriteBatches(t *testing.T) {
	cases := []struct {
		name     string
		interval *time.Duration // The config field. nil is omitted.
		pause    time.Duration  // The wait after the Writes of the end of the first connection.
		next     int            // The connections that then end at once.
		want     []int          // The ports deletes of each Write that has one. nil is any.
		hold     time.Duration  // The least time from the end of a Write to the next Write.
		atOnce   bool           // The ends of the next connections write with no wait.
	}{
		{name: "quiet", interval: new(time.Second), pause: 1100 * time.Millisecond, next: 1, want: []int{1, 1}, hold: time.Second, atOnce: true},
		{name: "burst", interval: new(time.Second), next: 3, want: []int{1, 3}, hold: time.Second},
		{name: "interval 0", interval: new(time.Duration(0)), next: 3, atOnce: true},
		{name: "config omitted", next: 3, hold: relay.DefaultTableWriteInterval},
		// The ends can come in two intervals of 400ms, so this case checks only the time between Writes.
		{name: "config set", interval: new(400 * time.Millisecond), next: 3, hold: 400 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := &writeLog{}
			e := newEnvWith(t, envOpts{interval: tc.interval, writes: log})
			as := make([]*agent, 1+tc.next)
			for i := range as {
				as[i] = e.dial(t, fmt.Sprintf("agent-%d", i))
				as[i].open(dpv1.Mode_MODE_QUIC)
			}
			// The first end comes after a quiet interval.
			time.Sleep(1100 * time.Millisecond)
			start := time.Now()
			require.NoError(t, as[0].qc.CloseWithError(0, ""))
			log.firstAfter(t, start, isTable(p4.Update_DELETE, dp.TableClassify))
			time.Sleep(tc.pause)
			next := time.Now()
			for _, a := range as[1:] {
				require.NoError(t, a.qc.CloseWithError(0, ""))
			}

			var ws []loggedWrite
			require.Eventually(t, func() bool {
				ws = log.with(portsDelete)
				n := 0
				for _, w := range ws {
					n += w.count(portsDelete)
				}
				return n == len(as)
			}, wait, 10*time.Millisecond, "ports deletes of the ends")
			var got []int
			for _, w := range ws {
				require.NoError(t, w.err)
				got = append(got, w.count(portsDelete))
				if !w.start.Before(next) {
					// The wait of a ports delete is one interval at most.
					assert.Less(t, w.end.Sub(next), tc.hold+500*time.Millisecond, "wait of a ports delete of the next ends")
				}
			}
			if tc.want != nil {
				assert.Equal(t, tc.want, got, "ports deletes of each Write; the next ends come in one interval")
			}
			var after []loggedWrite
			for _, w := range log.all() {
				if !w.start.Before(start) {
					after = append(after, w)
				}
			}
			for i := 1; i < len(after); i++ {
				assert.GreaterOrEqual(t, after[i].start.Sub(after[i-1].end), tc.hold, "time from Write %d to Write %d", i-1, i)
			}
			if tc.atOnce {
				w := log.firstAfter(t, next, portsDelete)
				assert.Less(t, w.start.Sub(next), 300*time.Millisecond, "wait of the first Write of the next ends")
			}
		})
	}
}

// TestTableWriteBadEvent checks a batch with one bad event: the root writes each event alone, so
// that the other events apply, and only the call of the bad event gets an error.
func TestTableWriteBadEvent(t *testing.T) {
	const badSPI = 0x2002
	vpcB := relay.VPCKey{Project: project, UID: "vpc-b"}
	netB := relay.Network{ID: 0x2345, Name: "net-b"}
	// The TX entry of the SA of the call of b is bad.
	bad := func(u *p4.Update) bool {
		se := &dpv1.PspSaEntry{}
		return isKeysIn(p4.Update_INSERT, dpv1.PspSaDirection_PSP_SA_DIRECTION_TX)(u) &&
			u.GetEntity().GetExternEntry().GetEntry().UnmarshalTo(se) == nil && se.GetSpi() == badSPI
	}
	log := &writeLog{bad: anyOf(bad)}
	e := newEnvWith(t, envOpts{interval: new(time.Second), writes: log})
	e.r.AddVPC(vpcB, netB)
	b, err := e.dialVPC(t, vpcB.UID, "agent-b")
	require.NoError(t, err)
	calls := []struct {
		a   *agent
		spi uint32
		vni uint32
	}{{e.dial(t, "agent-1"), 0x2001, netID}, {b, badSPI, netB.ID}, {e.dial(t, "agent-2"), 0x2003, netID}}
	for _, c := range calls {
		c.a.open(dpv1.Mode_MODE_QUIC)
		c.a.probe(e, pspSocket(t), 1)
	}

	// The root waits in the Read of its next tick, and the three Rekey calls come in that time, so
	// their events go in one batch.
	hold := newReadHold(time.Now())
	t.Cleanup(hold.free)
	log.hold.Store(hold)
	select {
	case <-hold.held:
	case <-time.After(wait):
		t.Fatal("no tick of the key engine")
	}
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	errs := make([]chan error, len(calls))
	for i, c := range calls {
		errs[i] = make(chan error, 1)
		go func() {
			_, err := c.a.rc.Rekey(t.Context(), offer(c.spi, key, c.vni, 1))
			errs[i] <- err
		}()
	}
	time.Sleep(time.Second)
	t0 := time.Now()
	hold.free()
	for i, c := range calls {
		select {
		case err := <-errs[i]:
			if c.spi == badSPI {
				assert.Equal(t, rpc.Unavailable, rpc.CodeOf(err), "error of the call of b: %v", err)
			} else {
				assert.NoError(t, err)
			}
		case <-time.After(wait):
			t.Fatal("no answer to Rekey")
		}
	}

	rxInsert := isKeysIn(p4.Update_INSERT, dpv1.PspSaDirection_PSP_SA_DIRECTION_RX)
	var ws []loggedWrite
	for _, w := range log.with(rxInsert) {
		if w.start.After(t0) {
			ws = append(ws, w)
		}
	}
	require.Len(t, ws, 4, "the batch, and the three events alone")
	assert.Equal(t, 3, ws[0].count(rxInsert))
	assert.Error(t, ws[0].err)
	failed := 0
	for _, w := range ws[1:] {
		assert.Equal(t, 1, w.count(rxInsert))
		if w.count(bad) > 0 {
			assert.Error(t, w.err)
			failed++
		} else {
			assert.NoError(t, w.err)
		}
	}
	assert.Equal(t, 1, failed)
	assert.Less(t, ws[3].start.Sub(ws[0].end), 300*time.Millisecond, "the events alone write at once")
}

// TestTableWriteBadOpen checks a batch with the bad first entries of a connection: the root writes
// each event alone, so the other event applies, and the relay closes the connection with its reason.
func TestTableWriteBadOpen(t *testing.T) {
	vpcB := relay.VPCKey{Project: project, UID: "vpc-b"}
	// The classify entry of a connection of vpc-b is bad.
	bad := func(u *p4.Update) bool {
		te := u.GetEntity().GetTableEntry()
		if u.GetType() != p4.Update_INSERT || te.GetTableId() != dp.TableClassify {
			return false
		}
		return slices.ContainsFunc(te.GetAction().GetAction().GetParams(), func(p *p4.Action_Param) bool {
			return p.GetParamId() == 1 && bytes.HasPrefix(p.GetValue(), []byte(vpcB.UID+"/"))
		})
	}
	log := &writeLog{bad: anyOf(bad)}
	e := newEnvWith(t, envOpts{interval: new(time.Second), writes: log})
	e.r.AddVPC(vpcB, relay.Network{ID: 0x2345, Name: "net-b"})
	a, x := e.dial(t, "agent-a"), e.dial(t, "agent-x")
	b, err := e.dialVPC(t, vpcB.UID, "agent-b")
	require.NoError(t, err)
	a.open(dpv1.Mode_MODE_QUIC)
	x.open(dpv1.Mode_MODE_QUIC)
	before := log.all()
	mark := before[len(before)-1].end.Add(time.Second)

	// The end of x comes just after its Write, so the delete of its ports entry waits for the mark.
	t0 := time.Now()
	require.NoError(t, x.qc.CloseWithError(0, ""))
	time.Sleep(200 * time.Millisecond)
	// The Welcome of b waits for its first entries, so they go at once with the delete in one batch.
	f := firstOf(t, b.begin(hello(dpv1.Mode_MODE_QUIC)))
	assert.Error(t, f.err)
	assert.Nil(t, f.m.GetWelcome(), "first message of b: %v", f.m)
	code, msg := b.closed()
	assert.Equal(t, dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, code)
	assert.Equal(t, "relay failed to add the connection", msg)

	var ws []loggedWrite
	for _, w := range log.with(func(u *p4.Update) bool { return portsDelete(u) || bad(u) }) {
		if !w.start.Before(t0) {
			ws = append(ws, w)
		}
	}
	require.Len(t, ws, 3, "the batch, and the two events alone")
	assert.True(t, ws[0].start.Before(mark), "Write of the batch at %v, mark at %v", ws[0].start, mark)
	for i, want := range []struct {
		deletes, bad int
		ok           bool
	}{{1, 1, false}, {1, 0, true}, {0, 1, false}} {
		assert.Equal(t, want.deletes, ws[i].count(portsDelete), "ports deletes of Write %d", i)
		assert.Equal(t, want.bad, ws[i].count(bad), "bad entries of Write %d", i)
		assert.Equal(t, want.ok, ws[i].err == nil, "result of Write %d: %v", i, ws[i].err)
	}
	// a has its classify entry, x deletes its own after its ports entry, and b has none.
	log.firstAfter(t, t0, isTable(p4.Update_DELETE, dp.TableClassify))
	n := 0
	require.NoError(t, log.SocketTarget.Read(t.Context(), &p4.ReadRequest{Entities: []*p4.Entity{{Entity: &p4.Entity_TableEntry{
		TableEntry: &p4.TableEntry{TableId: dp.TableClassify},
	}}}}, func(e *p4.Entity) {
		assert.False(t, bad(&p4.Update{Type: p4.Update_INSERT, Entity: e}))
		n++
	}))
	assert.Equal(t, 1, n)
}

// TestTableWriteVPCEnd checks the end of a VPC with no agents on the relay while the route of a
// mesh member waits for the interval: the route goes in at the mark, and then the end deletes it.
func TestTableWriteVPCEnd(t *testing.T) {
	vpcB := relay.VPCKey{Project: project, UID: "vpc-b"}
	refB := &dpv1.VPCRef{ProjectId: vpcB.Project, VpcUid: vpcB.UID}
	log := &writeLog{}
	e1, e2 := newMesh(t, envOpts{interval: new(time.Second), writes: log}, envOpts{interval: new(time.Duration(0))})
	for _, e := range []*env{e1, e2} {
		e.r.AddVPC(vpcB, relay.Network{ID: 0x2345, Name: "net-b"})
	}
	routeInsert := isTable(p4.Update_INSERT, dp.TableRoute)
	start := time.Now()
	b1 := e2.dialIn(t, vpcB, "agent-b1")
	b1.open(dpv1.Mode_MODE_QUIC)
	b1.attachIn(refB, "fd00:b1::/64")
	log.firstAfter(t, start, routeInsert)
	b2 := e2.dialIn(t, vpcB, "agent-b2")
	b2.open(dpv1.Mode_MODE_QUIC)
	t0 := time.Now()
	b2.attachIn(refB, "fd00:b2::/64")
	// After the write of the entries of the records of b2, its route waits for the next mark.
	src := log.firstAfter(t, t0, isTable(p4.Update_INSERT, dp.TableSource))
	time.Sleep(time.Until(src.end.Add(300 * time.Millisecond)))
	require.Empty(t, slices.DeleteFunc(log.with(routeInsert), func(w loggedWrite) bool { return w.start.Before(t0) }),
		"the route of b2 waits for the interval")
	e1.r.RemoveVPC(vpcB)
	route := log.firstAfter(t, t0, routeInsert)
	require.NoError(t, route.err)
	routes := func() int {
		n := 0
		require.NoError(t, log.SocketTarget.Read(t.Context(), &p4.ReadRequest{Entities: []*p4.Entity{{Entity: &p4.Entity_TableEntry{
			TableEntry: &p4.TableEntry{TableId: dp.TableRoute},
		}}}}, func(*p4.Entity) { n++ }))
		return n
	}
	assert.Eventually(t, func() bool { return routes() == 0 }, wait, 10*time.Millisecond, "route entries after the end of the VPC")
}

// TestTableWriteFailedRoute checks a failed write of the route entries of an attachment: Attach
// gets the error, and no agent gets the route. A next Attach then writes the route.
func TestTableWriteFailedRoute(t *testing.T) {
	const prefix = "fd00:9::/64"
	var refuse atomic.Bool
	routeInsert := isTable(p4.Update_INSERT, dp.TableRoute)
	log := &writeLog{bad: func(us []*p4.Update) bool { return refuse.Load() && slices.ContainsFunc(us, routeInsert) }}
	e := newEnvWith(t, envOpts{interval: new(300 * time.Millisecond), writes: log})
	w := e.dial(t, "watcher")
	w.open(dpv1.Mode_MODE_QUIC)
	w.attach()
	a := e.dial(t, "agent-a")
	a.open(dpv1.Mode_MODE_QUIC)
	refuse.Store(true)
	_, err := a.rc.Attach(t.Context(), &dpv1.AttachRequest{Vpc: vpcRef, Name: a.name, Routes: []string{prefix}})
	assert.Equal(t, rpc.Unavailable, rpc.CodeOf(err), "error: %v", err)
	ws := log.with(routeInsert)
	require.NotEmpty(t, ws)
	assert.Error(t, ws[len(ws)-1].err)
	// The route can come in the next interval.
	time.Sleep(500 * time.Millisecond)
	assert.Empty(t, w.all(func(m *dpv1.SessionResponse) bool {
		return slices.ContainsFunc(m.GetRouteDelta().GetAdd(), func(r *dpv1.Route) bool { return r.GetPrefix() == prefix })
	}), "routes of the failed attachment at the watcher")

	refuse.Store(false)
	a.attach(prefix)
	w.waitRoute(prefix, true)
}

// TestTableWriteFailedDelete checks a failed delete of the route entries at the end of a
// connection: the members still get the end of its announcement.
func TestTableWriteFailedDelete(t *testing.T) {
	const prefix = "fd00:1::/64"
	var refuse atomic.Bool
	routeDelete := isTable(p4.Update_DELETE, dp.TableRoute)
	log := &writeLog{bad: func(us []*p4.Update) bool { return refuse.Load() && slices.ContainsFunc(us, routeDelete) }}
	e1, e2 := newMesh(t, envOpts{interval: new(300 * time.Millisecond), writes: log}, envOpts{})
	a := e1.dial(t, "agent-a")
	a.open(dpv1.Mode_MODE_QUIC)
	a.attach(prefix)
	w := e2.dial(t, "watcher")
	w.open(dpv1.Mode_MODE_QUIC)
	w.attach()
	w.waitRoute(prefix, true)

	refuse.Store(true)
	require.NoError(t, a.qc.CloseWithError(0, ""))
	w.waitRoute(prefix, false)
	ws := log.with(routeDelete)
	require.NotEmpty(t, ws)
	assert.Error(t, ws[0].err)
}

// TestTableWriteChain checks the events that a waiting chain needs: the root writes each step of
// the chain at once, also when the last Write was just before, and each answer comes after the
// write of its changes.
func TestTableWriteChain(t *testing.T) {
	var attID string // The attachment that Detach ends.
	// In the PSP path case, peer at srcB sends to the agent at srcA, which has its PSP address at sock.
	var (
		peer       *agent
		srcA, srcB netip.Addr
		sock       *net.UDPConn
	)
	// In the Drain case, relay-2 (other) has agent-b with the same route as agent-a on relay-1.
	const drainPrefix = "fd00:3::/64"
	var (
		other  *env
		member *agent
		idB    string
	)
	cases := []struct {
		name string
		mesh bool // relay-1 is in a mesh with other.
		// setup runs before the call. Its last step writes, so the interval is not over at the call.
		setup func(t *testing.T, e *env, a *agent)
		// call makes the call and returns the arrival time of each answer.
		call func(t *testing.T, e *env, a *agent) []time.Time
		// need has the changes of the steps of the chain, in order.
		need []func(*p4.Update) bool
	}{
		{
			name:  "Welcome",
			setup: func(t *testing.T, e *env, _ *agent) { e.dial(t, "agent-h").open(dpv1.Mode_MODE_QUIC) },
			call: func(t *testing.T, _ *env, a *agent) []time.Time {
				f := firstOf(t, a.begin(hello(dpv1.Mode_MODE_QUIC)))
				require.NoError(t, f.err)
				require.NotNil(t, f.m.GetWelcome())
				return []time.Time{f.at}
			},
			need: []func(*p4.Update) bool{portsInsert},
		},
		{
			name:  "Attach",
			setup: func(t *testing.T, _ *env, a *agent) { a.open(dpv1.Mode_MODE_QUIC) },
			call: func(t *testing.T, _ *env, a *agent) []time.Time {
				a.attach()
				return []time.Time{time.Now()}
			},
			need: []func(*p4.Update) bool{isTable(p4.Update_INSERT, dp.TableSource), isTable(p4.Update_INSERT, dp.TableRoute)},
		},
		{
			name: "Detach",
			setup: func(t *testing.T, _ *env, a *agent) {
				a.open(dpv1.Mode_MODE_QUIC)
				attID = a.attach().GetAttachmentId()
			},
			call: func(t *testing.T, _ *env, a *agent) []time.Time {
				_, err := a.rc.Detach(t.Context(), &dpv1.DetachRequest{AttachmentId: attID})
				require.NoError(t, err)
				return []time.Time{time.Now()}
			},
			need: []func(*p4.Update) bool{
				isTable(p4.Update_DELETE, dp.TableRoute),
				isTable(p4.Update_DELETE, dp.TableSource),
				func(u *p4.Update) bool { return u.GetEntity().GetCounterEntry() != nil },
			},
		},
		{
			name: "Rekey to PSP mode",
			setup: func(t *testing.T, e *env, a *agent) {
				a.open(dpv1.Mode_MODE_QUIC)
				a.probe(e, pspSocket(t), 1)
			},
			call: func(t *testing.T, _ *env, a *agent) []time.Time {
				key := make([]byte, 16)
				_, _ = rand.Read(key)
				res, err := a.rc.Rekey(t.Context(), offer(0x1001, key, netID, 1))
				at := time.Now()
				require.NoError(t, err)
				require.Empty(t, res.GetRefusedSpis())
				return []time.Time{at, a.arrival(isRekey)}
			},
			need: []func(*p4.Update) bool{isKeys(p4.Update_INSERT), isTable(p4.Update_MODIFY, dp.TablePorts)},
		},
		{
			name: "RegisterLanes",
			setup: func(t *testing.T, e *env, a *agent) {
				a.open(dpv1.Mode_MODE_QUIC)
				a.toPSP(e, pspSocket(t), 1)
			},
			call: func(t *testing.T, _ *env, a *agent) []time.Time {
				_, err := a.rc.RegisterLanes(t.Context(), &dpv1.RegisterLanesRequest{Ports: []uint32{40000}})
				require.NoError(t, err)
				return []time.Time{time.Now()}
			},
			need: []func(*p4.Update) bool{isTable(p4.Update_MODIFY, dp.TablePorts)},
		},
		{
			name: "probe from a new address in PSP mode",
			setup: func(t *testing.T, e *env, a *agent) {
				a.open(dpv1.Mode_MODE_QUIC)
				a.toPSP(e, pspSocket(t), 1)
			},
			call: func(t *testing.T, e *env, a *agent) []time.Time {
				sock := pspSocket(t)
				a.probes++
				require.Equal(t, sock.LocalAddr().(*net.UDPAddr).AddrPort(), a.probe(e, sock, a.probes))
				return []time.Time{time.Now()}
			},
			need: []func(*p4.Update) bool{isTable(p4.Update_MODIFY, dp.TablePorts)},
		},
		{
			// The agent is in QUIC mode after the Down packet, so a packet to it is in a data frame.
			name: "PSP path lost",
			setup: func(t *testing.T, e *env, a *agent) {
				a.open(dpv1.Mode_MODE_QUIC)
				srcA = addr(t, a.attach())
				peer = e.dial(t, "agent-b")
				peer.open(dpv1.Mode_MODE_QUIC)
				srcB = addr(t, peer.attach())
				sock = pspSocket(t)
				a.toPSP(e, sock, 1)
				a.upCheck(e, sock)
				// The answer comes after a write, so the interval is not over at the call. The lane port
				// is not the port of sock.
				lane := uint32(40000)
				if sock.LocalAddr().(*net.UDPAddr).Port == int(lane) {
					lane++
				}
				_, err := a.rc.RegisterLanes(t.Context(), &dpv1.RegisterLanesRequest{Ports: []uint32{lane}})
				require.NoError(t, err)
			},
			call: func(t *testing.T, e *env, a *agent) []time.Time {
				a.loseCheck(e, sock)
				// The relay sends Down before the change, so a packet just after it can go in PSP.
				p := packet(srcB, srcA, 100)
				for start := time.Now(); time.Since(start) < 300*time.Millisecond; {
					peer.sendFrame(p)
					// The frame can come before the end of the Write call, so it is not an answer.
					if got := a.recvFrame(20 * time.Millisecond); got != nil {
						require.Equal(t, p, got)
						return nil
					}
				}
				require.Fail(t, "no data frame in 300ms after the Down packet")
				return nil
			},
			need: []func(*p4.Update) bool{isTable(p4.Update_MODIFY, dp.TablePorts)},
		},
		{
			// The Draining state moves the route to agent-b, and the member gets it before Drain.
			name: "Drain",
			mesh: true,
			setup: func(t *testing.T, e *env, a *agent) {
				a.open(dpv1.Mode_MODE_QUIC)
				idA := a.attach(drainPrefix).GetAttachmentId()
				b := other.dial(t, "agent-b")
				b.open(dpv1.Mode_MODE_QUIC)
				idB = b.attach(drainPrefix).GetAttachmentId()
				member = e.dial(t, "member")
				member.open(dpv1.Mode_MODE_QUIC)
				require.Eventually(t, func() bool {
					r := member.route(drainPrefix)
					return r.GetOrigin() == idA && slices.Contains(r.GetStandby(), idB)
				}, wait, 10*time.Millisecond)
				// The Welcome comes after a write, so the interval is not over at the call.
				e.dial(t, "agent-h").open(dpv1.Mode_MODE_QUIC)
			},
			call: func(t *testing.T, e *env, _ *agent) []time.Time {
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() {
					defer close(done)
					e.srv.Drain(ctx)
				}()
				t.Cleanup(func() {
					cancel()
					<-done
				})
				isDrain := func(m *dpv1.SessionResponse) bool { return m.GetDrain() != nil }
				moved := func(m *dpv1.SessionResponse) bool {
					return slices.ContainsFunc(m.GetRouteDelta().GetAdd(), func(r *dpv1.Route) bool {
						return r.GetPrefix() == drainPrefix && r.GetOrigin() == idB
					})
				}
				at := member.arrival(isDrain)
				member.arrival(moved)
				member.mu.Lock()
				iMoved, iDrain := slices.IndexFunc(member.msgs, moved), slices.IndexFunc(member.msgs, isDrain)
				member.mu.Unlock()
				require.Less(t, iMoved, iDrain, "the member got Drain before the route with the origin agent-b")
				return []time.Time{at}
			},
			need: []func(*p4.Update) bool{isTable(p4.Update_MODIFY, dp.TableRoute)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := &writeLog{}
			o := envOpts{interval: new(time.Second), writes: log}
			var e *env
			if tc.mesh {
				e, other = newMesh(t, o, envOpts{interval: new(time.Duration(0))})
			} else {
				e = newEnvWith(t, o)
			}
			a := e.dial(t, "agent-a")
			tc.setup(t, e, a)
			t0 := time.Now()
			ats := tc.call(t, e, a)
			prev := t0
			for i, f := range tc.need {
				w := log.firstAfter(t, t0, f)
				require.NoError(t, w.err)
				assert.False(t, w.start.Before(prev), "Write of step %d at %v, before the end %v of the step before", i, w.start, prev)
				assert.Less(t, w.start.Sub(t0), 300*time.Millisecond, "wait of the Write of step %d", i)
				prev = w.end
				for _, at := range ats {
					assert.True(t, at.After(w.end), "answer %v before the end %v of the Write of step %d", at, w.end, i)
				}
			}
		})
	}
}

// TestTableWriteKeyChanges checks the changes of the key engine, here the delete of the TX entry of
// an agent SA that expired: they wait for the next mark, and chain events that come in that time
// write once with them.
func TestTableWriteKeyChanges(t *testing.T) {
	// The interval is longer than the time to the tick after the expiry and the hold of its Read.
	const interval = 4 * time.Second
	cases := []struct {
		name  string
		burst int // The Rekey calls that come while the change waits.
	}{
		{name: "alone"},
		{name: "chain burst", burst: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := &writeLog{}
			e := newEnvWith(t, envOpts{interval: new(interval), writes: log})
			bs := make([]*agent, tc.burst)
			for i := range bs {
				bs[i] = e.dial(t, fmt.Sprintf("agent-%d", i))
				bs[i].open(dpv1.Mode_MODE_QUIC)
				bs[i].probe(e, pspSocket(t), 1)
			}
			// a changes to PSP mode with an agent SA that expires after 1.5s.
			a := e.dial(t, "agent-a")
			a.open(dpv1.Mode_MODE_QUIC)
			sock := pspSocket(t)
			a.probes++
			a.probe(e, sock, a.probes)
			key := make([]byte, 16)
			_, _ = rand.Read(key)
			req := offer(0x1001, key, netID, 1)
			req.GetOffer().GetSas()[0].ExpiresIn = durationpb.New(1500 * time.Millisecond)
			_, err := a.rc.Rekey(t.Context(), req)
			require.NoError(t, err)
			expiry := time.Now().Add(1500 * time.Millisecond)
			a.keepPath(e, sock)

			// A Write just before the expiry, so the delete of the TX entry waits for the mark.
			time.Sleep(time.Until(expiry.Add(-200 * time.Millisecond)))
			th := time.Now()
			e.dial(t, "agent-h").open(dpv1.Mode_MODE_QUIC)
			last := log.firstAfter(t, th, portsInsert)
			t1 := time.Now()
			if tc.burst > 0 {
				// The tick of the key engine after the expiry waits in its Read, and the Rekey calls
				// come in that time.
				hold := newReadHold(expiry.Add(50 * time.Millisecond))
				t.Cleanup(hold.free)
				log.hold.Store(hold)
				require.True(t, time.Now().Before(hold.from), "the Write of agent-h came after the expiry")
				select {
				case <-hold.held:
				case <-time.After(wait):
					t.Fatal("no tick of the key engine after the expiry")
				}
				errs := make(chan error, len(bs))
				for i, b := range bs {
					go func() {
						_, err := b.rc.Rekey(t.Context(), offer(uint32(0x2001+i), key, netID, 1))
						errs <- err
					}()
				}
				time.Sleep(time.Second)
				t1 = time.Now()
				hold.free()
				for range bs {
					select {
					case err := <-errs:
						require.NoError(t, err)
					case <-time.After(wait):
						t.Fatal("no answer to Rekey")
					}
				}
			}

			del := log.firstAfter(t, last.end, isKeysIn(p4.Update_DELETE, dpv1.PspSaDirection_PSP_SA_DIRECTION_TX))
			require.NoError(t, del.err)
			var after []loggedWrite
			for _, w := range log.all() {
				if w.start.After(last.end) {
					after = append(after, w)
				}
			}
			require.NotEmpty(t, after)
			assert.Equal(t, del.start, after[0].start, "the first Write after the Write of agent-h has the key change")
			mark := last.end.Add(interval)
			if tc.burst == 0 {
				assert.False(t, del.start.Before(mark), "Write of the key change at %v, before the mark %v", del.start, mark)
				return
			}
			assert.True(t, del.start.Before(mark), "Write of the burst at %v, after the mark %v", del.start, mark)
			assert.Less(t, del.start.Sub(t1), 300*time.Millisecond, "the chain events write at once")
			assert.Equal(t, tc.burst, del.count(isKeysIn(p4.Update_INSERT, dpv1.PspSaDirection_PSP_SA_DIRECTION_RX)), "RX inserts of the Rekey calls in the Write of the key change")
			n := 0
			for _, w := range after {
				if w.count(isKeys(p4.Update_INSERT)) > 0 {
					n++
				}
			}
			assert.Equal(t, 1, n, "Writes with keys inserts")
		})
	}
}

// TestTableWriteFinalCounts checks that the final counts of an attachment have each packet that
// the relay sent on, also when the delete of its ports entry waits for the interval.
func TestTableWriteFinalCounts(t *testing.T) {
	cases := []struct {
		name     string
		interval time.Duration
	}{
		{name: "interval 0", interval: 0},
		{name: "interval 300ms", interval: 300 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnvWith(t, envOpts{interval: new(tc.interval)})
			a := e.dial(t, "agent-a")
			a.open(dpv1.Mode_MODE_QUIC)
			resA := a.attach()
			b := e.dial(t, "agent-b")
			b.open(dpv1.Mode_MODE_QUIC)
			resB := b.attach()
			src, dst := addr(t, resA), addr(t, resB)

			// b counts the frames from a. a sends one frame each millisecond until the relay closes it.
			var got atomic.Uint64
			ctx, cancel := context.WithCancel(t.Context())
			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				for {
					f, err := b.qc.ReceiveDatagram(ctx)
					if err != nil {
						return
					}
					if _, inner, err := peerconn.DecodeData(f); err == nil && len(inner) >= 40 {
						if s, ok := netip.AddrFromSlice(inner[8:24]); ok && s == src {
							got.Add(1)
						}
					}
				}
			}()
			go func() {
				defer wg.Done()
				tick := time.NewTicker(time.Millisecond)
				defer tick.Stop()
				for {
					if a.qc.SendDatagram(peerconn.EncodeData(nil, netID, packet(src, dst, 200))) != nil {
						return
					}
					select {
					case <-stop:
						return
					case <-tick.C:
					}
				}
			}()
			defer func() {
				close(stop)
				cancel()
				wg.Wait()
			}()
			require.Eventually(t, func() bool { return got.Load() > 100 }, wait, 10*time.Millisecond)
			time.Sleep(tc.interval)

			// The Write of a new connection comes just before, so the delete of the ports entry of a
			// waits for the interval. The packets of a still go to b in that time.
			e.dial(t, "agent-h").open(dpv1.Mode_MODE_QUIC)
			e.addrs.loseSlot(resA.GetAttachmentId())
			end := e.waitEnd(t, resA.GetAttachmentId())
			require.Eventually(t, func() bool { return got.Load() >= end.RXPackets }, wait, 10*time.Millisecond)
			time.Sleep(300 * time.Millisecond)
			assert.Equal(t, got.Load(), end.RXPackets, "frames at b and the final receive count of a")
		})
	}
}

// TestTableWriteStop checks a stop of the relay while a batch waits for the interval: the relay
// ends, the root writes the batch at its mark and keeps the interval until it ends, an Attach that
// waits gets its answer, a Hello at the stop gets no Welcome, and no entry stays in the data plane.
func TestTableWriteStop(t *testing.T) {
	log := &writeLog{}
	e := newEnvWith(t, envOpts{interval: new(time.Second), writes: log})
	a, b, c := e.dial(t, "agent-a"), e.dial(t, "agent-b"), e.dial(t, "agent-c")
	a.open(dpv1.Mode_MODE_QUIC)
	// The Attach of a waits in Assign until the connection of a closes.
	held := e.addrs.holdOne()
	attached := make(chan error, 1)
	go func() {
		_, err := a.rc.Attach(context.Background(), &dpv1.AttachRequest{Vpc: vpcRef, Name: a.name})
		attached <- err
	}()
	select {
	case <-held:
	case <-time.After(wait):
		t.Fatal("the relay did not call Assign")
	}
	b.open(dpv1.Mode_MODE_QUIC)
	opened := log.all()
	require.Len(t, opened, 2)
	// The end of b comes just after the Write of b, so the delete of its ports entry waits.
	require.NoError(t, b.qc.CloseWithError(0, ""))
	time.Sleep(time.Until(opened[1].end.Add(500 * time.Millisecond)))
	require.Len(t, log.all(), 2, "the delete of the ports entry of b waits for the interval")

	stopAt := time.Now()
	stopped := make(chan struct{})
	go func() {
		e.stop()
		close(stopped)
	}()
	// The stop closes a, so its Attach gets an answer before the end of the connection.
	select {
	case err := <-attached:
		assert.Equal(t, rpc.Unavailable, rpc.CodeOf(err), "error of the Attach: %v", err)
		assert.NoError(t, a.qc.Context().Err(), "the connection of a closed before the answer")
	case <-time.After(wait):
		t.Fatal("no answer to Attach")
	}
	// The relay stops now, so it refuses a Hello.
	f := firstOf(t, c.begin(hello(dpv1.Mode_MODE_QUIC)))
	assert.Error(t, f.err)
	assert.Nil(t, f.m.GetWelcome(), "first message of c: %v", f.m)
	select {
	case <-stopped:
	case <-time.After(wait):
		t.Fatal("the relay did not stop")
	}
	// The root writes the pending batch at its mark, and keeps the interval until it ends.
	w := log.firstAfter(t, stopAt, portsDelete)
	assert.False(t, w.start.Before(opened[1].end.Add(time.Second)), "Write of the pending batch at %v", w.start)
	all := log.all()
	for i := 2; i < len(all); i++ {
		assert.GreaterOrEqual(t, all[i].start.Sub(all[i-1].end), time.Second, "time from Write %d to Write %d", i-1, i)
	}
	tables, keys := log.entries(t)
	assert.Zero(t, tables, "table entries")
	assert.Zero(t, keys, "keys entries")
}

// TestTableWriteMeshOrder checks the order for a route of a mesh member: the relay writes the
// entries of its records, then the route entry, and then gives the route to its agents.
func TestTableWriteMeshOrder(t *testing.T) {
	const prefix = "fd00:2::/64"
	log := &writeLog{}
	e1, e2 := newMesh(t, envOpts{interval: new(time.Second), writes: log}, envOpts{interval: new(time.Duration(0))})
	a := e1.dial(t, "agent-a")
	a.open(dpv1.Mode_MODE_QUIC)
	a.attach()
	b := e2.dial(t, "agent-b")
	b.open(dpv1.Mode_MODE_QUIC)
	// The Write of a new connection on relay-1 comes just before, so the changes of the route wait
	// for the interval.
	e1.dial(t, "agent-h").open(dpv1.Mode_MODE_QUIC)
	t0 := time.Now()
	b.attach(prefix)
	a.waitRoute(prefix, true)

	src := log.firstAfter(t, t0, isTable(p4.Update_INSERT, dp.TableSource))
	route := log.firstAfter(t, t0, isTable(p4.Update_INSERT, dp.TableRoute))
	require.NoError(t, src.err)
	require.NoError(t, route.err)
	assert.False(t, route.start.Before(src.end), "Write of the route at %v, before the end %v of the Write of the source entries", route.start, src.end)
	at := a.arrival(func(m *dpv1.SessionResponse) bool {
		return slices.ContainsFunc(m.GetRouteDelta().GetAdd(), func(r *dpv1.Route) bool { return r.GetPrefix() == prefix })
	})
	assert.True(t, at.After(route.end), "route at the agent at %v, before the end %v of the Write of the route", at, route.end)
}
