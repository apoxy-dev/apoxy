// SPDX-License-Identifier: AGPL-3.0-only

package relay_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
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
	"google.golang.org/protobuf/proto"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// writeLog is the data plane target of a test relay. It keeps each Write, and refuses a Write
// whose updates bad matches.
type writeLog struct {
	*vpctest.SocketTarget
	bad func([]*p4.Update) bool // Set it before the relay starts.

	mu     sync.Mutex
	writes []loggedWrite
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

var portsInsert = isTable(p4.Update_INSERT, dp.TablePorts)

// anyOf matches the updates of a Write when f matches one of them.
func anyOf(f func(*p4.Update) bool) func([]*p4.Update) bool {
	return func(us []*p4.Update) bool { return slices.ContainsFunc(us, f) }
}

// routeTo matches an insert or a modify of a route entry to dst.
func routeTo(dst netip.Prefix) func(*p4.Update) bool {
	ms := dp.RouteKey{Dst: dst}.Entry(nil).GetMatch()
	lpm := ms[slices.IndexFunc(ms, func(m *p4.FieldMatch) bool { return m.GetLpm() != nil })].GetLpm()
	return func(u *p4.Update) bool {
		te := u.GetEntity().GetTableEntry()
		return te.GetTableId() == dp.TableRoute && u.GetType() != p4.Update_DELETE &&
			slices.ContainsFunc(te.GetMatch(), func(m *p4.FieldMatch) bool { return proto.Equal(m.GetLpm(), lpm) })
	}
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

// TestTableWriteBatches checks the write rate of the root: one Write in each table write interval
// at most, and that Write has the changes of the interval. A change after a quiet interval writes
// at once.
func TestTableWriteBatches(t *testing.T) {
	cases := []struct {
		name     string
		interval *time.Duration // The config field. nil is omitted.
		pause    time.Duration  // The wait after the first connection opened.
		next     int            // The connections that then open at once.
		want     []int          // The ports inserts of each Write that has one. nil is any.
		hold     time.Duration  // The least time from the end of a Write to the next Write.
		atOnce   bool           // The next connections write with no wait.
	}{
		{name: "quiet", interval: new(time.Second), pause: time.Second, next: 1, want: []int{1, 1}, hold: time.Second, atOnce: true},
		{name: "burst", interval: new(time.Second), next: 3, want: []int{1, 3}, hold: time.Second},
		{name: "interval 0", interval: new(time.Duration(0)), next: 3, want: []int{1, 1, 1, 1}, atOnce: true},
		{name: "config omitted", next: 3, hold: relay.DefaultTableWriteInterval},
		// The Hellos can come in two intervals of 400ms, so this case checks only the time between Writes.
		{name: "config set", interval: new(400 * time.Millisecond), next: 3, hold: 400 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := &writeLog{}
			e := newEnvWith(t, envOpts{interval: tc.interval, writes: log})
			as := make([]*agent, 1+tc.next)
			for i := range as {
				as[i] = e.dial(t, fmt.Sprintf("agent-%d", i))
			}
			as[0].open(dpv1.Mode_MODE_QUIC)
			time.Sleep(tc.pause)
			start := time.Now()
			var cs []<-chan first
			for _, a := range as[1:] {
				cs = append(cs, a.begin(hello(dpv1.Mode_MODE_QUIC)))
			}
			for _, c := range cs {
				f := firstOf(t, c)
				require.NoError(t, f.err)
				require.NotNil(t, f.m.GetWelcome())
				// The wait of a Welcome is one interval at most.
				assert.Less(t, f.at.Sub(start), tc.hold+500*time.Millisecond)
			}

			ws := log.with(portsInsert)
			var got []int
			for _, w := range ws {
				require.NoError(t, w.err)
				got = append(got, w.count(portsInsert))
			}
			if tc.want != nil {
				assert.Equal(t, tc.want, got, "ports inserts of each Write; the Hellos come in one interval")
			}
			all := log.all()
			for i := 1; i < len(all); i++ {
				assert.GreaterOrEqual(t, all[i].start.Sub(all[i-1].end), tc.hold, "time from Write %d to Write %d", i-1, i)
			}
			if tc.atOnce {
				require.GreaterOrEqual(t, len(ws), 2)
				assert.Less(t, ws[1].start.Sub(start), 300*time.Millisecond, "wait of the first Write of the next connections")
			}
		})
	}
}

// TestTableWriteBadEvent checks a batch with one bad event: the root writes each event alone, so
// that the other events apply, and the bad event gets its error.
func TestTableWriteBadEvent(t *testing.T) {
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
	a1, a2, a3 := e.dial(t, "agent-1"), e.dial(t, "agent-2"), e.dial(t, "agent-3")
	b1, err := e.dialVPC(t, vpcB.UID, "agent-b")
	require.NoError(t, err)
	a1.open(dpv1.Mode_MODE_QUIC)
	// The three Hellos come in one interval, so their events go in one batch.
	c2, cb, c3 := a2.begin(hello(dpv1.Mode_MODE_QUIC)), b1.begin(hello(dpv1.Mode_MODE_QUIC)), a3.begin(hello(dpv1.Mode_MODE_QUIC))
	for _, c := range []<-chan first{c2, c3} {
		f := firstOf(t, c)
		require.NoError(t, f.err)
		assert.NotNil(t, f.m.GetWelcome())
	}
	assert.Error(t, firstOf(t, cb).err)
	code, msg := b1.closed()
	assert.Equal(t, dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, code)
	assert.Equal(t, "relay failed to add the connection", msg)

	ws := log.with(portsInsert)
	require.Len(t, ws, 5, "the Write of a1, the batch, and the three events alone")
	assert.Equal(t, 3, ws[1].count(portsInsert))
	assert.Error(t, ws[1].err)
	failed := 0
	for _, w := range ws[2:] {
		assert.Equal(t, 1, w.count(portsInsert))
		if w.count(bad) > 0 {
			assert.Error(t, w.err)
			failed++
		} else {
			assert.NoError(t, w.err)
		}
	}
	assert.Equal(t, 1, failed)
	assert.Less(t, ws[4].start.Sub(ws[1].end), 300*time.Millisecond, "the events alone write at once")
	// a1, a2 and a3 have their classify entries, and b1 has none.
	n := 0
	require.NoError(t, log.SocketTarget.Read(t.Context(), &p4.ReadRequest{Entities: []*p4.Entity{{Entity: &p4.Entity_TableEntry{
		TableEntry: &p4.TableEntry{TableId: dp.TableClassify},
	}}}}, func(e *p4.Entity) {
		assert.False(t, bad(&p4.Update{Type: p4.Update_INSERT, Entity: e}))
		n++
	}))
	assert.Equal(t, 3, n)
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

// TestTableWriteFailedFallback checks a failed write of the route of a fallback candidate: the
// relay does not write it again for the same report, a newer report that waits for the next mark
// gets its write, and the next call gets its answer.
func TestTableWriteFailedFallback(t *testing.T) {
	cases := []struct {
		name  string
		newer bool // A newer report comes while the first one waits for the mark.
	}{
		{name: "one report"},
		{name: "newer report", newer: true},
	}
	newer := netip.MustParsePrefix("fd61:706f:7879:12:3400:5::/96")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// While refuse has a prefix, the relay refuses each Write with a route to it and no
			// route to newer: the batch and the write of the event alone.
			var refuse atomic.Pointer[netip.Prefix]
			log := &writeLog{bad: func(us []*p4.Update) bool {
				p := refuse.Load()
				return p != nil && slices.ContainsFunc(us, routeTo(*p)) && !slices.ContainsFunc(us, routeTo(newer))
			}}
			e1, e2 := newMesh(t, envOpts{}, envOpts{interval: new(300 * time.Millisecond), writes: log})
			x1 := e1.dial(t, "agent-x")
			x1.open(dpv1.Mode_MODE_QUIC)
			resX1 := x1.attachRank(0)
			x2 := e2.dial(t, "agent-x")
			x2.open(dpv1.Mode_MODE_QUIC)
			resX2 := x2.attachRank(1)
			// The Write of a new connection comes just before, so the reports wait for the mark.
			e2.dial(t, "agent-h").open(dpv1.Mode_MODE_QUIC)

			pa := netip.MustParsePrefix(resX1.GetAddresses()[0])
			refuse.Store(&pa)
			t0 := time.Now()
			x2.report(resX2.GetAttachmentId(), "relay-1", resX1.GetAttachmentId(), pa.String())
			if tc.newer {
				// The newer report comes after the first one went up, and before the mark.
				time.Sleep(50 * time.Millisecond)
				x2.report(resX2.GetAttachmentId(), "relay-1", resX1.GetAttachmentId(), pa.String(), newer.String())
			}
			failed := log.firstAfter(t, t0, routeTo(pa))
			require.Error(t, failed.err)
			time.Sleep(time.Second)
			refuse.Store(nil)
			if tc.newer {
				w := log.firstAfter(t, t0, routeTo(newer))
				assert.NoError(t, w.err)
				assert.Positive(t, w.count(routeTo(pa)), "route to the first address in the Write of the newer report")
			} else {
				var tries int
				for _, w := range log.with(routeTo(pa)) {
					if !w.start.Before(t0) {
						tries++
					}
				}
				assert.LessOrEqual(t, tries, 2, "Writes of the fallback route: the batch and the event alone")
			}
			ctx, cancel := context.WithTimeout(t.Context(), wait)
			defer cancel()
			_, err := x2.rc.Detach(ctx, &dpv1.DetachRequest{AttachmentId: resX2.GetAttachmentId()})
			assert.NoError(t, err)
		})
	}
}

// TestTableWriteReplyOrder checks that each answer of the relay comes after the write of its
// changes, also when the changes wait for the interval.
func TestTableWriteReplyOrder(t *testing.T) {
	cases := []struct {
		name string
		// setup runs before the call. Then the changes of the call wait for the interval.
		setup func(t *testing.T, e *env, a *agent)
		// call makes the call and returns the arrival time of each answer.
		call func(t *testing.T, e *env, a *agent) []time.Time
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := &writeLog{}
			e := newEnvWith(t, envOpts{interval: new(300 * time.Millisecond), writes: log})
			a := e.dial(t, "agent-a")
			tc.setup(t, e, a)
			t0 := time.Now()
			ats := tc.call(t, e, a)
			for i, f := range tc.need {
				w := log.firstAfter(t, t0, f)
				require.NoError(t, w.err)
				for _, at := range ats {
					assert.True(t, at.After(w.end), "answer %v before the end %v of the Write of change %d", at, w.end, i)
				}
			}
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
// ends, each call gets its answer, no connection opens, and no entry stays in the data plane.
func TestTableWriteStop(t *testing.T) {
	log := &writeLog{}
	e := newEnvWith(t, envOpts{interval: new(time.Second), writes: log})
	a := e.dial(t, "agent-a")
	b := e.dial(t, "agent-b")
	a.open(dpv1.Mode_MODE_QUIC)
	opened := log.all()
	require.Len(t, opened, 1)

	attached := make(chan error, 1)
	go func() {
		_, err := a.rc.Attach(context.Background(), &dpv1.AttachRequest{Vpc: vpcRef, Name: a.name})
		attached <- err
	}()
	cb := b.begin(hello(dpv1.Mode_MODE_QUIC))
	time.Sleep(time.Until(opened[0].end.Add(500 * time.Millisecond)))
	require.Len(t, log.all(), 1, "the changes of the attachment and of b wait for the interval")

	stopAt := time.Now()
	stopped := make(chan struct{})
	go func() {
		e.stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(wait):
		t.Fatal("the relay did not stop")
	}
	select {
	case <-attached:
	case <-time.After(wait):
		t.Fatal("no answer to Attach")
	}
	f := firstOf(t, cb)
	assert.Nil(t, f.m.GetWelcome(), "first message of b: %v", f.m)
	// The root writes the pending batch at its mark, and keeps the interval until it ends.
	w := log.firstAfter(t, stopAt, portsInsert)
	assert.False(t, w.start.Before(opened[0].end.Add(time.Second)), "Write of the pending batch at %v", w.start)
	all := log.all()
	for i := 1; i < len(all); i++ {
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
