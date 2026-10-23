// SPDX-License-Identifier: AGPL-3.0-only

package relay_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// slot2 is the slot of the addresses of relay-2 of a test mesh.
const slot2 = "fd61:706f:7879:12:3400:100::/88"

// newMesh starts relay-1 and relay-2 as members of one mesh, with the addresses of relay-2 in
// slot 1, and waits until each has the other up.
func newMesh(t *testing.T, o1, o2 envOpts) (*env, *env) {
	t.Helper()
	ca, err := vpctest.NewCA()
	require.NoError(t, err)
	o1.id, o1.ca, o1.mesh = "relay-1", ca, true
	o2.id, o2.ca, o2.mesh, o2.slot = "relay-2", ca, true, 1
	e1, e2 := newEnvWith(t, o1), newEnvWith(t, o2)
	join(t, e1, e2)
	return e1, e2
}

// join makes each relay a member of the mesh of the others, and waits for their up changes.
func join(t *testing.T, envs ...*env) {
	t.Helper()
	for _, e := range envs {
		var ms []relay.MeshMember
		for _, o := range envs {
			if o != e {
				ms = append(ms, o.member())
			}
		}
		e.r.SetMembers(ms)
	}
	for _, e := range envs {
		for range len(envs) - 1 {
			c := e.change(t)
			require.True(t, c.Up, "change of %s: %+v", e.id, c)
		}
	}
}

func (e *env) member() relay.MeshMember {
	return relay.MeshMember{Name: e.id, Addr: e.quic.AddrPort()}
}

// change returns the next mesh change of the relay.
func (e *env) change(t *testing.T) relay.MeshChange {
	t.Helper()
	select {
	case c := <-e.changes:
		return c
	case <-time.After(wait):
		t.Fatalf("no mesh change of %s", e.id)
	}
	return relay.MeshChange{}
}

// noChange checks that the relay has no mesh change in d.
func (e *env) noChange(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case c := <-e.changes:
		t.Fatalf("mesh change of %s: %+v", e.id, c)
	case <-time.After(d):
	}
}

// dialIn opens a connection with a new cert of agent name in vpc.
func (e *env) dialIn(t *testing.T, vpc relay.VPCKey, name string) *agent {
	t.Helper()
	cred, err := e.ca.Credential(vpc.Project, vpc.UID, name, time.Hour)
	require.NoError(t, err)
	a, err := e.dialCred(t, name, cred)
	require.NoError(t, err)
	return a
}

// attachIn attaches the agent in vpc with routes and returns the answer.
func (a *agent) attachIn(vpc *dpv1.VPCRef, routes ...string) *dpv1.AttachResponse {
	a.t.Helper()
	res, err := a.rc.Attach(context.Background(), &dpv1.AttachRequest{Vpc: vpc, Name: a.name, Routes: routes})
	require.NoError(a.t, err)
	return res
}

// TestMeshUp checks the mesh sessions of two relays: each one has the other up, with the ID,
// the agent addresses and the version from Open.
func TestMeshUp(t *testing.T) {
	e1, e2 := newMesh(t, envOpts{}, envOpts{})
	cases := []struct {
		name  string
		e, of *env
	}{
		{name: "relay that dialed", e: e1, of: e2},
		{name: "relay that accepted", e: e2, of: e1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, tc.e.r.Up(tc.of.id))
			s := tc.e.r.Session(tc.of.id)
			require.NotNil(t, s)
			assert.Equal(t, tc.of.id, s.Name())
			assert.Equal(t, tc.of.id, s.Relay().GetId())
			assert.NotEmpty(t, s.Relay().GetAddresses())
			assert.Equal(t, dpv1.Revision, s.Version().GetRevision())
			select {
			case got := <-tc.e.sessions:
				assert.Equal(t, tc.of.id, got.Name())
			case <-time.After(wait):
				t.Fatal("no session hook")
			}
			assert.False(t, tc.e.r.Up("relay-9"), "a relay that is not a member")
			assert.Nil(t, tc.e.r.Session("relay-9"))
		})
	}
}

// TestMeshRoutes checks the announcements between two relays: the full set on a new session, the
// changes after it, and the Route.relay of a route of the other relay.
func TestMeshRoutes(t *testing.T) {
	cases := []struct {
		name   string
		before bool // relay-1 has the attachment before the mesh session.
	}{
		{name: "full set", before: true},
		{name: "changes after the full set"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := vpctest.NewCA()
			require.NoError(t, err)
			e1 := newEnvWith(t, envOpts{id: "relay-1", ca: ca, mesh: true})
			e2 := newEnvWith(t, envOpts{id: "relay-2", ca: ca, mesh: true, slot: 1})
			a := e1.dial(t, "agent-a")
			a.open(dpv1.Mode_MODE_QUIC)
			w := e2.dial(t, "watcher")
			w.open(dpv1.Mode_MODE_QUIC)
			w.attach()
			var res *dpv1.AttachResponse
			if tc.before {
				res = a.attach("fd00:1::/64")
			}
			join(t, e1, e2)
			if !tc.before {
				res = a.attach("fd00:1::/64")
			}

			// The slot of relay-1 and the advertised route name relay-1 for the watcher.
			r := w.waitRoute(slot, true)
			assert.Equal(t, "relay-1", r.GetOrigin())
			assert.Equal(t, "relay-1", r.GetRelay().GetId())
			assert.Equal(t, []string{"192.0.2.1"}, r.GetRelay().GetAddresses())
			r = w.waitRoute("fd00:1::/64", true)
			assert.Equal(t, res.GetAttachmentId(), r.GetOrigin())
			assert.Equal(t, "relay-1", r.GetRelay().GetId())
			// relay-1 gives the slot of relay-2 to its agent.
			assert.Equal(t, "relay-2", a.waitRoute(slot2, true).GetRelay().GetId())

			// A detach removes the routes on the other relay.
			_, err = a.rc.Detach(t.Context(), &dpv1.DetachRequest{AttachmentId: res.GetAttachmentId()})
			require.NoError(t, err)
			w.waitRoute("fd00:1::/64", false)
			w.waitRoute(slot, false)
		})
	}
}

// dropAbove drops each packet above n bytes that the data plane sends, as a path with a small MTU.
type dropAbove struct {
	net.PacketConn
	n int
}

func (c dropAbove) WriteTo(b []byte, to net.Addr) (int, error) {
	if len(b) > c.n {
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, to)
}

// TestMeshData sends packets from an agent of relay-1 to an agent of relay-2 on the trunk: the trunk
// keys, the entries of the records, the inner MTU from the full-size probe, and the trunk metrics.
func TestMeshData(t *testing.T) {
	cases := []struct {
		name    string
		mode    dpv1.Mode
		limited bool // The path between the relays takes at most 1320 bytes, so the probe fails.
		size    int
		pass    bool
	}{
		{name: "data frame", mode: dpv1.Mode_MODE_QUIC, size: 200, pass: true},
		{name: "full-size packet on a full path", mode: dpv1.Mode_MODE_PSP, size: 1400, pass: true},
		{name: "full-size packet on a limited path", mode: dpv1.Mode_MODE_PSP, limited: true, size: 1400},
		{name: "packet of 1280 bytes on a limited path", mode: dpv1.Mode_MODE_PSP, limited: true, size: 1280, pass: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := envOpts{mtu: 1412}
			if tc.limited {
				o.dataSend = func(pc net.PacketConn) net.PacketConn { return dropAbove{pc, 1320} }
			}
			e1, e2 := newMesh(t, o, o)
			a := e1.dial(t, "agent-a")
			a.open(tc.mode)
			resA := a.attach()
			b := e2.dial(t, "agent-b")
			b.open(tc.mode)
			resB := b.attach()
			// The routes come after the probe of the trunk.
			a.waitRoute(slot2, true)
			b.waitRoute(slot, true)
			p := packet(addr(t, resA), addr(t, resB), tc.size)
			if tc.mode == dpv1.Mode_MODE_QUIC {
				a.sendFrame(p)
				assert.Equal(t, p, b.recvFrame(wait))
				// The answer goes back on the same trunk.
				back := packet(addr(t, resB), addr(t, resA), tc.size)
				b.sendFrame(back)
				assert.Equal(t, back, a.recvFrame(wait))
				// Each relay counts one packet each way, with the PSP overhead, and has the RTT.
				for _, pair := range [][2]*env{{e1, e2}, {e2, e1}} {
					e, peer := pair[0], pair[1]
					for _, dir := range []string{"tx", "rx"} {
						n, _ := metric(t, e.r, "apoxy_vpc_relay_trunk_packets_total", "peer_relay", peer.id, "peer_relay_id", peer.id, "direction", dir)
						assert.EqualValues(t, 1, n, "%s packets of %s", dir, e.id)
						n, _ = metric(t, e.r, "apoxy_vpc_relay_trunk_bytes_total", "peer_relay", peer.id, "direction", dir)
						assert.EqualValues(t, tc.size+40, n, "%s bytes of %s", dir, e.id)
					}
					assert.Eventually(t, func() bool {
						rtt, ok := metric(t, e.r, "apoxy_vpc_relay_mesh_rtt_seconds", "peer_relay", peer.id)
						return ok && rtt > 0
					}, wait, 10*time.Millisecond, "mesh RTT of %s", e.id)
				}
			} else {
				sockA, sockB := pspSocket(t), pspSocket(t)
				a.toPSP(e1, sockA, 1)
				b.toPSP(e2, sockB, 1)
				a.keepPath(e1, sockA)
				b.keepPath(e2, sockB)
				a.sendPSP(e1, sockA, p)
				if tc.pass {
					assert.Equal(t, p, b.recvPSP(sockB, wait))
				} else {
					assert.Nil(t, b.recvPSP(sockB, 500*time.Millisecond), "a packet above the MTU of the trunk")
				}
			}
			// Each relay has the trunk drop series of each direction from the start. A packet above
			// the MTU of the trunk counts at the trunk port of relay-1 (tx).
			var mtuDrops float64
			if !tc.pass {
				mtuDrops = 1
			}
			for _, pair := range [][2]*env{{e1, e2}, {e2, e1}} {
				e, peer := pair[0], pair[1]
				for _, dir := range []string{"tx", "rx"} {
					vs := series(t, e.r, "apoxy_vpc_relay_trunk_dropped_packets_total", "peer_relay", peer.id, "peer_relay_id", peer.id, "direction", dir)
					assert.NotEmpty(t, vs, "%s trunk drops of %s", dir, e.id)
					want := 0.0
					if e == e1 && dir == "tx" {
						want = mtuDrops
					}
					assert.Equal(t, want, sum(vs), "%s trunk drops of %s", dir, e.id)
				}
			}
			n, _ := metric(t, e1.r, "apoxy_vpc_relay_trunk_dropped_packets_total", "peer_relay", e2.id, "direction", "tx", "reason", "mtu")
			assert.Equal(t, mtuDrops, n)
		})
	}
}

// metric returns the value of the first series of the metric name of c with the label pairs kv.
func metric(t *testing.T, c prometheus.Collector, name string, kv ...string) (float64, bool) {
	t.Helper()
	vs := series(t, c, name, kv...)
	if len(vs) == 0 {
		return 0, false
	}
	return vs[0], true
}

// series returns the values of the series of the metric name of c with the label pairs kv.
func series(t *testing.T, c prometheus.Collector, name string, kv ...string) []float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))
	mfs, err := reg.Gather()
	require.NoError(t, err)
	var out []float64
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			got := map[string]string{}
			for _, l := range m.GetLabel() {
				got[l.GetName()] = l.GetValue()
			}
			match := true
			for i := 0; i+1 < len(kv); i += 2 {
				match = match && got[kv[i]] == kv[i+1]
			}
			if !match {
				continue
			}
			if m.GetCounter() != nil {
				out = append(out, m.GetCounter().GetValue())
			} else {
				out = append(out, m.GetGauge().GetValue())
			}
		}
	}
	return out
}

func sum(vs []float64) float64 {
	var n float64
	for _, v := range vs {
		n += v
	}
	return n
}

// TestMeshTenants checks that each tenant has its own announcements: the end of the VPC of one
// tenant on a relay removes only its routes on the other relay.
func TestMeshTenants(t *testing.T) {
	e1, e2 := newMesh(t, envOpts{}, envOpts{})
	vpcB := relay.VPCKey{Project: "project-b", UID: "vpc-b"}
	refB := &dpv1.VPCRef{ProjectId: vpcB.Project, VpcUid: vpcB.UID}
	for _, e := range []*env{e1, e2} {
		e.r.AddTenant(vpcB.Project)
		e.r.AddVPC(vpcB, relay.Network{ID: 0x5678, Name: "net-b"})
	}
	cases := []struct {
		name  string
		vpc   relay.VPCKey
		ref   *dpv1.VPCRef
		route string
	}{
		{name: "tenant a", vpc: vpcKey, ref: vpcRef, route: "fd00:a::/64"},
		{name: "tenant b", vpc: vpcB, ref: refB, route: "fd00:b::/64"},
	}
	watchers := map[string]*agent{}
	for _, tc := range cases {
		a := e1.dialIn(t, tc.vpc, "agent-"+tc.vpc.UID)
		a.open(dpv1.Mode_MODE_QUIC)
		a.attachIn(tc.ref, tc.route)
		w := e2.dialIn(t, tc.vpc, "watcher-"+tc.vpc.UID)
		w.open(dpv1.Mode_MODE_QUIC)
		w.attachIn(tc.ref)
		watchers[tc.name] = w
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := watchers[tc.name]
			assert.Equal(t, "relay-1", w.waitRoute(tc.route, true).GetRelay().GetId())
		})
	}

	// The VPC of tenant b ends on relay-1. Tenant a keeps its routes.
	e1.r.RemoveVPC(vpcB)
	watchers["tenant b"].waitRoute("fd00:b::/64", false)
	assert.True(t, watchers["tenant a"].openAfter(300*time.Millisecond))
	assert.NotNil(t, watchers["tenant a"].route("fd00:a::/64"))
}

// TestMeshMemberEnds checks that the routes of a member go when its session ends, and the reason
// of its down change.
func TestMeshMemberEnds(t *testing.T) {
	cases := []struct {
		name string
		end  func(e1, e2 *env)
		want relay.MeshDown
	}{
		{name: "member stops", end: func(_, e2 *env) { e2.stop() }, want: relay.MeshRestart},
		{name: "member leaves the list", end: func(e1, _ *env) { e1.r.SetMembers(nil) }, want: relay.MeshRemoved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e1, e2 := newMesh(t, envOpts{}, envOpts{})
			a := e1.dial(t, "agent-a")
			a.open(dpv1.Mode_MODE_QUIC)
			a.attach()
			b := e2.dial(t, "agent-b")
			b.open(dpv1.Mode_MODE_QUIC)
			b.attach("fd00:2::/64")
			a.waitRoute("fd00:2::/64", true)
			a.waitRoute(slot2, true)

			tc.end(e1, e2)
			assert.Equal(t, relay.MeshChange{Name: "relay-2", Down: tc.want}, e1.change(t))
			a.waitRoute("fd00:2::/64", false)
			a.waitRoute(slot2, false)
			assert.False(t, e1.r.Up("relay-2"))
		})
	}
}

// TestMeshSnapshot checks that a relay gets the host snapshot of a member.
func TestMeshSnapshot(t *testing.T) {
	cases := []struct {
		name string
		data []byte // The snapshot of relay-2.
		code rpc.Code
	}{
		{name: "member has a snapshot", data: []byte("bytes of the host")},
		{name: "big snapshot", data: make([]byte, 3<<20+5)},
		{name: "no member has one", code: rpc.NotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e1, _ := newMesh(t, envOpts{}, envOpts{snapshot: func() []byte { return tc.data }})
			data, from, err := e1.r.FetchSnapshot(t.Context())
			require.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
			if tc.code != rpc.OK {
				return
			}
			assert.Equal(t, "relay-2", from)
			assert.Equal(t, tc.data, data)
		})
	}
}

// fakeMember is a mesh member that dials a relay and calls Open. It acks a Presence message only
// while ack is set, ends the call at a message while fail is set, and it has no trunk.
type fakeMember struct {
	dpv1.UnimplementedMeshServer
	t    *testing.T
	name string
	cert *tls.Certificate
	tr   *quic.Transport
	mux  *rpc.Mux
	ack  atomic.Bool
	fail atomic.Bool

	mu    sync.Mutex
	calls []*presenceCall
	added chan struct{}
}

// presenceCall is one Presence call of the relay to the fake member.
type presenceCall struct {
	msgs  chan *dpv1.PresenceUpdate
	ended chan struct{}
}

func newFakeMember(t *testing.T, ca *vpctest.CA, name string) *fakeMember {
	t.Helper()
	cert, err := ca.RelayCert(name)
	require.NoError(t, err)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	f := &fakeMember{t: t, name: name, cert: cert, tr: &quic.Transport{Conn: udp}, mux: rpc.NewMux(), added: make(chan struct{}, 64)}
	dpv1.RegisterMeshServer(f.mux, f)
	t.Cleanup(func() {
		_ = f.tr.Close()
		_ = udp.Close()
	})
	return f
}

func (f *fakeMember) member() relay.MeshMember {
	return relay.MeshMember{Name: f.name, Addr: f.tr.Conn.LocalAddr().(*net.UDPAddr).AddrPort()}
}

// open dials e and calls Open. It serves the calls of the relay until the connection closes.
func (f *fakeMember) open(e *env) *quic.Conn {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	qc, err := f.tr.Dial(ctx, e.quic, &tls.Config{
		Certificates: []tls.Certificate{*f.cert}, NextProtos: []string{dpv1.ALPNMesh}, InsecureSkipVerify: true,
	}, &quic.Config{KeepAlivePeriod: time.Second, MaxIdleTimeout: 5 * time.Second})
	require.NoError(f.t, err)
	f.t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	conn := rpc.NewConn(qc, f.mux)
	go func() { _ = conn.Serve(context.Background()) }()
	res, err := dpv1.NewMeshClient(conn).Open(ctx, &dpv1.MeshOpenRequest{
		Version: dpv1.LocalVersion("fake"), Name: f.name, Relay: &dpv1.RelayRef{Id: f.name},
		PspPort: uint32(f.member().Addr.Port()),
	})
	require.NoError(f.t, err)
	require.Equal(f.t, e.id, res.GetName())
	return qc
}

func (f *fakeMember) Presence(_ context.Context, st rpc.BidiStreamServer[dpv1.PresenceUpdate, dpv1.PresenceControl]) error {
	c := &presenceCall{msgs: make(chan *dpv1.PresenceUpdate, 1024), ended: make(chan struct{})}
	defer close(c.ended)
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	f.added <- struct{}{}
	for {
		u, err := st.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		c.msgs <- u
		if f.fail.Load() {
			return rpc.Errorf(rpc.InvalidArgument, "test")
		}
		if f.ack.Load() {
			if err := st.Send(&dpv1.PresenceControl{Ack: u.GetSeq()}); err != nil {
				return err
			}
		}
	}
}

// nextCall waits for the next Presence call of the relay.
func (f *fakeMember) nextCall(d time.Duration) *presenceCall {
	f.t.Helper()
	select {
	case <-f.added:
	case <-time.After(d):
		f.t.Fatalf("no Presence call in %v", d)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

// noCall checks that the relay opens no Presence call for d.
func (f *fakeMember) noCall(d time.Duration) {
	f.t.Helper()
	select {
	case <-f.added:
		f.t.Fatal("the relay opened a Presence call")
	case <-time.After(d):
	}
}

// first returns the first message of the call: the VPC list.
func (c *presenceCall) first(t *testing.T) *dpv1.PresenceUpdate {
	t.Helper()
	select {
	case u := <-c.msgs:
		return u
	case <-time.After(wait):
		t.Fatal("no Presence message")
	}
	return nil
}

// TestMeshPresenceCallEnd checks the end of a Presence call while the session stays. After a stall
// (no ack for 5 s), the relay opens the call again with the full VPC list. After a different
// cause, the tenant gets no new call until the next session.
func TestMeshPresenceCallEnd(t *testing.T) {
	cases := []struct {
		name  string
		fail  bool // The member ends the call at the first message.
		again bool // The relay opens the call again on the same session.
	}{
		{name: "stall", again: true},
		{name: "member ends the call", fail: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := vpctest.NewCA()
			require.NoError(t, err)
			e := newEnvWith(t, envOpts{id: "relay-1", ca: ca, mesh: true})
			a := e.dial(t, "agent-a")
			a.open(dpv1.Mode_MODE_QUIC)
			a.attach()
			f := newFakeMember(t, ca, "relay-0")
			f.fail.Store(tc.fail)
			e.r.SetMembers([]relay.MeshMember{f.member()})
			// The relay sends the first message after the session opens, so a stall ends the call
			// 5 s after start or later.
			start := time.Now()
			qc := f.open(e)
			assert.Equal(t, relay.MeshChange{Name: "relay-0", Up: true}, e.change(t))

			first := f.nextCall(wait)
			u := first.first(t)
			assert.EqualValues(t, 1, u.GetSeq())
			assert.True(t, u.GetEndOfVpcs())
			assert.Equal(t, project, u.GetVpcs()[0].GetProjectId())
			select {
			case <-first.ended:
			case <-time.After(wait):
				t.Fatal("the first call did not end")
			}
			f.ack.Store(true)
			f.fail.Store(false)
			if tc.again {
				assert.GreaterOrEqual(t, time.Since(start), 5*time.Second, "the call ends after 5 s with no ack")
				u = f.nextCall(wait).first(t)
				assert.EqualValues(t, 1, u.GetSeq(), "the new call starts again")
				assert.True(t, u.GetEndOfVpcs())
			} else {
				// A new attachment of the tenant does not open the call again on this session.
				b := e.dial(t, "agent-b")
				b.open(dpv1.Mode_MODE_QUIC)
				b.attach()
				f.noCall(time.Second)
			}
			assert.NoError(t, qc.Context().Err(), "the session stays")
			assert.True(t, e.r.Up("relay-0"))
			e.noChange(t, time.Second)
			if !tc.again {
				f.open(e)
				assert.True(t, f.nextCall(wait).first(t).GetEndOfVpcs(), "the next session opens the call again")
			}
		})
	}
}

// TestMeshSessionEnds checks the end of the session of a member: a new session replaces the old
// one with no down change, and the close of the member gives the reason of the down change.
func TestMeshSessionEnds(t *testing.T) {
	cases := []struct {
		name string
		code dpv1.MeshCloseCode
		want relay.MeshDown
	}{
		{name: "member closes the session", code: dpv1.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, want: relay.MeshLost},
		{name: "member restarts", code: dpv1.MeshCloseCode_MESH_CLOSE_CODE_RESTART, want: relay.MeshRestart},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := vpctest.NewCA()
			require.NoError(t, err)
			e := newEnvWith(t, envOpts{id: "relay-1", ca: ca, mesh: true})
			a := e.dial(t, "agent-a")
			a.open(dpv1.Mode_MODE_QUIC)
			a.attach()
			f := newFakeMember(t, ca, "relay-0")
			f.ack.Store(true)
			e.r.SetMembers([]relay.MeshMember{f.member()})
			old := f.open(e)
			assert.Equal(t, relay.MeshChange{Name: "relay-0", Up: true}, e.change(t))
			f.nextCall(wait)

			// A new session replaces the old one: the relay closes the old one, and opens
			// the Presence call again on the new one.
			qc := f.open(e)
			select {
			case <-old.Context().Done():
			case <-time.After(wait):
				t.Fatal("the relay did not close the old session")
			}
			var ae *quic.ApplicationError
			require.ErrorAs(t, context.Cause(old.Context()), &ae)
			assert.True(t, ae.Remote)
			assert.Equal(t, "a new session replaced this one", ae.ErrorMessage)
			assert.True(t, f.nextCall(wait).first(t).GetEndOfVpcs())
			e.noChange(t, 300*time.Millisecond)
			assert.True(t, e.r.Up("relay-0"))

			require.NoError(t, qc.CloseWithError(quic.ApplicationErrorCode(tc.code), "test"))
			assert.Equal(t, relay.MeshChange{Name: "relay-0", Down: tc.want}, e.change(t))
			assert.False(t, e.r.Up("relay-0"))
		})
	}
}
