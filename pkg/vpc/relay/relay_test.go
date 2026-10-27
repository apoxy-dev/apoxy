// SPDX-License-Identifier: AGPL-3.0-only

package relay_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp/aead"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const slot = "fd61:706f:7879:12:3400::/88"

// noSend is a Sender that drops all packets.
type noSend struct{}

func (noSend) Send(*dp.TxBatch) {}

func TestNewRouter(t *testing.T) {
	target := dp.New(noSend{}, aead.GCM{})
	ref := &dpv1.RelayRef{Id: relayID}
	cases := []struct {
		name    string
		cfg     relay.Config
		wantErr bool
	}{
		{name: "valid", cfg: relay.Config{Relay: ref, Target: target, Addresses: &vpctest.Addresses{}}},
		{name: "no relay ID", cfg: relay.Config{Relay: &dpv1.RelayRef{}, Target: target, Addresses: &vpctest.Addresses{}}, wantErr: true},
		{name: "no target", cfg: relay.Config{Relay: ref, Addresses: &vpctest.Addresses{}}, wantErr: true},
		{name: "no addresses", cfg: relay.Config{Relay: ref, Target: target}, wantErr: true},
		{name: "table write interval 0", cfg: relay.Config{Relay: ref, Target: target, Addresses: &vpctest.Addresses{}, TableWriteInterval: new(time.Duration(0))}},
		{name: "negative table write interval", cfg: relay.Config{Relay: ref, Target: target, Addresses: &vpctest.Addresses{},
			TableWriteInterval: new(-time.Millisecond)}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := relay.NewRouter(tc.cfg)
			assert.Equal(t, tc.wantErr, err != nil, "error: %v", err)
		})
	}
}

// TestDataPlaneMetrics checks the busy metric of the threads of the data plane, in seconds, and the
// drop series of the two handoff reasons.
func TestDataPlaneMetrics(t *testing.T) {
	busy := func() []dp.ThreadBusy {
		return []dp.ThreadBusy{
			{Kind: "rx", Index: 0, Busy: 1500 * time.Millisecond},
			{Kind: "worker", Index: 1, Busy: 2 * time.Second},
			{Kind: "kick", Index: 0},
		}
	}
	cases := []struct {
		name string
		busy func() []dp.ThreadBusy
		kv   []string
		want float64
		ok   bool
	}{
		{name: "an RX goroutine", busy: busy, kv: []string{"kind", "rx", "index", "0"}, want: 1.5, ok: true},
		{name: "a worker", busy: busy, kv: []string{"kind", "worker", "index", "1"}, want: 2, ok: true},
		{name: "an idle kicker", busy: busy, kv: []string{"kind", "kick", "index", "0"}, want: 0, ok: true},
		{name: "a thread that the data plane does not have", busy: busy, kv: []string{"kind", "worker", "index", "0"}},
		{name: "no busy times", kv: []string{"kind", "rx", "index", "0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := relay.NewRouter(relay.Config{Relay: &dpv1.RelayRef{Id: relayID}, Target: dp.New(noSend{}, aead.GCM{}),
				Addresses: &vpctest.Addresses{}, Busy: tc.busy})
			require.NoError(t, err)
			got, ok := metric(t, r, "apoxy_vpc_relay_busy_seconds_total", tc.kv...)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
			for _, reason := range []string{"worker_full", "worker_allowance"} {
				_, ok := metric(t, r, "apoxy_vpc_relay_dropped_packets_total", "reason", reason)
				assert.True(t, ok, "the drop series of %s", reason)
			}
		})
	}
}

// sampleTarget is a data plane that records the load samples of the key engine.
type sampleTarget struct {
	*dp.Pipeline
	samples chan time.Time
}

func (s sampleTarget) SampleLoad(now time.Time) {
	select {
	case s.samples <- now:
	default:
	}
	s.Pipeline.SampleLoad(now)
}

// TestLoadSamples checks that the key engine gives a LoadTarget a sample of the receive rates at
// each tick, each second.
func TestLoadSamples(t *testing.T) {
	tg := sampleTarget{Pipeline: dp.New(noSend{}, aead.GCM{}), samples: make(chan time.Time, 8)}
	r, err := relay.NewRouter(relay.Config{Relay: &dpv1.RelayRef{Id: relayID}, Target: tg, Addresses: &vpctest.Addresses{}})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	var got []time.Time
	for len(got) < 2 {
		select {
		case now := <-tg.samples:
			got = append(got, now)
		case <-time.After(5 * time.Second):
			t.Fatalf("%d load samples in 5 s", len(got))
		}
	}
	cancel()
	require.NoError(t, <-done)
	// A busy router can miss a tick, so two samples are a whole number of seconds apart.
	between := got[1].Sub(got[0])
	assert.GreaterOrEqual(t, between.Round(time.Second), time.Second, "the time between two samples: %v", between)
	assert.InDelta(t, between.Round(time.Second), between, float64(300*time.Millisecond), "the time between two samples")
}

func TestWelcome(t *testing.T) {
	e := newEnv(t)
	for _, mode := range []dpv1.Mode{dpv1.Mode_MODE_QUIC, dpv1.Mode_MODE_PSP} {
		t.Run(mode.String(), func(t *testing.T) {
			a := e.dial(t, "agent-1")
			w := a.open(mode)
			assert.Equal(t, relayID, w.GetRelayId())
			assert.EqualValues(t, e.data.Port, w.GetPspPort())
			assert.Empty(t, w.GetPspHost())
			assert.EqualValues(t, 3, w.GetMaxLanes())
			assert.Equal(t, dpv1.Revision, w.GetVersion().GetRevision())
			assert.Equal(t, dpv1.MinRevision, w.GetVersion().GetMinRevision())
			assert.Equal(t, a.qc.LocalAddr().String(), w.GetReflexiveAddress())
			cfg := a.waitMsg(1, func(m *dpv1.SessionResponse) bool { return m.GetConfig() != nil }).GetConfig()
			assert.EqualValues(t, netID, cfg.GetVpc().GetNetworkId())
			assert.NotZero(t, cfg.GetMtu())
			// The first table ends with a RouteDelta with no routes.
			a.waitMsg(1, func(m *dpv1.SessionResponse) bool {
				d := m.GetRouteDelta()
				return d != nil && len(d.GetAdd())+len(d.GetRemove()) == 0
			})
		})
	}
}

func TestHello(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name      string
		hello     *dpv1.Hello
		first     *dpv1.SessionRequest // In place of Hello.
		twice     bool                 // A second Session call after a good one.
		code      rpc.Code
		closeCode dpv1.RelayCloseCode
		sessions  float64 // Sessions that the relay counts for the revision of hello.
	}{
		{name: "first message is not Hello", first: &dpv1.SessionRequest{Msg: &dpv1.SessionRequest_Ack{Ack: &dpv1.Ack{}}}, code: rpc.InvalidArgument},
		{name: "no mode", hello: &dpv1.Hello{Version: dpv1.LocalVersion("test")}, code: rpc.InvalidArgument},
		// An agent at revision 22 can open a second QUIC connection for a session.
		{name: "revision 22", hello: &dpv1.Hello{Mode: dpv1.Mode_MODE_QUIC, Version: &dpv1.Version{Revision: 22, MinRevision: 21}},
			closeCode: dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UPGRADE},
		{name: "revision 23", hello: &dpv1.Hello{Mode: dpv1.Mode_MODE_QUIC, Version: &dpv1.Version{Revision: 23, MinRevision: 23}},
			code: rpc.OK, sessions: 1},
		{name: "second Session call", hello: hello(dpv1.Mode_MODE_QUIC), twice: true, code: rpc.FailedPrecondition, sessions: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rev := tc.hello.GetVersion().GetRevision()
			before := sessionsOf(t, rev)
			a := e.dial(t, "agent-1")
			if tc.twice {
				a.open(dpv1.Mode_MODE_QUIC)
			}
			st, err := a.rc.Session(t.Context())
			require.NoError(t, err)
			first := tc.first
			if first == nil {
				first = &dpv1.SessionRequest{Msg: &dpv1.SessionRequest_Hello{Hello: tc.hello}}
			}
			require.NoError(t, st.Send(first))
			_, err = st.Recv()
			if tc.closeCode != 0 {
				code, _ := a.closed()
				assert.Equal(t, tc.closeCode, code)
			} else {
				assert.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
			}
			// The relay counts a session after it answers the Session call.
			assert.Eventually(t, func() bool { return sessionsOf(t, rev)-before == tc.sessions }, wait, 10*time.Millisecond,
				"sessions of revision %d", rev)
		})
	}
}

// sessionsOf returns the Session calls of revision rev that the relay counted.
func sessionsOf(t *testing.T, rev uint32) float64 {
	t.Helper()
	mfs, err := metrics.Registry.Gather()
	require.NoError(t, err)
	var n float64
	for _, mf := range mfs {
		if mf.GetName() != "apoxy_vpc_relay_session_versions_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "revision" && l.GetValue() == strconv.FormatUint(uint64(rev), 10) {
					n += m.GetCounter().GetValue()
				}
			}
		}
	}
	return n
}

func TestAttach(t *testing.T) {
	tooMany := make([]string, 64)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("fd00:%x::/64", i+1)
	}
	cases := []struct {
		name    string
		mesh    bool
		vpc     *dpv1.VPCRef
		attName string
		routes  []string
		code    rpc.Code
		results []dpv1.RouteResult
	}{
		{name: "addresses only", vpc: vpcRef},
		{
			name:   "routes",
			vpc:    vpcRef,
			routes: []string{"fd00:1::/64", "::/0", "10.0.0.0/8", "::ffff:10.0.0.0/104", "fd61:706f:7879:12:34ff::/80"},
			results: []dpv1.RouteResult{
				dpv1.RouteResult_ROUTE_RESULT_ACCEPTED,
				dpv1.RouteResult_ROUTE_RESULT_DEFAULT_ROUTE,
				dpv1.RouteResult_ROUTE_RESULT_IPV4,
				dpv1.RouteResult_ROUTE_RESULT_IPV4,
				dpv1.RouteResult_ROUTE_RESULT_OVERLAPS_VPC,
			},
		},
		{name: "VPC of another cert", vpc: &dpv1.VPCRef{ProjectId: project, VpcUid: "vpc-b"}, code: rpc.PermissionDenied},
		{name: "no VPC", code: rpc.InvalidArgument},
		{name: "name not valid", vpc: vpcRef, attName: "Not_Valid", code: rpc.InvalidArgument},
		{name: "route not valid", vpc: vpcRef, routes: []string{"fd00::1"}, code: rpc.InvalidArgument},
		{name: "more than 64 prefixes with a mesh", mesh: true, vpc: vpcRef, routes: tooMany, code: rpc.InvalidArgument},
		{name: "more than 64 prefixes with no mesh", vpc: vpcRef, routes: tooMany, results: slices.Repeat([]dpv1.RouteResult{dpv1.RouteResult_ROUTE_RESULT_ACCEPTED}, len(tooMany))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnvWith(t, envOpts{mesh: tc.mesh})
			watcher := e.dial(t, "watcher")
			watcher.open(dpv1.Mode_MODE_QUIC)
			watcher.attach()
			a := e.dial(t, "agent-1")
			a.open(dpv1.Mode_MODE_QUIC)
			name := tc.attName
			if name == "" {
				name = "agent-1"
			}
			res, err := a.rc.Attach(t.Context(), &dpv1.AttachRequest{Vpc: tc.vpc, Name: name, Routes: tc.routes})
			require.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
			if tc.code != rpc.OK {
				if tc.mesh {
					// The addresses came from Assign: the relay releases them.
					require.Eventually(t, func() bool { return e.addrs.releases() == 1 }, wait, 10*time.Millisecond)
				}
				return
			}
			assert.Equal(t, []string{"fd61:706f:7879:12:3400:2::/96"}, res.GetAddresses())
			var results []dpv1.RouteResult
			for i, rs := range res.GetRoutes() {
				assert.Equal(t, netip.MustParsePrefix(tc.routes[i]).Masked().String(), rs.GetPrefix())
				results = append(results, rs.GetResult())
			}
			assert.Equal(t, tc.results, results)
			// The Attached hook runs after the answer.
			require.Eventually(t, func() bool { return e.addrs.isAttached(res.GetAttachmentId()) }, wait, 10*time.Millisecond)
			// The slot Route and the accepted routes name this relay.
			r := watcher.waitRoute(slot, true)
			assert.Equal(t, relayID, r.GetRelay().GetId())
			assert.Equal(t, []string{"192.0.2.1"}, r.GetRelay().GetAddresses())
			for i, rs := range res.GetRoutes() {
				if tc.results[i] == dpv1.RouteResult_ROUTE_RESULT_ACCEPTED {
					assert.Equal(t, relayID, watcher.waitRoute(rs.GetPrefix(), true).GetRelay().GetId())
					continue
				}
				assert.Nil(t, watcher.route(rs.GetPrefix()))
			}
		})
	}
}

func TestDetach(t *testing.T) {
	e := newEnv(t)
	b := e.dial(t, "agent-b")
	b.open(dpv1.Mode_MODE_QUIC)
	resB := b.attach()
	a := e.dial(t, "agent-a")
	a.open(dpv1.Mode_MODE_QUIC)
	res := a.attach("fd00:1::/64")
	b.waitRoute("fd00:1::/64", true)

	_, err := a.rc.Detach(t.Context(), &dpv1.DetachRequest{AttachmentId: res.GetAttachmentId()})
	require.NoError(t, err)
	b.waitRoute("fd00:1::/64", false)
	end := e.waitEnd(t, res.GetAttachmentId())
	assert.Equal(t, vpcKey, end.VPC)
	assert.Equal(t, "net-a", end.Network)
	// Release runs after the final counts.
	require.Eventually(t, func() bool { return e.addrs.isReleased(res.GetAttachmentId()) }, wait, 10*time.Millisecond)
	assert.Nil(t, e.statsOf(res.GetAttachmentId()))

	_, err = a.rc.Detach(t.Context(), &dpv1.DetachRequest{AttachmentId: res.GetAttachmentId()})
	assert.Equal(t, rpc.NotFound, rpc.CodeOf(err))
	// No route goes to the address of the detached attachment.
	b.sendFrame(packet(addr(t, resB), addr(t, res), 100))
	b.waitMsg(1, func(m *dpv1.SessionResponse) bool { return m.GetNoRoute() != nil })
	// The connection stays open.
	assert.True(t, a.openAfter(100*time.Millisecond))
}

// TestAssignEndsWithConnection checks that an Assign that waits ends when its connection closes,
// so the next attachments of the relay get their addresses.
func TestAssignEndsWithConnection(t *testing.T) {
	e := newEnv(t)
	held := e.addrs.holdOne()
	a := e.dial(t, "agent-a")
	a.open(dpv1.Mode_MODE_QUIC)
	go func() { _, _ = a.rc.Attach(context.Background(), &dpv1.AttachRequest{Vpc: vpcRef, Name: a.name}) }()
	select {
	case <-held:
	case <-time.After(wait):
		t.Fatal("the relay did not call Assign")
	}
	require.NoError(t, a.qc.CloseWithError(0, ""))

	b := e.dial(t, "agent-b")
	b.open(dpv1.Mode_MODE_QUIC)
	res := b.attach()
	assert.NotEmpty(t, res.GetAddresses())
	assert.Zero(t, e.addrs.releases(), "the held Assign gave no addresses")
}

// TestData checks the data frames of QUIC mode: forwarding, the source check, NoRoute and the
// counts.
func TestData(t *testing.T) {
	e := newEnv(t)
	a := e.dial(t, "agent-a")
	a.open(dpv1.Mode_MODE_QUIC)
	resA := a.attach()
	b := e.dial(t, "agent-b")
	b.open(dpv1.Mode_MODE_QUIC)
	resB := b.attach()

	for range 3 {
		p := packet(addr(t, resA), addr(t, resB), 200)
		a.sendFrame(p)
		assert.Equal(t, p, b.recvFrame(wait))
	}
	sa, sb := e.statsOf(resA.GetAttachmentId()), e.statsOf(resB.GetAttachmentId())
	require.NotNil(t, sa)
	require.NotNil(t, sb)
	assert.EqualValues(t, 3, sa.RXPackets)
	assert.EqualValues(t, 3*200, sa.RXBytes)
	assert.EqualValues(t, 3, sb.TXPackets)
	assert.EqualValues(t, 3*200, sb.TXBytes)
	assert.Equal(t, "agent-a", sa.Name)
	assert.Equal(t, "test", sa.Build)
	assert.Equal(t, "net-a", sa.Network)
	// A source that is not an address of the connection drops.
	a.sendFrame(packet(netip.MustParseAddr("fd00::1"), addr(t, resB), 200))
	b.noFrame(300 * time.Millisecond)
	assert.EqualValues(t, 3, e.statsOf(resB.GetAttachmentId()).TXPackets)

	// One NoRoute for each address in each second.
	isNoRoute := func(m *dpv1.SessionResponse) bool { return m.GetNoRoute() != nil }
	nowhere := netip.MustParseAddr("fd61:706f:7879:12:3400:ff::1")
	a.sendFrame(packet(addr(t, resA), nowhere, 100))
	a.sendFrame(packet(addr(t, resA), nowhere, 100))
	nr := a.waitMsg(1, isNoRoute).GetNoRoute()
	assert.Equal(t, nowhere.String(), nr.GetAddress())
	assert.Equal(t, vpcUID, nr.GetVpc().GetVpcUid())
	assert.EqualValues(t, netID, nr.GetVpc().GetNetworkId())
	time.Sleep(300 * time.Millisecond)
	assert.Len(t, a.all(isNoRoute), 1)
	time.Sleep(time.Second)
	a.sendFrame(packet(addr(t, resA), nowhere, 100))
	a.waitMsg(2, isNoRoute)
}

func TestPSPMode(t *testing.T) {
	e := newEnv(t)
	a := e.dial(t, "agent-a")
	a.open(dpv1.Mode_MODE_PSP)
	resA := a.attach()
	b := e.dial(t, "agent-b")
	b.open(dpv1.Mode_MODE_QUIC)
	resB := b.attach()
	sock := pspSocket(t)

	// Rekey needs a path probe first.
	_, err := a.rc.Rekey(t.Context(), offer(0x1001, make([]byte, 16), netID, 1))
	assert.Equal(t, rpc.FailedPrecondition, rpc.CodeOf(err), "error: %v", err)
	// An SA of another VNI is not valid.
	a.probes++
	a.probe(e, sock, a.probes)
	_, err = a.rc.Rekey(t.Context(), offer(0x1001, make([]byte, 16), netID+1, 1))
	assert.Equal(t, rpc.InvalidArgument, rpc.CodeOf(err), "error: %v", err)

	rk := a.toPSP(e, sock, 7)
	assert.EqualValues(t, 7, rk.GetGeneration())
	assert.EqualValues(t, netID, rk.GetOffer().GetSas()[0].GetVni())

	// From the agent in PSP to the agent in QUIC mode, and back.
	for range 3 {
		p := packet(addr(t, resA), addr(t, resB), 300)
		a.sendPSP(e, sock, p)
		assert.Equal(t, p, b.recvFrame(wait))
	}
	p := packet(addr(t, resB), addr(t, resA), 300)
	b.sendFrame(p)
	assert.Equal(t, p, a.recvPSP(sock, wait))

	// The relay reports what it got with its SA.
	rep := a.waitMsg(1, func(m *dpv1.SessionResponse) bool {
		for _, sa := range m.GetRxReport().GetSas() {
			if sa.GetSpi() == a.txSPI && sa.GetPackets() == 3 {
				return true
			}
		}
		return false
	})
	require.NotNil(t, rep)

	// Lane ports: all or none, at most LaneSources, not the session port.
	lanes := []*struct {
		ports []uint32
		code  rpc.Code
	}{
		{ports: []uint32{40001, 40002, 40003, 40004}, code: rpc.InvalidArgument},
		{ports: []uint32{uint32(sock.LocalAddr().(*net.UDPAddr).Port)}, code: rpc.InvalidArgument},
		{ports: []uint32{0}, code: rpc.InvalidArgument},
		{ports: []uint32{40001, 40001}, code: rpc.InvalidArgument},
		{ports: []uint32{40001, 40002}},
		{ports: nil},
	}
	for _, l := range lanes {
		_, err := a.rc.RegisterLanes(t.Context(), &dpv1.RegisterLanesRequest{Ports: l.ports})
		assert.Equal(t, l.code, rpc.CodeOf(err), "ports %v: %v", l.ports, err)
	}
	// The data path is the same after the lane changes.
	p = packet(addr(t, resB), addr(t, resA), 300)
	b.sendFrame(p)
	assert.Equal(t, p, a.recvPSP(sock, wait))
}

// TestPathLoss checks that a connection with no BFD packets on its PSP path changes back to QUIC
// mode, and that the relay SAs end.
func TestPathLoss(t *testing.T) {
	e := newEnv(t)
	a := e.dial(t, "agent-a")
	a.open(dpv1.Mode_MODE_PSP)
	resA := a.attach()
	b := e.dial(t, "agent-b")
	b.open(dpv1.Mode_MODE_QUIC)
	resB := b.attach()
	sock := pspSocket(t)
	a.toPSP(e, sock, 1)
	p := packet(addr(t, resB), addr(t, resA), 100)
	b.sendFrame(p)
	require.Equal(t, p, a.recvPSP(sock, wait))

	// The check finds no packet in its detect time: the relay sends in data frames again.
	start := time.Now()
	var got []byte
	for got == nil && time.Since(start) < 15*time.Second {
		b.sendFrame(packet(addr(t, resB), addr(t, resA), 100))
		got = a.recvFrame(500 * time.Millisecond)
	}
	require.NotNil(t, got, "no data frame after the path loss")
	t.Logf("Path lost after %v", time.Since(start).Round(100*time.Millisecond))
	// The relay SAs ended: PSP packets from the agent drop.
	a.sendPSP(e, sock, packet(addr(t, resA), addr(t, resB), 100))
	b.noFrame(500 * time.Millisecond)
	// Data frames from the agent go on.
	p = packet(addr(t, resA), addr(t, resB), 100)
	a.sendFrame(p)
	assert.Equal(t, p, b.recvFrame(wait))
	// The agent can change to PSP mode again.
	a.toPSP(e, sock, 2)
	p = packet(addr(t, resA), addr(t, resB), 100)
	a.sendPSP(e, sock, p)
	assert.Equal(t, p, b.recvFrame(wait))
}

// TestProbeMove checks that a probe with a larger counter from a new source moves the PSP
// address, and that the previous address stays valid for 5 seconds.
func TestProbeMove(t *testing.T) {
	e := newEnv(t)
	a := e.dial(t, "agent-a")
	a.open(dpv1.Mode_MODE_PSP)
	resA := a.attach()
	b := e.dial(t, "agent-b")
	b.open(dpv1.Mode_MODE_QUIC)
	resB := b.attach()
	old, cur, other := pspSocket(t), pspSocket(t), pspSocket(t)
	a.toPSP(e, old, 1)
	a.keepPath(e, cur)

	a.probes++
	assert.Equal(t, cur.LocalAddr().String(), a.probe(e, cur, a.probes).String())
	moved := time.Now()
	p := packet(addr(t, resB), addr(t, resA), 100)
	b.sendFrame(p)
	assert.Equal(t, p, a.recvPSP(cur, wait))

	// A probe with a counter that is not larger gets a reply and does not move the address.
	assert.Equal(t, other.LocalAddr().String(), a.probe(e, other, a.probes).String())
	p = packet(addr(t, resB), addr(t, resA), 100)
	b.sendFrame(p)
	assert.Equal(t, p, a.recvPSP(cur, wait))

	// The previous address is valid for a short time.
	p = packet(addr(t, resA), addr(t, resB), 100)
	a.sendPSP(e, old, p)
	assert.Equal(t, p, b.recvFrame(wait))
	time.Sleep(time.Until(moved.Add(5*time.Second + 500*time.Millisecond)))
	a.sendPSP(e, old, packet(addr(t, resA), addr(t, resB), 100))
	b.noFrame(300 * time.Millisecond)
	// The source that the relay did not take drops too.
	a.sendPSP(e, other, packet(addr(t, resA), addr(t, resB), 100))
	b.noFrame(300 * time.Millisecond)
	p = packet(addr(t, resA), addr(t, resB), 100)
	a.sendPSP(e, cur, p)
	assert.Equal(t, p, b.recvFrame(wait))
}

func TestRevocation(t *testing.T) {
	cases := []struct {
		name    string
		change  func(*trust)
		recheck string
		closed  bool
		both    bool // The connection of agent-b closes too.
	}{
		{name: "revoked", change: func(tr *trust) { tr.revoke("agent-a") }, recheck: project, closed: true},
		{name: "other agent revoked", change: func(tr *trust) { tr.revoke("agent-c") }, recheck: project},
		{name: "recheck of another project", change: func(tr *trust) { tr.revoke("agent-a") }, recheck: "project-b"},
		// With no trust data to check a cert, the relay ends each connection of the project.
		{name: "no trust data", change: func(tr *trust) { tr.setErr(errors.New("trust data too old")) }, recheck: project, closed: true, both: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			a := e.dial(t, "agent-a")
			a.open(dpv1.Mode_MODE_QUIC)
			res := a.attach()
			b := e.dial(t, "agent-b")
			b.open(dpv1.Mode_MODE_QUIC)
			b.attach()

			tc.change(e.trust)
			e.r.Recheck(tc.recheck)
			if tc.closed {
				code, _ := a.closed()
				assert.Equal(t, dpv1.RelayCloseCode_RELAY_CLOSE_CODE_CERT, code)
				e.waitEnd(t, res.GetAttachmentId())
				// A new connection with the revoked cert fails its handshake, or the relay closes
				// it at once.
				n, err := e.dialVPC(t, vpcUID, "agent-a")
				if err == nil {
					select {
					case <-n.qc.Context().Done():
					case <-time.After(wait):
						t.Fatal("connection with a revoked cert stays open")
					}
				}
			} else {
				assert.True(t, a.openAfter(500*time.Millisecond))
			}
			if tc.both {
				code, _ := b.closed()
				assert.Equal(t, dpv1.RelayCloseCode_RELAY_CLOSE_CODE_CERT, code)
				return
			}
			assert.True(t, b.openAfter(100*time.Millisecond))
		})
	}
}

func TestDrain(t *testing.T) {
	cases := []struct {
		name  string
		time  time.Duration
		leave bool // The agent closes its connection after Drain.
		// mesh makes relay-2 a member that is up: the alternate of the drain.
		mesh bool
		want []*dpv1.RelayRef
	}{
		{name: "agent moves to a member", time: wait, leave: true, mesh: true, want: []*dpv1.RelayRef{{Id: "relay-2", Addresses: []string{"192.0.2.2"}}}},
		{name: "drain time ends with no mesh", time: 500 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if tc.mesh {
				e, _ = newMesh(t, envOpts{}, envOpts{})
			}
			a := e.dial(t, "agent-a")
			a.open(dpv1.Mode_MODE_QUIC)
			res := a.attach()
			ctx, cancel := context.WithTimeout(context.Background(), tc.time)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				e.srv.Drain(ctx)
			}()

			d := a.waitMsg(1, func(m *dpv1.SessionResponse) bool { return m.GetDrain() != nil }).GetDrain()
			assert.Empty(t, cmp.Diff(tc.want, d.GetAlternates(), protocmp.Transform()))
			// A new connection gets the drain close.
			n := e.dial(t, "agent-n")
			code, _ := n.closed()
			assert.Equal(t, dpv1.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN, code)

			if tc.leave {
				_ = a.qc.CloseWithError(0, "moved")
			} else {
				code, _ := a.closed()
				assert.Equal(t, dpv1.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN, code)
			}
			select {
			case <-done:
			case <-time.After(wait):
				t.Fatal("Drain did not return")
			}
			e.waitEnd(t, res.GetAttachmentId())
		})
	}
}

// TestSlotLost checks that the end of an address lease closes the connection and ends and
// releases the attachment, and that the relay then has no route to its address.
func TestSlotLost(t *testing.T) {
	e := newEnv(t)
	a := e.dial(t, "agent-a")
	a.open(dpv1.Mode_MODE_QUIC)
	resA := a.attach()
	b := e.dial(t, "agent-b")
	b.open(dpv1.Mode_MODE_QUIC)
	resB := b.attach()

	e.addrs.loseSlot(resA.GetAttachmentId())
	code, msg := a.closed()
	assert.Equal(t, dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, code)
	assert.Contains(t, msg, "lease")
	// The attachment ends after V removed its route: the relay has no route to it now.
	e.waitEnd(t, resA.GetAttachmentId())
	b.sendFrame(packet(addr(t, resB), addr(t, resA), 100))
	b.waitMsg(1, func(m *dpv1.SessionResponse) bool { return m.GetNoRoute() != nil })
	require.Eventually(t, func() bool { return e.addrs.isReleased(resA.GetAttachmentId()) }, wait, 10*time.Millisecond)
	assert.True(t, b.openAfter(100*time.Millisecond))
}

// TestIndexReuse checks that the counts of a new attachment and a new connection start at zero
// when they get the counter cells of ended ones.
func TestIndexReuse(t *testing.T) {
	e := newEnv(t)
	b := e.dial(t, "agent-b")
	b.open(dpv1.Mode_MODE_QUIC)
	resB := b.attach()
	a := e.dial(t, "agent-a")
	a.open(dpv1.Mode_MODE_QUIC)
	resA := a.attach()
	for range 2 {
		a.sendFrame(packet(addr(t, resA), addr(t, resB), 100))
		require.NotNil(t, b.recvFrame(wait))
	}
	require.Eventually(t, func() bool {
		s := e.statsOf(resA.GetAttachmentId())
		return s != nil && s.RXPackets == 2
	}, wait, 50*time.Millisecond)

	// The connection ends: its final counts go to the host.
	_ = a.qc.CloseWithError(0, "")
	end := e.waitEnd(t, resA.GetAttachmentId())
	assert.EqualValues(t, 2, end.RXPackets)
	// B detaches and attaches again.
	_, err := b.rc.Detach(t.Context(), &dpv1.DetachRequest{AttachmentId: resB.GetAttachmentId()})
	require.NoError(t, err)
	endB := e.waitEnd(t, resB.GetAttachmentId())
	assert.EqualValues(t, 2, endB.TXPackets)
	resB2 := b.attach()

	a2 := e.dial(t, "agent-a")
	a2.open(dpv1.Mode_MODE_QUIC)
	resA2 := a2.attach()
	sa, sb := e.statsOf(resA2.GetAttachmentId()), e.statsOf(resB2.GetAttachmentId())
	require.NotNil(t, sa)
	require.NotNil(t, sb)
	assert.Zero(t, sa.RXPackets)
	assert.Zero(t, sb.TXPackets)
	assert.NotEqual(t, end.Instance, sa.Instance)

	a2.sendFrame(packet(addr(t, resA2), addr(t, resB2), 100))
	require.NotNil(t, b.recvFrame(wait))
	require.Eventually(t, func() bool {
		sa, sb := e.statsOf(resA2.GetAttachmentId()), e.statsOf(resB2.GetAttachmentId())
		return sa.RXPackets == 1 && sb.TXPackets == 1
	}, wait, 50*time.Millisecond)
}

func TestRemoveVPC(t *testing.T) {
	e := newEnv(t)
	a := e.dial(t, "agent-a")
	a.open(dpv1.Mode_MODE_QUIC)
	res := a.attach()

	e.r.RemoveVPC(vpcKey)
	a.closed()
	e.waitEnd(t, res.GetAttachmentId())
	require.Eventually(t, func() bool { return e.addrs.isReleased(res.GetAttachmentId()) }, wait, 10*time.Millisecond)
	n := e.dial(t, "agent-n")
	_, err := n.session(hello(dpv1.Mode_MODE_QUIC))
	assert.Equal(t, rpc.Unavailable, rpc.CodeOf(err), "error: %v", err)

	e.r.AddVPC(vpcKey, relay.Network{ID: netID, Name: "net-a"})
	require.Eventually(t, func() bool {
		c, err := e.dialVPC(t, vpcUID, "agent-n")
		if err != nil {
			return false
		}
		_, err = c.session(hello(dpv1.Mode_MODE_QUIC))
		return err == nil
	}, wait, 50*time.Millisecond)
}

// TestMTUChange checks that a new VPC MTU goes to new connections, and that an open connection
// keeps the MTU of its Welcome.
func TestMTUChange(t *testing.T) {
	mtu := func(a *agent) uint32 {
		return a.waitMsg(1, func(m *dpv1.SessionResponse) bool { return m.GetConfig() != nil }).GetConfig().GetMtu()
	}
	e := newEnv(t)
	a := e.dial(t, "agent-a")
	a.open(dpv1.Mode_MODE_PSP)
	assert.EqualValues(t, 1280, mtu(a))
	resA := a.attach()

	e.r.AddVPC(vpcKey, relay.Network{ID: netID, Name: "net-a", MTU: 1400})
	var b *agent
	require.Eventually(t, func() bool {
		b = e.dial(t, "agent-b")
		b.open(dpv1.Mode_MODE_PSP)
		return mtu(b) == 1400
	}, wait, 50*time.Millisecond, "a new connection gets the new MTU")
	resB := b.attach()
	sockA, sockB := pspSocket(t), pspSocket(t)
	// The relay takes an agent SPI once.
	b.rxSPI = 0x1002
	a.toPSP(e, sockA, 1)
	b.toPSP(e, sockB, 1)

	// The ports entry of a, which a writes again in PSP mode, keeps the MTU 1280.
	b.sendPSP(e, sockB, packet(addr(t, resB), addr(t, resA), 1300))
	assert.Nil(t, a.recvPSP(sockA, 300*time.Millisecond), "a packet above the MTU of the Welcome")
	p := packet(addr(t, resB), addr(t, resA), 1200)
	b.sendPSP(e, sockB, p)
	assert.Equal(t, p, a.recvPSP(sockA, wait))
}
