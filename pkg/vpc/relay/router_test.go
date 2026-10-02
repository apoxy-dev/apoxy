// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

var t0 = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

// fakeAddr is the remote address of a test session. Set it to move the
// session as a QUIC migration does.
type fakeAddr struct {
	mu sync.Mutex
	a  netip.AddrPort
}

func (f *fakeAddr) get() netip.AddrPort {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.a
}

func (f *fakeAddr) set(a string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.a = netip.MustParseAddrPort(a)
}

type testSession struct {
	*Session
	addr *fakeAddr
}

// addSession adds a session in vpc at addr with the routes.
func addSession(t *testing.T, r *Router, vpc VPCKey, id, addr string, routes ...string) testSession {
	t.Helper()
	fa := &fakeAddr{a: netip.MustParseAddrPort(addr)}
	s := newSession(Identity{VPC: vpc, ID: id}, fa.get)
	r.addSession(s, t0)
	for _, p := range routes {
		require.NoError(t, r.AddRoute(s, netip.MustParsePrefix(p), "att-"+id))
	}
	return testSession{s, fa}
}

func ref(k VPCKey) *dp.VPCRef {
	return &dp.VPCRef{ProjectId: k.Project, VpcUid: k.UID, NetworkId: 0x0a0b0c}
}

func register(k VPCKey, dst string, ttl time.Duration, spis ...uint32) *dp.RegisterSPIRequest {
	return &dp.RegisterSPIRequest{Vpc: ref(k), Destination: dst, Spis: spis, ExpiresIn: durationpb.New(ttl)}
}

var (
	vpcA = VPCKey{Project: "project-a", UID: "vpc-1"}
	// vpcB has the same VPC UID in another project: only the project differs.
	vpcB = VPCKey{Project: "project-b", UID: "vpc-1"}
)

func codeOf(err error) rpc.Code { return rpc.CodeOf(err) }

func TestKeyOf(t *testing.T) {
	cases := []struct {
		name string
		ref  *dp.VPCRef
		want VPCKey
		code rpc.Code
	}{
		{"full", &dp.VPCRef{ProjectId: "p", VpcUid: "u", NetworkId: 7}, VPCKey{"p", "u"}, rpc.OK},
		{"nil", nil, VPCKey{}, rpc.InvalidArgument},
		{"no project", &dp.VPCRef{VpcUid: "u"}, VPCKey{}, rpc.InvalidArgument},
		{"no uid", &dp.VPCRef{ProjectId: "p"}, VPCKey{}, rpc.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := KeyOf(tc.ref)
			assert.Equal(t, tc.code, codeOf(err))
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRegisterSPI(t *testing.T) {
	cases := []struct {
		name string
		req  *dp.RegisterSPIRequest
		code rpc.Code
	}{
		{"new", register(vpcA, "fd00::2", time.Minute, 10, 11), rpc.OK},
		{"same destination again", register(vpcA, "fd00::2", time.Minute, 1), rpc.OK},
		{"held for another destination", register(vpcA, "fd00::3", time.Minute, 1), rpc.AlreadyExists},
		{"one SPI held for another destination", register(vpcA, "fd00::3", time.Minute, 20, 1), rpc.AlreadyExists},
		{"no route", register(vpcA, "fd00::99", time.Minute, 30), rpc.NotFound},
		{"other VPC", register(vpcB, "fd00::2", time.Minute, 30), rpc.PermissionDenied},
		{"no SPIs", register(vpcA, "fd00::2", time.Minute), rpc.InvalidArgument},
		{"no expiry", &dp.RegisterSPIRequest{Vpc: ref(vpcA), Destination: "fd00::2", Spis: []uint32{30}}, rpc.InvalidArgument},
		{"negative expiry", register(vpcA, "fd00::2", -time.Second, 30), rpc.InvalidArgument},
		{"bad address", register(vpcA, "fd00::zz", time.Minute, 30), rpc.InvalidArgument},
		{"no VPC", &dp.RegisterSPIRequest{Destination: "fd00::2", Spis: []uint32{30}, ExpiresIn: durationpb.New(time.Minute)}, rpc.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			snd := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128")
			addSession(t, r, vpcA, "r2", "192.0.2.2:1000", "fd00::2/128")
			addSession(t, r, vpcA, "r3", "192.0.2.3:1000", "fd00::3/128")
			addSession(t, r, vpcB, "b2", "192.0.2.4:1000", "fd00::2/128")
			require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Minute, 1), t0))

			err := r.registerSPI(snd.Session, tc.req, t0)
			require.Equal(t, tc.code, codeOf(err), "error: %v", err)
			// A failed request installs nothing.
			want := map[uint32]string{1: "fd00::2"}
			if tc.code == rpc.OK {
				for _, spi := range tc.req.Spis {
					want[spi] = tc.req.Destination
				}
			}
			got := map[uint32]string{}
			for _, l := range r.SenderStats(snd.Session).Lanes {
				got[l.SPI] = l.Destination.String()
			}
			assert.Equal(t, want, got)
		})
	}
}

func TestForward(t *testing.T) {
	const size = 1400
	cases := []struct {
		name    string
		src     string
		spi     uint32
		at      time.Duration // After t0.
		move    string        // New sender address before the packet.
		want    Verdict
		wantDst string
	}{
		{"pass", "192.0.2.1:1000", 1, 0, "", Pass, "192.0.2.2:2000"},
		{"IPv4-mapped source", "[::ffff:192.0.2.1]:1000", 1, 0, "", Pass, "192.0.2.2:2000"},
		{"unknown source", "192.0.2.9:1000", 1, 0, "", DropUnknownSource, ""},
		{"source port differs", "192.0.2.1:1001", 1, 0, "", DropUnknownSource, ""},
		{"unknown SPI", "192.0.2.1:1000", 2, 0, "", DropUnknownSPI, ""},
		{"expired row", "192.0.2.1:1000", 1, 2 * time.Minute, "", DropUnknownSPI, ""},
		{"receiver's SPI from receiver", "192.0.2.2:2000", 1, 0, "", DropUnknownSPI, ""},
		{"new address after migration", "198.51.100.1:3000", 1, 0, "198.51.100.1:3000", Pass, "192.0.2.2:2000"},
		{"old address in overlap", "192.0.2.1:1000", 1, rebindOverlap - time.Second, "198.51.100.1:3000", Pass, "192.0.2.2:2000"},
		{"old address after overlap", "192.0.2.1:1000", 1, rebindOverlap + time.Second, "198.51.100.1:3000", DropUnknownSource, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			snd := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128")
			addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
			require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Minute, 1), t0))
			if tc.move != "" {
				snd.addr.set(tc.move)
				r.Sweep(t0)
			}
			dst, v := r.Forward(netip.MustParseAddrPort(tc.src), tc.spi, size, t0.Add(tc.at))
			assert.Equal(t, tc.want, v)
			if tc.wantDst != "" {
				assert.Equal(t, tc.wantDst, dst.String())
			}
		})
	}
}

func TestForwardCounters(t *testing.T) {
	r := NewRouter(nil, Config{LaneRate: 1 << 20, LaneBurst: 64 << 10})
	snd := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128")
	addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
	require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Minute, 1, 2), t0))
	src := netip.MustParseAddrPort("192.0.2.1:1000")

	// The burst is 64 KiB: 46 packets of 1400 B pass on lane 1, then the meter drops.
	var pass, drop int
	for range 50 {
		if _, v := r.Forward(src, 1, 1400, t0); v == Pass {
			pass++
		} else {
			require.Equal(t, DropMeter, v)
			drop++
		}
	}
	assert.Equal(t, 46, pass)
	// Each lane has its own meter.
	_, v := r.Forward(src, 2, 1400, t0)
	assert.Equal(t, Pass, v)
	_, v = r.Forward(src, 3, 1400, t0)
	assert.Equal(t, DropUnknownSPI, v)
	_, v = r.Forward(netip.MustParseAddrPort("192.0.2.9:1"), 1, 1400, t0)
	assert.Equal(t, DropUnknownSource, v)

	st := r.SenderStats(snd.Session)
	assert.Equal(t, SenderStats{
		DropUnknownSPI: 1,
		DropMeter:      uint64(drop),
		Lanes: []LaneStats{
			{SPI: 1, Destination: netip.MustParseAddr("fd00::2"), Packets: 46, Bytes: 46 * 1400, DropMeter: uint64(drop)},
			{SPI: 2, Destination: netip.MustParseAddr("fd00::2"), Packets: 1, Bytes: 1400},
		},
	}, st)
	assert.Equal(t, uint64(1), r.UnknownSourceDrops())
}

func TestForwardAllocs(t *testing.T) {
	r := NewRouter(nil, Config{LaneRate: 1 << 30, TunnelRate: 1 << 30})
	snd := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128")
	addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
	require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Minute, 1), t0))
	src := netip.MustParseAddrPort("192.0.2.1:1000")
	assert.Zero(t, testing.AllocsPerRun(1000, func() { r.Forward(src, 1, 1400, t0) }))
}

// TestRowRemoval checks each way that a row ends. The row is lane 1 from
// sender to receiver.
func TestRowRemoval(t *testing.T) {
	cases := []struct {
		name   string
		remove func(r *Router, snd, recv testSession)
		at     time.Duration // Time of the packet after t0.
		gone   bool
	}{
		{"kept", func(r *Router, _, _ testSession) {}, 0, false},
		{"unregister", func(r *Router, snd, _ testSession) {
			require.NoError(t, r.unregisterSPI(snd.Session, &dp.UnregisterSPIRequest{Vpc: ref(vpcA), Spis: []uint32{1}}))
		}, 0, true},
		{"unregister in another VPC", func(r *Router, snd, _ testSession) {
			err := r.unregisterSPI(snd.Session, &dp.UnregisterSPIRequest{Vpc: ref(vpcB), Spis: []uint32{1}})
			assert.Equal(t, rpc.PermissionDenied, codeOf(err))
		}, 0, false},
		{"expiry", func(r *Router, _, _ testSession) { r.Sweep(t0.Add(11 * time.Minute)) }, 0, true},
		{"idle", func(r *Router, _, _ testSession) { r.Sweep(t0.Add(rowIdle + time.Second)) }, rowIdle + 2*time.Second, true},
		{"not idle", func(r *Router, snd, _ testSession) {
			r.Forward(snd.addr.get(), 1, 100, t0.Add(4*time.Minute))
			r.Sweep(t0.Add(rowIdle + time.Second))
		}, rowIdle + 2*time.Second, false},
		{"permit change", func(r *Router, _, _ testSession) {
			r.SetPermit(func(VPCKey, string, VPCKey, netip.Addr) bool { return false })
		}, 0, true},
		{"permit change that allows", func(r *Router, _, _ testSession) { r.SetPermit(SameVPC) }, 0, false},
		{"receiver route removed", func(r *Router, _, recv testSession) {
			r.RemoveRoute(recv.Session, netip.MustParsePrefix("fd00::2/128"))
		}, 0, true},
		{"receiver closed", func(r *Router, _, recv testSession) { r.removeSession(recv.Session) }, 0, true},
		{"sender closed", func(r *Router, snd, _ testSession) { r.removeSession(snd.Session) }, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			snd := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128")
			recv := addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
			require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", 10*time.Minute, 1), t0))
			tc.remove(r, snd, recv)
			_, v := r.Forward(snd.addr.get(), 1, 100, t0.Add(tc.at))
			if tc.gone {
				assert.NotEqual(t, Pass, v)
				assert.Empty(t, r.SenderStats(snd.Session).Lanes)
				assert.Empty(t, recv.inbound)
			} else {
				assert.Equal(t, Pass, v)
			}
		})
	}
}

// TestLaneRekey runs the rekey after ICV failures: the receiver reports
// them, the sender registers the new SPI and unregisters the old one.
func TestLaneRekey(t *testing.T) {
	r := NewRouter(nil, Config{})
	snd := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128")
	recv := addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
	require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Minute, 0x1001), t0))

	r.ReportStatus(recv.Session, &dp.Status{IcvFailures: []*dp.ICVFailures{{Spi: 0x1001, Count: 40}, {Spi: 0x9999, Count: 1}}})
	r.ReportStatus(recv.Session, &dp.Status{IcvFailures: []*dp.ICVFailures{{Spi: 0x1001, Count: 2}}})
	lanes := r.SenderStats(snd.Session).Lanes
	require.Len(t, lanes, 1)
	assert.Equal(t, uint64(42), lanes[0].ICVFailures)

	require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Minute, 0x2002), t0))
	require.NoError(t, r.unregisterSPI(snd.Session, &dp.UnregisterSPIRequest{Vpc: ref(vpcA), Spis: []uint32{0x1001}}))
	_, v := r.Forward(snd.addr.get(), 0x1001, 100, t0)
	assert.Equal(t, DropUnknownSPI, v)
	dst, v := r.Forward(snd.addr.get(), 0x2002, 100, t0)
	assert.Equal(t, Pass, v)
	assert.Equal(t, recv.addr.get(), dst)
}

func TestResolvePeer(t *testing.T) {
	cases := []struct {
		name      string
		vpc       VPCKey
		addr      string
		relayOnly bool // Identity of the peer.
		want      *dp.ResolvePeerResponse
		code      rpc.Code
	}{
		{"local", vpcA, "fd00::2", false, &dp.ResolvePeerResponse{Reach: dp.Reach_REACH_LOCAL, P2P: true}, rpc.OK},
		{"longest prefix", vpcA, "10.1.2.3", false, &dp.ResolvePeerResponse{Reach: dp.Reach_REACH_LOCAL, P2P: true}, rpc.OK},
		{"relay-only peer", vpcA, "fd00::2", true, &dp.ResolvePeerResponse{Reach: dp.Reach_REACH_LOCAL}, rpc.OK},
		{"IPv4-mapped", vpcA, "::ffff:10.1.2.3", false, &dp.ResolvePeerResponse{Reach: dp.Reach_REACH_LOCAL, P2P: true}, rpc.OK},
		{"not found", vpcA, "fd00::99", false, nil, rpc.NotFound},
		{"other VPC", vpcB, "fd00::2", false, nil, rpc.PermissionDenied},
		{"bad address", vpcA, "nope", false, nil, rpc.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			c := addSession(t, r, vpcA, "caller", "192.0.2.1:1000", "fd00::1/128")
			peer := newSession(Identity{VPC: vpcA, ID: "peer", RelayOnly: tc.relayOnly},
				func() netip.AddrPort { return netip.MustParseAddrPort("192.0.2.2:2000") })
			r.addSession(peer, t0)
			require.NoError(t, r.AddRoute(peer, netip.MustParsePrefix("fd00::2/128"), "att"))
			require.NoError(t, r.AddRoute(peer, netip.MustParsePrefix("10.1.2.0/24"), "att"))
			// A shorter route of another session.
			addSession(t, r, vpcA, "other", "192.0.2.3:3000", "10.0.0.0/8")

			got, err := r.resolvePeer(c.Session, &dp.ResolvePeerRequest{Vpc: ref(tc.vpc), Address: tc.addr})
			require.Equal(t, tc.code, codeOf(err), "error: %v", err)
			if tc.want != nil {
				assert.Equal(t, tc.want.Reach, got.Reach)
				assert.Equal(t, tc.want.P2P, got.P2P)
			}
		})
	}
}

func TestAddRoute(t *testing.T) {
	r := NewRouter(nil, Config{})
	a := addSession(t, r, vpcA, "a", "192.0.2.1:1000")
	b := addSession(t, r, vpcA, "b", "192.0.2.2:1000")
	p := netip.MustParsePrefix("10.0.0.0/24")
	require.NoError(t, r.AddRoute(a.Session, p, "att"))
	require.NoError(t, r.AddRoute(a.Session, netip.MustParsePrefix("10.0.0.7/24"), "att"), "same masked prefix, same owner")
	assert.Equal(t, rpc.AlreadyExists, codeOf(r.AddRoute(b.Session, p, "att")))
	r.RemoveRoute(b.Session, p) // Not the owner: no change.
	assert.Equal(t, a.Session, r.lookup(vpcA, netip.MustParseAddr("10.0.0.1")))
	r.RemoveRoute(a.Session, p)
	assert.Nil(t, r.lookup(vpcA, netip.MustParseAddr("10.0.0.1")))
	require.NoError(t, r.AddRoute(b.Session, p, "att"))
	r.removeSession(b.Session)
	assert.Nil(t, r.lookup(vpcA, netip.MustParseAddr("10.0.0.1")))
	assert.Equal(t, rpc.FailedPrecondition, codeOf(r.AddRoute(b.Session, p, "att")))
	// The domain ends with its last session.
	r.removeSession(a.Session)
	assert.Empty(t, r.domains)
}

// TestProjectIsolation puts two projects with a VPC of the same name on one
// relay. The VPCs also have the same UID, the same network ID and the same
// addresses: only the project differs. No routes, SPI rows or packets cross.
func TestProjectIsolation(t *testing.T) {
	r := NewRouter(nil, Config{})
	type side struct{ snd, recv testSession }
	sides := map[VPCKey]side{
		vpcA: {
			addSession(t, r, vpcA, "a-sender", "192.0.2.1:1000", "fd00::1/128", "10.0.0.0/24"),
			addSession(t, r, vpcA, "a-receiver", "192.0.2.2:1000", "fd00::2/128", "10.0.1.0/24"),
		},
		vpcB: {
			addSession(t, r, vpcB, "b-sender", "198.51.100.1:1000", "fd00::1/128", "10.0.0.0/24"),
			addSession(t, r, vpcB, "b-receiver", "198.51.100.2:1000", "fd00::2/128", "10.0.1.0/24"),
		},
	}
	other := map[VPCKey]VPCKey{vpcA: vpcB, vpcB: vpcA}
	// The same SPI in both projects.
	const spi = 0x8000_0001
	for k, s := range sides {
		require.NoError(t, r.registerSPI(s.snd.Session, register(k, "fd00::2", time.Minute, spi), t0))
	}
	for k, s := range sides {
		t.Run(k.Project, func(t *testing.T) {
			o := sides[other[k]]
			// Routes: each address resolves in the own project only.
			for _, a := range []string{"fd00::2", "10.0.1.5"} {
				assert.Equal(t, s.recv.Session, r.lookup(k, netip.MustParseAddr(a)))
				_, err := r.resolvePeer(s.snd.Session, &dp.ResolvePeerRequest{Vpc: ref(other[k]), Address: a})
				assert.Equal(t, rpc.PermissionDenied, codeOf(err))
			}
			// SPI rows: no row to the other project.
			err := r.registerSPI(s.snd.Session, register(other[k], "fd00::2", time.Minute, spi+1), t0)
			assert.Equal(t, rpc.PermissionDenied, codeOf(err))
			lanes := r.SenderStats(s.snd.Session).Lanes
			require.Len(t, lanes, 1)
			assert.Equal(t, uint32(spi), lanes[0].SPI)
			assert.Len(t, s.recv.inbound, 1)
			for w := range s.recv.inbound {
				assert.Equal(t, s.snd.Session, w.sender)
			}
			// Packets: the own SPI goes to the own receiver only.
			dst, v := r.Forward(s.snd.addr.get(), spi, 100, t0)
			assert.Equal(t, Pass, v)
			assert.Equal(t, s.recv.addr.get(), dst)
			// The other project's sender address with this project's SPI
			// reaches its own receiver, never this one.
			dst, _ = r.Forward(o.snd.addr.get(), spi, 100, t0)
			assert.NotEqual(t, s.recv.addr.get(), dst)
			// The SPI of the other project's row from this project's receiver.
			_, v = r.Forward(s.recv.addr.get(), spi, 100, t0)
			assert.Equal(t, DropUnknownSPI, v)
		})
	}
	// Removing one project leaves the other one unchanged.
	r.removeSession(sides[vpcA].recv.Session)
	_, v := r.Forward(sides[vpcA].snd.addr.get(), spi, 100, t0)
	assert.Equal(t, DropUnknownSPI, v)
	dst, v := r.Forward(sides[vpcB].snd.addr.get(), spi, 100, t0)
	assert.Equal(t, Pass, v)
	assert.Equal(t, sides[vpcB].recv.addr.get(), dst)
}
