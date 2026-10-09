// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"errors"
	"maps"
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

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// The agents of the frame tests. server, neighbor and guest are on relay-m, and
// guest is in vpcB. The others are on relay-a and relay-b.
const (
	laptopTag = 0x010203 // Tag of laptop on relay-a.
	phoneTag  = 0x010204 // Tag of phone on relay-a.
	tabletTag = 0x010203 // Tag of tablet on relay-b: the tag of laptop on relay-a.

	laptopAddr   = "fd00:a::1"
	laptopNet    = "10.9.0.1" // In the advertised route of laptop.
	phoneAddr    = "fd00:d::1"
	tabletAddr   = "fd00:e::1"
	serverAddr   = "fd00:b::1"
	serverNet    = "10.8.0.1" // In the advertised route of server.
	neighborAddr = "fd00:b1::1"
	guestAddr    = "fd00:c::1" // In vpcB.
)

// memberFrame returns the datagram that a relay sends to a member for the
// peer frame of its session with tag.
func memberFrame(tag uint32, dst, src, pkt string) []byte {
	d, s := netip.MustParseAddr(dst).As16(), netip.MustParseAddr(src).As16()
	b := []byte{0x01, byte(tag >> 16), byte(tag >> 8), byte(tag)}
	b = append(b, d[:]...)
	b = append(b, s[:]...)
	return append(b, pkt...)
}

// dropCounts returns the drop counters of r that are not 0, by reason label.
func dropCounts(r *Router) map[string]uint64 {
	out := map[string]uint64{}
	for i := range r.drops {
		if n := r.drops[i].Load(); n > 0 {
			out[dropLabels[i]] = n
		}
	}
	return out
}

// frameWorld is a routeWorld with the agents of the frame tests, and the
// frames that each session of relay-m gets.
type frameWorld struct {
	*routeWorld
	first map[string]*MeshSession // First session of each member.
	got   map[string][][]byte
}

// newFrameWorld opens the mesh sessions at this revision, so the test must not
// call deliver: the stub carries no Presence call.
func newFrameWorld(t *testing.T) *frameWorld {
	t.Helper()
	w := &frameWorld{routeWorld: newRouteWorldAt(t, NewRouter(nil, Config{}), dp.Revision), got: map[string][][]byte{}}
	w.first = maps.Clone(w.mesh)
	// The first tag of relay-m has a value in each of its 3 bytes.
	w.r.tag = 0x0a0b0b
	w.session("server", vpcA, server, thisRevision())
	w.attach("server", "s", prefixB, "10.8.0.0/16")
	w.session("neighbor", vpcA, agentID(vpcA, "neighbor"), thisRevision())
	w.attach("neighbor", "n", "fd00:b1::/96")
	guest := w.session("guest", vpcB, agentID(vpcB, "guest"), thisRevision())
	require.NoError(t, w.r.attach(guest, &Attachment{ID: "g", VPC: vpcB, NetworkID: testVNI, Addresses: []netip.Prefix{netip.MustParsePrefix("fd00:c::/96")}}))
	for name, s := range w.sess {
		s.sendDatagram = func(b []byte) error {
			w.got[name] = append(w.got[name], slices.Clone(b))
			return nil
		}
	}
	w.entries("relay-a", 10)
	w.send("relay-b", atGen(liveEntry("t", agentID(vpcA, "tablet"), "base", tabletTag, "fd00:e::/96"), 10))
	return w
}

// atGen returns e with the generation gen.
func atGen(e *dp.Presence, gen uint64) *dp.Presence {
	e.Generation = gen
	return e
}

// entries sends the attachments of relay-a at generation gen on its newest
// session: two of laptop, and one of phone.
func (w *frameWorld) entries(member string, gen uint64) {
	w.t.Helper()
	w.send(member,
		atGen(liveEntry("x", laptop, "base", laptopTag, prefixA, prefixR), gen),
		atGen(liveEntry("x2", laptop, "base", laptopTag, "fd00:a2::/96"), gen),
		atGen(liveEntry("p", agentID(vpcA, "phone"), "base", phoneTag, "fd00:d::/96"), gen))
}

// cut ends the session of member with an idle timeout, as a lost path does.
func (w *frameWorld) cut(member string) {
	w.conns[member].cancel(&quic.IdleTimeoutError{})
	synctest.Wait()
}

// stop ends the session of member with RESTART, and drops its entries as the
// change of the member does.
func (w *frameWorld) stop(member string) {
	w.conns[member].cancel(&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART)})
	synctest.Wait()
	w.m.pres.down(MeshChange{Name: member, Down: MeshRestart})
}

// noRoutes returns the addresses of the NoRoute messages that wait for the
// sessions of relay-m.
func (w *frameWorld) noRoutes() []string {
	var out []string
	for _, s := range w.sess {
		for _, m := range w.r.takeSync(s) {
			if nr := m.GetNoRoute(); nr != nil {
				out = append(out, nr.GetAddress())
			}
		}
	}
	return out
}

// sent returns the datagrams that relay-m sent to its members, on their first
// and on their newest sessions.
func (w *frameWorld) sent() map[string][][]byte {
	out := map[string][][]byte{}
	for name, s := range w.first {
		sessions := []*MeshSession{s}
		if cur := w.mesh[name]; cur != s {
			sessions = append(sessions, cur)
		}
		for _, ms := range sessions {
			c := ms.qc.(*stubConn)
			c.mu.Lock()
			if len(c.sent) > 0 {
				out[name] = append(out[name], c.sent...)
			}
			c.mu.Unlock()
		}
	}
	return out
}

// TestMeshPeerFrameReceive gives relay-m the datagrams of its member relay-a.
// A session of relay-m gets a frame only after each check passes.
func TestMeshPeerFrameReceive(t *testing.T) {
	deny := func(VPCKey, string, VPCKey, netip.Addr) bool { return false }
	cases := []struct {
		name  string
		setup func(w *frameWorld)
		// The datagram is raw, or else the frame of the session with tag.
		tag      uint32
		dst, src string
		pkt      string
		raw      []byte
		old      bool   // The datagram comes on the first session of relay-a, not on the newest.
		to       string // Session of relay-m that gets the frame. Empty if the relay drops it.
		drop     string // Reason label of the drop.
	}{
		{name: "to a session of this relay", tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", to: "server"},
		{name: "to an IPv4 route of the session", tag: laptopTag, dst: serverNet, src: laptopAddr, pkt: "hi", to: "server"},
		{name: "empty packet", tag: laptopTag, dst: serverAddr, src: laptopAddr, to: "server"},
		{name: "packet of a peer session", tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: strings.Repeat("q", 1200), to: "server"},
		{name: "source in an advertised route of the sender", tag: laptopTag, dst: serverAddr, src: laptopNet, pkt: "hi", to: "server"},
		{name: "source of the second attachment of the sender", tag: laptopTag, dst: serverAddr, src: "fd00:a2::1", pkt: "hi", to: "server"},
		{name: "other session of the member", tag: phoneTag, dst: serverAddr, src: phoneAddr, pkt: "hi", to: "server"},
		{
			name:  "sender after the end of its second attachment",
			setup: func(w *frameWorld) { w.send("relay-a", goneAt("x2", 11)) },
			tag:   laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", to: "server",
		},

		// The source ownership check.
		{name: "source of another session of the member", tag: laptopTag, dst: serverAddr, src: phoneAddr, pkt: "hi", drop: "mesh_source"},
		{name: "source of a session of this relay", tag: laptopTag, dst: serverAddr, src: serverAddr, pkt: "hi", drop: "mesh_source"},
		{name: "source of a session of another member", tag: laptopTag, dst: serverAddr, src: tabletAddr, pkt: "hi", drop: "mesh_source"},
		{name: "source with no route", tag: laptopTag, dst: serverAddr, src: "fd00:f::1", pkt: "hi", drop: "mesh_source"},
		{
			name: "source that a session of this relay took from the sender",
			setup: func(w *frameWorld) {
				w.session("second", vpcA, agentID(vpcA, "second"), thisRevision())
				w.attach("second", "l", prefixA)
			},
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_source",
		},
		{
			name: "source that an entry of another member took from the sender",
			setup: func(w *frameWorld) {
				w.send("relay-b", atGen(liveEntry("t2", agentID(vpcA, "tablet"), "base", tabletTag, prefixA), 20))
			},
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_source",
		},
		{
			name: "source that an entry of another member with the same attachment ID took",
			setup: func(w *frameWorld) {
				w.send("relay-b", atGen(liveEntry("x", agentID(vpcA, "tablet"), "base", tabletTag, prefixA), 20))
			},
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_source",
		},
		{
			name: "source in a more specific route of another session",
			setup: func(w *frameWorld) {
				w.send("relay-a", atGen(liveEntry("p2", agentID(vpcA, "phone"), "base", phoneTag, "10.9.7.0/24"), 20))
			},
			tag: laptopTag, dst: serverAddr, src: "10.9.7.1", pkt: "hi", drop: "mesh_source",
		},
		{
			name: "sender with the network ID of another VPC",
			setup: func(w *frameWorld) {
				e := liveEntry("n", agentID(vpcA, "other"), "base", 0x77, "fd00:77::/96")
				e.Vpc.NetworkId = testVNI + 1
				w.send("relay-a", atGen(e, 20))
			},
			tag: 0x77, dst: serverAddr, src: "fd00:77::1", pkt: "hi", drop: "mesh_source",
		},

		// Permit.
		{name: "Permit denies", setup: func(w *frameWorld) { w.r.SetPermit(deny) }, tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_permit"},
		{
			name: "Permit gets the VPC and the subject of the sender",
			setup: func(w *frameWorld) {
				w.r.SetPermit(func(srcVPC VPCKey, id string, dstVPC VPCKey, dst netip.Addr) bool {
					return srcVPC == vpcA && id == laptop && dstVPC == vpcA && dst == netip.MustParseAddr(serverAddr)
				})
			},
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", to: "server",
		},
		{
			name: "Permit denies the subject of the sender",
			setup: func(w *frameWorld) {
				w.r.SetPermit(func(_ VPCKey, id string, _ VPCKey, _ netip.Addr) bool { return id != laptop })
			},
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_permit",
		},

		// Only a session of this relay gets a frame.
		{name: "destination on another member", tag: laptopTag, dst: tabletAddr, src: laptopAddr, pkt: "hi", drop: "mesh_not_local"},
		{name: "destination on the member of the sender", tag: laptopTag, dst: phoneAddr, src: laptopAddr, pkt: "hi", drop: "mesh_not_local"},
		{name: "destination with no route", tag: laptopTag, dst: "fd00:f::1", src: laptopAddr, pkt: "hi", drop: "mesh_not_local"},
		{name: "destination in another VPC", tag: laptopTag, dst: guestAddr, src: laptopAddr, pkt: "hi", drop: "mesh_not_local"},
		{
			// The longest route of the destination is of relay-b, in a route of server.
			name: "destination in a route of another member in a route of this relay",
			setup: func(w *frameWorld) {
				w.send("relay-b", atGen(liveEntry("t2", agentID(vpcA, "tablet"), "base", tabletTag, "10.8.7.0/24"), 20))
			},
			tag: laptopTag, dst: "10.8.7.1", src: laptopAddr, pkt: "hi", drop: "mesh_not_local",
		},
		{
			name: "session of the destination takes no frame",
			setup: func(w *frameWorld) {
				w.sess["server"].sendDatagram = func([]byte) error { return errors.New("closed") }
			},
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_not_sent",
		},

		// The sender tag.
		{name: "unknown tag", tag: 0x99, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_unknown_tag"},
		{name: "no tag", tag: 0, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_unknown_tag"},
		{name: "tag with other high bytes", tag: laptopTag & 0xff, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_unknown_tag"},
		{
			name:  "tag of an attachment that ended",
			setup: func(w *frameWorld) { w.send("relay-a", goneAt("x", 11), goneAt("x2", 11)) },
			tag:   laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_unknown_tag",
		},
		{
			name:  "member that stopped",
			setup: func(w *frameWorld) { w.stop("relay-a") },
			tag:   laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_old_session",
		},
		{
			name:  "tag of an older session of the member",
			setup: func(w *frameWorld) { w.openAt("relay-a", dp.Revision) },
			tag:   laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_old_session",
		},
		{
			name:  "datagram on an older session of the member",
			setup: func(w *frameWorld) { w.openAt("relay-a", dp.Revision) },
			old:   true,
			tag:   laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_old_session",
		},
		{
			name: "new session of the member sent the entries again",
			setup: func(w *frameWorld) {
				w.openAt("relay-a", dp.Revision)
				w.entries("relay-a", 10)
			},
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", to: "server",
		},
		{
			name: "new session of the member sent one of two entries again",
			setup: func(w *frameWorld) {
				w.openAt("relay-a", dp.Revision)
				w.send("relay-a", atGen(liveEntry("x2", laptop, "base", laptopTag, "fd00:a2::/96"), 10))
			},
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_source",
		},
		{
			name: "new session of the member sent the other entry again",
			setup: func(w *frameWorld) {
				w.openAt("relay-a", dp.Revision)
				w.send("relay-a", atGen(liveEntry("x", laptop, "base", laptopTag, prefixA, prefixR), 10))
			},
			tag: laptopTag, dst: serverAddr, src: "fd00:a2::1", pkt: "hi", drop: "mesh_source",
		},
		{
			name: "full set of the new session of the member has the entry",
			setup: func(w *frameWorld) {
				w.openAt("relay-a", dp.Revision)
				w.entries("relay-a", 10)
				w.full("relay-a")
			},
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", to: "server",
		},
		{
			name: "datagram on an older session after the full set of the new session",
			setup: func(w *frameWorld) {
				w.openAt("relay-a", dp.Revision)
				w.entries("relay-a", 10)
				w.full("relay-a")
			},
			old: true,
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_old_session",
		},
		{
			name: "full set of the new session of the member does not have the entry",
			setup: func(w *frameWorld) {
				w.openAt("relay-a", dp.Revision)
				w.full("relay-a", atGen(liveEntry("p", agentID(vpcA, "phone"), "base", phoneTag, "fd00:d::/96"), 10))
			},
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_unknown_tag",
		},
		{
			name: "other entry that the full set of the new session has",
			setup: func(w *frameWorld) {
				w.openAt("relay-a", dp.Revision)
				w.full("relay-a", atGen(liveEntry("p", agentID(vpcA, "phone"), "base", phoneTag, "fd00:d::/96"), 10))
			},
			tag: phoneTag, dst: serverAddr, src: phoneAddr, pkt: "hi", to: "server",
		},
		// The relay keeps the entries of a session that ended, and they give no sender.
		{
			name:  "session of the member ended",
			setup: func(w *frameWorld) { w.cut("relay-a") },
			tag:   laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_old_session",
		},
		{
			name:  "member that is down",
			setup: func(w *frameWorld) { w.cut("relay-a"); time.Sleep(24 * time.Hour); synctest.Wait() },
			tag:   laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_old_session",
		},
		{
			name: "new session of the member ended after it sent the entries again",
			setup: func(w *frameWorld) {
				w.cut("relay-a")
				w.openAt("relay-a", dp.Revision)
				w.entries("relay-a", 10)
				w.full("relay-a")
				w.cut("relay-a")
			},
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_old_session",
		},
		{
			name: "new session of a member that was down, before it sends the entry again",
			setup: func(w *frameWorld) {
				w.cut("relay-a")
				time.Sleep(time.Hour)
				synctest.Wait()
				w.openAt("relay-a", dp.Revision)
			},
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_old_session",
		},
		{
			name: "new session of a member that was down sent the entries again",
			setup: func(w *frameWorld) {
				w.cut("relay-a")
				time.Sleep(time.Hour)
				synctest.Wait()
				w.openAt("relay-a", dp.Revision)
				w.entries("relay-a", 10)
			},
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", to: "server",
		},
		{
			// The member started again, and its tag is now of an agent of vpcB
			// with the address of laptop.
			name: "tag of an older session that another VPC has now",
			setup: func(w *frameWorld) {
				w.openAt("relay-a", dp.Revision)
				e := liveEntry("z", agentID(vpcB, "visitor"), "base", laptopTag, prefixA)
				e.Vpc = ref(vpcB)
				w.send("relay-a", atGen(e, 30))
			},
			tag: laptopTag, dst: serverAddr, src: laptopAddr, pkt: "hi", drop: "mesh_not_local",
		},
		{
			name: "new owner of the tag in its own VPC",
			setup: func(w *frameWorld) {
				w.openAt("relay-a", dp.Revision)
				e := liveEntry("z", agentID(vpcB, "visitor"), "base", laptopTag, prefixA)
				e.Vpc = ref(vpcB)
				w.send("relay-a", atGen(e, 30))
			},
			tag: laptopTag, dst: guestAddr, src: laptopAddr, pkt: "hi", to: "guest",
		},

		// The form of the datagram.
		{name: "no bytes", raw: []byte{}, drop: "mesh_malformed"},
		{name: "one byte less than the header", raw: memberFrame(laptopTag, serverAddr, laptopAddr, "")[:meshPeerLen-1], drop: "mesh_malformed"},
		{name: "unknown type", raw: append([]byte{0x02}, memberFrame(laptopTag, serverAddr, laptopAddr, "hi")[1:]...), drop: "mesh_malformed"},
		{name: "frame of an agent", raw: peerFrame(netip.MustParseAddr(serverAddr), netip.MustParseAddr(laptopAddr), "hello"), drop: "mesh_unknown_tag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newFrameWorld(t)
				if tc.setup != nil {
					tc.setup(w)
				}
				w.drain()
				b := tc.raw
				if b == nil {
					b = memberFrame(tc.tag, tc.dst, tc.src, tc.pkt)
				}
				on := w.mesh["relay-a"]
				if tc.old {
					on = w.first["relay-a"]
				}
				w.m.pres.datagram(w.r, on, slices.Clone(b))

				want, drops := map[string][][]byte{}, map[string]uint64{}
				if tc.to != "" {
					want[tc.to] = [][]byte{peerconn.EncodeFromRelay(nil, netip.MustParseAddr(tc.src), []byte(tc.pkt))}
				} else {
					drops[tc.drop] = 1
				}
				assert.Equal(t, want, w.got, "frames of the sessions of this relay")
				assert.Equal(t, drops, dropCounts(w.r), "drop counters")
				assert.Empty(t, w.sent(), "datagrams to the members")
				assert.Empty(t, w.noRoutes(), "NoRoute messages")
				w.check()
			})
		})
	}
}

// TestMeshPeerFrameSend sends the peer frames of server on relay-m. A frame
// for an address of relay-a goes on its mesh session, with the tag of server.
func TestMeshPeerFrameSend(t *testing.T) {
	const serverTag = 0x0a0b0c
	deny := func(VPCKey, string, VPCKey, netip.Addr) bool { return false }
	lose := func(w *frameWorld) { w.cut("relay-a") }
	hello := memberFrame(serverTag, laptopAddr, serverAddr, "hello")
	cases := []struct {
		name     string
		setup    func(w *frameWorld)
		dst, src string
		pkt      string
		spare    bool     // The frame has spare bytes at its end, as a datagram from QUIC has.
		shard    bool     // The frame comes on a shard of server.
		to       string   // Member or session of relay-m that gets the frame. Empty if the relay drops it.
		drop     string   // Reason label of the drop.
		noRoute  []string // Addresses of the NoRoute messages for server.
	}{
		{name: "to an address of a member", dst: laptopAddr, src: serverAddr, pkt: "hello", to: "relay-a"},
		{name: "frame with spare bytes", dst: laptopAddr, src: serverAddr, pkt: "hello", spare: true, to: "relay-a"},
		{name: "to an IPv4 route of a member", dst: laptopNet, src: serverNet, pkt: "hello", to: "relay-a"},
		{name: "empty packet", dst: laptopAddr, src: serverAddr, to: "relay-a"},
		{name: "packet of a peer session", dst: laptopAddr, src: serverAddr, pkt: strings.Repeat("q", 1200), to: "relay-a"},
		{name: "to an address of the other member", dst: tabletAddr, src: serverAddr, pkt: "hello", to: "relay-b"},
		{name: "to a session of this relay", dst: neighborAddr, src: serverAddr, pkt: "hello", to: "neighbor"},
		{
			// The longest route of the destination is of relay-b, in a route of server.
			name: "to a route of a member in a route of this relay",
			setup: func(w *frameWorld) {
				w.send("relay-b", atGen(liveEntry("t2", agentID(vpcA, "tablet"), "base", tabletTag, "10.8.7.0/24"), 20))
			},
			dst: "10.8.7.1", src: serverAddr, pkt: "hello", to: "relay-b",
		},
		{
			name:  "largest frame that the mesh session takes",
			setup: func(w *frameWorld) { w.conns["relay-a"].max = len(hello) },
			dst:   laptopAddr, src: serverAddr, pkt: "hello", to: "relay-a",
		},
		{
			name:  "one byte too large for the mesh session",
			setup: func(w *frameWorld) { w.conns["relay-a"].max = len(hello) - 1 },
			dst:   laptopAddr, src: serverAddr, pkt: "hello", drop: "mesh_too_large",
		},
		{
			name:  "member from before the frames",
			setup: func(w *frameWorld) { w.openAt("relay-a", meshFramesRevision-1) },
			dst:   laptopAddr, src: serverAddr, pkt: "hello", drop: "mesh_old_member",
		},
		{
			name:  "member at the first revision with the frames",
			setup: func(w *frameWorld) { w.openAt("relay-a", meshFramesRevision) },
			dst:   laptopAddr, src: serverAddr, pkt: "hello", to: "relay-a",
		},
		{name: "member with no session", setup: lose, dst: laptopAddr, src: serverAddr, pkt: "hello", drop: "mesh_no_session"},
		{
			// The route of a member that is down stays, so the sender gets no NoRoute.
			name:  "member that is down",
			setup: func(w *frameWorld) { lose(w); time.Sleep(24 * time.Hour); synctest.Wait() },
			dst:   laptopAddr, src: serverAddr, pkt: "hello", drop: "mesh_no_session",
		},
		{
			name: "new session of a member that was down, before it sends the entry again",
			setup: func(w *frameWorld) {
				lose(w)
				time.Sleep(time.Hour)
				synctest.Wait()
				w.openAt("relay-a", dp.Revision)
			},
			dst: laptopAddr, src: serverAddr, pkt: "hello", to: "relay-a",
		},
		{
			name: "full set of the new session of the member has the entry",
			setup: func(w *frameWorld) {
				lose(w)
				w.openAt("relay-a", dp.Revision)
				w.entries("relay-a", 10)
				w.full("relay-a")
			},
			dst: laptopAddr, src: serverAddr, pkt: "hello", to: "relay-a",
		},
		{
			name: "full set of the new session of the member does not have the entry",
			setup: func(w *frameWorld) {
				lose(w)
				w.openAt("relay-a", dp.Revision)
				w.full("relay-a")
			},
			dst: laptopAddr, src: serverAddr, pkt: "hello", noRoute: []string{laptopAddr},
		},
		{
			name:  "mesh session that takes no datagram",
			setup: func(w *frameWorld) { w.conns["relay-a"].fail = errors.New("closed") },
			dst:   laptopAddr, src: serverAddr, pkt: "hello", drop: "mesh_no_session",
		},
		{name: "Permit denies", setup: func(w *frameWorld) { w.r.SetPermit(deny) }, dst: laptopAddr, src: serverAddr, pkt: "hello", noRoute: []string{laptopAddr}},
		{name: "no route", dst: "fd00:f::1", src: serverAddr, pkt: "hello", noRoute: []string{"fd00:f::1"}},
		{name: "source of a session of a member", dst: laptopAddr, src: phoneAddr, pkt: "hello"},
		// A shard has no tag and no route, so the relay sends none of its peer frames.
		{name: "frame on a shard of the sender", shard: true, dst: laptopAddr, src: serverAddr, pkt: "hello"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newFrameWorld(t)
				if tc.setup != nil {
					tc.setup(w)
				}
				w.drain()
				frame := slices.Clip(peerFrame(netip.MustParseAddr(tc.dst), netip.MustParseAddr(tc.src), tc.pkt))
				if tc.spare {
					frame = append(make([]byte, 0, 2*len(frame)), frame...)
				}
				from := w.sess["server"]
				if tc.shard {
					from = newSession(from.id, func() netip.AddrPort { return netip.AddrPort{} })
					w.r.addSession(from, t0)
					_, _, err := w.r.joinShard(from, "s", 1)
					require.NoError(t, err)
				}
				sent := w.r.forwardDatagram(from, frame, t0)

				local, far, drops := map[string][][]byte{}, map[string][][]byte{}, map[string]uint64{}
				switch {
				case tc.drop != "":
					drops[tc.drop] = 1
				case w.first[tc.to] != nil:
					far[tc.to] = [][]byte{memberFrame(serverTag, tc.dst, tc.src, tc.pkt)}
				case tc.to != "":
					local[tc.to] = [][]byte{peerconn.EncodeFromRelay(nil, netip.MustParseAddr(tc.src), []byte(tc.pkt))}
				}
				assert.Equal(t, tc.to != "", sent, "the relay sent the frame")
				assert.Equal(t, far, w.sent(), "datagrams to the members")
				assert.Equal(t, local, w.got, "frames of the sessions of this relay")
				assert.Equal(t, drops, dropCounts(w.r), "drop counters")
				assert.ElementsMatch(t, tc.noRoute, w.noRoutes(), "NoRoute messages")
				w.check()
			})
		})
	}
}

// TestMeshPeerFrameChanges gives relay-m datagrams while relay-b opens new
// sessions and the Permit rule changes. Each frame of relay-a gets to server.
func TestMeshPeerFrameChanges(t *testing.T) {
	const frames = 300
	w := newFrameWorld(t)
	onA, onB := w.mesh["relay-a"], w.mesh["relay-b"]
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for gen := uint64(11); ; gen++ {
			select {
			case <-done:
				return
			default:
			}
			w.openAt("relay-b", dp.Revision)
			// Each fourth session is too late with its full set. The entry of tablet
			// has another attachment ID on each session, so the entry before goes.
			if gen%4 == 0 {
				w.m.pres.expire(w.mesh["relay-b"])
			}
			w.full("relay-b", atGen(liveEntry([]string{"t", "t2"}[gen%2], agentID(vpcA, "tablet"), "base", tabletTag, "fd00:e::/96"), gen))
			w.r.SetPermit(SameVPC)
		}
	})
	for range frames {
		w.m.pres.datagram(w.r, onA, memberFrame(laptopTag, serverAddr, laptopAddr, "hi"))
		// The first session of relay-b is an older session after a short time.
		w.m.pres.datagram(w.r, onB, memberFrame(tabletTag, neighborAddr, tabletAddr, "hi"))
		assert.True(t, w.r.forwardDatagram(w.sess["server"], peerFrame(netip.MustParseAddr(laptopAddr), netip.MustParseAddr(serverAddr), "hi"), t0))
	}
	close(done)
	wg.Wait()
	assert.Len(t, w.got["server"], frames, "frames of server")
	assert.Len(t, w.sent()["relay-a"], frames, "datagrams to relay-a")
	drops := dropCounts(w.r)
	// For a short time after a late full set, no entry of relay-b has the tag.
	late := drops["mesh_old_session"] + drops["mesh_unknown_tag"]
	assert.Equal(t, uint64(frames), late+uint64(len(w.got["neighbor"])), "frames of relay-b that came or dropped")
	delete(drops, "mesh_old_session")
	delete(drops, "mesh_unknown_tag")
	assert.Empty(t, drops, "other drop counters")
	w.check()
}

// TestMeshPeerFramesBetweenRelays sends peer frames in the two directions
// between a session of relay-a and a session of relay-b, on a real mesh session.
func TestMeshPeerFramesBetweenRelays(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	a, b := newRouteRelay(t, ca, "relay-a"), newRouteRelay(t, ca, "relay-b")
	sa := a.session(t, "laptop", "192.0.2.1:1000", thisRevision())
	sb := b.session(t, "server", "192.0.2.2:1000", thisRevision())
	got := map[*Session]chan []byte{sa: make(chan []byte, 8), sb: make(chan []byte, 8)}
	for s, ch := range got {
		s.sendDatagram = func(b []byte) error {
			ch <- slices.Clone(b)
			return nil
		}
	}
	require.NoError(t, a.r.attach(sa, attachment("x", "fd00:1::/96")))
	require.NoError(t, b.r.attach(sb, attachment("y", "fd00:2::/96")))
	a.n.m.SetMembers([]MeshMember{b.n.member()})
	b.n.m.SetMembers([]MeshMember{a.n.member()})
	b.n.start(t)
	a.n.start(t)
	a.has(t, sa, "y fd00:2::/96")
	b.has(t, sb, "x fd00:1::/96")

	addrA, addrB := netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("fd00:2::1")
	// A peer session uses QUIC packets of 1200 B.
	pkt := strings.Repeat("q", 1200)
	for _, tc := range []struct {
		name     string
		from     *routeRelay
		s        *Session
		dst, src netip.Addr
		to       *Session
	}{
		{"relay-a to relay-b", a, sa, addrB, addrA, sb},
		{"relay-b to relay-a", b, sb, addrA, addrB, sa},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, pkt := range []string{"ping", pkt} {
				require.True(t, tc.from.r.forwardDatagram(tc.s, peerFrame(tc.dst, tc.src, pkt), time.Now()))
				select {
				case b := <-got[tc.to]:
					assert.Equal(t, peerconn.EncodeFromRelay(nil, tc.src, []byte(pkt)), b)
				case <-time.After(10 * time.Second):
					t.Fatal("the session of the other relay got no frame")
				}
			}
			// The relay does not split a frame that QUIC does not take.
			assert.False(t, tc.from.r.forwardDatagram(tc.s, peerFrame(tc.dst, tc.src, strings.Repeat("q", maxUDP)), time.Now()))
			assert.Equal(t, map[string]uint64{"mesh_too_large": 1}, dropCounts(tc.from.r))
		})
	}
	for _, ch := range got {
		assert.Empty(t, ch, "frames that no test sent")
	}
}
