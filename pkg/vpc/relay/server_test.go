// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func attach(t *testing.T, a agent, req *dp.AttachRequest) *dp.AttachResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := a.c.Attach(ctx, req)
	require.NoError(t, err)
	return res
}

func TestOverQUIC(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	snd := h.mustDial(t, ca.agentCert(t, vpcA, "sender"))
	rcv := h.mustDial(t, ca.agentCert(t, vpcA, "receiver"))
	sndSync, welcome, cfg := open(t, snd)
	assert.Equal(t, snd.src.String(), welcome.ReflexiveAddress)
	assert.Empty(t, cmp.Diff(&dp.Config{Vpc: ref(vpcA), Mtu: 1280, DnsServers: []string{"fd00::53"}}, cfg, protocmp.Transform()))
	open(t, rcv)

	res := attach(t, rcv, &dp.AttachRequest{Vpc: ref(vpcA), Name: "receiver.local", Labels: map[string]string{"app": "db"}})
	claims, err := VerifyGrant(res.Grant, h.relayRoots, time.Now())
	require.NoError(t, err)
	assert.Equal(t, res.AttachmentId, claims.AttachmentId)
	assert.Equal(t, agentID(vpcA, "receiver"), claims.Subject)
	assert.Equal(t, "relay-1", claims.RelayId)
	assert.Empty(t, cmp.Diff(ref(vpcA), claims.Vpc, protocmp.Transform()))
	require.Len(t, claims.Addresses, 1)
	assert.WithinDuration(t, h.session(t, rcv).notAfter, claims.NotAfter.AsTime(), time.Second, "the grant ends with the cert")
	addr := netip.MustParsePrefix(claims.Addresses[0]).Addr().Next()

	// The sender learns the route of the receiver in Sync. The revision is 2
	// if the empty first RouteDelta came before the attach.
	m := recv(t, sndSync).GetRouteDelta()
	require.NotNil(t, m)
	rev := m.Rev
	assert.Contains(t, []uint64{1, 2}, rev)
	assert.Empty(t, cmp.Diff(&dp.RouteDelta{Rev: rev, Add: []*dp.Route{{Vpc: ref(vpcA), Prefix: claims.Addresses[0], Origin: res.AttachmentId}}}, m, protocmp.Transform()))
	require.NoError(t, sndSync.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Ack{Ack: &dp.Ack{Rev: rev}}}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rp, err := snd.c.ResolvePeer(ctx, &dp.ResolvePeerRequest{Vpc: ref(vpcA), Address: addr.String()})
	require.NoError(t, err)
	assert.Equal(t, dp.Reach_REACH_LOCAL, rp.Reach)
	assert.True(t, rp.P2P)

	_, err = snd.c.RegisterSPI(ctx, register(vpcA, addr.String(), time.Minute, 7))
	require.NoError(t, err)
	// The relay takes the sender from the authenticated connection.
	dst, v := h.r.Forward(snd.src, 7, 1400, time.Now())
	require.Equal(t, Pass, v)
	assert.Equal(t, rcv.src, dst)
	_, v = h.r.Forward(rcv.src, 7, 1400, time.Now())
	assert.Equal(t, DropUnknownSPI, v)
	require.Eventually(t, func() bool {
		return h.r.SyncStats(h.session(t, snd)) == SyncStats{Rev: rev, Acked: rev}
	}, 5*time.Second, 5*time.Millisecond)

	// When the receiver goes, the sender loses its route and rows, and the
	// relay frees the addresses and the data peer.
	require.Equal(t, 1, h.addrs.count())
	require.NoError(t, rcv.qc.CloseWithError(0, ""))
	m = recv(t, sndSync).GetRouteDelta()
	require.NotNil(t, m)
	assert.Equal(t, rev+1, m.Rev)
	assert.Empty(t, m.Add)
	require.Len(t, m.Remove, 1)
	assert.Equal(t, claims.Addresses[0], m.Remove[0].Prefix)
	_, v = h.r.Forward(snd.src, 7, 1400, time.Now())
	assert.Equal(t, DropUnknownSPI, v)
	require.Eventually(t, func() bool { return h.addrs.count() == 0 }, 5*time.Second, 5*time.Millisecond)
}

// relayCalls are the unary calls that need the caller identity.
var relayCalls = []struct {
	method string
	json   string // Request from the JSON debug handler.
	call   func(ctx context.Context, c dp.RelayClient, vpc *dp.VPCRef) error
}{
	{dp.Relay_Attach_FullMethodName, `{"vpc":{"projectId":"project-a","vpcUid":"vpc-1"},"name":"laptop"}`,
		func(ctx context.Context, c dp.RelayClient, vpc *dp.VPCRef) error {
			_, err := c.Attach(ctx, &dp.AttachRequest{Vpc: vpc, Name: "laptop"})
			return err
		}},
	{dp.Relay_ResolvePeer_FullMethodName, `{"vpc":{"projectId":"project-a","vpcUid":"vpc-1"},"address":"fd00::2"}`,
		func(ctx context.Context, c dp.RelayClient, vpc *dp.VPCRef) error {
			_, err := c.ResolvePeer(ctx, &dp.ResolvePeerRequest{Vpc: vpc, Address: "fd00::2"})
			return err
		}},
	{dp.Relay_RegisterSPI_FullMethodName, `{"vpc":{"projectId":"project-a","vpcUid":"vpc-1"},"destination":"fd00::2","spis":[7],"expiresIn":"60s"}`,
		func(ctx context.Context, c dp.RelayClient, vpc *dp.VPCRef) error {
			_, err := c.RegisterSPI(ctx, &dp.RegisterSPIRequest{Vpc: vpc, Destination: "fd00::2", Spis: []uint32{7}, ExpiresIn: durationpb.New(time.Minute)})
			return err
		}},
	{dp.Relay_UnregisterSPI_FullMethodName, `{"vpc":{"projectId":"project-a","vpcUid":"vpc-1"},"spis":[7]}`,
		func(ctx context.Context, c dp.RelayClient, vpc *dp.VPCRef) error {
			_, err := c.UnregisterSPI(ctx, &dp.UnregisterSPIRequest{Vpc: vpc, Spis: []uint32{7}})
			return err
		}},
}

func shortName(method string) string { return method[strings.LastIndex(method, "/")+1:] }

// TestUnauthenticated checks that calls with no session fail with
// Unauthenticated, from the JSON debug handler and from a served connection.
func TestUnauthenticated(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	// A connection that passes the handshake, served with no session.
	stranger := h.mustDial(t, ca.agentCert(t, vpcA, "stranger"))
	s := h.session(t, stranger)
	h.r.removeSession(s)
	srv := httptest.NewServer(rpc.JSONHandler(h.mux))
	defer srv.Close()

	for _, tc := range relayCalls {
		t.Run(shortName(tc.method), func(t *testing.T) {
			resp, err := http.Post(srv.URL+tc.method, "application/json", strings.NewReader(tc.json))
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "JSON debug handler")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			assert.Equal(t, rpc.Unauthenticated, rpc.CodeOf(tc.call(ctx, stranger.c, ref(vpcA))), "connection with no session")
		})
	}
	t.Run("Session", func(t *testing.T) {
		st, err := stranger.c.Session(context.Background())
		require.NoError(t, err)
		// Send gets io.EOF when the relay refuses the call first. Recv gives the status.
		if err := st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{Mode: dp.Mode_MODE_PSP}}}); err != io.EOF {
			require.NoError(t, err)
		}
		_, err = st.Recv()
		assert.Equal(t, rpc.Unauthenticated, rpc.CodeOf(err))
	})
}

// TestCertVPC checks that each call uses only the VPC in the agent cert,
// also when Permit allows all.
func TestCertVPC(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	h.r.SetPermit(func(VPCKey, string, VPCKey, netip.Addr) bool { return true })
	a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
	open(t, a)
	peer := h.mustDial(t, ca.agentCert(t, vpcA, "peer"))
	require.NoError(t, h.r.AddRoute(h.session(t, peer), netip.MustParsePrefix("fd00::2/128"), "att"))

	refs := []struct {
		name string
		vpc  *dp.VPCRef
		code rpc.Code
	}{
		{"cert VPC", ref(vpcA), rpc.OK},
		{"another project", ref(vpcB), rpc.PermissionDenied},
		{"another VPC", ref(VPCKey{Project: vpcA.Project, UID: "vpc-2"}), rpc.PermissionDenied},
	}
	for _, call := range relayCalls {
		for _, tc := range refs {
			t.Run(shortName(call.method)+"/"+tc.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				err := call.call(ctx, a.c, tc.vpc)
				assert.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
			})
		}
	}
}

func TestSessionErrors(t *testing.T) {
	cases := []struct {
		name  string
		first *dp.SessionRequest
		code  rpc.Code
	}{
		{"not Hello", &dp.SessionRequest{Msg: &dp.SessionRequest_Ack{Ack: &dp.Ack{Rev: 1}}}, rpc.InvalidArgument},
		{"no mode", &dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{}}}, rpc.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCA(t)
			h := newHarness(t, ca)
			a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
			st, err := a.c.Session(context.Background())
			require.NoError(t, err)
			require.NoError(t, st.Send(tc.first))
			_, err = st.Recv()
			assert.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
		})
	}

	t.Run("second Session call", func(t *testing.T) {
		ca := newCA(t)
		h := newHarness(t, ca)
		a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
		open(t, a)
		st, err := a.c.Session(context.Background())
		require.NoError(t, err)
		require.NoError(t, st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{Mode: dp.Mode_MODE_PSP}}}))
		_, err = st.Recv()
		assert.Equal(t, rpc.FailedPrecondition, rpc.CodeOf(err))
	})
	t.Run("VPC data too old", func(t *testing.T) {
		ca := newCA(t)
		h := newHarness(t, ca)
		h.nets.failVPC(vpcA)
		a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
		st, err := a.c.Session(context.Background())
		require.NoError(t, err)
		require.NoError(t, st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{Mode: dp.Mode_MODE_PSP}}}))
		_, err = st.Recv()
		assert.Equal(t, rpc.Unavailable, rpc.CodeOf(err))
	})
	t.Run("end of the Session call closes the session", func(t *testing.T) {
		ca := newCA(t)
		h := newHarness(t, ca)
		a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
		st, _, _ := open(t, a)
		require.NoError(t, st.CloseSend())
		assert.Equal(t, quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED), closeCode(t, a.qc))
	})
	t.Run("close gives the error of the Session call", func(t *testing.T) {
		ca := newCA(t)
		h := newHarness(t, ca)
		a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
		st, _, _ := open(t, a)
		require.NoError(t, st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{Mode: dp.Mode_MODE_PSP}}}))
		assert.Equal(t, quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED), closeCode(t, a.qc))
		var ae *quic.ApplicationError
		require.ErrorAs(t, context.Cause(a.qc.Context()), &ae)
		assert.Contains(t, ae.ErrorMessage, "unexpected message")
	})
}

// TestSync checks the routes that a session gets: the routes of its VPC
// when the Session call opens, then each change with the next revision.
func TestSync(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	other := h.mustDial(t, ca.agentCert(t, vpcA, "other"))
	res := attach(t, other, &dp.AttachRequest{Vpc: ref(vpcA), Name: "other", Routes: []string{"10.1.0.0/16"}})
	// A session in another project with the same VPC UID and route.
	b := h.mustDial(t, ca.agentCert(t, vpcB, "b"))
	attach(t, b, &dp.AttachRequest{Vpc: ref(vpcB), Name: "b", Routes: []string{"10.1.0.0/16"}})

	a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
	// Its own attachment does not come back to it in Sync.
	attach(t, a, &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop", Routes: []string{"10.2.0.0/16"}})
	st, _, _ := open(t, a)
	first := recv(t, st).GetRouteDelta()
	require.NotNil(t, first)
	assert.Empty(t, cmp.Diff(&dp.RouteDelta{Rev: 1, Add: []*dp.Route{
		{Vpc: ref(vpcA), Prefix: "10.1.0.0/16", Origin: res.AttachmentId},
		{Vpc: ref(vpcA), Prefix: "fd00:1::/96", Origin: res.AttachmentId},
	}}, first, protocmp.Transform()))

	res2 := attach(t, other, &dp.AttachRequest{Vpc: ref(vpcA), Name: "other-2"})
	second := recv(t, st).GetRouteDelta()
	require.NotNil(t, second)
	assert.Empty(t, cmp.Diff(&dp.RouteDelta{Rev: 2, Add: []*dp.Route{
		{Vpc: ref(vpcA), Prefix: "fd00:4::/96", Origin: res2.AttachmentId},
	}}, second, protocmp.Transform()))

	require.NoError(t, other.qc.CloseWithError(0, ""))
	third := recv(t, st).GetRouteDelta()
	require.NotNil(t, third)
	assert.Equal(t, uint64(3), third.Rev)
	assert.Empty(t, third.Add)
	assert.Len(t, third.Remove, 3)
}

func TestQueueRoute(t *testing.T) {
	r := NewRouter(nil, Config{})
	s := addSession(t, r, vpcA, "s", "192.0.2.1:1")
	o := addSession(t, r, vpcA, "o", "192.0.2.2:1")
	rt := route{netip.MustParsePrefix("10.0.0.0/8"), "a"}
	added := &dp.RouteDelta{Add: []*dp.Route{{Prefix: "10.0.0.0/8", Origin: "a"}}}
	cases := []struct {
		name string
		ops  []bool // Changes of rt: true adds, false removes.
		own  bool   // The owner of rt has the subject of s.
		want *dp.RouteDelta
		// Agent names of s and of the owner, from Hello. An agent from before
		// revision 2 has no name.
		self, owner string
	}{
		{"first take with no routes", nil, false, &dp.RouteDelta{Rev: 1}, "", ""},
		{"add", []bool{true}, false, added, "", ""},
		{"add then remove", []bool{true, false}, false, nil, "", ""},
		{"remove then add", []bool{false, true}, false, nil, "", ""},
		{"remove", []bool{false}, false, &dp.RouteDelta{Remove: []*dp.Route{{Prefix: "10.0.0.0/8", Origin: "a"}}}, "", ""},
		{"route of its own subject", []bool{true}, true, nil, "", ""},
		{"route of its own agent", []bool{true}, true, nil, "x", "x"},
		{"route of another agent of its subject", []bool{true}, true, added, "x", "y"},
		{"route of its subject, owner with no name", []bool{true}, true, nil, "x", ""},
		{"route of its subject, session with no name", []bool{true}, true, nil, "", "y"},
		{"other subject with the same name", []bool{true}, false, added, "x", "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			owner := o.Session
			if tc.own {
				owner = addSession(t, r, vpcA, "s", "192.0.2.3:1").Session
			}
			r.mu.Lock()
			s.name, owner.name = tc.self, tc.owner
			for _, add := range tc.ops {
				s.queueRoute(rt, owner, add)
			}
			r.mu.Unlock()
			msgs := r.takeSync(s.Session)
			if tc.want == nil {
				assert.Empty(t, msgs)
				return
			}
			require.Len(t, msgs, 1)
			got := msgs[0].GetRouteDelta()
			want := proto.Clone(tc.want).(*dp.RouteDelta)
			if want.Rev == 0 {
				want.Rev = got.Rev
			}
			assert.Empty(t, cmp.Diff(want, got, protocmp.Transform()))
		})
	}
}

func TestAttach(t *testing.T) {
	cases := []struct {
		name  string
		req   *dp.AttachRequest
		setup func(h *harness)
		code  rpc.Code
	}{
		{"good", &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop.example.com", Labels: map[string]string{"apoxy.dev/app": "db"}, Routes: []string{"10.9.0.0/16"}}, nil, rpc.OK},
		{"bad name", &dp.AttachRequest{Vpc: ref(vpcA), Name: "Laptop_1"}, nil, rpc.InvalidArgument},
		{"bad label", &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop", Labels: map[string]string{"a b": "c"}}, nil, rpc.InvalidArgument},
		{"bad route", &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop", Routes: []string{"10.9.0.0"}}, nil, rpc.InvalidArgument},
		{"route of another session", &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop", Routes: []string{"10.9.0.0/16", "10.8.0.0/16"}}, nil, rpc.AlreadyExists},
		{"another VPC", &dp.AttachRequest{Vpc: ref(vpcB), Name: "laptop"}, nil, rpc.PermissionDenied},
		{"VPC data too old", &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"}, func(h *harness) { h.nets.failVPC(vpcA) }, rpc.Unavailable},
		{"no addresses", &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"}, func(h *harness) { h.addrs.fail(errors.New("no slot")) }, rpc.Unavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCA(t)
			h := newHarness(t, ca)
			other := h.mustDial(t, ca.agentCert(t, vpcA, "other"))
			if tc.name == "route of another session" {
				require.NoError(t, h.r.AddRoute(h.session(t, other), netip.MustParsePrefix("10.8.0.0/16"), "x"))
			}
			if tc.setup != nil {
				tc.setup(h)
			}
			a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			res, err := a.c.Attach(ctx, tc.req)
			require.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
			s := h.session(t, a)
			h.r.mu.RLock()
			routes := append([]netip.Prefix{}, s.routes...)
			h.r.mu.RUnlock()
			if tc.code != rpc.OK {
				// A failed attach keeps no route and no address.
				assert.Empty(t, routes)
				assert.Zero(t, h.addrs.count())
				assert.Empty(t, h.addrs.attachedCalls(), "the host got a failed attach as complete")
				return
			}
			claims, err := VerifyGrant(res.Grant, h.relayRoots, time.Now())
			require.NoError(t, err)
			assert.ElementsMatch(t, []netip.Prefix{netip.MustParsePrefix(claims.Addresses[0]), netip.MustParsePrefix("10.9.0.0/16")}, routes)
			assert.Equal(t, 1, h.addrs.count())
		})
	}
}

// TestAttachedCalls checks what the host gets for the attachments of one
// session: one Attached call for each, and a Release when each one ends.
func TestAttachedCalls(t *testing.T) {
	cases := []struct {
		name     string
		attaches int
		// end is how attachments end: "detach" is a Detach of the first one,
		// "close" is the end of the session, "" is no end.
		end      string
		wantHeld int // Attachments that the host holds at the end.
	}{
		{"one attachment", 1, "", 1},
		{"two attachments of one session", 2, "", 2},
		{"detach of one of two", 2, "detach", 1},
		{"session ends", 2, "close", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCA(t)
			h := newHarness(t, ca)
			a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			seen := map[string]bool{}
			for i := range tc.attaches {
				res := attach(t, a, &dp.AttachRequest{Vpc: ref(vpcA), Name: fmt.Sprintf("agent-%d", i)})
				claims, err := VerifyGrant(res.Grant, h.relayRoots, time.Now())
				require.NoError(t, err)
				// The call comes before the reply, with the addresses of the grant.
				calls := h.addrs.attachedCalls()
				require.Len(t, calls, i+1)
				assert.Equal(t, res.AttachmentId, calls[i].id)
				assert.Equal(t, claims.Addresses, prefixStrings(calls[i].addrs))
				assert.False(t, seen[claims.Addresses[0]], "two attachments got the address %s", claims.Addresses[0])
				seen[claims.Addresses[0]] = true
			}
			first := h.addrs.attachedCalls()[0].id

			switch tc.end {
			case "detach":
				_, err := a.c.Detach(ctx, &dp.DetachRequest{AttachmentId: first})
				require.NoError(t, err)
			case "close":
				require.NoError(t, a.qc.CloseWithError(0, ""))
			}
			require.Eventually(t, func() bool { return h.addrs.count() == tc.wantHeld }, 5*time.Second, 5*time.Millisecond,
				"the host holds %d attachments, want %d", h.addrs.count(), tc.wantHeld)
			assert.Len(t, h.addrs.attachedCalls(), tc.attaches)
		})
	}
}

func TestDetach(t *testing.T) {
	cases := []struct {
		name      string
		id        func(x, other string) string // The ID to detach, from x of a and other of another agent.
		twice     bool
		noSession bool
		code      rpc.Code
	}{
		{name: "attachment of the session", id: func(x, _ string) string { return x }, code: rpc.OK},
		{name: "twice", id: func(x, _ string) string { return x }, twice: true, code: rpc.NotFound},
		{name: "unknown", id: func(string, string) string { return "unknown" }, code: rpc.NotFound},
		{name: "attachment of another session", id: func(_, other string) string { return other }, code: rpc.NotFound},
		{name: "connection with no session", id: func(x, _ string) string { return x }, noSession: true, code: rpc.Unauthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCA(t)
			h := newHarness(t, ca)
			watcher := h.mustDial(t, ca.agentCert(t, vpcA, "watcher"))
			st, _, _ := open(t, watcher)
			other := h.mustDial(t, ca.agentCert(t, vpcA, "other"))
			otherRes := attach(t, other, &dp.AttachRequest{Vpc: ref(vpcA), Name: "other"})
			a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
			base := attach(t, a, &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"})
			x := attach(t, a, &dp.AttachRequest{Vpc: ref(vpcA), Name: "sandbox-1", Routes: []string{"10.9.0.0/16"}})
			// The watcher has the address of each attachment and the route of x.
			for added := 0; added < 4; {
				added += len(recv(t, st).GetRouteDelta().GetAdd())
			}
			s := h.session(t, a)
			if tc.noSession {
				h.r.removeSession(s)
			}
			routes := func() []netip.Prefix {
				h.r.mu.RLock()
				defer h.r.mu.RUnlock()
				return slices.Clone(s.routes)
			}
			before, count := routes(), h.addrs.count()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			id := tc.id(x.AttachmentId, otherRes.AttachmentId)
			_, err := a.c.Detach(ctx, &dp.DetachRequest{AttachmentId: id})
			if tc.twice {
				require.NoError(t, err)
				before, count = routes(), h.addrs.count()
				_, err = a.c.Detach(ctx, &dp.DetachRequest{AttachmentId: id})
			}
			require.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
			if tc.code != rpc.OK {
				assert.Equal(t, before, routes(), "no route changes")
				assert.Equal(t, count, h.addrs.count(), "no address changes")
				return
			}
			claims, err := VerifyGrant(x.Grant, h.relayRoots, time.Now())
			require.NoError(t, err)
			baseClaims, err := VerifyGrant(base.Grant, h.relayRoots, time.Now())
			require.NoError(t, err)
			assert.Equal(t, []netip.Prefix{netip.MustParsePrefix(baseClaims.Addresses[0])}, routes(), "the other attachment keeps its routes")
			assert.Equal(t, count-1, h.addrs.count())
			var removed []*dp.Route
			for len(removed) < 2 {
				removed = append(removed, recv(t, st).GetRouteDelta().GetRemove()...)
			}
			slices.SortFunc(removed, func(a, b *dp.Route) int { return strings.Compare(a.Prefix, b.Prefix) })
			assert.Empty(t, cmp.Diff([]*dp.Route{
				{Vpc: ref(vpcA), Prefix: "10.9.0.0/16", Origin: x.AttachmentId},
				{Vpc: ref(vpcA), Prefix: claims.Addresses[0], Origin: x.AttachmentId},
			}, removed, protocmp.Transform()))
		})
	}
}

// takeWorld has sessions old, new and third of one agent, and watcher and
// other of two other agents. The agent has the attachments x*, and other has y.
type takeWorld struct {
	t    *testing.T
	r    *Router
	sess map[string]*Session
	byID map[string]*Session // Session of each attachment.
	err  error               // Error of the last attach.
}

func (w *takeWorld) attach(name, id string, routes ...string) {
	s := w.sess[name]
	a := &Attachment{ID: id, VPC: vpcA, Subject: s.id.ID}
	for _, p := range routes {
		a.Routes = append(a.Routes, netip.MustParsePrefix(p))
	}
	if w.err = w.r.attach(s, a); w.err == nil {
		w.byID[id] = s
	}
}

func (w *takeWorld) detach(name, id string) {
	_, err := w.r.detach(w.sess[name], id)
	require.NoError(w.t, err)
}

func (w *takeWorld) close(name string) { w.r.removeSession(w.sess[name]) }

// rename gives session name the agent name of a Hello.
func (w *takeWorld) rename(name, agent string) {
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	w.sess[name].name = agent
}

// changes returns the route changes that wait for session name, as
// "-origin prefix" and "+origin prefix". A session of the agent gets no route
// of the agent.
func (w *takeWorld) changes(name string) []string {
	var out []string
	for _, m := range w.r.takeSync(w.sess[name]) {
		for _, rt := range m.GetRouteDelta().GetRemove() {
			out = append(out, "-"+rt.Origin+" "+rt.Prefix)
		}
		for _, rt := range m.GetRouteDelta().GetAdd() {
			out = append(out, "+"+rt.Origin+" "+rt.Prefix)
		}
	}
	if w.sess[name].id.ID == agentID(vpcA, "laptop") {
		for _, c := range out {
			assert.NotEqual(w.t, "x", c[1:2], "session %s gets the route %s of its own agent", name, c)
		}
	}
	return out
}

func (w *takeWorld) drain() {
	for name := range w.sess {
		w.changes(name)
	}
}

// TestTakeOver checks that the owner of an advertised route is the newest live
// attachment of the agent that lists it. Another agent cannot take it.
func TestTakeOver(t *testing.T) {
	const p = "10.9.0.0/16"
	cases := []struct {
		name  string
		steps func(w *takeWorld)
		code  rpc.Code // Of the last attach.
		owner string   // Attachment that owns p at the end. Empty for no route.
		delta []string // Changes of the watcher after the last drain.
	}{
		{
			name:  "same agent takes over",
			steps: func(w *takeWorld) { w.attach("new", "x2", p) },
			owner: "x2", delta: []string{"-x1 " + p, "+x2 " + p},
		},
		{
			name:  "other agent cannot take over",
			steps: func(w *takeWorld) { w.attach("other", "y", p) },
			code:  rpc.AlreadyExists, owner: "x1",
		},
		{
			name:  "same agent name takes over",
			steps: func(w *takeWorld) { w.rename("old", "a"); w.rename("new", "a"); w.attach("new", "x2", p) },
			owner: "x2", delta: []string{"-x1 " + p, "+x2 " + p},
		},
		{
			name:  "other agent name of the subject cannot take over",
			steps: func(w *takeWorld) { w.rename("old", "a"); w.rename("new", "b"); w.attach("new", "x2", p) },
			code:  rpc.AlreadyExists, owner: "x1",
		},
		{
			name:  "session with no agent name takes over",
			steps: func(w *takeWorld) { w.rename("old", "a"); w.attach("new", "x2", p) },
			owner: "x2", delta: []string{"-x1 " + p, "+x2 " + p},
		},
		{
			name:  "session with an agent name takes over from a session with no name",
			steps: func(w *takeWorld) { w.rename("new", "b"); w.attach("new", "x2", p) },
			owner: "x2", delta: []string{"-x1 " + p, "+x2 " + p},
		},
		{
			name:  "close of the old session keeps the route",
			steps: func(w *takeWorld) { w.attach("new", "x2", p); w.drain(); w.close("old") },
			owner: "x2",
		},
		{
			name:  "detach of the old attachment keeps the route",
			steps: func(w *takeWorld) { w.attach("new", "x2", p); w.drain(); w.detach("old", "x1") },
			owner: "x2",
		},
		{
			name:  "close of the new session gives the route back",
			steps: func(w *takeWorld) { w.attach("new", "x2", p); w.drain(); w.close("new") },
			owner: "x1", delta: []string{"-x2 " + p, "+x1 " + p},
		},
		{
			name:  "detach of the new attachment gives the route back",
			steps: func(w *takeWorld) { w.attach("new", "x2", p); w.drain(); w.detach("new", "x2") },
			owner: "x1", delta: []string{"-x2 " + p, "+x1 " + p},
		},
		{
			name: "the newest live attachment gets the route",
			steps: func(w *takeWorld) {
				w.attach("new", "x2", p)
				w.attach("third", "x3", p)
				w.drain()
				w.close("third")
			},
			owner: "x2", delta: []string{"-x3 " + p, "+x2 " + p},
		},
		{
			name:  "newer attachment on the same session",
			steps: func(w *takeWorld) { w.attach("old", "x1b", p) },
			owner: "x1b", delta: []string{"-x1 " + p, "+x1b " + p},
		},
		{
			name:  "no live attachment lists the route",
			steps: func(w *takeWorld) { w.detach("old", "x1") },
			delta: []string{"-x1 " + p},
		},
		{
			name: "failed attach changes nothing",
			steps: func(w *takeWorld) {
				w.attach("other", "y", "10.8.0.0/16")
				w.drain()
				w.attach("new", "x2", p, "10.8.0.0/16")
			},
			code: rpc.AlreadyExists, owner: "x1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			w := &takeWorld{t: t, r: r, sess: map[string]*Session{}, byID: map[string]*Session{}}
			add := func(name, id, addr string) { w.sess[name] = addSession(t, r, vpcA, id, addr).Session }
			add("watcher", agentID(vpcA, "watcher"), "192.0.2.1:1")
			add("other", agentID(vpcA, "other"), "192.0.2.2:1")
			add("old", agentID(vpcA, "laptop"), "192.0.2.3:1")
			w.attach("old", "x1", p)
			require.NoError(t, w.err)
			// The new sessions get the routes of the VPC when they join.
			add("new", agentID(vpcA, "laptop"), "192.0.2.3:2")
			add("third", agentID(vpcA, "laptop"), "192.0.2.3:3")
			require.NoError(t, r.registerSPI(w.sess["watcher"], register(vpcA, "10.9.0.1", time.Minute, 7), t0))
			w.drain()

			tc.steps(w)
			require.Equal(t, tc.code, rpc.CodeOf(w.err), "error: %v", w.err)
			assert.Equal(t, tc.delta, w.changes("watcher"))
			w.drain()
			r.mu.RLock()
			defer r.mu.RUnlock()
			o, ok := r.domains[vpcA].routes[netip.MustParsePrefix(p)]
			row := w.sess["watcher"].rows[7]
			if tc.owner == "" {
				assert.False(t, ok, "p has no route")
				assert.Nil(t, row, "the row to p is removed")
			} else {
				assert.Equal(t, tc.owner, o.origin)
				assert.Same(t, w.byID[tc.owner], o.s)
				require.NotNil(t, row)
				assert.Same(t, o.s, row.receiver, "the row to p follows the route")
			}
			// Each session of the agent can send from p. Other agents cannot.
			x := netip.MustParseAddr("10.9.0.1")
			for name, s := range w.sess {
				assert.Equal(t, ok && s.id.ID == agentID(vpcA, "laptop"), s.sources(x), name)
			}
		})
	}
}

func TestVerifyGrant(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	claims := &dp.GrantClaims{
		Vpc: ref(vpcA), AttachmentId: "att-1", Subject: agentID(vpcA, "laptop"),
		Addresses: []string{"fd00:1::/96"}, RelayId: "relay-1", NotAfter: timestamppb.New(now.Add(time.Hour)),
	}
	cases := []struct {
		name   string
		key    crypto.Signer
		claims func(c *dp.GrantClaims)     // Changes the claims before signing.
		grant  func(g *dp.AttachmentGrant) // Changes the grant after signing.
		roots  func(own *x509.CertPool) *x509.CertPool
		chain  bool // Wildcard cert from an intermediate CA.
		at     time.Time
		ok     bool
		is     error // The error is this one. Nil means any error.
	}{
		{name: "ECDSA", key: newKey(t), ok: true},
		{name: "Ed25519", key: edKey, ok: true},
		{name: "RSA", key: rsaKey, ok: true},
		{name: "changed claims", key: newKey(t), grant: func(g *dp.AttachmentGrant) { g.Claims[len(g.Claims)-1] ^= 1 }},
		{name: "changed signature", key: newKey(t), grant: func(g *dp.AttachmentGrant) { g.Signature[len(g.Signature)-1] ^= 1 }},
		{name: "other relay cert", key: newKey(t), grant: func(g *dp.AttachmentGrant) {
			other, _ := relayCert(t, "relay-1", newKey(t))
			g.RelayChain = other.Certificate
		}},
		{name: "no relay cert", key: newKey(t), grant: func(g *dp.AttachmentGrant) { g.RelayChain = nil }},
		{name: "intermediate and wildcard", key: newKey(t), chain: true, ok: true},
		{name: "no intermediate", key: newKey(t), chain: true, grant: func(g *dp.AttachmentGrant) { g.RelayChain = g.RelayChain[:1] }},
		{name: "bad intermediate", key: newKey(t), chain: true, grant: func(g *dp.AttachmentGrant) { g.RelayChain[1] = []byte("x") }},
		{name: "wildcard does not cover the relay ID", key: newKey(t), chain: true, claims: func(c *dp.GrantClaims) { c.RelayId = "relay-1.other.example.net" }},
		{name: "relay ID not in the cert", key: newKey(t), claims: func(c *dp.GrantClaims) { c.RelayId = "relay-2" }},
		{name: "other roots", key: newKey(t), roots: func(*x509.CertPool) *x509.CertPool { return newCA(t).pool() }},
		{name: "ended", key: newKey(t), at: now.Add(time.Hour)},
		{name: "minimum revision of this build", key: newKey(t), claims: func(c *dp.GrantClaims) { c.MinRevision = dp.Revision }, ok: true},
		{name: "minimum revision above this build", key: newKey(t), claims: func(c *dp.GrantClaims) { c.MinRevision = dp.Revision + 1 }, is: ErrGrantRevision},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, roots := relayCert(t, "relay-1", tc.key)
			c := proto.Clone(claims).(*dp.GrantClaims)
			if tc.chain {
				cert, roots = relayChain(t, tc.key)
				c.RelayId = "relay-1.relay.example.net"
			}
			if tc.claims != nil {
				tc.claims(c)
			}
			signed, err := SignGrant(cert, c)
			require.NoError(t, err)
			if tc.grant != nil {
				tc.grant(signed)
			}
			if tc.roots != nil {
				roots = tc.roots(roots)
			}
			at := now
			if !tc.at.IsZero() {
				at = tc.at
			}
			got, err := VerifyGrant(signed, roots, at)
			if !tc.ok {
				assert.Error(t, err)
				if tc.is != nil {
					assert.ErrorIs(t, err, tc.is)
				}
				return
			}
			require.NoError(t, err)
			assert.Empty(t, cmp.Diff(c, got, protocmp.Transform()))
		})
	}
}

func TestNoRoute(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
	st, _, _ := open(t, a)
	s := h.session(t, a)
	peer := h.mustDial(t, ca.agentCert(t, vpcA, "peer"))
	require.NoError(t, h.r.AddRoute(h.session(t, peer), netip.MustParsePrefix("fd00::2/128"), "att"))
	recv(t, st) // The route of the peer.

	now := time.Now()
	assert.Same(t, h.session(t, peer), h.r.Route(s, netip.MustParseAddr("fd00::2"), now))
	missing := netip.MustParseAddr("fd00::9")
	assert.Nil(t, h.r.Route(s, missing, now))
	assert.Nil(t, h.r.Route(s, missing, now.Add(500*time.Millisecond)), "second miss in 1 s")
	assert.Nil(t, h.r.Route(s, missing, now.Add(time.Second)))
	for range 2 {
		m := recv(t, st).GetNoRoute()
		require.NotNil(t, m)
		assert.Empty(t, cmp.Diff(&dp.NoRoute{Vpc: ref(vpcA), Address: "fd00::9"}, m, protocmp.Transform()))
	}
	// Permit denies: the same as no route.
	h.r.SetPermit(func(VPCKey, string, VPCKey, netip.Addr) bool { return false })
	assert.Nil(t, h.r.Route(s, netip.MustParseAddr("fd00::2"), now))
	assert.Equal(t, "fd00::2", recv(t, st).GetNoRoute().GetAddress())
}

func TestDrain(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	mover := h.mustDial(t, ca.agentCert(t, vpcA, "mover"))
	moverSync, _, _ := open(t, mover)
	stayer := h.mustDial(t, ca.agentCert(t, vpcA, "stayer"))
	stayerSync, _, _ := open(t, stayer)
	h.session(t, mover)
	h.session(t, stayer)

	alternates := []*dp.RelayRef{{Id: "relay-2", Addresses: []string{"192.0.2.2:443"}}}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		h.srv.Drain(ctx, alternates)
		close(done)
	}()
	for _, st := range []syncStream{moverSync, stayerSync} {
		m := recv(t, st).GetDrain()
		require.NotNil(t, m)
		assert.Empty(t, cmp.Diff(&dp.Drain{Alternates: alternates}, m, protocmp.Transform()))
	}
	// The relay refuses new sessions.
	late, err := h.dial(t, ca.agentCert(t, vpcA, "late"))
	if err == nil {
		assert.Equal(t, quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN), closeCode(t, late.qc))
	}
	// One agent moves. The relay closes the other when the drain time ends.
	require.NoError(t, mover.qc.CloseWithError(0, ""))
	assert.Equal(t, quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN), closeCode(t, stayer.qc))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Drain did not return")
	}
}

// TestAttachmentAddressLoss ends the address lease of an attachment. The relay
// closes the session and removes its routes before the address is freed.
func TestAttachmentAddressLoss(t *testing.T) {
	cases := []struct {
		name         string
		duringAssign bool
	}{
		{"lease ends after the attach", false},
		{"lease ends during the attach", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCA(t)
			h := newHarness(t, ca)
			h.addrs.loseOnAssign = tc.duringAssign
			a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
			open(t, a)
			s := h.session(t, a)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			res, err := a.c.Attach(ctx, &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"})
			if tc.duringAssign {
				require.Error(t, err)
				assert.Empty(t, h.addrs.attachedCalls(), "the host got a failed attach as complete")
			} else {
				require.NoError(t, err)
				lost := h.addrs.onLost(res.AttachmentId)
				require.NotNil(t, lost)
				lost()
			}
			h.r.mu.RLock()
			_, active := h.r.sessions[s]
			d := h.r.domains[vpcA]
			h.r.mu.RUnlock()
			assert.False(t, active, "the session is still in the router")
			assert.Nil(t, d, "the routes stay after the lease ended")
			assert.Equal(t, quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED), closeCode(t, a.qc))
			require.Eventually(t, func() bool { return h.addrs.count() == 0 }, 5*time.Second, 5*time.Millisecond)
		})
	}
}
