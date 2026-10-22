// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
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
	"testing/synctest"
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
	sayHello(t, other)
	res := attach(t, other, &dp.AttachRequest{Vpc: ref(vpcA), Name: "other", Routes: []string{"10.1.0.0/16"}})
	// A session in another project with the same VPC UID and route.
	b := h.mustDial(t, ca.agentCert(t, vpcB, "b"))
	sayHello(t, b)
	attach(t, b, &dp.AttachRequest{Vpc: ref(vpcB), Name: "b", Routes: []string{"10.1.0.0/16"}})

	a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
	// Its own attachment does not come back to it in Sync.
	st, _, _ := open(t, a)
	attach(t, a, &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop", Routes: []string{"10.2.0.0/16"}})
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

// TestQueueRoute checks that a route change in the sync queue cancels the
// opposite change that waits there.
func TestQueueRoute(t *testing.T) {
	r := NewRouter(nil, Config{})
	s := addSession(t, r, vpcA, "s", "192.0.2.1:1")
	rt := route{netip.MustParsePrefix("10.0.0.0/8"), "a"}
	cases := []struct {
		name string
		ops  []bool // Changes of rt: true adds, false removes.
		want *dp.RouteDelta
	}{
		{"first take with no routes", nil, &dp.RouteDelta{Rev: 1}},
		{"add", []bool{true}, &dp.RouteDelta{Add: []*dp.Route{{Prefix: "10.0.0.0/8", Origin: "a"}}}},
		{"add then remove", []bool{true, false}, nil},
		{"remove then add", []bool{false, true}, nil},
		{"remove", []bool{false}, &dp.RouteDelta{Remove: []*dp.Route{{Prefix: "10.0.0.0/8", Origin: "a"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r.mu.Lock()
			for _, add := range tc.ops {
				s.queueRoute(rt, add)
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
		{"route that another session announces", &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop", Routes: []string{"10.9.0.0/16"}}, nil, rpc.OK},
		{"no Hello", &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"}, nil, rpc.FailedPrecondition},
		{"another VPC", &dp.AttachRequest{Vpc: ref(vpcB), Name: "laptop"}, nil, rpc.PermissionDenied},
		{"VPC data too old", &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"}, func(h *harness) { h.nets.failVPC(vpcA) }, rpc.Unavailable},
		{"no addresses", &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"}, func(h *harness) { h.addrs.fail(errors.New("no slot")) }, rpc.Unavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCA(t)
			h := newHarness(t, ca)
			other := h.mustDial(t, ca.agentCert(t, vpcA, "other"))
			if tc.name == "route that another session announces" {
				require.NoError(t, h.r.AddRoute(h.session(t, other), netip.MustParsePrefix("10.9.0.0/16"), "x"))
			}
			a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
			if tc.name != "no Hello" {
				sayHello(t, a)
			}
			if tc.setup != nil {
				tc.setup(h)
			}
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

// TestAttachRoutes checks that a refused advertised route does not fail the
// Attach, and is in no route table, mesh entry or host route.
func TestAttachRoutes(t *testing.T) {
	const (
		accepted   = dp.RouteResult_ROUTE_RESULT_ACCEPTED
		defaultRt  = dp.RouteResult_ROUTE_RESULT_DEFAULT_ROUTE
		overlaps   = dp.RouteResult_ROUTE_RESULT_OVERLAPS_VPC
		ipv4Mapped = dp.RouteResult_ROUTE_RESULT_IPV4
	)
	// route is an advertised route as the agent sends it, and the answer of
	// the relay. The answer has the prefix in the masked form.
	type route struct {
		prefix string
		want   dp.RouteResult
	}
	cases := []struct {
		name string
		rev  uint32 // Revision of the agent.
		// routes are the advertised routes, in the order of the request.
		routes []route
	}{
		{name: "no routes", rev: dp.Revision},
		{name: "IPv4 route", rev: dp.Revision, routes: []route{{prefix: "10.9.0.0/16", want: accepted}}},
		{name: "IPv6 route", rev: dp.Revision, routes: []route{{prefix: "2001:db8::/32", want: accepted}}},
		{name: "IPv4 host route", rev: dp.Revision, routes: []route{{prefix: "10.9.0.1/32", want: accepted}}},
		{name: "shortest IPv4 route that is not the default", rev: dp.Revision, routes: []route{{prefix: "128.0.0.0/1", want: accepted}}},
		{name: "IPv4 default route", rev: dp.Revision, routes: []route{{prefix: "0.0.0.0/0", want: defaultRt}}},
		{name: "IPv6 default route", rev: dp.Revision, routes: []route{{prefix: "::/0", want: defaultRt}}},
		{name: "default route with host bits", rev: dp.Revision, routes: []route{{prefix: "10.1.2.3/0", want: defaultRt}}},
		{name: "IPv4-mapped prefix", rev: dp.Revision, routes: []route{{prefix: "::ffff:10.9.0.0/112", want: ipv4Mapped}}},
		{name: "all IPv4-mapped addresses", rev: dp.Revision, routes: []route{{prefix: "::ffff:0.0.0.0/96", want: ipv4Mapped}}},
		{name: "the VPC network", rev: dp.Revision, routes: []route{{prefix: "fd00:1::/72", want: overlaps}}},
		{name: "prefix in the VPC network", rev: dp.Revision, routes: []route{{prefix: "fd00:1::7:0:0/96", want: overlaps}}},
		{name: "address of the attachment", rev: dp.Revision, routes: []route{{prefix: "fd00:1::1/128", want: overlaps}}},
		{name: "prefix with the VPC network in it", rev: dp.Revision, routes: []route{{prefix: "fd00::/8", want: overlaps}}},
		{name: "network after the VPC network", rev: dp.Revision, routes: []route{{prefix: "fd00:1:0:0:100::/72", want: accepted}}},
		{name: "network before the VPC network", rev: dp.Revision, routes: []route{{prefix: "fd00:0:ffff:ffff:ff00::/72", want: accepted}}},
		{name: "address after the VPC network", rev: dp.Revision, routes: []route{{prefix: "fd00:1:0:0:100::/128", want: accepted}}},
		{name: "good and bad routes", rev: dp.Revision, routes: []route{
			{prefix: "10.9.0.0/16", want: accepted},
			{prefix: "0.0.0.0/0", want: defaultRt},
			{prefix: "2001:db8::1/32", want: accepted},
			{prefix: "fd00:1::/80", want: overlaps},
			{prefix: "::ffff:192.0.2.0/120", want: ipv4Mapped},
			{prefix: "::/0", want: defaultRt},
			{prefix: "192.0.2.0/24", want: accepted},
		}},
		{name: "only bad routes", rev: dp.Revision, routes: []route{{prefix: "::/0", want: defaultRt}, {prefix: "fd00:1::/72", want: overlaps}}},
		{name: "first revision with the statuses", rev: announcerRevision, routes: []route{{prefix: "10.9.0.0/16", want: accepted}, {prefix: "::/0", want: defaultRt}}},
		{name: "agent below the revision of the statuses", rev: announcerRevision - 1, routes: []route{
			{prefix: "10.9.0.0/16", want: accepted},
			{prefix: "0.0.0.0/0", want: defaultRt},
			{prefix: "fd00:1::/72", want: overlaps},
			{prefix: "::ffff:10.9.0.0/112", want: ipv4Mapped},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCA(t)
			h := newHarness(t, ca)
			a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
			sayHelloAt(t, a, tc.rev)

			req := &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"}
			var statuses []*dp.RouteStatus
			var good []netip.Prefix
			for _, r := range tc.routes {
				req.Routes = append(req.Routes, r.prefix)
				masked := netip.MustParsePrefix(r.prefix).Masked().String()
				statuses = append(statuses, &dp.RouteStatus{Prefix: masked, Result: r.want})
				if r.want == accepted {
					good = append(good, netip.MustParsePrefix(masked))
				}
			}
			if tc.rev < announcerRevision {
				statuses = nil
			}
			res := attach(t, a, req)
			assert.Empty(t, cmp.Diff(statuses, res.Routes, protocmp.Transform()), "statuses")

			claims, err := VerifyGrant(res.Grant, h.relayRoots, time.Now())
			require.NoError(t, err)
			require.Equal(t, []string{"fd00:1::/96"}, claims.Addresses)
			announced := append([]netip.Prefix{netip.MustParsePrefix("fd00:1::/96")}, good...)

			s := h.session(t, a)
			h.r.mu.RLock()
			table := slices.Clone(s.routes)
			entry := presenceOf(s, s.attachments[0])
			h.r.mu.RUnlock()
			assert.ElementsMatch(t, announced, table, "route table")
			assert.Equal(t, prefixStrings(announced), entry.Prefixes, "entry for the other relays")
			calls := h.addrs.attachedCalls()
			require.Len(t, calls, 1)
			assert.Equal(t, good, calls[0].routes, "routes that the host gets")
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
			sayHello(t, a)
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
			sayHello(t, other)
			otherRes := attach(t, other, &dp.AttachRequest{Vpc: ref(vpcA), Name: "other"})
			a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
			sayHello(t, a)
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

// TestAttachGrantLife checks that the grant of Attach ends GrantLife after the
// call, also when the agent cert ends before that.
func TestAttachGrantLife(t *testing.T) {
	ca := newCA(t)
	cases := []struct {
		name string
		cert tls.Certificate
	}{
		{"cert that ends after the grant", ca.agentCert(t, vpcA, "laptop")},
		{"cert that ends before the grant", ca.shortCert(t, vpcA, "laptop")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, ca)
			a := h.mustDial(t, tc.cert)
			sayHello(t, a)
			before := time.Now()
			res := attach(t, a, &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"})
			after := time.Now()
			claims, err := VerifyGrant(res.Grant, h.relayRoots, after)
			require.NoError(t, err)
			end := claims.NotAfter.AsTime()
			assert.False(t, end.Before(before.Add(GrantLife)) || end.After(after.Add(GrantLife)),
				"end %v, call from %v to %v", end, before, after)
		})
	}
}

// TestGrant checks the Grant call: a session gets a grant only for its own
// attachment, with the claims of the grant of Attach and an end GrantLife later.
func TestGrant(t *testing.T) {
	cases := []struct {
		name  string
		id    func(own, other string) string // The ID in the call, from that of a and that of another agent.
		noKey bool                           // The relay has no key for grants.
		code  rpc.Code
	}{
		{name: "attachment of the session", id: func(own, _ string) string { return own }, code: rpc.OK},
		{name: "attachment of another session", id: func(_, other string) string { return other }, code: rpc.NotFound},
		{name: "unknown attachment", id: func(string, string) string { return "unknown" }, code: rpc.NotFound},
		{name: "no ID", id: func(string, string) string { return "" }, code: rpc.NotFound},
		{name: "relay with no key", id: func(own, _ string) string { return own }, noKey: true, code: rpc.Unavailable},
	}
	ca := newCA(t)
	h := newHarness(t, ca)
	other := h.mustDial(t, ca.agentCert(t, vpcA, "other"))
	sayHello(t, other)
	otherRes := attach(t, other, &dp.AttachRequest{Vpc: ref(vpcA), Name: "other"})
	a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
	sayHello(t, a)
	own := attach(t, a, &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop", Routes: []string{"10.9.0.0/16"}})
	first, err := VerifyGrant(own.Grant, h.relayRoots, time.Now())
	require.NoError(t, err)
	// The claims of the two grants differ only in the end time.
	sameClaims := func(t *testing.T, g *dp.AttachmentGrant, now time.Time) {
		claims, err := VerifyGrant(g, h.relayRoots, now)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(first, claims, protocmp.Transform(), protocmp.IgnoreFields(&dp.GrantClaims{}, "not_after")))
		assert.WithinDuration(t, now.Add(GrantLife), claims.NotAfter.AsTime(), time.Second)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := h.srv
			if tc.noKey {
				srv = &Server{R: h.r, RelayID: "relay-1"}
			}
			now := time.Now()
			g, err := srv.grant(h.session(t, a), tc.id(own.AttachmentId, otherRes.AttachmentId), now)
			require.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
			if tc.code != rpc.OK {
				return
			}
			sameClaims(t, g, now)
			claims, err := VerifyGrant(g, h.relayRoots, now)
			require.NoError(t, err)
			assert.True(t, claims.NotAfter.AsTime().Equal(now.Add(GrantLife)), "end %v, call at %v", claims.NotAfter.AsTime(), now)
			_, err = VerifyGrant(g, h.relayRoots, now.Add(GrantLife))
			assert.ErrorContains(t, err, "grant has ended")
		})
	}

	t.Run("call of an agent", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err := a.c.Grant(ctx, &dp.GrantRequest{AttachmentId: own.AttachmentId})
		require.NoError(t, err)
		sameClaims(t, res.Grant, time.Now())
		_, err = a.c.Grant(ctx, &dp.GrantRequest{AttachmentId: otherRes.AttachmentId})
		assert.Equal(t, rpc.NotFound, rpc.CodeOf(err), "error: %v", err)
	})
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

// TestDrain drains a relay with sessions of each kind. Each session gets Drain,
// and only a session with the routes of other relays gets the alternates.
func TestDrain(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	this := dp.LocalVersion("test")
	agents := []struct {
		name  string
		hello *dp.Hello
		alts  bool // The session gets the alternates.
		a     agent
		st    syncStream
	}{
		{name: "mover", hello: &dp.Hello{Version: this}, alts: true},
		{name: "stayer", hello: &dp.Hello{Version: this}, alts: true},
		{name: "first revision with the routes of other relays", hello: &dp.Hello{Version: &dp.Version{Revision: 6}}, alts: true},
		{name: "local routes only", hello: &dp.Hello{Version: this, LocalRoutesOnly: true}},
		{name: "revision before the routes of other relays", hello: &dp.Hello{Version: &dp.Version{Revision: 5}}},
		{name: "no version", hello: &dp.Hello{}},
	}
	for i := range agents {
		a := &agents[i]
		a.a = h.mustDial(t, ca.agentCert(t, vpcA, fmt.Sprintf("agent-%d", i)))
		var err error
		a.st, err = a.a.c.Session(context.Background())
		require.NoError(t, err)
		a.hello.Mode = dp.Mode_MODE_QUIC
		require.NoError(t, a.st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: a.hello}}))
		require.NotNil(t, recv(t, a.st).GetWelcome(), a.name)
		require.NotNil(t, recv(t, a.st).GetConfig(), a.name)
		h.session(t, a.a)
	}

	alternates := []*dp.RelayRef{
		{Id: "relay-2", Addresses: []string{"192.0.2.2:443"}},
		{Id: "relay-3", Addresses: []string{"192.0.2.3:443", "[2001:db8::3]:443"}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		h.srv.Drain(ctx, alternates)
		close(done)
	}()
	for _, a := range agents {
		m := recv(t, a.st).GetDrain()
		require.NotNil(t, m, a.name)
		want := &dp.Drain{}
		if a.alts {
			want.Alternates = alternates
		}
		assert.Empty(t, cmp.Diff(want, m, protocmp.Transform()), a.name)
	}
	// The relay refuses new sessions.
	late, err := h.dial(t, ca.agentCert(t, vpcA, "late"))
	if err == nil {
		assert.Equal(t, quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN), closeCode(t, late.qc))
	}
	// One agent moves. The relay closes the others when the drain time ends.
	require.NoError(t, agents[0].a.qc.CloseWithError(0, ""))
	for _, a := range agents[1:] {
		assert.Equal(t, quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN), closeCode(t, a.a.qc), a.name)
	}
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

// TestDrainState checks that each entry gets the draining state before its
// session gets Drain, so another relay selects its own standby.
func TestDrainState(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// The agent laptop has the attachment x on the relay that drains, and
		// the attachment y, with a higher rank, on the other relay.
		w, other := newRouteWorld(t, NewRouter(nil, Config{})), newRouteWorld(t, NewRouter(nil, Config{}))
		local := w.session("local", vpcA, laptop, namedHello("base"))
		type sentEntry struct {
			e *dp.Presence
			// drainQueued is true if the session had its Drain at the time of the entry.
			drainQueued bool
		}
		var sent []sentEntry
		w.r.mu.Lock()
		w.r.presence = func(e *dp.Presence) {
			queued := slices.ContainsFunc(local.sync.out, func(m *dp.SessionResponse) bool { return m.GetDrain() != nil })
			sent = append(sent, sentEntry{e, queued})
		}
		w.r.mu.Unlock()
		w.attach("local", "x", prefixA, prefixR)
		require.Len(t, sent, 1)

		other.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
		other.session("local", vpcA, laptop, namedHello("base"))
		y := attachment("y", prefixB)
		y.Routes, y.Rank = []netip.Prefix{netip.MustParsePrefix(prefixR)}, 1
		require.NoError(t, other.r.attach(other.sess["local"], y))
		other.send("relay-a", sent[0].e)
		endHold()
		require.Equal(t, []string{"x@relay-a", "y@relay-m"}, entriesOf(other.r, prefixR))
		other.drain()

		sent = nil
		(&Server{R: w.r}).Drain(t.Context(), nil)
		require.Len(t, sent, 1, "entries at the start of the drain")
		assert.Equal(t, stateDraining, sent[0].e.GetState())
		assert.False(t, sent[0].drainQueued, "the session got Drain before its entry had the draining state")
		var drains int
		for _, m := range w.r.takeSync(local) {
			if m.GetDrain() != nil {
				drains++
			}
		}
		assert.Equal(t, 1, drains, "Drain messages of the session")
		assert.Equal(t, []string{"x@relay-m"}, entriesOf(w.r, prefixR), "the entries of the relay that drains stay")

		other.send("relay-a", sent[0].e)
		assert.Equal(t, []string{"y@relay-m", "x@relay-a"}, entriesOf(other.r, prefixR))
		assert.Equal(t, []string{"-x " + prefixR, "+y " + prefixR + " standby=x"}, other.changes("watcher"))
		assert.Equal(t, "x@relay-a", other.table(vpcA)[prefixA], "the route of the address stays")
		other.check()

		// An attachment that comes during the drain has the draining state too.
		sent = nil
		w.attach("local", "x2", prefixB)
		require.Len(t, sent, 1)
		assert.Equal(t, stateDraining, sent[0].e.GetState())
	})
}

// TestSessionLiveness checks on real QUIC that an agent that stops with no
// close is suspect after suspectAfter, before the idle timeout.
func TestSessionLiveness(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	h := newHarness(t, ca)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.r.Run(ctx)
	a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
	open(t, a)
	s := h.session(t, a)
	// The liveness check writes these fields with the read lock.
	read := func() (state dp.AnnouncerState, last time.Time) {
		h.r.mu.Lock()
		defer h.r.mu.Unlock()
		return s.state, s.live.last
	}

	// An idle agent that answers stays normal for more than suspectAfter.
	_, start := read()
	time.Sleep(suspectAfter + AgentKeepAlive)
	state, last := read()
	require.Equal(t, stateNormal, state, "state of an idle session")
	require.Greater(t, last.Sub(start), suspectAfter, "the relay heard the agent after the keep-alive")

	// The socket of the agent closes, so the agent sends no close and no answer.
	require.NoError(t, a.tr.Conn.Close())
	stopped := time.Now()
	require.Eventually(t, func() bool {
		state, _ := read()
		return state == stateSuspect
	}, suspectAfter+3*time.Second, livenessInterval/5, "the session of a silent agent is suspect")
	// The last packet came at most one keep-alive period before the stop.
	assert.GreaterOrEqual(t, time.Since(stopped), suspectAfter-AgentKeepAlive-time.Second)
	h.r.mu.RLock()
	_, kept := h.r.sessions[s]
	h.r.mu.RUnlock()
	assert.True(t, kept, "the session is gone before the idle timeout")
}
