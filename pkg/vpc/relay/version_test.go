// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/apoxy-dev/apoxy/build"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// withVersion makes a relay with the protocol version v. Nil is a relay from
// before revisions.
func withVersion(v *dp.Version) func(*Router) {
	return func(r *Router) { r.ver = v }
}

// hello starts the Session call of a with the Hello h.
func hello(t *testing.T, a agent, h *dp.Hello) syncStream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	st, err := a.c.Session(ctx)
	require.NoError(t, err)
	// Send gets io.EOF when the relay refuses the call first. Recv gives the status.
	if err := st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: h}}); err != io.EOF {
		require.NoError(t, err)
	}
	return st
}

// statusRelay is a relay service that reports the status of each Session call.
type statusRelay struct {
	dp.RelayServer
	codes chan<- rpc.Code
}

func (s statusRelay) Session(ctx context.Context, st rpc.BidiStreamServer[dp.SessionRequest, dp.SessionResponse]) error {
	err := s.RelayServer.Session(ctx, st)
	select {
	case s.codes <- rpc.CodeOf(err):
	default:
	}
	return err
}

// sessionStatus gives the status of each Session call that ends on the relay
// of h. Call it before the first agent dials.
func sessionStatus(t *testing.T, h *harness) <-chan rpc.Code {
	t.Helper()
	codes := make(chan rpc.Code, 16)
	set := false
	h.srv.muxOnce.Do(func() {
		h.srv.mux, set = rpc.NewMux(), true
		dp.RegisterRelayServer(h.srv.mux, statusRelay{RelayServer: h.srv, codes: codes})
	})
	require.True(t, set, "the relay served a connection before")
	return codes
}

// requireStatus checks the status of the next Session call that ends.
func requireStatus(t *testing.T, codes <-chan rpc.Code, want rpc.Code) {
	t.Helper()
	select {
	case got := <-codes:
		assert.Equal(t, want, got)
	case <-time.After(5 * time.Second):
		t.Fatal("no Session call ended in 5 s")
	}
}

// requireUpgrade checks that the relay closed the connection of a with
// UPGRADE and the reason.
func requireUpgrade(t *testing.T, a agent, reason string) {
	t.Helper()
	assert.Equal(t, quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_UPGRADE), closeCode(t, a.qc))
	var ae *quic.ApplicationError
	require.ErrorAs(t, context.Cause(a.qc.Context()), &ae)
	assert.True(t, ae.Remote)
	assert.Equal(t, reason, ae.ErrorMessage)
}

// TestSessionRevision opens sessions between agents and relays of different
// revisions. A side from before revisions sends no Version.
func TestSessionRevision(t *testing.T) {
	this := dp.LocalVersion(build.BuildVersion)
	later := &dp.Version{Revision: dp.Revision + 1, MinRevision: dp.Revision + 1, Build: "later"}
	cases := []struct {
		name    string
		relay   []func(*Router) // Empty means a relay of this build.
		agent   *dp.Version     // Nil means an agent from before revisions.
		welcome *dp.Version     // Version in Welcome.
		upgrade string          // Reason of the UPGRADE close. Empty means that the session opens.
	}{
		{name: "agent from before revisions", welcome: this},
		{name: "agent of revision 1", agent: &dp.Version{Revision: 1, Build: "revision-1"}, welcome: this},
		{name: "agent of this revision", agent: this, welcome: this},
		{name: "agent of a later revision", agent: &dp.Version{Revision: dp.Revision + 1, Build: "later"}, welcome: this},
		{name: "relay from before revisions", relay: []func(*Router){withVersion(nil)}, agent: this},
		{
			name:    "relay minimum is the agent revision",
			relay:   []func(*Router){withVersion(&dp.Version{Revision: dp.Revision, MinRevision: dp.Revision})},
			agent:   this,
			welcome: &dp.Version{Revision: dp.Revision, MinRevision: dp.Revision},
		},
		{
			name:    "relay minimum above the agent",
			relay:   []func(*Router){withVersion(later)},
			agent:   this,
			upgrade: fmt.Sprintf("agent revision %d is below the relay minimum %d", dp.Revision, dp.Revision+1),
		},
		{
			name:    "relay minimum above an agent from before revisions",
			relay:   []func(*Router){withVersion(later)},
			upgrade: fmt.Sprintf("agent revision 0 is below the relay minimum %d", dp.Revision+1),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCA(t)
			h := newHarness(t, ca, tc.relay...)
			status := sessionStatus(t, h)
			a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
			st := hello(t, a, &dp.Hello{Mode: dp.Mode_MODE_PSP, Version: tc.agent})
			m, err := st.Recv()
			if tc.upgrade != "" {
				// The close comes before the call status, so the agent gets only the close.
				require.Error(t, err)
				requireUpgrade(t, a, tc.upgrade)
				requireStatus(t, status, rpc.FailedPrecondition)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, m.GetWelcome(), "first message: %v", m)
			got := m.GetWelcome().GetVersion()
			assert.True(t, proto.Equal(tc.welcome, got), "Welcome has the version %v, want %v", got, tc.welcome)
			m, err = st.Recv()
			require.NoError(t, err)
			require.NotNil(t, m.GetConfig(), "second message: %v", m)

			s := h.session(t, a)
			for n := range dp.Revision + 3 {
				assert.Equal(t, tc.agent.GetRevision() >= n, h.r.agentAtLeast(s, n), "agent at revision %d or later", n)
			}
			// The session works: the relay attaches the agent and signs its grant.
			res := attach(t, a, &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"})
			_, err = VerifyGrant(res.GetGrant(), h.relayRoots, time.Now())
			assert.NoError(t, err)
		})
	}
}

// TestAgentNames opens two sessions with one cert name. From revision 2 an
// agent sends its name in Hello, and two names are two agents. With no name
// in one of the sessions, the two sessions are one agent, as before revision 2.
func TestAgentNames(t *testing.T) {
	const advertised = "10.9.0.0/16"
	this := dp.LocalVersion(build.BuildVersion)
	one := &dp.Version{Revision: 1, Build: "revision-1"}
	cases := []struct {
		name          string
		first, second *dp.Hello
		two           bool // The relay has the two sessions as two agents.
	}{
		{name: "two sessions of revision 1", first: &dp.Hello{Version: one}, second: &dp.Hello{Version: one}},
		{name: "two sessions from before revisions", first: &dp.Hello{}, second: &dp.Hello{}},
		{name: "revision 1, then a name", first: &dp.Hello{Version: one}, second: &dp.Hello{Version: this, Name: "b"}},
		{name: "a name, then revision 1", first: &dp.Hello{Version: this, Name: "a"}, second: &dp.Hello{Version: one}},
		{name: "one name", first: &dp.Hello{Version: this, Name: "a"}, second: &dp.Hello{Version: this, Name: "a"}},
		{name: "two names", first: &dp.Hello{Version: this, Name: "a"}, second: &dp.Hello{Version: this, Name: "b"}, two: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCA(t)
			h := newHarness(t, ca)
			// start opens a session in QUIC mode, where the first RouteDelta comes after Config.
			start := func(first *dp.Hello) (agent, syncStream) {
				a := h.mustDial(t, ca.agentCert(t, vpcA, "shared"))
				first.Mode = dp.Mode_MODE_QUIC
				st := hello(t, a, first)
				m, err := st.Recv()
				require.NoError(t, err)
				require.NotNil(t, m.GetWelcome(), "first message: %v", m)
				m, err = st.Recv()
				require.NoError(t, err)
				require.NotNil(t, m.GetConfig(), "second message: %v", m)
				return a, st
			}
			routes := func(d *dp.RouteDelta) []string {
				var out []string
				for _, rt := range d.GetAdd() {
					out = append(out, rt.GetOrigin()+" "+rt.GetPrefix())
				}
				return out
			}
			a, stA := start(tc.first)
			resA := attach(t, a, &dp.AttachRequest{Vpc: ref(vpcA), Name: "a", Routes: []string{advertised}})
			claimsA, err := VerifyGrant(resA.GetGrant(), h.relayRoots, time.Now())
			require.NoError(t, err)

			// The first RouteDelta of the second session has the routes of the
			// first session only when they are two agents.
			b, stB := start(tc.second)
			m, err := stB.Recv()
			require.NoError(t, err)
			require.NotNil(t, m.GetRouteDelta(), "third message: %v", m)
			var want []string
			if tc.two {
				want = []string{resA.GetAttachmentId() + " " + advertised, resA.GetAttachmentId() + " " + claimsA.GetAddresses()[0]}
			}
			assert.Equal(t, want, routes(m.GetRouteDelta()))

			// The address route of the second session goes to the first session
			// only when they are two agents.
			resB := attach(t, b, &dp.AttachRequest{Vpc: ref(vpcA), Name: "b"})
			claimsB, err := VerifyGrant(resB.GetGrant(), h.relayRoots, time.Now())
			require.NoError(t, err)
			if tc.two {
				assert.Equal(t, []string{resB.GetAttachmentId() + " " + claimsB.GetAddresses()[0]}, routes(recv(t, stA).GetRouteDelta()))
			}

			// One agent moves its advertised route to its new attachment. Another
			// agent of the subject cannot take it.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = b.c.Attach(ctx, &dp.AttachRequest{Vpc: ref(vpcA), Name: "b-2", Routes: []string{advertised}})
			if tc.two {
				assert.Equal(t, rpc.AlreadyExists, rpc.CodeOf(err), "error: %v", err)
			} else {
				assert.NoError(t, err)
			}
			h.r.mu.RLock()
			owner := h.r.domains[vpcA].routes[netip.MustParsePrefix(advertised)]
			h.r.mu.RUnlock()
			assert.Equal(t, tc.two, owner.origin == resA.GetAttachmentId(), "the first attachment keeps the route")
		})
	}
}

// TestShardRevision joins shards of different revisions to a session.
func TestShardRevision(t *testing.T) {
	this := dp.LocalVersion(build.BuildVersion)
	relay := &dp.Version{Revision: dp.Revision, MinRevision: dp.Revision, Build: "relay"}
	cases := []struct {
		name    string
		shard   *dp.Version // Nil means an agent from before revisions.
		upgrade string      // Reason of the UPGRADE close. Empty means that the shard joins.
	}{
		{name: "shard of this revision", shard: this},
		{name: "shard below the relay minimum", upgrade: fmt.Sprintf("agent revision 0 is below the relay minimum %d", dp.Revision)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCA(t)
			w := &shardWorld{h: newHarness(t, ca, withVersion(relay)), ca: ca, cert: ca.agentCert(t, vpcA, "laptop")}
			status := sessionStatus(t, w.h)
			w.owner = w.h.mustDial(t, w.cert)
			w.sync = hello(t, w.owner, &dp.Hello{Mode: dp.Mode_MODE_QUIC, Version: this})
			for _, want := range []string{"Welcome", "Config"} {
				m, err := w.sync.Recv()
				require.NoError(t, err)
				require.NotNil(t, m.GetMsg(), "want %s", want)
			}
			att := attach(t, w.owner, &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"}).AttachmentId

			a := w.dial(t, w.cert)
			st := hello(t, a, &dp.Hello{Mode: dp.Mode_MODE_QUIC, Shard: &dp.Shard{AttachmentId: att, Index: 1}, Version: tc.shard})
			m, err := st.Recv()
			if tc.upgrade != "" {
				// The Session call of the owner continues, so this status is of the shard call.
				require.Error(t, err)
				requireUpgrade(t, a, tc.upgrade)
				requireStatus(t, status, rpc.FailedPrecondition)
				assert.NoError(t, w.owner.qc.Context().Err(), "the owner session stays")
				return
			}
			require.NoError(t, err)
			require.NotNil(t, m.GetWelcome(), "first message: %v", m)
			got := m.GetWelcome().GetVersion()
			assert.True(t, proto.Equal(relay, got), "Welcome has the version %v, want %v", got, relay)
		})
	}
}
