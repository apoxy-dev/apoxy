// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// beforeRevisions is the version of a build from before revisions: it sends
// no Version.
func beforeRevisions() *dp.Version { return nil }

// revision1 is the version of a build of revision 1: it has no agent names.
func revision1() *dp.Version { return &dp.Version{Revision: 1, Build: "revision-1"} }

// needsThis is the version of a build of this revision that does not work
// with an older revision.
func needsThis() *dp.Version {
	return &dp.Version{Revision: dp.Revision, MinRevision: dp.Revision, Build: "needs-this"}
}

// needsLater is the version of a build of the next revision that does not
// work with this revision.
func needsLater() *dp.Version {
	return &dp.Version{Revision: dp.Revision + 1, MinRevision: dp.Revision + 1, Build: "needs-later"}
}

// revisionOf returns the revision of the version that v gives. Nil means the
// version of this build.
func revisionOf(v func() *dp.Version) uint32 {
	if v == nil {
		return dp.Revision
	}
	return v().GetRevision()
}

// TestRevisionSkew sends UDP both ways between agents of different revisions
// on a relay of this build. An agent from before revisions sends no Version.
func TestRevisionSkew(t *testing.T) {
	cases := []struct {
		name string
		a, b func() *dp.Version // Nil means an agent of this build.
		mode TransportMode      // Mode of a.
	}{
		{name: "all of this revision"},
		{name: "agent from before revisions", a: beforeRevisions},
		{name: "agent of revision 1", a: revision1},
		{name: "agent from before revisions in QUIC mode", a: beforeRevisions, mode: TransportQUIC},
		{name: "both agents from before revisions", a: beforeRevisions, b: beforeRevisions},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			a := w.agent(t, "a", r, agentOptions{version: tc.a, mode: tc.mode})
			b := w.agent(t, "b", r, agentOptions{version: tc.b})
			ea, eb := a.attached(t), b.attached(t)

			// Each agent knows the revision of the relay from Welcome.
			for _, ta := range []*testAgent{a, b} {
				for n := range dp.Revision + 3 {
					assert.Equal(t, dp.Revision >= n, ta.current().relayAtLeast(n), "relay at revision %d or later", n)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			require.NoError(t, a.a.Connect(ctx, eb.addr))
			require.NoError(t, b.a.Connect(ctx, ea.addr))
			echo(t, b.stack, eb.addr, 9000)
			echo(t, a.stack, ea.addr, 9001)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "from a")
			ping(t, b.stack, eb.addr, ea.addr, 9001, "from b")

			// Each agent knows the revision of the other agent from Open.
			pa, pb := onlyPeer(t, a.a), onlyPeer(t, b.a)
			for n := range dp.Revision + 3 {
				assert.Equal(t, revisionOf(tc.b) >= n, pa.atLeast(n), "b at revision %d or later", n)
				assert.Equal(t, revisionOf(tc.a) >= n, pb.atLeast(n), "a at revision %d or later", n)
			}
		})
	}
}

// TestRelayAtLeast checks the relay revision that the agent has from Welcome.
// A relay from before revisions sends no Version and is at revision 0.
func TestRelayAtLeast(t *testing.T) {
	cases := []struct {
		name    string
		version *dp.Version // Version in Welcome.
		n       uint32
		want    bool
	}{
		{name: "no version at revision 0", n: 0, want: true},
		{name: "no version below revision 1", n: 1},
		{name: "this revision", version: &dp.Version{Revision: dp.Revision}, n: dp.Revision, want: true},
		{name: "this revision below the next", version: &dp.Version{Revision: dp.Revision}, n: dp.Revision + 1},
		{name: "later revision", version: &dp.Version{Revision: dp.Revision + 1}, n: dp.Revision, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := &relayConn{version: tc.version}
			assert.Equal(t, tc.want, rc.relayAtLeast(tc.n))
		})
	}
}

// TestRelayRevisions dials relays that refuse the agent as too old, and relays
// below the minimum of the agent. Run ends when no relay takes the agent and
// one refuses it. An agent that needs a newer relay dials the next relay.
func TestRelayRevisions(t *testing.T) {
	reason := fmt.Sprintf("agent revision %d is below the relay minimum %d", dp.Revision, dp.Revision+1)
	cases := []struct {
		name    string
		relays  int                // Number of relays.
		refuse  int                // The first relays refuse the agent as too old.
		agent   func() *dp.Version // Nil means an agent of this build.
		upgrade bool               // Run ends with ErrUpgrade.
		attach  int                // Number of the relay that the agent attaches to. 0 is no relay.
		// dials is the number of dials that relay-1 refuses, with one spare dial.
		// 0 is no check: with three relays, the agent can dial relay-1 two times.
		dials int32
	}{
		{name: "the relay refuses the agent", relays: 1, refuse: 1, upgrade: true},
		{name: "all relays refuse the agent", relays: 2, refuse: 2, upgrade: true},
		{name: "next relay takes the agent", relays: 2, refuse: 1, attach: 2, dials: 2},
		{name: "last relay takes the agent", relays: 3, refuse: 2, attach: 3},
		{name: "agent minimum is the relay revision", relays: 1, agent: needsThis, attach: 1},
		{name: "all relays below the agent minimum", relays: 2, agent: needsLater},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.refuse = map[string]string{}
			var relays []*testRelay
			var refs []identity.Relay
			for i := range tc.relays {
				id := fmt.Sprintf("relay-%d", i+1)
				if i < tc.refuse {
					w.refuse[id] = reason
				}
				r := w.relay(t, id)
				relays, refs = append(relays, r), append(refs, r.ref())
			}
			runErr := make(chan error, 1)
			// A relay that refuses the agent answers no path probe, so the agent sends
			// PSP with no probe before Hello.
			a := w.agent(t, "a", relays[0], agentOptions{relays: refs, version: tc.agent, runErr: runErr, mode: TransportPSP})

			if tc.upgrade {
				select {
				case err := <-runErr:
					require.ErrorIs(t, err, ErrUpgrade)
					assert.ErrorContains(t, err, reason, "the error gives the minimum")
					assert.True(t, slices.ContainsFunc(relays, func(r *testRelay) bool { return strings.Contains(err.Error(), "relay "+r.addr) }),
						"the error names the relay: %v", err)
				case <-time.After(10 * time.Second):
					t.Fatal("Run did not return in 10 s")
				}
				assert.Empty(t, a.attach, "agent attached")
				return
			}
			if tc.attach == 0 {
				// The agent continues to dial: a relay upgrade can make it pass.
				select {
				case <-a.attach:
					t.Fatal("agent attached to a relay below its minimum")
				case err := <-runErr:
					t.Fatalf("Run returned: %v", err)
				case <-time.After(time.Second):
				}
				return
			}
			a.attached(t)
			rc := a.current()
			assert.Equal(t, relays[tc.attach-1].addr, rc.addr)
			assert.True(t, rc.relayAtLeast(a.a.ver.GetMinRevision()))
			if tc.dials != 0 {
				// Relay-1 refuses one spare dial. The next spare dial comes after
				// upgradeRetry, not after the short wait of other dial errors.
				refused := &relays[0].refused
				require.Eventually(t, func() bool {
					a.a.wakeSpares()
					return refused.Load() == tc.dials
				}, 10*time.Second, 10*time.Millisecond, "spare dial to relay-1")
				assert.Never(t, func() bool {
					a.a.wakeSpares()
					return refused.Load() > tc.dials
				}, minBackoff+300*time.Millisecond, 50*time.Millisecond, "relay-1 got a spare dial again")
			}
			// The agent stays attached while the other relays refuse its spare session.
			select {
			case err := <-runErr:
				t.Fatalf("Run returned: %v", err)
			case <-time.After(200 * time.Millisecond):
			}
			assert.Same(t, rc, a.current())
			assert.NoError(t, rc.qc.Context().Err())
			assert.Nil(t, a.spare(), "spare session")
		})
	}
}

// TestPeerRevisions opens a peer session where one agent needs a newer
// revision than the other has. No peer session stays, and the relay sessions do.
func TestPeerRevisions(t *testing.T) {
	cases := []struct {
		name    string
		a, b    func() *dp.Version // a dials b.
		upgrade bool               // a is the agent that is too old.
		want    string             // Text in the Connect error of a.
	}{
		{
			name: "listener minimum above the dialer", a: beforeRevisions, b: needsThis, upgrade: true,
			want: fmt.Sprintf("dialer revision 0 is below the listener minimum %d", dp.Revision),
		},
		{
			name: "dialer minimum above the listener", a: needsThis, b: beforeRevisions,
			want: fmt.Sprintf("listener revision 0 is below the dialer minimum %d", dp.Revision),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			// A relay of this build takes the two agents.
			r := w.relay(t, "relay-1")
			a := w.agent(t, "a", r, agentOptions{version: tc.a})
			b := w.agent(t, "b", r, agentOptions{version: tc.b})
			a.attached(t)
			eb := b.attached(t)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := a.a.Connect(ctx, eb.addr)
			require.ErrorContains(t, err, tc.want)
			assert.Equal(t, tc.upgrade, errors.Is(err, ErrUpgrade), "error: %v", err)
			assert.Equal(t, !tc.upgrade, errors.Is(err, errRevision), "error: %v", err)
			require.Eventually(t, func() bool { return peerCount(a.a) == 0 && peerCount(b.a) == 0 },
				5*time.Second, 10*time.Millisecond, "no peer session stays")
			assert.NoError(t, a.current().qc.Context().Err(), "relay session of a")
			assert.NoError(t, b.current().qc.Context().Err(), "relay session of b")
		})
	}
}

// TestGrantsUnimplemented checks that a peer session stays when the peer has
// no Grants call. The peer gets no grant changes.
func TestGrantsUnimplemented(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	a, b := w.agent(t, "a", r, agentOptions{}), w.agent(t, "b", r, agentOptions{noGrants: true})
	ea, eb := a.attached(t), b.attached(t)
	echo(t, a.stack, ea.addr, 9000)
	echo(t, b.stack, eb.addr, 9001)
	ping(t, b.stack, eb.addr, ea.addr, 9000, "to a")
	pa, pb := onlyPeer(t, a.a), onlyPeer(t, b.a)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	noGrants := func() bool {
		pa.mu.Lock()
		defer pa.mu.Unlock()
		return pa.noGrants
	}
	require.False(t, noGrants())
	_, err := a.a.Attach(ctx, AttachmentSpec{Name: "a-2"})
	require.NoError(t, err)
	require.Eventually(t, noGrants, 5*time.Second, 10*time.Millisecond, "a learns that b has no Grants call")
	// The next change makes no call.
	require.NoError(t, a.a.Detach(ctx, "a-2"))

	ping(t, b.stack, eb.addr, ea.addr, 9000, "to a again")
	ping(t, a.stack, ea.addr, eb.addr, 9001, "to b")
	assert.Same(t, pa, onlyPeer(t, a.a), "a keeps its peer session")
	assert.Same(t, pb, onlyPeer(t, b.a), "b keeps its peer session")
	assert.NoError(t, pa.qc.Context().Err())
	pa.mu.Lock()
	assert.False(t, pa.sending)
	assert.Empty(t, pa.sendAdd)
	assert.Empty(t, pa.sendRemove)
	pa.mu.Unlock()
}

// TestAttachGrant checks the attach errors for a grant that the agent refuses.
// A grant that needs a newer revision gives an ErrUpgrade.
func TestAttachGrant(t *testing.T) {
	cases := []struct {
		name    string
		claims  func(*dp.GrantClaims)
		upgrade bool
		want    string
	}{
		{
			name:    "grant needs a newer revision",
			claims:  func(c *dp.GrantClaims) { c.MinRevision = dp.Revision + 1 },
			upgrade: true,
			want:    fmt.Sprintf("relay 192.0.2.1:443: grant needs a newer protocol revision: the grant needs revision %d, and the verifier has revision %d", dp.Revision+1, dp.Revision),
		},
		{
			name:   "grant ended",
			claims: func(c *dp.GrantClaims) { c.NotAfter = timestamppb.New(time.Now().Add(-time.Minute)) },
			want:   "grant has ended",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			a := w.stubAgent(t, "a")
			grant := extraGrant(t, w.relayCA.relayCert(t, "relay-1"), "a", "attachment-a", "fd00:a::/96", tc.claims)
			b, err := proto.Marshal(&dp.AttachResponse{AttachmentId: "attachment-a", Grant: grant})
			require.NoError(t, err)
			a.rc.addr, a.rc.c = "192.0.2.1:443", &grantRelay{answers: [][]byte{b}}

			err = a.rc.attach(context.Background(), time.Now())
			require.ErrorContains(t, err, tc.want)
			var ue *upgradeError
			assert.Equal(t, tc.upgrade, errors.As(err, &ue), "error: %v", err)
			assert.Equal(t, tc.upgrade, errors.Is(err, ErrUpgrade), "error: %v", err)
		})
	}
}

func TestRelayUpgrade(t *testing.T) {
	const addr = "192.0.2.1:443"
	upgrade := quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_UPGRADE)
	drain := quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN)
	reason := "agent revision 1 is below the relay minimum 2"
	closed := &quic.ApplicationError{Remote: true, ErrorCode: upgrade, ErrorMessage: reason}
	cases := []struct {
		name string
		err  error
		want string // Text of the ErrUpgrade. Empty means that the error does not change.
	}{
		{name: "remote close UPGRADE in the call error", err: rpc.Errorf(rpc.Unavailable, "%w", closed), want: "agent needs an upgrade: relay 192.0.2.1:443: " + reason},
		{
			name: "remote close UPGRADE as the connection cause",
			err:  fmt.Errorf("%w (connection: %w)", rpc.Errorf(rpc.Unavailable, "stream reset"), closed),
			want: "agent needs an upgrade: relay 192.0.2.1:443: " + reason,
		},
		{name: "local close UPGRADE", err: &quic.ApplicationError{ErrorCode: upgrade, ErrorMessage: reason}},
		{name: "remote close DRAIN", err: &quic.ApplicationError{Remote: true, ErrorCode: drain}},
		{name: "status FailedPrecondition", err: rpc.Errorf(rpc.FailedPrecondition, "%s", reason)},
		{
			name: "grant needs a newer revision",
			err:  fmt.Errorf("%w: the grant needs revision 2, and the verifier has revision 1", relay.ErrGrantRevision),
			want: "agent needs an upgrade: relay 192.0.2.1:443: grant needs a newer protocol revision: the grant needs revision 2, and the verifier has revision 1",
		},
		{name: "other grant error", err: errors.New("grant has ended")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Run finds the error in the errors of all relays of a dial.
			got := errors.Join(errors.New("relay 192.0.2.2:443: timeout"), fmt.Errorf("relay %s: %w", addr, relayUpgrade(addr, tc.err)))
			var ue *upgradeError
			if tc.want == "" {
				assert.NotErrorIs(t, got, ErrUpgrade)
				assert.False(t, errors.As(got, &ue))
				assert.ErrorIs(t, got, tc.err)
				return
			}
			require.ErrorIs(t, got, ErrUpgrade)
			require.True(t, errors.As(got, &ue))
			assert.EqualError(t, ue, tc.want)
		})
	}
}

func TestRefusedUpgrade(t *testing.T) {
	upgrade := quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_UPGRADE)
	bad := quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_BAD_GRANT)
	const reason = "dialer revision 0 is below the listener minimum 1"
	cases := []struct {
		name  string
		err   error // Error of the Open call. Nil means no call.
		close error // Cause of the connection close; nil if open.
		want  bool
	}{
		{name: "remote close UPGRADE", err: errors.New("stream reset"), close: &quic.ApplicationError{Remote: true, ErrorCode: upgrade, ErrorMessage: reason}, want: true},
		{name: "remote close UPGRADE with no call", close: &quic.ApplicationError{Remote: true, ErrorCode: upgrade, ErrorMessage: reason}, want: true},
		{name: "local close UPGRADE", err: errors.New("stream reset"), close: &quic.ApplicationError{ErrorCode: upgrade, ErrorMessage: reason}},
		{name: "remote close BAD_GRANT", err: errors.New("stream reset"), close: &quic.ApplicationError{Remote: true, ErrorCode: bad, ErrorMessage: reason}},
		{name: "status FailedPrecondition", err: rpc.Errorf(rpc.FailedPrecondition, "%s", reason)},
		{name: "open connection with no call"},
		// The call can end before the close cause is set.
		{name: "remote UPGRADE in the call error", err: rpc.Errorf(rpc.Unavailable, "%w", &quic.ApplicationError{Remote: true, ErrorCode: upgrade, ErrorMessage: reason}), want: true},
		{name: "local UPGRADE in the call error", err: rpc.Errorf(rpc.Unavailable, "%w", &quic.ApplicationError{ErrorCode: upgrade, ErrorMessage: reason})},
		{name: "remote BAD_GRANT in the call error", err: rpc.Errorf(rpc.Unavailable, "%w", &quic.ApplicationError{Remote: true, ErrorCode: bad, ErrorMessage: reason})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qc := newFakeConn()
			if tc.close != nil {
				qc.cancel(tc.close)
			}
			got, ok := refusedUpgrade(qc, tc.err)
			assert.Equal(t, tc.want, ok)
			if tc.want {
				assert.Equal(t, reason, got)
			}
		})
	}
}

func TestCloseCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want dp.PeerCloseCode
	}{
		{name: "duplicate", err: fmt.Errorf("peer: %w", errDuplicate), want: dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE},
		{name: "peer below the minimum", err: fmt.Errorf("%w: dialer revision 0 is below the listener minimum 1", errRevision), want: dp.PeerCloseCode_PEER_CLOSE_CODE_UPGRADE},
		// This agent is the old side, so the peer does not get UPGRADE.
		{name: "grant needs a newer revision", err: fmt.Errorf("%w: %w", ErrUpgrade, relay.ErrGrantRevision), want: dp.PeerCloseCode_PEER_CLOSE_CODE_BAD_GRANT},
		{name: "bad grant", err: errors.New("grant has ended"), want: dp.PeerCloseCode_PEER_CLOSE_CODE_BAD_GRANT},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, quic.ApplicationErrorCode(tc.want), closeCode(tc.err))
		})
	}
}
