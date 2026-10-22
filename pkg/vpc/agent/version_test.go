// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// TestRelayRevision checks the relay revision against the minimum of the agent.
func TestRelayRevision(t *testing.T) {
	cases := []struct {
		name         string
		relay, agent *dp.Version
		want         string // Error text. Empty means no error.
	}{
		{name: "equal revisions", relay: &dp.Version{Revision: 21}, agent: &dp.Version{Revision: 21, MinRevision: 21}},
		{name: "relay one below the minimum", relay: &dp.Version{Revision: 20}, agent: &dp.Version{Revision: 21, MinRevision: 21},
			want: "relay revision 20 is below the agent minimum 21"},
		{name: "no relay version against minimum 0", agent: &dp.Version{Revision: 21}},
		{name: "no relay version against minimum 1", agent: &dp.Version{Revision: 21, MinRevision: 1},
			want: "relay revision 0 is below the agent minimum 1"},
		{name: "relay above the minimum", relay: &dp.Version{Revision: 22}, agent: &dp.Version{Revision: 21, MinRevision: 21}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := relayRevision(tc.relay, tc.agent)
			if tc.want == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tc.want)
		})
	}
}

// TestRelayRevisions dials relays that refuse the agent as too old, and relays
// Run ends when no relay takes the agent and one refuses it.
func TestRelayRevisions(t *testing.T) {
	reason := fmt.Sprintf("agent revision %d is below the relay minimum %d", dp.Revision, dp.Revision+1)
	cases := []struct {
		name    string
		relays  int  // Number of relays.
		refuse  int  // The first relays refuse the agent as too old.
		upgrade bool // Run ends with ErrUpgrade.
	}{
		{name: "the relay refuses the agent", relays: 1, refuse: 1, upgrade: true},
		{name: "all relays refuse the agent", relays: 2, refuse: 2, upgrade: true},
		{name: "next relay takes the agent", relays: 2, refuse: 1},
		{name: "last relay takes the agent", relays: 3, refuse: 2},
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
			a := w.agent(t, "a", relays[0], agentOptions{relays: refs, runErr: runErr, mode: TransportAuto})

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
			a.attached(t)
			rc := a.current()
			var takes []string
			for _, r := range relays[tc.refuse:] {
				takes = append(takes, r.addr)
			}
			assert.Contains(t, takes, rc.addr, "the agent attached to a relay that did not refuse it")
			// The attached agent does not dial a relay that refused it again.
			var refused []int32
			for _, r := range relays[:tc.refuse] {
				refused = append(refused, r.refused.Load())
			}
			assert.Never(t, func() bool {
				for i, r := range relays[:tc.refuse] {
					if r.refused.Load() != refused[i] {
						return true
					}
				}
				return false
			}, minBackoff+300*time.Millisecond, 50*time.Millisecond, "dials that a relay refused")
			// The agent stays attached after another relay refused it.
			select {
			case err := <-runErr:
				t.Fatalf("Run returned: %v", err)
			case <-time.After(200 * time.Millisecond):
			}
			sameSession(t, rc, a.current())
			assert.False(t, rc.ended())
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
		{name: "other error", err: errors.New("attach: deadline exceeded")},
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
