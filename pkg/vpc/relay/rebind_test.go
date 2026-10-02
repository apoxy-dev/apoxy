// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// TestWatchAddr checks that only the QUIC connection moves a session. Data
// from a new source and Moved alone do not move it.
func TestWatchAddr(t *testing.T) {
	const old, next = "192.0.2.1:1000", "198.51.100.1:3000"
	cases := []struct {
		name     string
		move     bool   // The connection moves to next after Moved.
		src      string // Source of a data packet after the watch.
		wantAddr string
		want     Verdict
	}{
		{"data from new source", false, next, old, DropUnknownSource},
		{"old address", false, old, old, Pass},
		{"connection moves", true, next, next, Pass},
		{"old address in overlap", true, old, next, Pass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := NewRouter(nil, Config{})
				snd := addSession(t, r, vpcA, "sender", old, "fd00::1/128")
				addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
				require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Minute, 1), time.Now()))
				_, v := r.Forward(netip.MustParseAddrPort(next), 1, 100, time.Now())
				require.Equal(t, DropUnknownSource, v, "data before Moved")

				r.watchAddr(snd.Session)
				if tc.move {
					time.Sleep(22 * time.Millisecond)
					snd.addr.set(next)
					time.Sleep(movePoll)
					synctest.Wait()
					assert.Equal(t, next, r.Addr(snd.Session).String(), "one poll after the move")
				}
				time.Sleep(moveWait + movePoll)
				synctest.Wait()
				assert.False(t, snd.watching.Load(), "watch ended")
				r.Sweep(time.Now())

				assert.Equal(t, tc.wantAddr, r.Addr(snd.Session).String())
				r.mu.RLock()
				_, learned := r.bySource[netip.MustParseAddrPort(next)]
				r.mu.RUnlock()
				assert.Equal(t, tc.move, learned)
				_, v = r.Forward(netip.MustParseAddrPort(tc.src), 1, 100, time.Now())
				assert.Equal(t, tc.want, v)
			})
		})
	}
}

// TestSessionMessages checks that Moved and a message of a newer agent do
// not end the Session call.
func TestSessionMessages(t *testing.T) {
	cases := []struct {
		name string
		m    *dp.SessionRequest
	}{
		{"Moved", &dp.SessionRequest{Msg: &dp.SessionRequest_Moved{Moved: &dp.Moved{}}}},
		{"unknown message", &dp.SessionRequest{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCA(t)
			h := newHarness(t, ca)
			a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
			st, _, _ := open(t, a)
			s := h.session(t, a)
			require.Eventually(t, func() bool { return h.r.SyncStats(s).Rev > 0 }, 5*time.Second, 5*time.Millisecond)
			require.NoError(t, st.Send(tc.m))
			// The relay applies the Ack only if the call is still open.
			rev := h.r.SyncStats(s).Rev
			require.NoError(t, st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Ack{Ack: &dp.Ack{Rev: rev}}}))
			require.Eventually(t, func() bool { return h.r.SyncStats(s).Acked == rev }, 5*time.Second, 5*time.Millisecond)
			assert.NoError(t, context.Cause(a.qc.Context()))
		})
	}
}
