// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// TestConnectionMove checks that a move of the QUIC connection does not change
// the PSP address of a session. Only a path probe does.
func TestConnectionMove(t *testing.T) {
	const old, next = "192.0.2.1:1000", "198.51.100.1:3000"
	cases := []struct {
		name string
		src  string // Source of a data packet after the move.
		want Verdict
	}{
		{"data from the address of the connection", next, DropUnknownSource},
		{"data from the PSP address", old, Pass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			snd := addSession(t, r, vpcA, "sender", old, "fd00::1/128")
			addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
			require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Minute, 1), t0))
			snd.addr.set(next)
			r.Sweep(t0.Add(time.Second))
			assert.Equal(t, old, r.Addr(snd.Session).String())
			_, v := r.Forward(netip.MustParseAddrPort(tc.src), 1, 100, t0.Add(time.Second))
			assert.Equal(t, tc.want, v)
		})
	}
}

// unknownRequest returns a SessionRequest with an empty message in field num,
// which this build does not know.
func unknownRequest(num protowire.Number) *dp.SessionRequest {
	m := &dp.SessionRequest{}
	m.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, num, protowire.BytesType), nil))
	return m
}

// TestSessionMessages checks that the removed message of an older agent and a
// message of a newer agent do not end the Session call.
func TestSessionMessages(t *testing.T) {
	cases := []struct {
		name string
		m    *dp.SessionRequest
	}{
		{"removed message in field 4", unknownRequest(4)},
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
