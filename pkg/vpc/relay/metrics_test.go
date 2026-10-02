// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func connectCount(t *testing.T, mode string) uint64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, connectSeconds.WithLabelValues(mode).(prometheus.Metric).Write(&m))
	return m.GetHistogram().GetSampleCount()
}

func TestSessionMetrics(t *testing.T) {
	cases := []struct {
		name   string
		mode   dp.Mode
		reason dp.FallbackReason
		spare  bool
		labels []string // Labels of the session counter.
	}{
		{name: "PSP", mode: dp.Mode_MODE_PSP, labels: []string{"psp", "none"}},
		{name: "QUIC from the config", mode: dp.Mode_MODE_QUIC, reason: dp.FallbackReason_FALLBACK_REASON_CONFIG, labels: []string{"quic", "config"}},
		{name: "QUIC after a probe timeout", mode: dp.Mode_MODE_QUIC, reason: dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT, labels: []string{"quic", "probe_timeout"}},
		{name: "unknown reason", mode: dp.Mode_MODE_QUIC, reason: dp.FallbackReason(9), labels: []string{"quic", "unknown"}},
		{name: "spare in PSP", mode: dp.Mode_MODE_PSP, spare: true, labels: []string{"psp", "spare"}},
		{name: "spare in QUIC", mode: dp.Mode_MODE_QUIC, reason: dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT, spare: true, labels: []string{"quic", "spare"}},
	}
	ca := newCA(t)
	h := newHarness(t, ca)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessions := testutil.ToFloat64(sessionsTotal.WithLabelValues(tc.labels...))
			connects := connectCount(t, tc.labels[0])

			a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
			st, err := a.c.Session(context.Background())
			require.NoError(t, err)
			require.NoError(t, st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{Mode: tc.mode, FallbackReason: tc.reason, Spare: tc.spare}}}))
			for _, want := range []string{"Welcome", "Config"} {
				m, err := st.Recv()
				require.NoError(t, err)
				require.NotNil(t, m.GetMsg(), "want %s", want)
			}
			assert.Equal(t, sessions+1, testutil.ToFloat64(sessionsTotal.WithLabelValues(tc.labels...)))

			// Only the first time to connect of a session counts.
			for range 2 {
				require.NoError(t, st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Status{Status: &dp.Status{ConnectTime: durationpb.New(120 * time.Millisecond)}}}))
			}
			// The call ends after the relay reads all messages.
			require.NoError(t, st.CloseSend())
			for {
				if _, err := st.Recv(); err != nil {
					break
				}
			}
			assert.Equal(t, connects+1, connectCount(t, tc.labels[0]))
		})
	}
}
