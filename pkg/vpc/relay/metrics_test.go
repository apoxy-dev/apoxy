// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"strconv"
	"strings"
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

// TestSessionVersionMetric checks the labels of the session counter by
// version. The counter by mode and reason does not change.
func TestSessionVersionMetric(t *testing.T) {
	rev := strconv.FormatUint(uint64(dp.Revision), 10)
	cases := []struct {
		name    string
		version *dp.Version // Nil means an agent from before revisions.
		labels  []string
	}{
		{name: "agent from before revisions", labels: []string{"0", "unknown"}},
		{name: "release build", version: &dp.Version{Revision: dp.Revision, Build: "1.2.3"}, labels: []string{rev, "1.2.3"}},
		{name: "no build", version: &dp.Version{Revision: dp.Revision}, labels: []string{rev, "unknown"}},
		{name: "build with other characters", version: &dp.Version{Revision: dp.Revision, Build: "1.2.3 (a b)"}, labels: []string{rev, "1.2.3__a_b_"}},
	}
	ca := newCA(t)
	h := newHarness(t, ca)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			versions := testutil.ToFloat64(sessionVersions.WithLabelValues(tc.labels...))
			sessions := testutil.ToFloat64(sessionsTotal.WithLabelValues("psp", "none"))

			a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
			st := hello(t, a, &dp.Hello{Mode: dp.Mode_MODE_PSP, Version: tc.version})
			for _, want := range []string{"Welcome", "Config"} {
				m, err := st.Recv()
				require.NoError(t, err)
				require.NotNil(t, m.GetMsg(), "want %s", want)
			}
			assert.Equal(t, versions+1, testutil.ToFloat64(sessionVersions.WithLabelValues(tc.labels...)))
			assert.Equal(t, sessions+1, testutil.ToFloat64(sessionsTotal.WithLabelValues("psp", "none")))
		})
	}
}

func TestBuildLabel(t *testing.T) {
	cases := []struct {
		name  string
		build string
		want  string
	}{
		{name: "release", build: "0.23.1", want: "0.23.1"},
		{name: "pseudo-version", build: "0.23.2-0.20261006074632-e30585d6232e", want: "0.23.2-0.20261006074632-e30585d6232e"},
		{name: "build metadata", build: "v1.0.0+local_tree", want: "v1.0.0+local_tree"},
		{name: "empty", build: "", want: "unknown"},
		{name: "space and quotes", build: `v1 "x"`, want: "v1__x_"},
		{name: "label syntax", build: `a",b="c`, want: "a__b__c"},
		{name: "control and other bytes", build: "v1\n\x00\xc3\xa9", want: "v1____"},
		{name: "too long", build: strings.Repeat("a", 100), want: strings.Repeat("a", maxBuildLabel)},
		{name: "too long with other characters", build: strings.Repeat("a b", 100), want: strings.Repeat("a_b", 14)[:maxBuildLabel]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, buildLabel(tc.build))
		})
	}
}

// TestVersionLabels checks that the label set keeps a fixed number of pairs.
func TestVersionLabels(t *testing.T) {
	var l versionLabelSet
	rev := strconv.FormatUint(uint64(dp.Revision), 10)
	assert.Equal(t, []string{"0", "unknown"}, l.of(nil))
	for i := 1; i < maxVersionLabels; i++ {
		build := "build-" + strconv.Itoa(i)
		assert.Equal(t, []string{rev, build}, l.of(&dp.Version{Revision: dp.Revision, Build: build}))
	}
	cases := []struct {
		name    string
		version *dp.Version
		want    []string
	}{
		{name: "new build of a revision of this relay", version: &dp.Version{Revision: dp.Revision, Build: "new"}, want: []string{rev, "other"}},
		{name: "new build of revision 0", version: &dp.Version{Build: "new"}, want: []string{"0", "other"}},
		{name: "new build of a later revision", version: &dp.Version{Revision: dp.Revision + 1, Build: "new"}, want: []string{"other", "other"}},
		{name: "revision with no upper limit", version: &dp.Version{Revision: 1 << 31}, want: []string{"other", "other"}},
		{name: "pair from before the limit", version: &dp.Version{Revision: dp.Revision, Build: "build-1"}, want: []string{rev, "build-1"}},
		{name: "agent from before revisions", want: []string{"0", "unknown"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A pair over the limit does not take a place, so each case runs two times.
			for range 2 {
				assert.Equal(t, tc.want, l.of(tc.version))
			}
		})
	}
	assert.Len(t, l.seen, maxVersionLabels)
}
