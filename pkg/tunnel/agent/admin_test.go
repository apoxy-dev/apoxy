package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConnectionTracker(t *testing.T) {
	cases := []struct {
		name       string
		required   int
		active     int32
		wantActive int
		wantNeeded int
		wantReady  bool
	}{
		{name: "zero required clamps to one", required: 0, wantNeeded: 1},
		{name: "below target is not ready", required: 2, active: 1, wantActive: 1, wantNeeded: 2},
		{name: "target is ready", required: 2, active: 2, wantActive: 2, wantNeeded: 2, wantReady: true},
		{name: "above target stays ready", required: 2, active: 3, wantActive: 3, wantNeeded: 2, wantReady: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tracker := NewConnectionTracker(tc.required)
			for range tc.active {
				tracker.ConnectionOpened()
			}
			require.Equal(t, tc.wantActive, tracker.ActiveConnections())
			require.Equal(t, tc.wantNeeded, tracker.RequiredConnections())
			require.Equal(t, tc.wantReady, tracker.Ready())
		})
	}
}

func TestConnectionTrackerHandlers(t *testing.T) {
	cases := []struct {
		name       string
		required   int
		active     int32
		handler    func(*ConnectionTracker) http.HandlerFunc
		wantStatus int
		wantBody   string
	}{
		{
			name:       "liveness does not depend on connections",
			required:   2,
			handler:    func(*ConnectionTracker) http.HandlerFunc { return LivenessHandler },
			wantStatus: http.StatusOK,
			wantBody:   "process is live",
		},
		{
			name:       "readiness fails below target",
			required:   2,
			active:     1,
			handler:    func(tracker *ConnectionTracker) http.HandlerFunc { return tracker.ReadinessHandler },
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "1/2",
		},
		{
			name:       "readiness succeeds at target",
			required:   2,
			active:     2,
			handler:    func(tracker *ConnectionTracker) http.HandlerFunc { return tracker.ReadinessHandler },
			wantStatus: http.StatusOK,
			wantBody:   "2/2",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tracker := NewConnectionTracker(tc.required)
			for range tc.active {
				tracker.ConnectionOpened()
			}
			rec := httptest.NewRecorder()
			tc.handler(tracker)(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			require.Equal(t, tc.wantStatus, rec.Code)
			require.Contains(t, rec.Body.String(), tc.wantBody)
		})
	}
}
