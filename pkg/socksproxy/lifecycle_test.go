package socksproxy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestComputeConnDeadline(t *testing.T) {
	start := time.Unix(1000, 0)
	now := time.Unix(1100, 0) // 100s after start

	tests := []struct {
		name     string
		idle     time.Duration
		maxLife  time.Duration
		wantSet  bool
		wantTime time.Time
	}{
		{
			name:    "both disabled -> no deadline",
			idle:    0,
			maxLife: 0,
			wantSet: false,
		},
		{
			name:     "idle only -> now+idle",
			idle:     30 * time.Second,
			maxLife:  0,
			wantSet:  true,
			wantTime: now.Add(30 * time.Second),
		},
		{
			name:     "maxLife only -> start+maxLife",
			idle:     0,
			maxLife:  500 * time.Second,
			wantSet:  true,
			wantTime: start.Add(500 * time.Second),
		},
		{
			name:     "both, idle is earlier -> idle wins",
			idle:     30 * time.Second,
			maxLife:  500 * time.Second, // start+500 = 1500 ; now+30 = 1130 -> idle earlier
			wantSet:  true,
			wantTime: now.Add(30 * time.Second),
		},
		{
			name:     "both, maxLife is earlier -> maxLife wins",
			idle:     300 * time.Second, // now+300 = 1400
			maxLife:  150 * time.Second, // start+150 = 1150 -> maxLife earlier
			wantSet:  true,
			wantTime: start.Add(150 * time.Second),
		},
		{
			name:    "negative durations disabled",
			idle:    -1 * time.Second,
			maxLife: -1 * time.Second,
			wantSet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := computeConnDeadline(start, tt.idle, tt.maxLife, now)
			require.Equal(t, tt.wantSet, ok)
			if tt.wantSet {
				require.True(t, got.Equal(tt.wantTime), "want %v got %v", tt.wantTime, got)
			}
		})
	}
}
