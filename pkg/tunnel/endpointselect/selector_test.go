package endpointselect

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRandomSelector_Select(t *testing.T) {
	t.Run("returns error for empty endpoints", func(t *testing.T) {
		s := NewRandomSelector()
		_, err := s.Select(context.Background(), []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no endpoints")
	})

	t.Run("returns single endpoint", func(t *testing.T) {
		s := NewRandomSelector()
		addr, err := s.Select(context.Background(), []string{"192.0.2.1:9443"})
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.1:9443", addr)
	})

	t.Run("returns one of multiple endpoints", func(t *testing.T) {
		s := NewRandomSelector()
		endpoints := []string{"192.0.2.1:9443", "192.0.2.2:9443", "192.0.2.3:9443"}

		// Run multiple times to verify randomness.
		results := make(map[string]int)
		for i := 0; i < 100; i++ {
			addr, err := s.Select(context.Background(), endpoints)
			require.NoError(t, err)
			results[addr]++
		}

		// All endpoints should be selected at least once.
		for _, ep := range endpoints {
			assert.Contains(t, results, ep, "endpoint %s was never selected", ep)
		}
	})

	t.Run("SelectWithResults returns result", func(t *testing.T) {
		s := NewRandomSelector()
		addr, results, err := s.SelectWithResults(context.Background(), []string{"192.0.2.1:9443"})
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.1:9443", addr)
		require.Len(t, results, 1)
		assert.Equal(t, "192.0.2.1:9443", results[0].Addr)
		assert.WithinDuration(t, time.Now(), results[0].ProbedAt, time.Second)
	})
}

func TestLatencySelector_Select(t *testing.T) {
	t.Run("returns error for empty endpoints", func(t *testing.T) {
		s := NewLatencySelector()
		_, err := s.Select(context.Background(), []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no endpoints")
	})

	t.Run("returns single endpoint without probing", func(t *testing.T) {
		s := NewLatencySelector()
		addr, results, err := s.SelectWithResults(context.Background(), []string{"192.0.2.1:9443"})
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.1:9443", addr)
		require.Len(t, results, 1)
		// Single endpoint should not have latency measured.
		assert.Zero(t, results[0].Latency)
	})

	t.Run("returns error when all probes fail", func(t *testing.T) {
		s := NewLatencySelector(
			WithProbeTimeout(100*time.Millisecond),
			WithInsecureSkipVerify(true),
		)
		// Use invalid addresses that will fail to connect.
		endpoints := []string{"192.0.2.1:9443", "192.0.2.2:9443"}

		_, results, err := s.SelectWithResults(context.Background(), endpoints)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "all endpoint probes failed")
		require.Len(t, results, 2)
		// All results should have errors.
		for _, r := range results {
			assert.Error(t, r.Error)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		s := NewLatencySelector(
			WithProbeTimeout(5*time.Second),
			WithInsecureSkipVerify(true),
		)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately.

		_, err := s.Select(ctx, []string{"192.0.2.1:9443", "192.0.2.2:9443"})
		require.Error(t, err)
	})

	t.Run("options are applied", func(t *testing.T) {
		s := NewLatencySelector(
			WithProbeTimeout(500*time.Millisecond),
			WithMaxConcurrent(5),
			WithInsecureSkipVerify(true),
		)
		assert.Equal(t, 500*time.Millisecond, s.opts.probeTimeout)
		assert.Equal(t, 5, s.opts.maxConcurrent)
		assert.True(t, s.opts.insecureSkip)
	})
}

func TestNewSelector(t *testing.T) {
	t.Run("creates latency selector", func(t *testing.T) {
		s, err := NewSelector(StrategyLatency)
		require.NoError(t, err)
		assert.IsType(t, &LatencySelector{}, s)
	})

	t.Run("creates random selector", func(t *testing.T) {
		s, err := NewSelector(StrategyRandom)
		require.NoError(t, err)
		assert.IsType(t, &RandomSelector{}, s)
	})

	t.Run("returns error for unknown strategy", func(t *testing.T) {
		_, err := NewSelector(SelectionStrategy("unknown"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown endpoint selection strategy")
	})
}

func TestParseStrategy(t *testing.T) {
	tests := []struct {
		input    string
		expected SelectionStrategy
		wantErr  bool
	}{
		{"latency", StrategyLatency, false},
		{"random", StrategyRandom, false},
		{"unknown", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			strategy, err := ParseStrategy(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, strategy)
			}
		})
	}
}
