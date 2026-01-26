// Package endpointselect provides endpoint selection strategies for tunnel connections.
package endpointselect

import (
	"context"
	"fmt"
	"time"
)

// SelectionStrategy defines the type for endpoint selection strategies.
type SelectionStrategy string

const (
	// StrategyLatency selects the endpoint with the lowest latency.
	StrategyLatency SelectionStrategy = "latency"
	// StrategyRandom selects a random endpoint.
	StrategyRandom SelectionStrategy = "random"
)

// ProbeResult contains the result of probing a single endpoint.
type ProbeResult struct {
	// Addr is the endpoint address that was probed.
	Addr string
	// Latency is the measured latency for the endpoint.
	// Zero if the probe failed.
	Latency time.Duration
	// Error contains any error that occurred during probing.
	Error error
	// ProbedAt is the time when the probe was performed.
	ProbedAt time.Time
}

// Selector is the interface for endpoint selection strategies.
type Selector interface {
	// Select returns the best endpoint from the given list based on
	// the selection strategy. Returns an error if no endpoint could be selected.
	Select(ctx context.Context, endpoints []string) (string, error)

	// SelectWithResults returns the best endpoint along with all probe results.
	// This is useful for logging and debugging.
	SelectWithResults(ctx context.Context, endpoints []string) (string, []ProbeResult, error)
}

// NewSelector creates a new Selector based on the given strategy.
func NewSelector(strategy SelectionStrategy, opts ...Option) (Selector, error) {
	switch strategy {
	case StrategyLatency:
		return NewLatencySelector(opts...), nil
	case StrategyRandom:
		return NewRandomSelector(), nil
	default:
		return nil, fmt.Errorf("unknown endpoint selection strategy: %s", strategy)
	}
}

// ParseStrategy parses a string into a SelectionStrategy.
func ParseStrategy(s string) (SelectionStrategy, error) {
	switch s {
	case string(StrategyLatency):
		return StrategyLatency, nil
	case string(StrategyRandom):
		return StrategyRandom, nil
	default:
		return "", fmt.Errorf("unknown endpoint selection strategy: %s", s)
	}
}
