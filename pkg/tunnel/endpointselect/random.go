package endpointselect

import (
	"context"
	"errors"
	"math/rand"
	"time"
)

// RandomSelector selects a random endpoint from the list.
type RandomSelector struct{}

// NewRandomSelector creates a new RandomSelector.
func NewRandomSelector() *RandomSelector {
	return &RandomSelector{}
}

// Select returns a random endpoint from the list.
func (s *RandomSelector) Select(ctx context.Context, endpoints []string) (string, error) {
	addr, _, err := s.SelectWithResults(ctx, endpoints)
	return addr, err
}

// SelectWithResults returns a random endpoint along with a single result entry.
func (s *RandomSelector) SelectWithResults(ctx context.Context, endpoints []string) (string, []ProbeResult, error) {
	if len(endpoints) == 0 {
		return "", nil, errors.New("no endpoints provided")
	}

	selected := endpoints[rand.Intn(len(endpoints))]
	result := []ProbeResult{{
		Addr:     selected,
		ProbedAt: time.Now(),
	}}

	return selected, result, nil
}
