package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExitCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{name: "ok", want: 0},
		{name: "error", err: errors.New("client failed"), want: 1},
		{name: "regression", err: fmt.Errorf("%w: 1 of 2 results failed", errRegression), want: 1},
		{name: "infra", err: fmt.Errorf("%w: %w", errInfra, errSteal), want: 3},
		{name: "regression and infra", err: errors.Join(errRegression, errInfra), want: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, exitCode(tc.err))
		})
	}
}

func TestStealErr(t *testing.T) {
	cases := []struct {
		name    string
		steal   float64
		max     float64
		wantErr string
	}{
		{name: "no check", steal: 50, max: -1},
		{name: "no steal at max 0", steal: 0, max: 0},
		{name: "steal at max 0", steal: 0.01, max: 0, wantErr: "too much CPU steal: 0.01% in rep 2, -max-steal is 0%"},
		{name: "at the limit", steal: 5, max: 5},
		{name: "above the limit", steal: 7.1, max: 5, wantErr: "too much CPU steal: 7.10% in rep 2, -max-steal is 5%"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := stealErr(Run{Rep: 2, StealPercent: tc.steal}, tc.max)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, errSteal)
			assert.EqualError(t, err, tc.wantErr)
		})
	}
}
