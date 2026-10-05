// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFwdSenders(t *testing.T) {
	cases := []struct {
		name        string
		procs, want int
	}{
		{"one CPU", 1, 1},
		{"two CPUs", 2, 1},
		{"three CPUs", 3, 1},
		{"four CPUs", 4, 2},
		{"five CPUs", 5, 2},
		{"six CPUs", 6, 3},
		{"eight CPUs", 8, 4},
		{"the upper limit", 9, maxFwdSenders},
		{"many CPUs", 192, maxFwdSenders},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, fwdSenders(tc.procs))
		})
	}
}
