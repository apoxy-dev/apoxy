// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"testing"
	"time"
)

// TestLivenessObserve checks when the QUIC packet count of an agent makes it silent, and when
// it makes a silent agent normal again.
func TestLivenessObserve(t *testing.T) {
	type check struct {
		at      time.Duration // From the start of the connection.
		packets uint64        // The packet count at the check.
		silent  bool
	}
	cases := []struct {
		name    string
		noCount bool
		checks  []check
	}{
		{name: "packets keep coming", checks: []check{
			{2 * time.Second, 2, false}, {4 * time.Second, 4, false}, {8 * time.Second, 8, false},
		}},
		{name: "no packets after the start", checks: []check{
			{suspectAfter - livenessInterval, 0, false}, {suspectAfter, 0, true},
		}},
		{name: "packets stop", checks: []check{
			{time.Second, 1, false}, {time.Second + suspectAfter - livenessInterval, 1, false},
			{time.Second + suspectAfter, 1, true},
		}},
		{name: "silent agent answers for normalAfter", checks: []check{
			{suspectAfter, 0, true},
			{suspectAfter + time.Second, 1, true},
			{suspectAfter + 3*time.Second, 2, true},
			{suspectAfter + time.Second + normalAfter, 3, false},
		}},
		{name: "silence above normalQuiet starts normalAfter again", checks: []check{
			{suspectAfter, 0, true},
			{suspectAfter + time.Second, 1, true},
			{suspectAfter + time.Second + normalQuiet + livenessInterval, 2, true},
			{suspectAfter + time.Second + normalAfter, 3, true},
			{suspectAfter + 3*time.Second + normalAfter, 4, true},
			{suspectAfter + time.Second + normalQuiet + livenessInterval + normalAfter, 5, false},
		}},
		{name: "connection with no count", noCount: true, checks: []check{
			{suspectAfter, 0, false}, {2 * suspectAfter, 0, false},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Unix(1000, 0)
			var packets uint64
			l := liveness{last: start, since: start}
			if !tc.noCount {
				l.received = func() uint64 { return packets }
			}
			for _, c := range tc.checks {
				packets = c.packets
				if got := l.observe(start.Add(c.at)); got != c.silent {
					t.Fatalf("at %s with %d packets: silent is %t, want %t", c.at, c.packets, got, c.silent)
				}
			}
		})
	}
}
