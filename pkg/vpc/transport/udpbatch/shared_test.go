// SPDX-License-Identifier: AGPL-3.0-only

package udpbatch

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// fakeRaw is a RawConn that counts its calls.
type fakeRaw struct {
	controlErr       error
	controls, writes int
}

func (f *fakeRaw) Control(fn func(uintptr)) error {
	f.controls++
	if f.controlErr == nil {
		fn(3)
	}
	return f.controlErr
}

func (f *fakeRaw) Read(func(uintptr) bool) error { return nil }

func (f *fakeRaw) Write(fn func(uintptr) bool) error {
	f.writes++
	for !fn(3) {
	}
	return nil
}

// TestSharedRawWrite checks that a write uses the write lock of the socket only
// when the socket cannot take the data at once.
func TestSharedRawWrite(t *testing.T) {
	cases := []struct {
		name       string
		refusals   int // The calls that the socket refuses before it takes the data.
		controlErr error
		wantCalls  int
		wantWrites int
	}{
		{name: "socket takes the data", wantCalls: 1},
		{name: "socket is full", refusals: 1, wantCalls: 2, wantWrites: 1},
		{name: "socket stays full", refusals: 3, wantCalls: 4, wantWrites: 1},
		{name: "socket is closed", controlErr: net.ErrClosed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := &fakeRaw{controlErr: tc.controlErr}
			r := newSharedRaw(raw)
			calls := 0
			// Two writes show that the state of one write does not stay for the next.
			for range 2 {
				calls = 0
				err := r.Write(func(fd uintptr) bool {
					assert.Equal(t, uintptr(3), fd)
					calls++
					return calls > tc.refusals
				})
				assert.ErrorIs(t, err, tc.controlErr)
				assert.Equal(t, tc.wantCalls, calls)
			}
			assert.Equal(t, 2, raw.controls)
			assert.Equal(t, 2*tc.wantWrites, raw.writes)
		})
	}
}
