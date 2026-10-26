// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNameThread names the OS thread of the caller and gives back its old name. The kernel keeps
// the first 15 bytes, and a name with a NUL byte does not change the name.
func TestNameThread(t *testing.T) {
	cases := []struct {
		name string
		set  string
		want string
	}{
		{name: "short", set: "relay-test", want: "relay-test"},
		{name: "kick", set: KickThread, want: KickThread},
		{name: "long", set: "relay-name-longer-than-15", want: "relay-name-long"},
		{name: "nul", set: "bad\x00name", want: "first"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var old, comm, back string
			var err error
			done := make(chan struct{})
			go func() {
				defer close(done)
				// The Go runtime keeps the main thread when its locked goroutine ends, so it gets its
				// old name back.
				runtime.LockOSThread()
				defer nameThread(nameThread("first"))
				old = nameThread(tc.set)
				var b []byte
				b, err = os.ReadFile("/proc/thread-self/comm")
				comm = strings.TrimSuffix(string(b), "\n")
				back = nameThread("last")
			}()
			<-done
			require.NoError(t, err)
			assert.Equal(t, "first", old)
			assert.Equal(t, tc.want, comm)
			assert.Equal(t, tc.want, back)
		})
	}
}
