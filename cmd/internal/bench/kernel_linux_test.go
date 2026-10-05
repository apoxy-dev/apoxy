// SPDX-License-Identifier: AGPL-3.0-only

package bench

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestKernel writes the kernel counters through the marks of the profiles.
// Without the rights for BPF, the files have only the counters of /proc.
func TestKernel(t *testing.T) {
	cases := []struct {
		name   string
		window time.Duration
		files  []string
	}{
		{name: "sampler from the start", files: []string{"-1.txt", "-2.txt"}},
		{name: "sampler from the middle", window: 60 * time.Millisecond, files: []string{"-1.txt", "-m.txt", "-2.txt"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefix := filepath.Join(t.TempDir(), "k")
			r, err := Profiles{Kernel: prefix}.Start()
			require.NoError(t, err)
			err = r.Mark(1, tc.window)
			bpf := err == nil
			if !bpf && !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EACCES) {
				require.NoError(t, err)
			}
			time.Sleep(tc.window + 50*time.Millisecond)
			if err := r.Mark(2, 0); bpf {
				require.NoError(t, err)
			}
			require.NoError(t, r.Stop())
			for _, name := range tc.files {
				b, err := os.ReadFile(prefix + name)
				require.NoError(t, err)
				for _, part := range []string{"## time\n", "## /proc/stat\n", "## /proc/softirqs\n", "## ksoftirqd\n"} {
					assert.Contains(t, string(b), part, name)
				}
				assert.Equal(t, bpf, strings.Contains(string(b), "## irqtime\n"), name)
			}
			if !bpf {
				t.Skip("no rights for BPF programs")
			}
			b, err := os.ReadFile(prefix + "-stacks.txt")
			require.NoError(t, err)
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			assert.True(t, strings.HasPrefix(lines[0], "# period_ns 2003000 "), lines[0])
			require.Greater(t, len(lines), 2, "the sampler got no stack")
			assert.True(t, strings.HasPrefix(lines[1], "s "), lines[1])
			assert.True(t, strings.HasPrefix(lines[len(lines)-1], "c "), lines[len(lines)-1])
		})
	}
}

// TestKernelEndBeforeMiddle ends the window before the sampler starts.
func TestKernelEndBeforeMiddle(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "k")
	r, err := Profiles{Kernel: prefix}.Start()
	require.NoError(t, err)
	_ = r.Mark(1, time.Hour)
	_ = r.Mark(2, 0)
	require.NoError(t, r.Stop())
	_, err = os.Stat(prefix + "-2.txt")
	require.NoError(t, err)
	_, err = os.Stat(prefix + "-m.txt")
	assert.ErrorIs(t, err, os.ErrNotExist)
}
