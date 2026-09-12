package envoy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCgroupReaderMemoryLimit(t *testing.T) {
	cases := []struct {
		name      string
		content   string
		absent    bool
		want      int64
		wantKnown bool
	}{
		{name: "limit is set", content: "2147483648\n", want: 2147483648, wantKnown: true},
		{name: "limit is unlimited", content: "max\n"},
		{name: "limit is not a number", content: "nope\n"},
		{name: "file is absent", absent: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if !tc.absent {
				require.NoError(t, os.WriteFile(filepath.Join(root, "memory.max"), []byte(tc.content), 0o644))
			}

			got, known := (&cgroupReader{root: root}).memoryLimit()

			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantKnown, known)
		})
	}
}

func TestCgroupReaderOOMKills(t *testing.T) {
	cases := []struct {
		name      string
		content   string
		absent    bool
		want      int64
		wantKnown bool
	}{
		{
			name:      "counter is published",
			content:   "low 0\nhigh 0\nmax 3\noom 2\noom_kill 1\n",
			want:      1,
			wantKnown: true,
		},
		{
			name:      "counter is zero",
			content:   "oom_kill 0\n",
			wantKnown: true,
		},
		{name: "counter is absent", content: "low 0\nhigh 0\n"},
		{name: "counter is not a number", content: "oom_kill x\n"},
		{name: "file is absent", absent: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if !tc.absent {
				require.NoError(t, os.WriteFile(filepath.Join(root, "memory.events"), []byte(tc.content), 0o644))
			}

			got, known := (&cgroupReader{root: root}).oomKills()

			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantKnown, known)
		})
	}
}

// useCgroupRoot points the runtime at a cgroup directory for the test.
func useCgroupRoot(t *testing.T, root string) {
	t.Helper()

	previous := defaultCgroupReader
	defaultCgroupReader = func() *cgroupReader { return &cgroupReader{root: root} }
	t.Cleanup(func() { defaultCgroupReader = previous })
}

func TestRecordExitReadsTheOOMKiller(t *testing.T) {
	cases := []struct {
		name       string
		script     string
		killsAtEnd string
		known      bool
		killsAt    int64
		wantReason string
	}{
		{
			name:       "kill after an OOM event",
			script:     "kill -KILL $$",
			killsAtEnd: "oom_kill 2\n",
			known:      true,
			killsAt:    1,
			wantReason: ExitReasonOOMKill,
		},
		{
			name:       "kill without an OOM event",
			script:     "kill -KILL $$",
			killsAtEnd: "oom_kill 1\n",
			known:      true,
			killsAt:    1,
			wantReason: ExitReasonSignal,
		},
		{
			name:       "cgroup does not publish the count",
			script:     "kill -KILL $$",
			wantReason: ExitReasonSignal,
		},
		{
			name:       "exit after an OOM event stays an exit",
			script:     "exit 1",
			killsAtEnd: "oom_kill 2\n",
			known:      true,
			killsAt:    1,
			wantReason: ExitReasonExit,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.killsAtEnd != "" {
				require.NoError(t, os.WriteFile(filepath.Join(root, "memory.events"), []byte(tc.killsAtEnd), 0o644))
			}
			useCgroupRoot(t, root)

			r := &Runtime{}
			r.tel.oomKills = tc.killsAt
			r.tel.oomKillsKnown = tc.known

			r.recordExit(exitedProcess(t, tc.script), nil, time.Now())

			got := r.RuntimeStatus()
			require.NotNil(t, got.LastExit)
			assert.Equal(t, tc.wantReason, got.LastExit.Reason)
		})
	}
}
