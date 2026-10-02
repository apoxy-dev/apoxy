package main

import (
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProcStat(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    cpuTimes
		wantErr bool
	}{
		{
			name: "full line",
			in:   "cpu  19648 100 21103 623682 74618 50 15809 0 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n",
			want: cpuTimes{User: 197.48, System: 211.03, IRQ: 158.59, Idle: 6983},
		},
		{
			name: "steal",
			in:   "cpu 100 0 100 650 50 0 0 100 0 0\n",
			want: cpuTimes{User: 1, System: 1, Idle: 7, Steal: 1},
		},
		{
			name: "old kernel with 7 values",
			in:   "cpu 100 0 200 300 0 0 50\n",
			want: cpuTimes{User: 1, System: 2, IRQ: 0.5, Idle: 3},
		},
		{name: "short line", in: "cpu 1 2 3\n", wantErr: true},
		{name: "bad number", in: "cpu a 0 0 0 0 0 0 0\n", wantErr: true},
		{name: "no cpu line", in: "intr 1 2 3\n", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseProcStat(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.InDelta(t, tc.want.User, got.User, 1e-9)
			assert.InDelta(t, tc.want.System, got.System, 1e-9)
			assert.InDelta(t, tc.want.IRQ, got.IRQ, 1e-9)
			assert.InDelta(t, tc.want.Idle, got.Idle, 1e-9)
			assert.InDelta(t, tc.want.Steal, got.Steal, 1e-9)
		})
	}
}

func TestStealPercent(t *testing.T) {
	start := cpuTimes{User: 10, System: 5, IRQ: 1, Idle: 100, Steal: 2}
	cases := []struct {
		name string
		end  cpuTimes
		want float64
	}{
		{name: "no time", end: start, want: 0},
		{name: "no steal", end: cpuTimes{User: 20, System: 10, IRQ: 2, Idle: 200, Steal: 2}, want: 0},
		{name: "steal", end: cpuTimes{User: 14, System: 7, IRQ: 1, Idle: 128, Steal: 8}, want: 15},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.InDelta(t, tc.want, stealPercent(start, tc.end), 1e-9)
		})
	}
}

func TestParseCPUInfo(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "x86",
			in:   "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz\nprocessor\t: 1\nmodel name\t: other\n",
			want: "Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz",
		},
		{
			name: "arm64",
			in:   "processor\t: 0\nBogoMIPS\t: 48.00\nCPU implementer\t: 0x61\nCPU architecture: 8\nCPU part\t: 0x039\n\nprocessor\t: 1\nCPU implementer\t: 0x41\nCPU part\t: 0xd0c\n",
			want: "implementer 0x61 part 0x039",
		},
		{name: "empty", in: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseCPUInfo(tc.in))
		})
	}
}

func TestParseLoadAvg(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    float64
		wantErr bool
	}{
		{name: "normal", in: "13.48 15.10 17.43 9/1820 81285\n", want: 13.48},
		{name: "empty", in: "\n", wantErr: true},
		{name: "not a number", in: "x 1 2\n", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLoadAvg(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParsePIDStat(t *testing.T) {
	const tail = " 0 -1 4194560 100 0 0 0 250 130 7 3 20 0 1 0 100 0 0\n"
	cases := []struct {
		name    string
		in      string
		want    pidStat
		wantErr bool
	}{
		{name: "normal", in: "1234 (iperf3) S 1 1234 1234" + tail, want: pidStat{ppid: 1, utime: 250, stime: 130, cutime: 7, cstime: 3}},
		{name: "comm with spaces and parens", in: "77 (a) b (c)) R 70 70 70" + tail, want: pidStat{ppid: 70, utime: 250, stime: 130, cutime: 7, cstime: 3}},
		{name: "short", in: "1 (x) S 1 1 1 0\n", wantErr: true},
		{name: "no comm", in: "1 x S 1 1 1" + tail, wantErr: true},
		{name: "bad ppid", in: "1 (x) S a 1 1" + tail, wantErr: true},
		{name: "bad time", in: "1 (x) S 1 1 1 0 -1 0 0 0 0 0 a 0 0 0\n", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePIDStat(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTreeCPU(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs /proc")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestTreeCPUHelper$")
	cmd.Env = append(os.Environ(), "PERFRIG_TREE_HELPER=parent")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = cmd.Wait()
	})

	require.Eventually(t, func() bool {
		u, s, err := treeCPU(pid)
		return err == nil && u+s >= 0.3
	}, 1500*time.Millisecond, 50*time.Millisecond)

	require.NoError(t, syscall.Kill(-pid, syscall.SIGKILL))
	_ = cmd.Wait()
	_, _, err := treeCPU(pid)
	require.ErrorIs(t, err, errNoProcess)
}

// TestTreeCPUHelper is not a test. For TestTreeCPU, the parent starts a child in
// a new process group that uses CPU for 2 s, then sleeps.
func TestTreeCPUHelper(t *testing.T) {
	switch os.Getenv("PERFRIG_TREE_HELPER") {
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=^TestTreeCPUHelper$")
		child.Env = append(os.Environ(), "PERFRIG_TREE_HELPER=spin")
		child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		_ = child.Run()
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "spin":
		for end := time.Now().Add(2 * time.Second); time.Now().Before(end); {
		}
		os.Exit(0)
	}
}

func TestParseSocket(t *testing.T) {
	cases := []struct {
		in      string
		want    Socket
		wantErr bool
	}{
		{in: "tcp:5201", want: Socket{Proto: "tcp", Port: 5201}},
		{in: "udp:4433", want: Socket{Proto: "udp", Port: 4433}},
		{in: "none", want: Socket{}},
		{in: "", want: Socket{}},
		{in: "sctp:1", wantErr: true},
		{in: "tcp", wantErr: true},
		{in: "tcp:0", wantErr: true},
		{in: "udp:70000", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseSocket(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTableHasSocket(t *testing.T) {
	const tcp = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1451 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0200C80A:D2F0 0200C80A:1451 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 20 4 30 10 -1
`
	const tcp6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1151 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
`
	const udp = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:115C 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4 2 0000000000000000 0
`
	cases := []struct {
		name  string
		table string
		s     Socket
		want  bool
	}{
		{name: "tcp listen", table: tcp, s: Socket{Proto: "tcp", Port: 5201}, want: true},
		{name: "tcp other port", table: tcp, s: Socket{Proto: "tcp", Port: 5202}, want: false},
		{name: "tcp established only", table: tcp, s: Socket{Proto: "tcp", Port: 53999}, want: false},
		{name: "tcp6 listen", table: tcp6, s: Socket{Proto: "tcp", Port: 4433}, want: true},
		{name: "udp bound", table: udp, s: Socket{Proto: "udp", Port: 4444}, want: true},
		{name: "header only", table: "  sl  local_address\n", s: Socket{Proto: "tcp", Port: 5201}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tableHasSocket(tc.table, tc.s))
		})
	}
}
