package envoy

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const snmpFixture = `Ip: Forwarding DefaultTTL InReceives
Ip: 1 64 1234
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 8 9 2 41 5 100 110 1 0 77 0
Udp: InDatagrams NoPorts
Udp: 3 4
`

const netstatFixture = `TcpExt: SyncookiesSent ListenOverflows ListenDrops TCPAbortOnData TCPAbortOnClose
TcpExt: 0 12 13 14 15
IpExt: InNoRoutes InTruncatedPkts
IpExt: 1 2
`

func TestParseProcNetCounters(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		prefix string
		key    string
		want   int64
	}{
		{name: "tcp out resets", input: snmpFixture, prefix: "Tcp", key: "OutRsts", want: 77},
		{name: "tcp established resets", input: snmpFixture, prefix: "Tcp", key: "EstabResets", want: 41},
		{name: "negative value", input: snmpFixture, prefix: "Tcp", key: "MaxConn", want: -1},
		{name: "other protocol", input: snmpFixture, prefix: "Udp", key: "NoPorts", want: 4},
		{name: "listen overflows", input: netstatFixture, prefix: "TcpExt", key: "ListenOverflows", want: 12},
		{name: "abort on close", input: netstatFixture, prefix: "TcpExt", key: "TCPAbortOnClose", want: 15},
		{name: "unknown counter", input: netstatFixture, prefix: "TcpExt", key: "Nope", want: 0},
		{name: "empty input", input: "", prefix: "Tcp", key: "OutRsts", want: 0},
		{name: "header without values", input: "Tcp: OutRsts\n", prefix: "Tcp", key: "OutRsts", want: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseProcNetCounters([]byte(tc.input))

			assert.Equal(t, tc.want, got[tc.prefix][tc.key])
		})
	}
}

func TestParseMaxOpenFiles(t *testing.T) {
	const limits = `Limit                     Soft Limit           Hard Limit           Units
Max cpu time              unlimited            unlimited            seconds
Max open files            65535                1048576              files
`

	cases := []struct {
		name  string
		input string
		want  int64
	}{
		{name: "soft limit is a number", input: limits, want: 65535},
		{name: "limit is unlimited", input: "Max open files            unlimited            unlimited            files\n"},
		{name: "line is absent", input: "Max cpu time              unlimited\n"},
		{name: "file is empty"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseMaxOpenFiles([]byte(tc.input)))
		})
	}
}

func TestParseResidentBytes(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  int64
	}{
		{name: "resident pages", input: "1000 250 100 1 0 99 0\n", want: 250 * 4096},
		{name: "too few fields", input: "1000\n"},
		{name: "field is not a number", input: "1000 x\n"},
		{name: "file is empty"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseResidentBytes([]byte(tc.input), 4096))
		})
	}
}

func TestProcfsReadsProcessAndNetworkCounters(t *testing.T) {
	root := t.TempDir()
	pidDir := filepath.Join(root, "42")
	require.NoError(t, os.MkdirAll(filepath.Join(pidDir, "fd"), 0o755))
	for _, fd := range []string{"0", "1", "2"} {
		require.NoError(t, os.WriteFile(filepath.Join(pidDir, "fd", fd), nil, 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(pidDir, "limits"),
		[]byte("Max open files            65535                1048576              files\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(pidDir, "statm"), []byte("1000 250 100 1 0 99 0\n"), 0o644))

	require.NoError(t, os.MkdirAll(filepath.Join(root, "net"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "net", "snmp"), []byte(snmpFixture), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "net", "netstat"), []byte(netstatFixture), 0o644))

	p := &procfs{root: root, pageSize: 4096}

	ps, err := p.ProcessStats(42)
	require.NoError(t, err)
	assert.Equal(t, processStats{OpenFDs: 3, MaxFDs: 65535, RSSBytes: 250 * 4096}, ps)

	tc, err := p.TCPCounters()
	require.NoError(t, err)
	assert.Equal(t, tcpCounters{
		OutRsts:         77,
		EstabResets:     41,
		AbortOnClose:    15,
		AbortOnData:     14,
		ListenOverflows: 12,
		ListenDrops:     13,
	}, tc)

	_, err = p.ProcessStats(7)
	assert.Error(t, err)
}

// stubReaders is a process and network reader with fixed values.
type stubReaders struct {
	proc processStats
	tcp  tcpCounters
	err  error
}

// ProcessStats implements the processReader interface.
func (s *stubReaders) ProcessStats(int) (processStats, error) { return s.proc, s.err }

// TCPCounters implements the netReader interface.
func (s *stubReaders) TCPCounters() (tcpCounters, error) { return s.tcp, s.err }

// useStubReaders points the runtime at stub readers for the test.
func useStubReaders(t *testing.T, s *stubReaders) {
	t.Helper()

	previous := systemReaders
	systemReaders = func() (processReader, netReader) {
		if s == nil {
			return nil, nil
		}
		return s, s
	}
	t.Cleanup(func() { systemReaders = previous })
}

func TestCloseDownWindow(t *testing.T) {
	exitedAt := time.Now().Add(-2 * time.Second)

	cases := []struct {
		name        string
		lastSample  *tcpCounters
		atExit      tcpCounters
		atNextStart tcpCounters
		lastExit    *ExitInfo
		wantAborted int64
		wantRefused int64
	}{
		{
			name: "the kernel finished the resets after the exit",
			// The exit recorded 7 resets. The kernel reset the remaining
			// sockets while Envoy was gone, so the window holds all 18.
			lastSample:  &tcpCounters{EstabResets: 100, OutRsts: 500},
			atExit:      tcpCounters{EstabResets: 107, OutRsts: 505},
			atNextStart: tcpCounters{EstabResets: 118, OutRsts: 560},
			lastExit:    &ExitInfo{Reason: ExitReasonSignal, Code: "SIGKILL", ConnectionsAborted: 7},
			wantAborted: 18,
			wantRefused: 55,
		},
		{
			name:        "no connection was open and none arrived",
			lastSample:  &tcpCounters{EstabResets: 100, OutRsts: 500},
			atExit:      tcpCounters{EstabResets: 100, OutRsts: 500},
			atNextStart: tcpCounters{EstabResets: 100, OutRsts: 500},
			lastExit:    &ExitInfo{Reason: ExitReasonExit, Code: "0"},
		},
		{
			name:        "counters were reset",
			lastSample:  &tcpCounters{EstabResets: 100, OutRsts: 500},
			atExit:      tcpCounters{EstabResets: 107, OutRsts: 505},
			atNextStart: tcpCounters{},
			lastExit:    &ExitInfo{Reason: ExitReasonExit, Code: "0", ConnectionsAborted: 7},
		},
		{
			name:        "no sample was taken before the exit",
			atExit:      tcpCounters{OutRsts: 505},
			atNextStart: tcpCounters{EstabResets: 118, OutRsts: 560},
			lastExit:    &ExitInfo{Reason: ExitReasonExit, Code: "0"},
			wantRefused: 55,
		},
		{
			name:        "no exit was recorded",
			atExit:      tcpCounters{OutRsts: 505},
			atNextStart: tcpCounters{OutRsts: 560},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useStubReaders(t, &stubReaders{tcp: tc.atNextStart})

			r := &Runtime{}
			r.status.LastExit = tc.lastExit
			r.tel.window = &restartWindow{
				LastSample: tc.lastSample,
				AtExit:     tc.atExit,
				At:         exitedAt,
			}

			r.closeDownWindow(context.Background())

			assert.Nil(t, r.tel.window)
			if tc.lastExit == nil {
				assert.Nil(t, r.status.LastExit)
				return
			}
			require.NotNil(t, r.status.LastExit)
			assert.Equal(t, tc.wantAborted, r.status.LastExit.ConnectionsAborted)
			assert.Equal(t, tc.wantRefused, r.status.LastExit.ConnectionsRefused)
		})
	}
}

func TestCloseDownWindowLogsTheWindow(t *testing.T) {
	useStubReaders(t, &stubReaders{tcp: tcpCounters{EstabResets: 118, OutRsts: 560}})

	capture := &captureLogs{}
	previous := slog.Default()
	slog.SetDefault(slog.New(capture))
	t.Cleanup(func() { slog.SetDefault(previous) })

	r := &Runtime{}
	r.status.LastExit = &ExitInfo{Reason: ExitReasonSignal, Code: "SIGKILL", ConnectionsAborted: 7}
	r.tel.window = &restartWindow{
		LastSample: &tcpCounters{EstabResets: 100, OutRsts: 500},
		AtExit:     tcpCounters{EstabResets: 107, OutRsts: 505},
		At:         time.Now().Add(-2 * time.Second),
	}

	r.closeDownWindow(context.Background())

	require.Equal(t, 1, capture.called)
	assert.Equal(t, "Envoy restart window closed", capture.msg)
	assert.Equal(t, slog.LevelInfo, capture.level)
	assert.Equal(t, "18", capture.attrs["connections_aborted"])
	assert.Equal(t, "55", capture.attrs["connections_refused"])
	assert.Contains(t, capture.attrs, "down_window")
}

func TestRecordExitCountsAbortedConnections(t *testing.T) {
	cases := []struct {
		name        string
		lastSampled *tcpCounters
		atExit      tcpCounters
		readers     bool
		wantAborted int64
	}{
		{
			name: "connections were torn down at the exit",
			// An abort on close also resets an established connection, so
			// only EstabResets counts, and it counts one time. The value is a
			// floor until the next start closes the window.
			lastSampled: &tcpCounters{EstabResets: 10, AbortOnClose: 2, AbortOnData: 1},
			atExit:      tcpCounters{EstabResets: 42, AbortOnClose: 30, AbortOnData: 3},
			readers:     true,
			wantAborted: 32,
		},
		{
			name:        "no connection was torn down",
			lastSampled: &tcpCounters{EstabResets: 10},
			atExit:      tcpCounters{EstabResets: 10},
			readers:     true,
		},
		{
			name:        "counter was reset",
			lastSampled: &tcpCounters{EstabResets: 10},
			atExit:      tcpCounters{},
			readers:     true,
		},
		{
			name:    "no sample was taken before the exit",
			atExit:  tcpCounters{EstabResets: 42},
			readers: true,
		},
		{
			name:        "kernel counters are not readable",
			lastSampled: &tcpCounters{EstabResets: 10},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.readers {
				useStubReaders(t, &stubReaders{tcp: tc.atExit})
			} else {
				useStubReaders(t, nil)
			}

			r := &Runtime{}
			r.tel.lastTCP = tc.lastSampled

			r.recordExit(exitedProcess(t, "exit 0"), nil, time.Now())

			got := r.RuntimeStatus()
			require.NotNil(t, got.LastExit)
			assert.Equal(t, tc.wantAborted, got.LastExit.ConnectionsAborted)
			if !tc.readers {
				assert.Nil(t, r.tel.window)
				return
			}
			// The window keeps both bounds, so that the next start can count
			// the resets the kernel had not finished at the exit.
			require.NotNil(t, r.tel.window)
			assert.Equal(t, tc.atExit, r.tel.window.AtExit)
			assert.Equal(t, tc.lastSampled, r.tel.window.LastSample)
		})
	}
}

func TestSampleReadsTheProcessCounters(t *testing.T) {
	useStubReaders(t, &stubReaders{
		proc: processStats{OpenFDs: 9, MaxFDs: 1024, RSSBytes: 2048},
		tcp:  tcpCounters{OutRsts: 7},
	})

	r := &Runtime{}
	r.status.Running = true
	r.pid = 1234

	got := r.sample()

	require.NotNil(t, got.Process)
	assert.Equal(t, int64(9), got.Process.OpenFDs)
	require.NotNil(t, got.TCP)
	assert.Equal(t, int64(7), got.TCP.OutRsts)
}

func TestSampleLeavesOutTheProcessCountersWhileEnvoyIsDown(t *testing.T) {
	useStubReaders(t, &stubReaders{tcp: tcpCounters{OutRsts: 7}})

	r := &Runtime{}

	got := r.sample()

	assert.Nil(t, got.Process)
	require.NotNil(t, got.TCP)
}
