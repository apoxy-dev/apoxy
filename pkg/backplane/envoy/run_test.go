package envoy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	xdstypes "github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
)

func TestVendorEnvoyIfNotExists(t *testing.T) {
	payload := []byte("#!/bin/sh\necho envoy\n")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])

	cases := []struct {
		name string
		// checksum is the body of the ".sha256" file. An empty body is served
		// as 404.
		checksum string
		wantErr  string
	}{
		{
			name:     "checksum matches",
			checksum: digest,
		},
		{
			name:     "checksum file holds the file name",
			checksum: digest + "  envoy-1.35.13-linux-x86_64\n",
		},
		{
			name:     "checksum is in upper case",
			checksum: strings.ToUpper(digest),
		},
		{
			name:     "no checksum is published",
			checksum: "",
		},
		{
			name:     "checksum does not match",
			checksum: strings.Repeat("a", sha256HexLen),
			wantErr:  "envoy checksum mismatch",
		},
		{
			name:     "checksum is malformed",
			checksum: "not-a-digest",
			wantErr:  "is not a sha256 digest",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch req.URL.Path {
				case "/envoy":
					w.Write(payload)
				case "/envoy.sha256":
					if tc.checksum == "" {
						http.NotFound(w, req)
						return
					}
					w.Write([]byte(tc.checksum))
				default:
					http.NotFound(w, req)
				}
			}))
			defer srv.Close()

			dir := t.TempDir()
			path := filepath.Join(dir, "envoy")
			r := &Runtime{
				EnvoyPath: path,
				Release:   &URLRelease{URL: srv.URL + "/envoy"},
			}

			err := r.vendorEnvoyIfNotExists(context.Background())

			entries, readErr := os.ReadDir(dir)
			require.NoError(t, readErr)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Empty(t, entries, "no binary and no temporary file must be left")
				return
			}

			require.NoError(t, err)
			require.Len(t, entries, 1, "only the envoy binary must be left")
			assert.Equal(t, "envoy", entries[0].Name())

			got, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, payload, got)

			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
		})
	}
}

func TestVendorEnvoyIfNotExistsKeepsExistingBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "envoy")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0755))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		t.Errorf("unexpected download of %s", req.URL.Path)
	}))
	defer srv.Close()

	r := &Runtime{
		EnvoyPath: path,
		Release:   &URLRelease{URL: srv.URL + "/envoy"},
	}
	require.NoError(t, r.vendorEnvoyIfNotExists(context.Background()))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, []byte("old"), got)
}

// exitedProcess runs a short shell command and returns its final state.
func exitedProcess(t *testing.T, script string) *os.ProcessState {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	_ = cmd.Run()
	if cmd.ProcessState == nil {
		t.Skip("shell is not available")
	}
	return cmd.ProcessState
}

func TestExitReason(t *testing.T) {
	cases := []struct {
		name       string
		script     string
		nilState   bool
		wantReason string
		wantCode   string
	}{
		{
			name:       "process exits with an error code",
			script:     "exit 7",
			wantReason: ExitReasonExit,
			wantCode:   "7",
		},
		{
			name:       "process exits cleanly",
			script:     "exit 0",
			wantReason: ExitReasonExit,
			wantCode:   "0",
		},
		{
			name:       "process is terminated",
			script:     "kill -TERM $$",
			wantReason: ExitReasonSignal,
			wantCode:   "SIGTERM",
		},
		{
			name:       "process is killed",
			script:     "kill -KILL $$",
			wantReason: ExitReasonSignal,
			wantCode:   "SIGKILL",
		},
		{
			name:       "process never started",
			nilState:   true,
			wantReason: ExitReasonStartFailed,
			wantCode:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state *os.ProcessState
			if !tc.nilState {
				state = exitedProcess(t, tc.script)
			}

			reason, code := exitReason(state)

			assert.Equal(t, tc.wantReason, reason)
			assert.Equal(t, tc.wantCode, code)
		})
	}
}

func TestRecordExit(t *testing.T) {
	cases := []struct {
		name       string
		script     string
		err        error
		sample     *adminSample
		wantCode   int
		wantReason string
		wantKey    ExitKey
	}{
		{
			name:       "process exits with an error code",
			script:     "exit 7",
			err:        errors.New("exit status 7"),
			wantCode:   7,
			wantReason: ExitReasonExit,
			wantKey:    ExitKey{Reason: ExitReasonExit, Code: "7"},
		},
		{
			name:       "process exits cleanly",
			script:     "exit 0",
			wantCode:   0,
			wantReason: ExitReasonExit,
			wantKey:    ExitKey{Reason: ExitReasonExit, Code: "0"},
		},
		{
			name:       "process is killed while it serves traffic",
			script:     "kill -KILL $$",
			sample:     &adminSample{At: time.Now().UTC().Add(-2 * time.Second), RequestsInFlight: 12, Connections: 34},
			wantCode:   -1,
			wantReason: ExitReasonSignal,
			wantKey:    ExitKey{Reason: ExitReasonSignal, Code: "SIGKILL"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := exitedProcess(t, tc.script)

			startedAt := time.Now().Add(-time.Minute)
			r := &Runtime{}
			r.status.Running = true
			r.status.StartedAt = startedAt
			r.tel.lastSample = tc.sample

			before := time.Now().UTC()
			r.recordExit(state, tc.err, startedAt)
			got := r.RuntimeStatus()

			assert.False(t, got.Running)
			assert.Equal(t, state, got.ProcState)
			require.NotNil(t, got.LastExit)
			assert.Equal(t, state, got.LastExit.ProcState)
			assert.Equal(t, tc.err, got.LastExit.Err)
			assert.False(t, got.LastExit.At.Before(before))
			assert.Equal(t, tc.wantCode, got.ProcState.ExitCode())
			assert.NotEmpty(t, procStateString(got.ProcState))
			assert.Equal(t, tc.wantReason, got.LastExit.Reason)
			assert.Equal(t, tc.wantKey.Code, got.LastExit.Code)
			assert.Greater(t, got.LastExit.Uptime, 59*time.Second)
			assert.Equal(t, map[ExitKey]int64{tc.wantKey: 1}, got.ExitCounts)

			if tc.sample == nil {
				assert.Nil(t, got.LastExit.RequestsInFlight)
				assert.Nil(t, got.LastExit.Connections)
				return
			}
			require.NotNil(t, got.LastExit.RequestsInFlight)
			require.NotNil(t, got.LastExit.Connections)
			assert.Equal(t, int64(12), *got.LastExit.RequestsInFlight)
			assert.Equal(t, int64(34), *got.LastExit.Connections)
			assert.Greater(t, got.LastExit.SampleAge, time.Second)
		})
	}
}

func TestRecordExitCountsEveryExit(t *testing.T) {
	r := &Runtime{}

	r.recordExit(exitedProcess(t, "exit 1"), nil, time.Now())
	r.recordExit(exitedProcess(t, "exit 1"), nil, time.Now())
	r.recordExit(exitedProcess(t, "exit 0"), nil, time.Now())

	assert.Equal(t, map[ExitKey]int64{
		{Reason: ExitReasonExit, Code: "1"}: 2,
		{Reason: ExitReasonExit, Code: "0"}: 1,
	}, r.RuntimeStatus().ExitCounts)
}

func TestRecordExitWithoutProcessState(t *testing.T) {
	r := &Runtime{}
	r.status.Running = true

	r.recordExit(nil, errors.New("envoy did not start"), time.Time{})

	got := r.RuntimeStatus()
	assert.False(t, got.Running)
	assert.Nil(t, got.ProcState)
	require.NotNil(t, got.LastExit)
	assert.EqualError(t, got.LastExit.Err, "envoy did not start")
	assert.Equal(t, "unknown", procStateString(got.ProcState))
	assert.Equal(t, ExitReasonStartFailed, got.LastExit.Reason)
	assert.Empty(t, got.LastExit.Code)
	assert.Zero(t, got.LastExit.Uptime)
}

func TestRecordRestart(t *testing.T) {
	r := &Runtime{}
	assert.Equal(t, 0, r.RuntimeStatus().Restarts)

	r.recordRestart()
	r.recordRestart()

	assert.Equal(t, 2, r.RuntimeStatus().Restarts)
}

func TestExitMetadata(t *testing.T) {
	exitedAt := time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)

	cases := []struct {
		name         string
		metadata     *xdstypes.NodeMetadata
		restarts     int
		lastExit     *ExitInfo
		wantNil      bool
		wantRestarts int32
		wantExit     *xdstypes.NodeEnvoyExit
	}{
		{
			name:    "no metadata is configured",
			wantNil: true,
		},
		{
			name:     "first start carries no exit",
			metadata: &xdstypes.NodeMetadata{Name: "replica-1"},
		},
		{
			name:         "restart carries the last exit",
			metadata:     &xdstypes.NodeMetadata{Name: "replica-1"},
			restarts:     2,
			lastExit:     &ExitInfo{At: exitedAt, Reason: ExitReasonSignal, Code: "SIGSEGV"},
			wantRestarts: 2,
			wantExit: &xdstypes.NodeEnvoyExit{
				At:     metav1.NewTime(exitedAt),
				Reason: ExitReasonSignal,
				Code:   "SIGSEGV",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runtime{nodeMetadata: tc.metadata}
			r.status.Restarts = tc.restarts
			r.status.LastExit = tc.lastExit

			got := r.exitMetadata()

			if tc.wantNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, "replica-1", got.Name)
			assert.Equal(t, tc.wantRestarts, got.EnvoyRestarts)
			assert.Equal(t, tc.wantExit, got.LastEnvoyExit)
			// The runtime must not write into the configured metadata.
			assert.Zero(t, tc.metadata.EnvoyRestarts)
			assert.Nil(t, tc.metadata.LastEnvoyExit)
		})
	}
}

// captureLogs collects the attributes of one log record.
type captureLogs struct {
	level  slog.Level
	msg    string
	attrs  map[string]string
	called int
}

// Enabled implements the slog.Handler interface.
func (c *captureLogs) Enabled(context.Context, slog.Level) bool { return true }

// Handle implements the slog.Handler interface.
func (c *captureLogs) Handle(_ context.Context, rec slog.Record) error {
	c.called++
	c.level = rec.Level
	c.msg = rec.Message
	c.attrs = make(map[string]string, rec.NumAttrs())
	rec.Attrs(func(a slog.Attr) bool {
		c.attrs[a.Key] = a.Value.String()
		return true
	})
	return nil
}

// WithAttrs implements the slog.Handler interface.
func (c *captureLogs) WithAttrs([]slog.Attr) slog.Handler { return c }

// WithGroup implements the slog.Handler interface.
func (c *captureLogs) WithGroup(string) slog.Handler { return c }

func TestLogExit(t *testing.T) {
	requests := int64(7)
	connections := int64(11)

	cases := []struct {
		name      string
		lastExit  *ExitInfo
		wantCalls int
		wantLevel slog.Level
		wantAttrs map[string]string
	}{
		{
			name:      "no exit was recorded",
			wantCalls: 0,
		},
		{
			name: "clean exit",
			lastExit: &ExitInfo{
				At:     time.Now(),
				Reason: ExitReasonExit,
				Code:   "0",
				Uptime: time.Minute,
			},
			wantCalls: 1,
			wantLevel: slog.LevelInfo,
			wantAttrs: map[string]string{"reason": "exit", "code": "0", "uptime": "1m0s"},
		},
		{
			name: "kill with a sample",
			lastExit: &ExitInfo{
				At:                 time.Now(),
				Reason:             ExitReasonOOMKill,
				Code:               "SIGKILL",
				Uptime:             2 * time.Minute,
				RequestsInFlight:   &requests,
				Connections:        &connections,
				SampleAge:          3 * time.Second,
				ConnectionsAborted: 4,
				ConnectionsRefused: 5,
			},
			wantCalls: 1,
			wantLevel: slog.LevelError,
			wantAttrs: map[string]string{
				"reason":              "oom_kill",
				"code":                "SIGKILL",
				"requests_in_flight":  "7",
				"connections":         "11",
				"sample_age":          "3s",
				"connections_aborted": "4",
				"connections_refused": "5",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capture := &captureLogs{}
			previous := slog.Default()
			slog.SetDefault(slog.New(capture))
			t.Cleanup(func() { slog.SetDefault(previous) })

			r := &Runtime{}
			r.status.LastExit = tc.lastExit
			r.status.Restarts = 3

			r.logExit(context.Background(), 4242)

			require.Equal(t, tc.wantCalls, capture.called)
			if tc.wantCalls == 0 {
				return
			}
			assert.Equal(t, "Envoy exited", capture.msg)
			assert.Equal(t, tc.wantLevel, capture.level)
			for key, want := range tc.wantAttrs {
				assert.Equal(t, want, capture.attrs[key], key)
			}
			for _, key := range []string{"reason", "code", "core_dump", "uptime", "requests_in_flight",
				"connections", "sample_age", "connections_aborted", "connections_refused",
				"pid", "restarts", "release"} {
				assert.Contains(t, capture.attrs, key)
			}
			assert.Equal(t, "4242", capture.attrs["pid"])
			assert.Equal(t, "3", capture.attrs["restarts"])
		})
	}
}
