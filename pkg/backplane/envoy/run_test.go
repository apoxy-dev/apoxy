package envoy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

func TestRecordExit(t *testing.T) {
	cases := []struct {
		name     string
		script   string
		err      error
		wantCode int
	}{
		{
			name:     "process exits with an error code",
			script:   "exit 7",
			err:      errors.New("exit status 7"),
			wantCode: 7,
		},
		{
			name:     "process exits cleanly",
			script:   "exit 0",
			wantCode: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := exitedProcess(t, tc.script)

			r := &Runtime{}
			r.status.Running = true
			r.status.StartedAt = time.Now().Add(-time.Minute)

			before := time.Now().UTC()
			r.recordExit(state, tc.err)
			got := r.RuntimeStatus()

			assert.False(t, got.Running)
			assert.Equal(t, state, got.ProcState)
			require.NotNil(t, got.LastExit)
			assert.Equal(t, state, got.LastExit.ProcState)
			assert.Equal(t, tc.err, got.LastExit.Err)
			assert.False(t, got.LastExit.At.Before(before))
			assert.Equal(t, tc.wantCode, got.ProcState.ExitCode())
			assert.NotEmpty(t, procStateString(got.ProcState))
		})
	}
}

func TestRecordExitWithoutProcessState(t *testing.T) {
	r := &Runtime{}
	r.status.Running = true

	r.recordExit(nil, errors.New("envoy did not start"))

	got := r.RuntimeStatus()
	assert.False(t, got.Running)
	assert.Nil(t, got.ProcState)
	require.NotNil(t, got.LastExit)
	assert.EqualError(t, got.LastExit.Err, "envoy did not start")
	assert.Equal(t, "unknown", procStateString(got.ProcState))
}

func TestRecordRestart(t *testing.T) {
	r := &Runtime{}
	assert.Equal(t, 0, r.RuntimeStatus().Restarts)

	r.recordRestart()
	r.recordRestart()

	assert.Equal(t, 2, r.RuntimeStatus().Restarts)
}
