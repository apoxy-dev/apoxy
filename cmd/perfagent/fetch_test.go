package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	retryBase = time.Millisecond
}

func TestFetch(t *testing.T) {
	content := []byte("binary")
	sum := sha256Hex(content)
	var flaky atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write(content)
		case "/flaky":
			if flaky.Add(1) < 3 {
				http.Error(w, "slow down", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write(content)
		default:
			http.Error(w, "no such key", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cases := []struct {
		name    string
		file    File
		present []byte
		wantErr string
	}{
		{name: "URL", file: File{Name: "a", URL: srv.URL + "/ok", SHA256: sum}},
		{name: "URL after 503", file: File{Name: "a", URL: srv.URL + "/flaky", SHA256: sum}},
		{name: "URL with a bad sha256", file: File{Name: "a", URL: srv.URL + "/ok", SHA256: testSHA}, wantErr: "sha256 is"},
		{name: "URL not found", file: File{Name: "a", URL: srv.URL + "/none?X-Amz-Signature=secret", SHA256: sum}, wantErr: "HTTP 404"},
		{name: "present", file: File{Name: "a", SHA256: sum}, present: content},
		{name: "present with a bad sha256", file: File{Name: "a", SHA256: sum}, present: []byte("other"), wantErr: "sha256 is"},
		{name: "missing", file: File{Name: "a", SHA256: sum}, wantErr: "has no URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.present != nil {
				require.NoError(t, os.WriteFile(filepath.Join(dir, tc.file.Name), tc.present, 0o600))
			}
			err := fetch(context.Background(), srv.Client(), tc.file, dir, 0o755)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				assert.NotContains(t, err.Error(), "secret")
				return
			}
			require.NoError(t, err)
			st, err := os.Stat(filepath.Join(dir, tc.file.Name))
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o755), st.Mode().Perm())
		})
	}
}

func TestPut(t *testing.T) {
	var calls atomic.Int32
	var got []byte
	var length int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		if r.Method != http.MethodPut {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		length = r.ContentLength
		got, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()

	require.NoError(t, put(context.Background(), srv.Client(), srv.URL+"/key", []byte("results")))
	assert.Equal(t, int32(2), calls.Load())
	assert.Equal(t, int64(7), length)
	assert.Equal(t, "results", string(got))
}

func TestRedactURLError(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	_, err := get(context.Background(), client, "https://127.0.0.1:1/runs/x?X-Amz-Signature=secret")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "secret")
	assert.Contains(t, err.Error(), "https://127.0.0.1:1/runs/x")
}
