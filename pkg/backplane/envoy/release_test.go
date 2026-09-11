package envoy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindLatestVersion(t *testing.T) {
	tests := []struct {
		name     string
		versions []string
		expected string
	}{
		{
			name:     "empty list",
			versions: []string{},
			expected: "",
		},
		{
			name:     "single version",
			versions: []string{"1.0.0"},
			expected: "1.0.0",
		},
		{
			name:     "semver with v prefix",
			versions: []string{"v1.0.0", "v1.1.0", "v0.9.0"},
			expected: "v1.1.0",
		},
		{
			name:     "semver without v prefix",
			versions: []string{"1.0.0", "1.1.0", "0.9.0"},
			expected: "1.1.0",
		},
		{
			name:     "mixed semver with and without v prefix",
			versions: []string{"v1.0.0", "1.1.0", "v0.9.0"},
			expected: "1.1.0",
		},
		{
			name:     "real envoy versions",
			versions: []string{"v1.22.0", "v1.23.1", "v1.21.5", "v1.24.0"},
			expected: "v1.24.0",
		},
		{
			name:     "non-semver versions",
			versions: []string{"alpha", "beta", "rc1", "stable"},
			expected: "stable",
		},
		{
			name:     "mixed format versions",
			versions: []string{"1.0", "1.0.1", "1"},
			expected: "1.0.1",
		},
		{
			name:     "random version strings",
			versions: []string{"20220101", "20230101", "20210101"},
			expected: "20230101",
		},
		{
			name:     "complex mixed versions",
			versions: []string{"v1.2.3-alpha", "1.2.3", "v1.2.3-rc1", "v1.2.3"},
			expected: "v1.2.3-rc1", // Note: string comparison puts "-" after letters
		},
		{
			name:     "sha mixed versions",
			versions: []string{"v1.2.3@sha256:1234567890", "v1.2.2", "v1.2.3-rc1", "v1.2.3"},
			expected: "v1.2.3@sha256:1234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findLatestVersion(tt.versions)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseChecksum(t *testing.T) {
	digest := strings.Repeat("ab", 32)

	tests := []struct {
		name     string
		body     string
		expected string
		wantErr  bool
	}{
		{
			name:     "digest only",
			body:     digest,
			expected: digest,
		},
		{
			name:     "digest and file name",
			body:     digest + "  envoy-1.35.13-linux-x86_64\n",
			expected: digest,
		},
		{
			name:     "upper case digest",
			body:     strings.ToUpper(digest),
			expected: digest,
		},
		{
			name:    "empty file",
			body:    "  \n",
			wantErr: true,
		},
		{
			name:    "digest is too short",
			body:    digest[:63],
			wantErr: true,
		},
		{
			name:    "digest is not hexadecimal",
			body:    strings.Repeat("z", 64),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sum, err := parseChecksum(tt.body)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, sum)
		})
	}
}

func TestFetchChecksum(t *testing.T) {
	digest := strings.Repeat("cd", 32)

	tests := []struct {
		name     string
		status   int
		body     string
		expected string
		wantErr  bool
	}{
		{
			name:     "checksum is published",
			status:   http.StatusOK,
			body:     digest,
			expected: digest,
		},
		{
			name:   "checksum is not published",
			status: http.StatusNotFound,
		},
		{
			name:   "server fails",
			status: http.StatusInternalServerError,
		},
		{
			name:    "checksum is malformed",
			status:  http.StatusOK,
			body:    "not-a-digest",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				require.Equal(t, "/envoy.sha256", req.URL.Path)
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			sum, err := fetchChecksum(context.Background(), srv.URL+"/envoy")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, sum)
		})
	}
}

func TestURLReleaseDownloadChecksum(t *testing.T) {
	digest := strings.Repeat("ef", 32)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		require.Equal(t, "/bin/envoy.sha256", req.URL.Path)
		w.Write([]byte(digest + "  envoy\n"))
	}))
	defer srv.Close()

	r := &URLRelease{URL: srv.URL + "/bin/envoy"}
	sum, err := r.DownloadChecksum(context.Background())
	require.NoError(t, err)
	assert.Equal(t, digest, sum)
}

func TestGitHubReleaseBinaryURL(t *testing.T) {
	tests := []struct {
		name    string
		release *GitHubRelease
		expects string
	}{
		{
			name:    "release binary",
			release: &GitHubRelease{Version: "v1.35.13"},
			expects: "https://github.com/envoyproxy/envoy/releases/download/v1.35.13/envoy-1.35.13-",
		},
		{
			name:    "contrib binary",
			release: &GitHubRelease{Version: "v1.35.13", Contrib: true},
			expects: "https://github.com/envoyproxy/envoy/releases/download/v1.35.13/envoy-contrib-1.35.13-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := tt.release.binaryURL(context.Background())
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(url, tt.expects), "unexpected URL %s", url)
		})
	}
}
