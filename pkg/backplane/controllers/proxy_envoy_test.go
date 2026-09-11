package controllers

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/backplane/envoy"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

func proxyWithEnvoy(cfg *corev1alpha2.EnvoyConfig) *corev1alpha2.Proxy {
	return &corev1alpha2.Proxy{
		Spec: corev1alpha2.ProxySpec{
			Envoy: cfg,
		},
	}
}

func TestEnvoyRelease(t *testing.T) {
	tests := []struct {
		name     string
		opts     *options
		proxy    *corev1alpha2.Proxy
		expected envoy.ReleaseDownloader
	}{
		{
			name: "release URL flag wins over the proxy",
			opts: &options{releaseURL: "https://flag/envoy", envoyVersion: "v1.35.13"},
			proxy: proxyWithEnvoy(&corev1alpha2.EnvoyConfig{
				Version:    "v1.36.1",
				ReleaseURL: "https://proxy/envoy",
			}),
			expected: &envoy.URLRelease{URL: "https://flag/envoy"},
		},
		{
			name: "proxy release URL wins over the versions",
			opts: &options{envoyVersion: "v1.35.13"},
			proxy: proxyWithEnvoy(&corev1alpha2.EnvoyConfig{
				Version:    "v1.36.1",
				ReleaseURL: "https://proxy/envoy",
			}),
			expected: &envoy.URLRelease{URL: "https://proxy/envoy"},
		},
		{
			name:     "proxy version wins over the version flag",
			opts:     &options{envoyVersion: "v1.35.13"},
			proxy:    proxyWithEnvoy(&corev1alpha2.EnvoyConfig{Version: "v1.36.1"}),
			expected: &envoy.GitHubRelease{Version: "v1.36.1"},
		},
		{
			name:     "proxy version gets a v prefix",
			opts:     &options{},
			proxy:    proxyWithEnvoy(&corev1alpha2.EnvoyConfig{Version: "1.36.1"}),
			expected: &envoy.GitHubRelease{Version: "v1.36.1"},
		},
		{
			name:     "proxy version keeps the contrib flag",
			opts:     &options{useEnvoyContrib: true},
			proxy:    proxyWithEnvoy(&corev1alpha2.EnvoyConfig{Version: "v1.36.1"}),
			expected: &envoy.GitHubRelease{Version: "v1.36.1", Contrib: true},
		},
		{
			name:     "empty proxy config falls back to the version flag",
			opts:     &options{envoyVersion: "v1.35.13"},
			proxy:    proxyWithEnvoy(&corev1alpha2.EnvoyConfig{}),
			expected: &envoy.GitHubRelease{Version: "v1.35.13"},
		},
		{
			name:     "proxy without an envoy config falls back to the version flag",
			opts:     &options{envoyVersion: "v1.35.13"},
			proxy:    proxyWithEnvoy(nil),
			expected: &envoy.GitHubRelease{Version: "v1.35.13"},
		},
		{
			name:     "version flag without a proxy",
			opts:     &options{envoyVersion: envoy.DefaultVersion},
			proxy:    nil,
			expected: &envoy.GitHubRelease{Version: envoy.DefaultVersion},
		},
		{
			name:     "contrib flag without a version",
			opts:     &options{useEnvoyContrib: true},
			proxy:    nil,
			expected: &envoy.GitHubRelease{Contrib: true},
		},
		{
			name:     "no release is selected",
			opts:     &options{},
			proxy:    nil,
			expected: nil,
		},
		{
			name:     "no release is selected for an empty proxy config",
			opts:     &options{},
			proxy:    proxyWithEnvoy(&corev1alpha2.EnvoyConfig{}),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ProxyReconciler{options: tt.opts}
			assert.Equal(t, tt.expected, r.envoyRelease(tt.proxy))
		})
	}
}

// warnRecorder collects the warnings that a test logs.
type warnRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (h *warnRecorder) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *warnRecorder) Handle(_ context.Context, rec slog.Record) error {
	if rec.Level != slog.LevelWarn {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, rec.Message)
	return nil
}

func (h *warnRecorder) WithAttrs(_ []slog.Attr) slog.Handler { return h }

func (h *warnRecorder) WithGroup(_ string) slog.Handler { return h }

func TestWarnOnEnvoyReleaseChange(t *testing.T) {
	rec := &warnRecorder{}
	logger := slog.New(rec)

	r := &ProxyReconciler{options: &options{envoyVersion: "v1.35.13"}}
	r.Runtime.Release = &envoy.GitHubRelease{Version: "v1.35.13"}

	// The same new release warns one time only.
	changed := proxyWithEnvoy(&corev1alpha2.EnvoyConfig{Version: "v1.36.1"})
	r.warnOnEnvoyReleaseChange(changed, logger)
	r.warnOnEnvoyReleaseChange(changed, logger)
	require.Len(t, rec.msgs, 1)
	assert.Contains(t, rec.msgs[0], "restart the backplane")

	// A different release warns again.
	r.warnOnEnvoyReleaseChange(proxyWithEnvoy(&corev1alpha2.EnvoyConfig{Version: "v1.37.0"}), logger)
	require.Len(t, rec.msgs, 2)

	// The running release raises no warning.
	r.warnOnEnvoyReleaseChange(proxyWithEnvoy(&corev1alpha2.EnvoyConfig{Version: "v1.35.13"}), logger)
	assert.Len(t, rec.msgs, 2)
}
