package v1alpha2

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func defaultedProxy(provider InfraProvider, tel *ProxyTelementry) *Proxy {
	p := &Proxy{
		Spec: ProxySpec{
			Provider:  provider,
			Telemetry: tel,
		},
	}
	p.Default()
	return p
}

func TestValidate_CloudTelemetryRejected(t *testing.T) {
	msg := "telemetry settings are not configurable for cloud proxies; use CloudMonitoringIntegration instead"

	tests := []struct {
		name      string
		provider  InfraProvider
		telemetry *ProxyTelementry
		wantErrs  int
		wantField string
	}{
		{
			name:     "cloud provider with nil telemetry is valid",
			provider: InfraProviderCloud,
			wantErrs: 0,
		},
		{
			name:     "empty provider (defaults to cloud) with nil telemetry is valid",
			provider: "",
			wantErrs: 0,
		},
		{
			name:      "cloud provider with empty telemetry is valid",
			provider:  InfraProviderCloud,
			telemetry: &ProxyTelementry{},
			wantErrs:  0,
		},
		{
			name:     "cloud provider with accessLogs rejected",
			provider: InfraProviderCloud,
			telemetry: &ProxyTelementry{
				AccessLogs: &ProxyAccessLogs{
					JSON: map[string]string{"key": "value"},
				},
			},
			wantErrs:  1,
			wantField: "spec.telemetry.accessLogs",
		},
		{
			name:     "cloud provider with contentLogs rejected",
			provider: InfraProviderCloud,
			telemetry: &ProxyTelementry{
				ContentLogs: &ProxyContentLogs{RequestBodyEnabled: true},
			},
			wantErrs:  1,
			wantField: "spec.telemetry.contentLogs",
		},
		{
			name:     "cloud provider with tracing rejected",
			provider: InfraProviderCloud,
			telemetry: &ProxyTelementry{
				Tracing: &ProxyTracing{Enabled: true},
			},
			wantErrs:  1,
			wantField: "spec.telemetry.tracing",
		},
		{
			name:     "cloud provider with otelCollectorConfig rejected",
			provider: InfraProviderCloud,
			telemetry: &ProxyTelementry{
				OtelCollectorConfig: &LocalObjectReference{Name: "cfg"},
			},
			wantErrs:  1,
			wantField: "spec.telemetry.otelCollectorConfig",
		},
		{
			name:     "cloud provider with thirdPartySinks rejected",
			provider: InfraProviderCloud,
			telemetry: &ProxyTelementry{
				ThirdPartySinks: &ThirdPartySinks{
					DatadogLogs: &APIKey{Key: "key"},
				},
			},
			wantErrs:  1,
			wantField: "spec.telemetry.thirdPartySinks",
		},
		{
			name:     "cloud provider with multiple telemetry fields rejected",
			provider: "",
			telemetry: &ProxyTelementry{
				AccessLogs:  &ProxyAccessLogs{JSON: map[string]string{"k": "v"}},
				Tracing:     &ProxyTracing{Enabled: true},
				ContentLogs: &ProxyContentLogs{RequestBodyEnabled: true},
			},
			wantErrs: 3,
		},
		{
			name:     "kubernetes provider with telemetry is valid",
			provider: InfraProviderKubernetes,
			telemetry: &ProxyTelementry{
				Tracing: &ProxyTracing{Enabled: true},
			},
			wantErrs: 0,
		},
		{
			name:     "unmanaged provider with telemetry is valid",
			provider: InfraProviderUnmanaged,
			telemetry: &ProxyTelementry{
				AccessLogs:          &ProxyAccessLogs{JSON: map[string]string{"k": "v"}},
				OtelCollectorConfig: &LocalObjectReference{Name: "cfg"},
			},
			wantErrs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := defaultedProxy(tt.provider, tt.telemetry)
			errs := p.Validate(context.Background())
			if len(errs) != tt.wantErrs {
				t.Errorf("Validate() returned %d errors, want %d: %v", len(errs), tt.wantErrs, errs)
			}
			if tt.wantField != "" && len(errs) > 0 {
				if errs[0].Field != tt.wantField {
					t.Errorf("Validate() error field = %q, want %q", errs[0].Field, tt.wantField)
				}
			}
			if tt.wantErrs > 0 {
				for _, e := range errs {
					if e.Detail != msg {
						t.Errorf("Validate() error detail = %q, want %q", e.Detail, msg)
					}
				}
			}
		})
	}
}

func TestValidateUpdate_CloudTelemetryRejected(t *testing.T) {
	old := defaultedProxy(InfraProviderCloud, nil)
	updated := defaultedProxy(InfraProviderCloud, &ProxyTelementry{
		Tracing: &ProxyTracing{Enabled: true},
	})

	errs := old.ValidateUpdate(context.Background(), updated)
	if len(errs) != 1 {
		t.Fatalf("ValidateUpdate() returned %d errors, want 1: %v", len(errs), errs)
	}
	if errs[0].Field != "spec.telemetry.tracing" {
		t.Errorf("ValidateUpdate() error field = %q, want %q", errs[0].Field, "spec.telemetry.tracing")
	}
}

func TestValidate_DrainTimeout(t *testing.T) {
	p := &Proxy{
		Spec: ProxySpec{
			Provider: InfraProviderKubernetes,
			Shutdown: &ShutdownConfig{
				DrainTimeout:     &metav1.Duration{Duration: 10 * time.Second},
				MinimumDrainTime: &metav1.Duration{Duration: 30 * time.Second},
			},
		},
	}
	p.Default()

	errs := p.Validate(context.Background())
	if len(errs) != 1 {
		t.Fatalf("Validate() returned %d errors, want 1: %v", len(errs), errs)
	}
	if errs[0].Field != "spec.shutdown.minimumDrainTime" {
		t.Errorf("Validate() error field = %q, want %q", errs[0].Field, "spec.shutdown.minimumDrainTime")
	}
}

func defaultedEnvoyProxy(provider InfraProvider, envoy *EnvoyConfig) *Proxy {
	p := &Proxy{
		Spec: ProxySpec{
			Provider: provider,
			Envoy:    envoy,
		},
	}
	p.Default()
	return p
}

func TestValidate_Envoy(t *testing.T) {
	type wantErr struct {
		field string
		typ   field.ErrorType
	}

	cases := []struct {
		name     string
		provider InfraProvider
		envoy    *EnvoyConfig
		want     []wantErr
	}{
		{
			name:     "unmanaged provider without envoy settings",
			provider: InfraProviderUnmanaged,
		},
		{
			name:     "empty envoy settings are allowed",
			provider: InfraProviderUnmanaged,
			envoy:    &EnvoyConfig{},
		},
		{
			name:     "version with a leading v",
			provider: InfraProviderUnmanaged,
			envoy:    &EnvoyConfig{Version: "v1.35.13"},
		},
		{
			name:     "version without a leading v",
			provider: InfraProviderUnmanaged,
			envoy:    &EnvoyConfig{Version: "1.35.13"},
		},
		{
			name:     "version and release URL together",
			provider: InfraProviderUnmanaged,
			envoy: &EnvoyConfig{
				Version:    "v1.35.13",
				ReleaseURL: "https://example.com/envoy-static",
			},
		},
		{
			name:     "kubernetes provider can set envoy settings",
			provider: InfraProviderKubernetes,
			envoy:    &EnvoyConfig{Version: "v1.35.13"},
		},
		{
			name:     "version is not a release tag",
			provider: InfraProviderUnmanaged,
			envoy:    &EnvoyConfig{Version: "latest"},
			want:     []wantErr{{"spec.envoy.version", field.ErrorTypeInvalid}},
		},
		{
			name:     "version misses the patch number",
			provider: InfraProviderUnmanaged,
			envoy:    &EnvoyConfig{Version: "v1.35"},
			want:     []wantErr{{"spec.envoy.version", field.ErrorTypeInvalid}},
		},
		{
			name:     "release URL with a different scheme",
			provider: InfraProviderUnmanaged,
			envoy:    &EnvoyConfig{ReleaseURL: "ftp://example.com/envoy-static"},
			want:     []wantErr{{"spec.envoy.releaseURL", field.ErrorTypeInvalid}},
		},
		{
			name:     "release URL without a scheme",
			provider: InfraProviderUnmanaged,
			envoy:    &EnvoyConfig{ReleaseURL: "example.com/envoy-static"},
			want:     []wantErr{{"spec.envoy.releaseURL", field.ErrorTypeInvalid}},
		},
		{
			name:     "release URL without a host",
			provider: InfraProviderUnmanaged,
			envoy:    &EnvoyConfig{ReleaseURL: "https:///envoy-static"},
			want:     []wantErr{{"spec.envoy.releaseURL", field.ErrorTypeInvalid}},
		},
		{
			name:     "release URL that does not parse",
			provider: InfraProviderUnmanaged,
			envoy:    &EnvoyConfig{ReleaseURL: "https://exa mple.com/%zz"},
			want:     []wantErr{{"spec.envoy.releaseURL", field.ErrorTypeInvalid}},
		},
		{
			name:     "cloud provider cannot set envoy settings",
			provider: InfraProviderCloud,
			envoy:    &EnvoyConfig{Version: "v1.35.13"},
			want:     []wantErr{{"spec.envoy", field.ErrorTypeForbidden}},
		},
		{
			name:  "empty provider defaults to cloud",
			envoy: &EnvoyConfig{},
			want:  []wantErr{{"spec.envoy", field.ErrorTypeForbidden}},
		},
		{
			name:     "cloud provider with a bad version reports both",
			provider: InfraProviderCloud,
			envoy:    &EnvoyConfig{Version: "latest"},
			want: []wantErr{
				{"spec.envoy", field.ErrorTypeForbidden},
				{"spec.envoy.version", field.ErrorTypeInvalid},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := defaultedEnvoyProxy(tc.provider, tc.envoy)
			errs := p.Validate(context.Background())
			require.Len(t, errs, len(tc.want), "errors: %v", errs)
			for i, w := range tc.want {
				assert.Equal(t, w.field, errs[i].Field)
				assert.Equal(t, w.typ, errs[i].Type)
				if w.typ == field.ErrorTypeForbidden {
					assert.Equal(t, "envoy settings are not configurable for cloud proxies", errs[i].Detail)
				}
			}
		})
	}
}
