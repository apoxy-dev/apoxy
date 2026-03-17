package v1alpha2

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
			name:     "cloud provider with empty telemetry is valid",
			provider: InfraProviderCloud,
			telemetry: &ProxyTelementry{},
			wantErrs: 0,
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
				AccessLogs: &ProxyAccessLogs{JSON: map[string]string{"k": "v"}},
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
