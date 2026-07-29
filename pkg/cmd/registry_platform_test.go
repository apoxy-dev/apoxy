package cmd

import (
	"testing"

	"github.com/google/uuid"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
)

func TestRegistryHostForAPI(t *testing.T) {
	cases := []struct {
		name    string
		apiHost string
		want    string
	}{
		{"prod", "api.apoxy.dev", "registry.apoxy.dev"},
		{"staging", "api-staging.apoxy.dev", "registry.staging.apoxy.dev"},
		{"dev", "api.apoxy.localhost", "registry.apoxy.localhost"},
		{"empty", "", ""},
		{"unknown host", "api.example.com", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := registryHostForAPI(tc.apiHost); got != tc.want {
				t.Fatalf("registryHostForAPI(%q) = %q, want %q", tc.apiHost, got, tc.want)
			}
		})
	}
}

func TestProjectAPIHost(t *testing.T) {
	cases := []struct {
		name    string
		project configv1alpha1.Project
		want    string
	}{
		{"default hosted", configv1alpha1.Project{}, "api.apoxy.dev"},
		{"url", configv1alpha1.Project{APIBaseURL: "https://api-staging.apoxy.dev"}, "api-staging.apoxy.dev"},
		{"url with port", configv1alpha1.Project{APIBaseURL: "https://api.apoxy.localhost:8443"}, "api.apoxy.localhost"},
		{"host override wins", configv1alpha1.Project{APIBaseURL: "https://localhost:9050", APIBaseHost: "api.apoxy.localhost"}, "api.apoxy.localhost"},
		{"host override with port", configv1alpha1.Project{APIBaseHost: "api.apoxy.localhost:8443"}, "api.apoxy.localhost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := projectAPIHost(tc.project); got != tc.want {
				t.Fatalf("projectAPIHost(%+v) = %q, want %q", tc.project, got, tc.want)
			}
		})
	}
}

func TestPlatformRegistryTLSClientConfig(t *testing.T) {
	if cfg := (&platformRegistry{Host: "registry.apoxy.dev"}).tlsClientConfig(); cfg != nil {
		t.Fatalf("hosted registry must use default TLS verification, got %+v", cfg)
	}
	cfg := (&platformRegistry{Host: "registry.apoxy.localhost"}).tlsClientConfig()
	if cfg == nil || !cfg.InsecureSkipVerify {
		t.Fatalf("dev registry must skip TLS verification, got %+v", cfg)
	}
}

func TestPlatformRegistryDefaultRepo(t *testing.T) {
	id := uuid.MustParse("7ce458d7-e20c-443c-aeeb-dbc5663c1240")
	pr := &platformRegistry{Host: "registry.apoxy.dev", ProjectID: id}
	want := "registry.apoxy.dev/7ce458d7-e20c-443c-aeeb-dbc5663c1240/myworker"
	if got := pr.DefaultRepo("myworker"); got != want {
		t.Fatalf("DefaultRepo() = %q, want %q", got, want)
	}
}
