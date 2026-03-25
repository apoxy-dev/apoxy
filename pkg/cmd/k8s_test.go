package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOnboardingPath(t *testing.T) {
	got := onboardingPath("silent-hill", "gateway", "docker.io/apoxy/apoxy:v0.1.6-dev-849f400", "")
	want := "/v1/onboarding/k8s.yaml?cluster_name=silent-hill&image=docker.io%2Fapoxy%2Fapoxy%3Av0.1.6-dev-849f400&mirror=gateway"
	if got != want {
		t.Fatalf("onboardingPath() = %q, want %q", got, want)
	}
}

func TestOnboardingPathWithVersion(t *testing.T) {
	got := onboardingPath("silent-hill", "gateway", "", "v0.3.0")
	want := "/v1/onboarding/k8s.yaml?cluster_name=silent-hill&mirror=gateway&version=v0.3.0"
	if got != want {
		t.Fatalf("onboardingPath() = %q, want %q", got, want)
	}
}

func TestOnboardingPathWithoutParams(t *testing.T) {
	got := onboardingPath("", "", "", "")
	want := "/v1/onboarding/k8s.yaml"
	if got != want {
		t.Fatalf("onboardingPath() = %q, want %q", got, want)
	}
}

func TestLoadKubeClientConfigUsesCurrentContextByDefault(t *testing.T) {
	kubeconfig := writeTestKubeconfig(t)

	cfg, kubeContext, err := loadKubeClientConfig(kubeconfig, "")
	if err != nil {
		t.Fatalf("loadKubeClientConfig() error = %v", err)
	}

	if kubeContext != "kind-dev.local" {
		t.Fatalf("kube context = %q, want %q", kubeContext, "kind-dev.local")
	}
	if cfg.Host != "https://kind-dev.local.example" {
		t.Fatalf("host = %q, want %q", cfg.Host, "https://kind-dev.local.example")
	}
}

func TestLoadKubeClientConfigOverridesContext(t *testing.T) {
	kubeconfig := writeTestKubeconfig(t)

	cfg, kubeContext, err := loadKubeClientConfig(kubeconfig, "staging")
	if err != nil {
		t.Fatalf("loadKubeClientConfig() error = %v", err)
	}

	if kubeContext != "staging" {
		t.Fatalf("kube context = %q, want %q", kubeContext, "staging")
	}
	if cfg.Host != "https://staging.example" {
		t.Fatalf("host = %q, want %q", cfg.Host, "https://staging.example")
	}
}

func TestResolveKubeconfigPathPrefersExplicitPath(t *testing.T) {
	t.Setenv("KUBECONFIG", "/tmp/from-env")

	got := resolveKubeconfigPath("/tmp/from-flag")
	if got != "/tmp/from-flag" {
		t.Fatalf("resolveKubeconfigPath() = %q, want %q", got, "/tmp/from-flag")
	}
}

func TestResolveKubeconfigPathFallsBackToEnv(t *testing.T) {
	t.Setenv("KUBECONFIG", "/tmp/from-env")

	got := resolveKubeconfigPath("")
	if got != "/tmp/from-env" {
		t.Fatalf("resolveKubeconfigPath() = %q, want %q", got, "/tmp/from-env")
	}
}

func writeTestKubeconfig(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	data := []byte(`
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://kind-dev.local.example
  name: kind-dev.local
- cluster:
    server: https://staging.example
  name: staging
contexts:
- context:
    cluster: kind-dev.local
    user: test-user
  name: kind-dev.local
- context:
    cluster: staging
    user: test-user
  name: staging
current-context: kind-dev.local
users:
- name: test-user
  user:
    token: test-token
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	return path
}
