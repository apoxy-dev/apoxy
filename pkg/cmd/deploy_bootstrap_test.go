package cmd

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestGenerateServiceName(t *testing.T) {
	// DNS-1123 label: lowercase alphanumerics and dashes, must start and end
	// with an alphanumeric, at most 63 chars.
	valid := regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	for i := 0; i < 100; i++ {
		name := generateServiceName()
		if !valid.MatchString(name) || len(name) > 63 {
			t.Fatalf("generated name %q is not a valid DNS-1123 label", name)
		}
		if !strings.Contains(name, "-") {
			t.Fatalf("generated name %q is not adjective-noun shaped", name)
		}
	}
}

func TestBootstrapServiceManifest(t *testing.T) {
	cases := []struct {
		name     string
		svcName  string
		repo     string
		wantRepo bool
	}{
		{name: "with repo", svcName: "elegant-turing", repo: "registry.example.com/elegant-turing", wantRepo: true},
		{name: "without repo", svcName: "bold-hopper", repo: "", wantRepo: false},
		{name: "repo with port", svcName: "swift-curie", repo: "127.0.0.1:5005/swift-curie", wantRepo: true},
		{name: "repo needing YAML quoting", svcName: "calm-bohr", repo: "registry.example.com/calm-bohr #1", wantRepo: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "service.yaml")
			if err := writeBootstrapManifest(path, tc.svcName, tc.repo); err != nil {
				t.Fatalf("writeBootstrapManifest: %v", err)
			}

			// The generated file must round-trip through the same loader
			// deploy uses, and carry exactly the fields the user chose.
			svc, err := loadComputeService(path)
			if err != nil {
				t.Fatalf("loadComputeService on generated manifest: %v", err)
			}
			if got := svc.GetName(); got != tc.svcName {
				t.Errorf("name = %q, want %q", got, tc.svcName)
			}
			gotRepo, found, err := unstructured.NestedString(svc.Object, "spec", "source", "oci", "repo")
			if err != nil {
				t.Fatalf("reading repo from generated manifest: %v", err)
			}
			if tc.wantRepo && gotRepo != tc.repo {
				t.Errorf("repo = %q, want %q", gotRepo, tc.repo)
			}
			if !tc.wantRepo && found {
				t.Errorf("manifest should omit spec.source.oci.repo when no repo given, got %q", gotRepo)
			}

			// A second write must refuse to clobber the file.
			if err := writeBootstrapManifest(path, "other", ""); err == nil {
				t.Error("second writeBootstrapManifest should fail on existing file")
			}
		})
	}
}
