package cmd

import (
	"encoding/json"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func serviceWithOCI(oci map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "compute.apoxy.dev/v1alpha1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "api"},
		"spec": map[string]any{
			"source": map[string]any{"oci": oci},
		},
	}}
}

func ociFromDoc(t *testing.T, doc []byte) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(doc, &got); err != nil {
		t.Fatalf("unmarshaling apply doc: %v", err)
	}
	oci, found, err := unstructured.NestedMap(got, "spec", "source", "oci")
	if err != nil || !found {
		t.Fatalf("apply doc has no spec.source.oci (found=%v, err=%v): %s", found, err, doc)
	}
	return oci
}

// TestManifestApplyDoc_OmitsDigest is the regression test for the re-deploy
// field-ownership conflict: the manifest manager must not claim
// spec.source.oci.digest, which deployFieldManager owns via applyDigestPin.
// Claiming it under both is what made every re-deploy of changed code fail with
// `conflict with "apoxy-deploy": .spec.source.oci.digest`.
func TestManifestApplyDoc_OmitsDigest(t *testing.T) {
	tests := []struct {
		name string
		oci  map[string]any
	}{
		{
			name: "digest resolved by a previous deploy",
			oci: map[string]any{
				"repo":   "registry.apoxy.dev/proj/api",
				"digest": "sha256:cdd30143029f908e3338c9528904f2f8b4375d7623b4af1354d39f7d8332b6fb",
			},
		},
		{
			// The shape cookbook manifests use: an empty digest placeholder
			// keeping `oci` a non-empty map.
			name: "empty digest placeholder in the file",
			oci: map[string]any{
				"repo":   "registry.apoxy.dev/proj/api",
				"digest": "",
			},
		},
		{
			name: "no digest at all",
			oci:  map[string]any{"repo": "registry.apoxy.dev/proj/api"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := manifestApplyDoc(serviceWithOCI(tc.oci))
			if err != nil {
				t.Fatalf("manifestApplyDoc() error = %v", err)
			}
			oci := ociFromDoc(t, doc)
			if got, ok := oci["digest"]; ok {
				t.Errorf("apply doc claims spec.source.oci.digest = %v; it must be left to %q", got, deployFieldManager)
			}
			// Repo is required by the CRD, so stripping the digest must not
			// take it with it or a first-ever deploy would fail validation.
			if got := oci["repo"]; got != "registry.apoxy.dev/proj/api" {
				t.Errorf("apply doc repo = %v, want the manifest's repo preserved", got)
			}
		})
	}
}

// TestManifestApplyDoc_DoesNotMutateInput guards the caller: applyDigestPin
// reads identity off the same object after the manifest apply, and a future
// caller may read the digest off it too.
func TestManifestApplyDoc_DoesNotMutateInput(t *testing.T) {
	const dig = "sha256:cdd30143029f908e3338c9528904f2f8b4375d7623b4af1354d39f7d8332b6fb"
	svc := serviceWithOCI(map[string]any{
		"repo":   "registry.apoxy.dev/proj/api",
		"digest": dig,
	})

	if _, err := manifestApplyDoc(svc); err != nil {
		t.Fatalf("manifestApplyDoc() error = %v", err)
	}

	got, found, err := unstructured.NestedString(svc.Object, "spec", "source", "oci", "digest")
	if err != nil || !found {
		t.Fatalf("input Service lost spec.source.oci.digest (found=%v, err=%v)", found, err)
	}
	if got != dig {
		t.Errorf("input Service digest = %q, want %q unchanged", got, dig)
	}
}
