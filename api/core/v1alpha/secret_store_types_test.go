package v1alpha

import (
	"testing"
)

func TestParseScope(t *testing.T) {
	cases := []struct {
		name        string
		scope       string
		wantSurface string
		wantGlob    string
		wantErr     bool
	}{
		{name: "bare surface", scope: "compute", wantSurface: "compute", wantGlob: "*"},
		{name: "surface with glob", scope: "compute:frontend-*", wantSurface: "compute", wantGlob: "frontend-*"},
		{name: "surface with exact name", scope: "compute:api", wantSurface: "compute", wantGlob: "api"},
		{name: "empty surface", scope: ":x", wantErr: true},
		{name: "empty glob", scope: "compute:", wantErr: true},
		{name: "empty scope", scope: "", wantErr: true},
		{name: "invalid glob", scope: `compute:[`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			surface, glob, err := ParseScope(tc.scope)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseScope(%q) = (%q, %q), want error", tc.scope, surface, glob)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseScope(%q): %v", tc.scope, err)
			}
			if surface != tc.wantSurface || glob != tc.wantGlob {
				t.Errorf("ParseScope(%q) = (%q, %q), want (%q, %q)", tc.scope, surface, glob, tc.wantSurface, tc.wantGlob)
			}
		})
	}
}

func TestScopeAllows(t *testing.T) {
	cases := []struct {
		name    string
		scopes  []string
		surface string
		useName string
		want    bool
	}{
		{name: "empty scopes admit everyone", scopes: nil, surface: "compute", useName: "anything", want: true},
		{name: "bare surface admits any name", scopes: []string{"compute"}, surface: "compute", useName: "web-1", want: true},
		{name: "bare surface rejects other surface", scopes: []string{"compute"}, surface: "gateway", useName: "web-1", want: false},
		{name: "glob match", scopes: []string{"compute:frontend-*"}, surface: "compute", useName: "frontend-a", want: true},
		{name: "glob mismatch", scopes: []string{"compute:frontend-*"}, surface: "compute", useName: "backend-a", want: false},
		{name: "exact name", scopes: []string{"compute:api"}, surface: "compute", useName: "api", want: true},
		{name: "any of several scopes", scopes: []string{"gateway", "compute:web-*"}, surface: "compute", useName: "web-2", want: true},
		{name: "invalid scope entries are skipped", scopes: []string{":", "compute:web-*"}, surface: "compute", useName: "web-2", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &SecretStore{Spec: SecretStoreSpec{Scopes: tc.scopes}}
			if got := s.ScopeAllows(tc.surface, tc.useName); got != tc.want {
				t.Errorf("ScopeAllows(%q, %q) with scopes %v = %v, want %v", tc.surface, tc.useName, tc.scopes, got, tc.want)
			}
		})
	}
}

func TestComputeKeyStatus(t *testing.T) {
	got := ComputeKeyStatus(map[string]string{"b": "2", "a": "1"})
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "b" {
		t.Fatalf("keys = %+v, want sorted [a b]", got)
	}
	for _, k := range got {
		if len(k.Digest) != len("sha256:")+8 || k.Digest[:7] != "sha256:" {
			t.Errorf("digest %q: want sha256:<8 hex>", k.Digest)
		}
	}
	// Digest must be value-dependent and stable.
	again := ComputeKeyStatus(map[string]string{"a": "1"})
	if again[0].Digest != got[0].Digest {
		t.Errorf("digest not stable: %q vs %q", again[0].Digest, got[0].Digest)
	}
	changed := ComputeKeyStatus(map[string]string{"a": "other"})
	if changed[0].Digest == got[0].Digest {
		t.Errorf("digest did not change with value")
	}
	if ComputeKeyStatus(nil) != nil {
		t.Errorf("nil map must yield nil status")
	}
}
