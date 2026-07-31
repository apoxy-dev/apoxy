// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"testing"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

func TestBundleImageRef(t *testing.T) {
	cases := []struct {
		name    string
		ref     computev1alpha1.BundleRef
		want    string
		wantErr bool
	}{
		{"digest preferred", computev1alpha1.BundleRef{Repo: "r/x", Digest: "sha256:d", Tag: "latest"}, "r/x@sha256:d", false},
		{"tag fallback", computev1alpha1.BundleRef{Repo: "r/x", Tag: "v1"}, "r/x:v1", false},
		{"no repository", computev1alpha1.BundleRef{Tag: "v1"}, "", true},
		{"neither digest nor tag", computev1alpha1.BundleRef{Repo: "r/x"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BundleImageRef(tc.ref)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
