package v1alpha1

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
)

// cmpOpts lets go-cmp compare specs whose embedded ObjectMeta carries a
// metav1.Time (its wrapped time.Time has unexported fields).
var cmpOpts = cmp.Options{
	cmp.Comparer(func(a, b metav1.Time) bool { return a.Time.Equal(b.Time) }),
}

// httpBackendTemplate is the template every service defaults to when none is
// authored: an http1 backend, no runtime.
func httpBackendTemplate() ServiceTemplateSpec {
	return ServiceTemplateSpec{Spec: ServiceConfigSpec{
		ServiceConfig: ServiceConfig{Backend: &BackendConfig{Protocol: HTTP1}},
	}}
}

func TestServiceDefault(t *testing.T) {
	withRuntime := func(date string) ServiceTemplateSpec {
		tpl := httpBackendTemplate()
		tpl.Spec.Runtime = &ServiceRuntime{CompatibilityDate: date}
		return tpl
	}

	cases := []struct {
		name string
		in   ServiceSpec
		want ServiceSpec
	}{
		{
			name: "neither block materializes http1 backend and revHistory 10",
			in:   ServiceSpec{Template: ServiceTemplateSpec{Spec: ServiceConfigSpec{Runtime: &ServiceRuntime{CompatibilityDate: "x"}}}},
			want: ServiceSpec{Template: withRuntime("x"), RevisionHistoryLimit: ptr.To(int32(10))},
		},
		{
			name: "explicit revHistory preserved",
			in:   ServiceSpec{RevisionHistoryLimit: ptr.To(int32(3)), Template: ServiceTemplateSpec{Spec: ServiceConfigSpec{Runtime: &ServiceRuntime{CompatibilityDate: "x"}}}},
			want: ServiceSpec{Template: withRuntime("x"), RevisionHistoryLimit: ptr.To(int32(3))},
		},
		{
			name: "zero revHistory preserved (nil-vs-zero)",
			in:   ServiceSpec{RevisionHistoryLimit: ptr.To(int32(0)), Template: ServiceTemplateSpec{Spec: ServiceConfigSpec{Runtime: &ServiceRuntime{CompatibilityDate: "x"}}}},
			want: ServiceSpec{Template: withRuntime("x"), RevisionHistoryLimit: ptr.To(int32(0))},
		},
		{
			name: "oci source tag defaults to latest",
			in:   ServiceSpec{Source: ServiceSource{OCI: &BundleRef{Repo: "r"}}},
			want: ServiceSpec{
				Template:             httpBackendTemplate(),
				Source:               ServiceSource{OCI: &BundleRef{Repo: "r", Tag: "latest"}},
				RevisionHistoryLimit: ptr.To(int32(10)),
			},
		},
		{
			name: "oci source digest pinned not tagged",
			in:   ServiceSpec{Source: ServiceSource{OCI: &BundleRef{Repo: "r", Digest: "sha256:a"}}},
			want: ServiceSpec{
				Template:             httpBackendTemplate(),
				Source:               ServiceSource{OCI: &BundleRef{Repo: "r", Digest: "sha256:a"}},
				RevisionHistoryLimit: ptr.To(int32(10)),
			},
		},
		{
			name: "oci source password scrubbed into passwordData",
			in: ServiceSpec{Source: ServiceSource{OCI: &BundleRef{
				Repo: "r", Digest: "sha256:a",
				Credentials: &OCICredentials{Username: "bob", Password: "hunter2"},
			}}},
			want: ServiceSpec{
				Template: httpBackendTemplate(),
				Source: ServiceSource{OCI: &BundleRef{
					Repo: "r", Digest: "sha256:a",
					Credentials: &OCICredentials{Username: "bob", PasswordData: []byte("hunter2")},
				}},
				RevisionHistoryLimit: ptr.To(int32(10)),
			},
		},
		{
			name: "oci source explicit passwordData wins over password",
			in: ServiceSpec{Source: ServiceSource{OCI: &BundleRef{
				Repo: "r", Digest: "sha256:a",
				Credentials: &OCICredentials{Password: "stale", PasswordData: []byte("hunter2")},
			}}},
			want: ServiceSpec{
				Template: httpBackendTemplate(),
				Source: ServiceSource{OCI: &BundleRef{
					Repo: "r", Digest: "sha256:a",
					Credentials: &OCICredentials{PasswordData: []byte("hunter2")},
				}},
				RevisionHistoryLimit: ptr.To(int32(10)),
			},
		},
		{
			name: "git source defaults production branch and output tag",
			in:   ServiceSpec{Source: ServiceSource{Git: &GitSource{GitRepo: GitRepo{URL: "https://x/r.git"}, Build: BuildConfig{Output: BundleRef{Repo: "registry/out"}}}}},
			want: ServiceSpec{
				Template: httpBackendTemplate(),
				Source: ServiceSource{Git: &GitSource{
					GitRepo:  GitRepo{URL: "https://x/r.git"},
					Build:    BuildConfig{Output: BundleRef{Repo: "registry/out", Tag: "latest"}},
					Triggers: Triggers{ProductionBranch: "main"},
				}},
				RevisionHistoryLimit: ptr.To(int32(10)),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &Service{Spec: tc.in}
			w.Default()
			if diff := cmp.Diff(tc.want, w.Spec, cmpOpts); diff != "" {
				t.Errorf("Default() spec mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestServiceRevisionDefault(t *testing.T) {
	cases := []struct {
		name string
		in   ServiceConfigSpec
		want ServiceConfigSpec
	}{
		{
			name: "backend empty protocol filled http1",
			in:   ServiceConfigSpec{ServiceConfig: ServiceConfig{Backend: &BackendConfig{}}},
			want: ServiceConfigSpec{ServiceConfig: ServiceConfig{Backend: &BackendConfig{Protocol: HTTP1}}},
		},
		{
			name: "backend explicit tcp preserved",
			in:   ServiceConfigSpec{ServiceConfig: ServiceConfig{Backend: &BackendConfig{Protocol: TCP, Port: ptr.To(int32(9000))}}},
			want: ServiceConfigSpec{ServiceConfig: ServiceConfig{Backend: &BackendConfig{Protocol: TCP, Port: ptr.To(int32(9000))}}},
		},
		{
			name: "filter empty enums filled (and no backend materialized)",
			in:   ServiceConfigSpec{ServiceConfig: ServiceConfig{Filter: &FilterConfig{}}},
			want: ServiceConfigSpec{ServiceConfig: ServiceConfig{Filter: &FilterConfig{Phase: RequestPhase, FailureMode: FailClosed}}},
		},
		{
			name: "filter partial enums preserved",
			in:   ServiceConfigSpec{ServiceConfig: ServiceConfig{Filter: &FilterConfig{Phase: BothPhases, FailureMode: FailOpen}}},
			want: ServiceConfigSpec{ServiceConfig: ServiceConfig{Filter: &FilterConfig{Phase: BothPhases, FailureMode: FailOpen}}},
		},
		{
			name: "both set left untouched but enums filled",
			in:   ServiceConfigSpec{ServiceConfig: ServiceConfig{Filter: &FilterConfig{}, Backend: &BackendConfig{}}},
			want: ServiceConfigSpec{ServiceConfig: ServiceConfig{
				Filter:  &FilterConfig{Phase: RequestPhase, FailureMode: FailClosed},
				Backend: &BackendConfig{Protocol: HTTP1},
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &ServiceRevision{Spec: ServiceRevisionSpec{ServiceConfigSpec: tc.in}}
			r.Default()
			if diff := cmp.Diff(tc.want, r.Spec.ServiceConfigSpec); diff != "" {
				t.Errorf("Default() config mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// defaultValidater is the create-path contract both Service and ServiceRevision
// satisfy: the scheme defaults the object, then the strategy validates it.
type defaultValidater interface {
	Default()
	Validate(context.Context) field.ErrorList
}

// TestDefaultThenValidatePipeline ties the two units together exactly as the
// aggregated apiserver sequences them on create: a minimally-specified object
// must survive defaulting and pass validation.
func TestDefaultThenValidatePipeline(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		obj  defaultValidater
	}{
		{
			name: "revision: empty config + resolved bundle",
			obj: &ServiceRevision{Spec: ServiceRevisionSpec{
				Bundle:            BundleRef{Repo: "r", Digest: "sha256:a"},
				ServiceConfigSpec: ServiceConfigSpec{Runtime: &ServiceRuntime{CompatibilityDate: "2024-01-01"}},
			}},
		},
		{
			name: "service: oci source, empty template",
			obj:  &Service{Spec: ServiceSpec{Source: ServiceSource{OCI: &BundleRef{Repo: "r"}}}},
		},
		{
			name: "service: git source, empty template",
			obj: &Service{Spec: ServiceSpec{Source: ServiceSource{Git: &GitSource{
				GitRepo: GitRepo{URL: "https://x/r.git"},
				Build:   BuildConfig{Output: BundleRef{Repo: "registry/out"}},
			}}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.obj.Default()
			if errs := tc.obj.Validate(ctx); len(errs) != 0 {
				t.Errorf("defaulted object failed validation: %v", errFields(errs))
			}
		})
	}
}
