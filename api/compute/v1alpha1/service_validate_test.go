package v1alpha1

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

func hasField(errs field.ErrorList, f string) bool {
	for _, e := range errs {
		if e.Field == f {
			return true
		}
	}
	return false
}

func errFields(errs field.ErrorList) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, e.Field+"("+string(e.Type)+")")
	}
	return out
}

// assertErrs checks that every path in want produced an error. An empty want
// asserts acceptance (no errors). exactCount > 0 additionally pins len(errs).
func assertErrs(t *testing.T, errs field.ErrorList, want []string, exactCount int) {
	t.Helper()
	if len(want) == 0 {
		if len(errs) != 0 {
			t.Fatalf("expected no errors, got %v", errFields(errs))
		}
		return
	}
	for _, f := range want {
		if !hasField(errs, f) {
			t.Errorf("missing error on %q; got %v", f, errFields(errs))
		}
	}
	if exactCount > 0 && len(errs) != exactCount {
		t.Errorf("expected %d errors, got %d: %v", exactCount, len(errs), errFields(errs))
	}
}

// validRevision returns a minted-revision-shaped object that passes Validate:
// a digest-pinned bundle plus an http1 backend.
func validRevision() *ServiceRevision {
	return &ServiceRevision{Spec: ServiceRevisionSpec{
		ServiceConfigSpec: ServiceConfigSpec{
			ServiceConfig: ServiceConfig{Backend: &BackendConfig{Protocol: HTTP1}},
			Runtime:       &ServiceRuntime{CompatibilityDate: "2024-01-01"},
		},
		Bundle: BundleRef{Repo: "registry/app", Digest: "sha256:abc"},
	}}
}

// Each row mutates a fresh validRevision(); rows with no want expect acceptance,
// rows with want expect those error paths (count pins the total when > 0).
func TestServiceRevisionValidate(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(r *ServiceRevision)
		want  []string
		count int
	}{
		// --- backend: L7 (http1/http2) forbids port; L4 (tcp/udp) requires it ---
		{
			name: "backend http1 no port",
			mut:  func(r *ServiceRevision) {},
		},
		{
			name:  "backend http1 with port forbidden",
			mut:   func(r *ServiceRevision) { r.Spec.Backend.Port = ptr.To(int32(8080)) },
			want:  []string{"spec.backend.port"},
			count: 1,
		},
		{
			name:  "backend http2 with port forbidden",
			mut:   func(r *ServiceRevision) { r.Spec.Backend = &BackendConfig{Protocol: HTTP2, Port: ptr.To(int32(443))} },
			want:  []string{"spec.backend.port"},
			count: 1,
		},
		{
			name:  "backend empty protocol with port forbidden",
			mut:   func(r *ServiceRevision) { r.Spec.Backend = &BackendConfig{Port: ptr.To(int32(80))} },
			want:  []string{"spec.backend.port"},
			count: 1,
		},
		{
			name:  "backend tcp no port required",
			mut:   func(r *ServiceRevision) { r.Spec.Backend = &BackendConfig{Protocol: TCP} },
			want:  []string{"spec.backend.port"},
			count: 1,
		},
		{
			name: "backend tcp with port ok",
			mut:  func(r *ServiceRevision) { r.Spec.Backend = &BackendConfig{Protocol: TCP, Port: ptr.To(int32(9000))} },
		},
		{
			name:  "backend udp no port required",
			mut:   func(r *ServiceRevision) { r.Spec.Backend = &BackendConfig{Protocol: UDP} },
			want:  []string{"spec.backend.port"},
			count: 1,
		},
		{
			name: "backend udp with port ok",
			mut:  func(r *ServiceRevision) { r.Spec.Backend = &BackendConfig{Protocol: UDP, Port: ptr.To(int32(53))} },
		},
		{
			name:  "backend tcp port zero invalid",
			mut:   func(r *ServiceRevision) { r.Spec.Backend = &BackendConfig{Protocol: TCP, Port: ptr.To(int32(0))} },
			want:  []string{"spec.backend.port"},
			count: 1,
		},
		{
			name:  "backend tcp port too high invalid",
			mut:   func(r *ServiceRevision) { r.Spec.Backend = &BackendConfig{Protocol: TCP, Port: ptr.To(int32(70000))} },
			want:  []string{"spec.backend.port"},
			count: 1,
		},
		{
			name:  "backend http port out of range two errors",
			mut:   func(r *ServiceRevision) { r.Spec.Backend = &BackendConfig{Protocol: HTTP1, Port: ptr.To(int32(70000))} },
			want:  []string{"spec.backend.port"},
			count: 2,
		},
		{
			name:  "backend bad protocol",
			mut:   func(r *ServiceRevision) { r.Spec.Backend = &BackendConfig{Protocol: "grpc"} },
			want:  []string{"spec.backend.protocol"},
			count: 1,
		},

		// --- filter ---
		{
			name: "filter only valid",
			mut: func(r *ServiceRevision) {
				r.Spec.Backend = nil
				r.Spec.Filter = &FilterConfig{Phase: RequestPhase, FailureMode: FailClosed}
			},
		},
		{
			name: "filter empty enums ok",
			mut: func(r *ServiceRevision) {
				r.Spec.Backend = nil
				r.Spec.Filter = &FilterConfig{}
			},
		},
		{
			name: "filter bad phase",
			mut: func(r *ServiceRevision) {
				r.Spec.Backend = nil
				r.Spec.Filter = &FilterConfig{Phase: "middle"}
			},
			want:  []string{"spec.filter.phase"},
			count: 1,
		},
		{
			name: "filter bad failureMode",
			mut: func(r *ServiceRevision) {
				r.Spec.Backend = nil
				r.Spec.Filter = &FilterConfig{FailureMode: "explode"}
			},
			want:  []string{"spec.filter.failureMode"},
			count: 1,
		},

		// --- mode union ---
		{
			name:  "both set mutually exclusive",
			mut:   func(r *ServiceRevision) { r.Spec.Filter = &FilterConfig{} },
			want:  []string{"spec.backend"},
			count: 1,
		},
		{
			name: "neither set accepted (no union error)",
			mut:  func(r *ServiceRevision) { r.Spec.Backend = nil },
		},

		// --- runtime (relaxed: optional; only flag empty date when block present) ---
		{
			name: "runtime nil ok",
			mut:  func(r *ServiceRevision) { r.Spec.Runtime = nil },
		},
		{
			name:  "runtime present empty date",
			mut:   func(r *ServiceRevision) { r.Spec.Runtime = &ServiceRuntime{} },
			want:  []string{"spec.runtime.compatibilityDate"},
			count: 1,
		},

		// --- bundle (always present; minted requires concrete digest; creds exclusive) ---
		{
			name:  "bundle empty repo and digest",
			mut:   func(r *ServiceRevision) { r.Spec.Bundle = BundleRef{} },
			want:  []string{"spec.bundle.repo", "spec.bundle.digest"},
			count: 2,
		},
		{
			name:  "bundle empty repo",
			mut:   func(r *ServiceRevision) { r.Spec.Bundle = BundleRef{Digest: "sha256:a"} },
			want:  []string{"spec.bundle.repo"},
			count: 1,
		},
		{
			name:  "bundle minted no digest",
			mut:   func(r *ServiceRevision) { r.Spec.Bundle = BundleRef{Repo: "r"} },
			want:  []string{"spec.bundle.digest"},
			count: 1,
		},
		{
			name: "bundle both credentials",
			mut: func(r *ServiceRevision) {
				r.Spec.Bundle = BundleRef{Repo: "r", Digest: "sha256:a", Credentials: &OCICredentials{}, CredentialsRef: &OCICredentialsRef{}}
			},
			want:  []string{"spec.bundle.credentialsRef"},
			count: 1,
		},
		{
			name: "bundle credentialsRef alone is not supported yet",
			mut: func(r *ServiceRevision) {
				r.Spec.Bundle = BundleRef{Repo: "r", Digest: "sha256:a", CredentialsRef: &OCICredentialsRef{}}
			},
			want:  []string{"spec.bundle.credentialsRef"},
			count: 1,
		},

		// --- bindings (discriminated union: exactly one block, matching type) ---
		{
			name: "binding secret ok",
			mut: func(r *ServiceRevision) {
				r.Spec.Bindings = []Binding{{Name: "S", Type: SecretBindingType, Secret: &SecretBinding{}}}
			},
		},
		{
			name: "binding kv ok",
			mut: func(r *ServiceRevision) {
				r.Spec.Bindings = []Binding{{Name: "K", Type: KVBindingType, KV: &KVBinding{Namespace: "ns"}}}
			},
		},
		{
			name: "binding service ok",
			mut: func(r *ServiceRevision) {
				r.Spec.Bindings = []Binding{{Name: "V", Type: ServiceBindingType, Service: &ServiceBinding{ServiceRef: "other"}}}
			},
		},
		{
			name: "binding type secret missing block",
			mut: func(r *ServiceRevision) {
				r.Spec.Bindings = []Binding{{Name: "S", Type: SecretBindingType}}
			},
			want:  []string{"spec.bindings[0].secret"},
			count: 1,
		},
		{
			name: "binding type kv missing block",
			mut: func(r *ServiceRevision) {
				r.Spec.Bindings = []Binding{{Name: "K", Type: KVBindingType}}
			},
			want:  []string{"spec.bindings[0].kv"},
			count: 1,
		},
		{
			name: "binding type service missing block",
			mut: func(r *ServiceRevision) {
				r.Spec.Bindings = []Binding{{Name: "V", Type: ServiceBindingType}}
			},
			want:  []string{"spec.bindings[0].service"},
			count: 1,
		},
		{
			name: "binding kv block declared secret",
			mut: func(r *ServiceRevision) {
				r.Spec.Bindings = []Binding{{Name: "X", Type: SecretBindingType, KV: &KVBinding{Namespace: "n"}}}
			},
			want:  []string{"spec.bindings[0].secret", "spec.bindings[0].kv"},
			count: 2,
		},
		{
			name: "binding secret block declared kv",
			mut: func(r *ServiceRevision) {
				r.Spec.Bindings = []Binding{{Name: "X", Type: KVBindingType, Secret: &SecretBinding{}}}
			},
			want:  []string{"spec.bindings[0].kv", "spec.bindings[0].secret"},
			count: 2,
		},
		{
			name: "binding two blocks set",
			mut: func(r *ServiceRevision) {
				r.Spec.Bindings = []Binding{{Name: "X", Type: SecretBindingType, Secret: &SecretBinding{}, Service: &ServiceBinding{ServiceRef: "w"}}}
			},
			want:  []string{"spec.bindings[0]", "spec.bindings[0].service"},
			count: 2,
		},
		{
			name:  "binding bad type",
			mut:   func(r *ServiceRevision) { r.Spec.Bindings = []Binding{{Name: "X", Type: "queue"}} },
			want:  []string{"spec.bindings[0].type"},
			count: 1,
		},
		{
			name: "binding missing name",
			mut: func(r *ServiceRevision) {
				r.Spec.Bindings = []Binding{{Type: SecretBindingType, Secret: &SecretBinding{}}}
			},
			want:  []string{"spec.bindings[0].name"},
			count: 1,
		},
		{
			name: "binding duplicate names",
			mut: func(r *ServiceRevision) {
				r.Spec.Bindings = []Binding{
					{Name: "D", Type: KVBindingType, KV: &KVBinding{Namespace: "a"}},
					{Name: "D", Type: KVBindingType, KV: &KVBinding{Namespace: "b"}},
				}
			},
			want:  []string{"spec.bindings[1].name"},
			count: 1,
		},
		{
			name: "binding empty names not duplicate",
			mut: func(r *ServiceRevision) {
				r.Spec.Bindings = []Binding{
					{Type: SecretBindingType, Secret: &SecretBinding{}},
					{Type: SecretBindingType, Secret: &SecretBinding{}},
				}
			},
			want:  []string{"spec.bindings[0].name", "spec.bindings[1].name"},
			count: 2,
		},

		// --- env (unique, non-empty names) ---
		{
			name:  "env missing name",
			mut:   func(r *ServiceRevision) { r.Spec.Env = []EnvVar{{Value: "v"}} },
			want:  []string{"spec.env[0].name"},
			count: 1,
		},
		{
			name: "env duplicate names",
			mut: func(r *ServiceRevision) {
				r.Spec.Env = []EnvVar{{Name: "E", Value: "1"}, {Name: "E", Value: "2"}}
			},
			want:  []string{"spec.env[1].name"},
			count: 1,
		},
		{
			name: "env empty names not duplicate",
			mut: func(r *ServiceRevision) {
				r.Spec.Env = []EnvVar{{Value: "1"}, {Value: "2"}}
			},
			want:  []string{"spec.env[0].name", "spec.env[1].name"},
			count: 2,
		},
		{
			name: "env unique ok",
			mut: func(r *ServiceRevision) {
				r.Spec.Env = []EnvVar{{Name: "A", Value: "1"}, {Name: "B", Value: "2"}}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validRevision()
			tc.mut(r)
			assertErrs(t, r.Validate(context.Background()), tc.want, tc.count)
		})
	}
}

// validOCIService is push mode: source.oci set, no git, no bundle in template.
func validOCIService() *Service {
	return &Service{Spec: ServiceSpec{
		Template: ServiceTemplateSpec{Spec: ServiceConfigSpec{
			ServiceConfig: ServiceConfig{Backend: &BackendConfig{Protocol: HTTP1}},
			Runtime:       &ServiceRuntime{CompatibilityDate: "2024-01-01"},
		}},
		Source: ServiceSource{OCI: &BundleRef{Repo: "registry/app", Tag: "v1"}},
	}}
}

func validGitSource() *GitSource {
	return &GitSource{
		GitRepo: GitRepo{URL: "https://example.com/r.git"},
		Build:   BuildConfig{Output: BundleRef{Repo: "registry/out"}},
	}
}

// Each row mutates a fresh validOCIService(); rows with no want expect acceptance.
func TestServiceValidate(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(w *Service)
		want  []string
		count int
	}{
		// --- source union: exactly one of oci / git ---
		{
			name: "oci only",
			mut:  func(w *Service) {},
		},
		{
			name: "git only",
			mut:  func(w *Service) { w.Spec.Source = ServiceSource{Git: validGitSource()} },
		},
		{
			name:  "both oci and git",
			mut:   func(w *Service) { w.Spec.Source.Git = validGitSource() },
			want:  []string{"spec.source"},
			count: 1,
		},
		{
			name:  "neither oci nor git",
			mut:   func(w *Service) { w.Spec.Source = ServiceSource{} },
			want:  []string{"spec.source"},
			count: 1,
		},

		// --- source variant validation ---
		{
			name: "source git url empty",
			mut: func(w *Service) {
				w.Spec.Source = ServiceSource{Git: &GitSource{Build: BuildConfig{Output: BundleRef{Repo: "registry/out"}}}}
			},
			want:  []string{"spec.source.git.url"},
			count: 1,
		},
		{
			name: "source git build output repo empty",
			mut: func(w *Service) {
				w.Spec.Source = ServiceSource{Git: &GitSource{GitRepo: GitRepo{URL: "https://x/r.git"}}}
			},
			want:  []string{"spec.source.git.build.output.repo"},
			count: 1,
		},
		{
			name:  "source oci empty repo",
			mut:   func(w *Service) { w.Spec.Source = ServiceSource{OCI: &BundleRef{}} },
			want:  []string{"spec.source.oci.repo"},
			count: 1,
		},

		// --- compatibilityDate may come from the bundle manifest, so a missing
		// runtime block is accepted in either source mode ---
		{
			name: "git mode no runtime accepted",
			mut: func(w *Service) {
				w.Spec.Template.Spec.Runtime = nil
				w.Spec.Source = ServiceSource{Git: validGitSource()}
			},
		},
		{
			name: "oci mode no runtime accepted",
			mut:  func(w *Service) { w.Spec.Template.Spec.Runtime = nil },
		},

		// --- liveRevision: pinned name must be well-formed; empty (auto) is fine ---
		{
			name: "liveRevision pinned valid",
			mut:  func(w *Service) { w.Spec.LiveRevision = "app-00002" },
		},
		{
			name: "liveRevision malformed",
			mut:  func(w *Service) { w.Spec.LiveRevision = "Bad_Name" },
			want: []string{"spec.liveRevision"},
		},

		// --- other ---
		{
			name:  "negative revisionHistoryLimit",
			mut:   func(w *Service) { w.Spec.RevisionHistoryLimit = ptr.To(int32(-1)) },
			want:  []string{"spec.revisionHistoryLimit"},
			count: 1,
		},

		// --- template metadata: namespace + system-owned identity fields rejected;
		// name/generateName/labels/annotations honored ---
		{
			name:  "template metadata namespace forbidden",
			mut:   func(w *Service) { w.Spec.Template.Namespace = "x" },
			want:  []string{"spec.template.metadata.namespace"},
			count: 1,
		},
		{
			name:  "template metadata uid forbidden",
			mut:   func(w *Service) { w.Spec.Template.UID = "u" },
			want:  []string{"spec.template.metadata.uid"},
			count: 1,
		},
		{
			name: "template metadata ownerReferences forbidden",
			mut: func(w *Service) {
				w.Spec.Template.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v", Kind: "K", Name: "n", UID: "u"}}
			},
			want:  []string{"spec.template.metadata.ownerReferences"},
			count: 1,
		},
		{
			name:  "template metadata finalizers forbidden",
			mut:   func(w *Service) { w.Spec.Template.Finalizers = []string{"apoxy.dev/x"} },
			want:  []string{"spec.template.metadata.finalizers"},
			count: 1,
		},
		{
			name: "template metadata name labels annotations allowed",
			mut: func(w *Service) {
				w.Spec.Template.Name = "rev-1"
				w.Spec.Template.GenerateName = "rev-"
				w.Spec.Template.Labels = map[string]string{"a": "b"}
				w.Spec.Template.Annotations = map[string]string{"c": "d"}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := validOCIService()
			tc.mut(w)
			assertErrs(t, w.Validate(context.Background()), tc.want, tc.count)
		})
	}
}

func TestBuildValidate(t *testing.T) {
	cases := []struct {
		name  string
		spec  BuildSpec
		want  []string
		count int
	}{
		{
			name: "happy",
			spec: BuildSpec{ServiceRef: "w", Commit: "abc123", Ref: "main"},
		},
		{
			name:  "missing serviceRef",
			spec:  BuildSpec{Commit: "abc", Ref: "main"},
			want:  []string{"spec.serviceRef"},
			count: 1,
		},
		{
			name:  "missing commit",
			spec:  BuildSpec{ServiceRef: "w", Ref: "main"},
			want:  []string{"spec.commit"},
			count: 1,
		},
		{
			name:  "missing ref",
			spec:  BuildSpec{ServiceRef: "w", Commit: "abc"},
			want:  []string{"spec.ref"},
			count: 1,
		},
		{
			name:  "all missing",
			spec:  BuildSpec{},
			want:  []string{"spec.serviceRef", "spec.commit", "spec.ref"},
			count: 3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Build{Spec: tc.spec}
			assertErrs(t, b.Validate(context.Background()), tc.want, tc.count)
		})
	}
}

// Each row drives ValidateUpdate(neu, old); rows with no want expect acceptance.
// Mode and minted-spec immutability are the only update-time invariants; source
// switches and within-mode edits are allowed.
func TestValidateUpdateImmutability(t *testing.T) {
	ctx := context.Background()

	// Builders return an object differing from its "valid" baseline in exactly
	// one dimension, so each row reads as a clean old-vs-new pair.
	filterService := func() *Service {
		w := validOCIService()
		w.Spec.Template.Spec.Backend = nil
		w.Spec.Template.Spec.Filter = &FilterConfig{Phase: RequestPhase, FailureMode: FailClosed}
		return w
	}
	http2Service := func() *Service {
		w := validOCIService()
		w.Spec.Template.Spec.Backend = &BackendConfig{Protocol: HTTP2}
		return w
	}
	gitService := func() *Service {
		w := validOCIService()
		w.Spec.Source = ServiceSource{Git: validGitSource()}
		return w
	}
	badPortService := func() *Service {
		w := validOCIService()
		w.Spec.Template.Spec.Backend = &BackendConfig{Protocol: HTTP1, Port: ptr.To(int32(8080))}
		return w
	}
	http2Revision := func() *ServiceRevision {
		r := validRevision()
		r.Spec.Backend = &BackendConfig{Protocol: HTTP2}
		return r
	}
	build := func(commit string) *Build {
		return &Build{Spec: BuildSpec{ServiceRef: "w", Commit: commit, Ref: "main"}}
	}

	cases := []struct {
		name  string
		neu   resourcestrategy.ValidateUpdater
		old   runtime.Object
		want  []string
		count int
	}{
		{
			name:  "service mode switch backend to filter rejected",
			neu:   filterService(),
			old:   validOCIService(),
			want:  []string{"spec.template"},
			count: 1,
		},
		{
			name:  "service mode switch filter to backend rejected",
			neu:   validOCIService(),
			old:   filterService(),
			want:  []string{"spec.template"},
			count: 1,
		},
		{
			name: "service within-mode edit accepted",
			neu:  http2Service(),
			old:  validOCIService(),
		},
		{
			name: "service source switch push to git accepted",
			neu:  gitService(),
			old:  validOCIService(),
		},
		{
			name: "service old wrong type skips immutability",
			neu:  validOCIService(),
			old:  &ServiceRevision{},
		},
		{
			name:  "service invalid new still reports validate errors",
			neu:   badPortService(),
			old:   validOCIService(),
			want:  []string{"spec.template.spec.backend.port"},
			count: 1,
		},
		{
			name:  "revision spec change rejected",
			neu:   http2Revision(),
			old:   validRevision(),
			want:  []string{"spec"},
			count: 1,
		},
		{
			name: "revision spec unchanged accepted",
			neu:  validRevision(),
			old:  validRevision(),
		},
		{
			name: "revision old wrong type falls back to validate",
			neu:  validRevision(),
			old:  &Service{},
		},
		{
			name:  "build spec change rejected",
			neu:   build("b"),
			old:   build("a"),
			want:  []string{"spec"},
			count: 1,
		},
		{
			name: "build spec unchanged accepted",
			neu:  build("a"),
			old:  build("a"),
		},
		{
			name: "build old wrong type falls back to validate",
			neu:  build("a"),
			old:  &Service{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertErrs(t, tc.neu.ValidateUpdate(ctx, tc.old), tc.want, tc.count)
		})
	}
}
