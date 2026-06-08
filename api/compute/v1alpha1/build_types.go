package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/apoxy-dev/apoxy/api/resource"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

// =============================================================================
// Source (push oci / git CI) — embedded in ServiceSpec, NOT a standalone kind.
// =============================================================================

type GitRepo struct {
	// URL of the git repository.
	URL string `json:"url"`
	// +optional
	CredentialsRef *OCICredentialsRef `json:"credentialsRef,omitempty"`
}

type BuildConfig struct {
	// RootDir within the repo, default ".".
	// +optional
	RootDir string `json:"rootDir,omitempty"`
	// Builder image used to produce the bundle (e.g. an image wrapping wrangler/esbuild).
	// +optional
	Builder string `json:"builder,omitempty"`
	// Command overrides the builder default build command.
	// +optional
	Command []string `json:"command,omitempty"`
	// Output is where built bundles are pushed. The per-build digest lands in Build.Status.
	Output BundleRef `json:"output"`
	// +optional
	Env []EnvVar `json:"env,omitempty"`
}

type Triggers struct {
	// ProductionBranch is built+promoted on push. Default "main".
	// +optional
	// +kubebuilder:default="main"
	ProductionBranch string `json:"productionBranch,omitempty"`
	// Paths, if set, restricts triggering to changes under these globs.
	// +optional
	Paths []string `json:"paths,omitempty"`
	// OnPullRequest enables preview builds for PR branches.
	// +optional
	OnPullRequest bool `json:"onPullRequest,omitempty"`
}

type PreviewPolicy struct {
	// Enabled spawns ephemeral preview Services (owned by this Service) per
	// non-production branch / PR.
	Enabled bool `json:"enabled"`
	// TTL after which idle previews are garbage-collected.
	// +optional
	TTL *metav1.Duration `json:"ttl,omitempty"`
}

// ServiceSource is where a Service's bundle comes from. Exactly one variant is
// set; the populated member IS the discriminator. The resolved digest always
// lands in the minted ServiceRevision.spec.bundle — users never author a bundle
// directly.
type ServiceSource struct {
	// OCI is a directly-pushed OCI bundle (push model). The controller
	// resolves its tag to a digest and mints a revision pinned to that digest.
	// +optional
	OCI *BundleRef `json:"oci,omitempty"`
	// Git is a git/CI build pipeline (git model). Builds produce the digest and
	// mint revisions.
	// +optional
	Git *GitSource `json:"git,omitempty"`
}

// GitSource is the self-contained git/CI pipeline for a Service (spec.source.git).
// Everything git-related lives here: the repo, how it's built, what triggers a
// build, and optional preview environments. Whether a new build goes live is not
// configured here — that is governed by spec.liveRevision (empty = auto-promote
// the latest revision, set = pinned).
type GitSource struct {
	GitRepo  `json:",inline"`
	Build    BuildConfig `json:"build"`
	Triggers Triggers    `json:"triggers"`
	// +optional
	Previews *PreviewPolicy `json:"previews,omitempty"`
}

// =============================================================================
// Build (immutable record of one build attempt).
// =============================================================================

type BuildPhase string

const (
	BuildPending   BuildPhase = "Pending"
	BuildRunning   BuildPhase = "Building"
	BuildSucceeded BuildPhase = "Succeeded"
	BuildFailed    BuildPhase = "Failed"
)

// BuildSpec is the immutable input of a build. Builds are owned (ownerRef) by
// the Service whose spec.source produced them.
type BuildSpec struct {
	// ServiceRef is the owning Service.
	ServiceRef corev1alpha.ObjectName `json:"serviceRef"`
	// Commit being built.
	Commit string `json:"commit"`
	// Ref (branch or tag) the commit came from.
	Ref string `json:"ref"`
}

type BuildStatus struct {
	// +optional
	Phase BuildPhase `json:"phase,omitempty"`
	// Bundle is the produced artifact (digest filled) on success.
	// +optional
	Bundle *BundleRef `json:"bundle,omitempty"`
	// LogsRef points at build logs (e.g. an object-store URL).
	// +optional
	LogsRef string `json:"logsRef,omitempty"`
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`
	// +optional
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

var _ resource.StatusSubResource = &BuildStatus{}

func (s *BuildStatus) SubResourceName() string { return "status" }

func (s *BuildStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	if parent, ok := obj.(*Build); ok {
		parent.Status = *s
	}
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Build struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              BuildSpec   `json:"spec,omitempty"`
	Status            BuildStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &Build{}
	_ resource.Object                      = &Build{}
	_ resource.ObjectWithStatusSubResource = &Build{}
	_ rest.SingularNameProvider            = &Build{}
)

func (b *Build) GetObjectMeta() *metav1.ObjectMeta     { return &b.ObjectMeta }
func (b *Build) NamespaceScoped() bool                 { return false }
func (b *Build) New() runtime.Object                   { return &Build{} }
func (b *Build) NewList() runtime.Object               { return &BuildList{} }
func (b *Build) IsStorageVersion() bool                { return true }
func (b *Build) GetSingularName() string               { return "build" }
func (b *Build) GetStatus() resource.StatusSubResource { return &b.Status }
func (b *Build) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "builds",
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type BuildList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Build `json:"items"`
}

var _ resource.ObjectList = &BuildList{}

func (l *BuildList) GetListMeta() *metav1.ListMeta { return &l.ListMeta }
