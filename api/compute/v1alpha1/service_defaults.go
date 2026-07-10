package v1alpha1

import (
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

var (
	_ resourcestrategy.Defaulter = &Service{}
	_ resourcestrategy.Defaulter = &ServiceRevision{}
)

// Default fills server-side defaults for a Service. Cross-field invariants
// (mode mutual-exclusion, source union, port rules, immutability) are enforced
// in Validate (service_validate.go), not here.
func (w *Service) Default() {
	if w.Spec.RevisionHistoryLimit == nil {
		w.Spec.RevisionHistoryLimit = ptr.To(int32(10))
	}
	defaultConfigSpec(&w.Spec.Template.Spec)
	defaultSource(&w.Spec.Source)
}

// Default fills server-side defaults for a ServiceRevision. Revisions are
// normally minted by the controller already resolved, but a direct create is
// defaulted the same way.
func (r *ServiceRevision) Default() {
	defaultConfigSpec(&r.Spec.ServiceConfigSpec)
	defaultBundleRef(&r.Spec.Bundle)
}

// defaultConfigSpec resolves the runtime-mode union into an explicit, fully
// defaulted block so the stored object is unambiguous: a service with no config
// becomes an http1 backend, and a partially-specified block has its enum
// defaults filled. Defaults are applied in Go rather than relying solely on
// +kubebuilder:default markers because these types are served through the
// aggregated apiserver, where those markers do not fire.
func defaultConfigSpec(s *ServiceConfigSpec) {
	// Neither block set -> backend is the default mode. Leave a both-set
	// (invalid) config untouched so Validate can reject it as authored.
	if s.Filter == nil && s.Backend == nil {
		s.Backend = &BackendConfig{}
	}
	if b := s.Backend; b != nil && b.Protocol == "" {
		b.Protocol = HTTP1
	}
	if f := s.Filter; f != nil {
		if f.Phase == "" {
			f.Phase = RequestPhase
		}
		if f.FailureMode == "" {
			f.FailureMode = FailClosed
		}
	}
}

// defaultSource fills the per-variant defaults of the bundle source: a pushed
// oci ref with no digest falls back to the "latest" tag, and a git pipeline gets
// the conventional "main" production branch and the same tag fallback for its
// build output registry.
func defaultSource(src *ServiceSource) {
	if src.OCI != nil {
		defaultBundleRef(src.OCI)
	}
	if src.Git != nil {
		if src.Git.Triggers.ProductionBranch == "" {
			src.Git.Triggers.ProductionBranch = "main"
		}
		defaultBundleRef(&src.Git.Build.Output)
	}
}

// defaultBundleRef applies the registry-conventional "latest" tag when a bundle
// is pinned by neither digest nor tag, and enforces the write-only Password
// contract by moving it into PasswordData (raw bytes — see the OCICredentials
// doc) so the human-readable string field never round-trips on reads.
func defaultBundleRef(b *BundleRef) {
	if b.Digest == "" && b.Tag == "" {
		b.Tag = "latest"
	}
	if c := b.Credentials; c != nil && c.Password != "" {
		if len(c.PasswordData) == 0 {
			c.PasswordData = []byte(c.Password)
		}
		c.Password = ""
	}
}
