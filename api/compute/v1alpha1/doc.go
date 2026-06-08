// +k8s:openapi-gen=true
// +groupName=compute.apoxy.dev
// +k8s:deepcopy-gen=package

// Package v1alpha1 contains the compute.apoxy.dev API group, a redesign of the
// extensions.apoxy.dev/v1alpha2 EdgeFunction around the workerd runtime and OCI
// bundles as the primary code-distribution mechanism.
//
// Object model:
//
//	(push) Service.spec.source.oci --resolve tag--> (digest) --\
//	                                                            >--> ServiceRevision.spec.bundle --> served
//	(git)  Service.spec.source.git --> Build --emits--> (digest) -/
//
// The OCI bundle digest is the single primitive a Service runs, and it appears
// only on a minted ServiceRevision.spec.bundle — never authored in the template.
// Both code sources are variants of one field, spec.source: an oci push or a
// git/CI pipeline (mutually exclusive). The controller resolves the source to a
// digest, mints a ServiceRevision, and reports liveRevision/latestRevision in
// status; it never writes spec. spec.liveRevision selects which revision serves
// (empty = the latest ready revision, set = pinned for rollback or manual
// promotion).
//
// Tenancy: single tenant per account. All kinds are cluster-scoped.
package v1alpha1 // import "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
