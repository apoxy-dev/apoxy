// +k8s:openapi-gen=true
// +kubebuilder:object:generate=true
// +groupName=vpc.apoxy.dev
// +k8s:deepcopy-gen=package,register

// Package v1alpha1 contains the vpc.apoxy.dev API group: private connectivity
// domains (VPCNetwork), service-like addressing over tunnel connections
// (VPCService), relay instance tracking (Relay), and per-connection tracking
// (Tunnel). All kinds are cluster-scoped. See
// docs/vpc-binding-relay-network-api.mdx in the apoxy-cloud repository for the
// design.
package v1alpha1 // import "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
