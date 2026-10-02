package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AgentEnrollmentSpec is the enroll request of one agent.
type AgentEnrollmentSpec struct {
	// Agent name in the cert SAN. Must be a DNS label.
	// +required
	AgentName string `json:"agentName"`

	// PEM "CERTIFICATE REQUEST" signed with a P-256 key. The server uses only
	// its public key.
	// +required
	CSR string `json:"csr"`
}

// AgentEnrollmentStatus holds the issued cert.
type AgentEnrollmentStatus struct {
	// PEM agent cert with the SAN spiffe://<project>/vpc/<vpc-uid>/agent/<name>.
	// +optional
	Certificate string `json:"certificate,omitempty"`

	// PEM CA certs that relays and peers trust for agent certs.
	// +optional
	CABundle string `json:"caBundle,omitempty"`

	// NotAfter of the cert.
	// +optional
	ExpiresAt metav1.Time `json:"expiresAt,omitzero"`

	// Ready relays that serve the VPC.
	// +optional
	Relays []EnrollmentRelay `json:"relays,omitempty"`

	// PEM CA certs that relay certs and relay grants chain to. Empty means
	// the system roots.
	// +optional
	RelayRoots string `json:"relayRoots,omitempty"`
}

// EnrollmentRelay is one relay that an agent can dial.
type EnrollmentRelay struct {
	// Name in the relay cert. Grants of the relay carry it as the relay ID.
	ID string `json:"id"`

	// Underlay host:port addresses of the relay.
	Addresses []string `json:"addresses"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AgentEnrollment is the body of POST vpcnetworks/<name>/enroll. It is not
// stored.
type AgentEnrollment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AgentEnrollmentSpec   `json:"spec"`
	Status AgentEnrollmentStatus `json:"status,omitempty"`
}

// AgentRevocationSpec names the agent to revoke.
type AgentRevocationSpec struct {
	// Agent name in the cert SAN.
	// +required
	AgentName string `json:"agentName"`
}

// AgentRevocationStatus holds the revoke time.
type AgentRevocationStatus struct {
	// Certs of the agent with NotBefore at or before this time are revoked.
	// +optional
	RevokedAt metav1.Time `json:"revokedAt,omitzero"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AgentRevocation is the body of POST vpcnetworks/<name>/revoke. It is not
// stored; the server adds the agent to VPCNetwork.status.revokedAgents.
type AgentRevocation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AgentRevocationSpec   `json:"spec"`
	Status AgentRevocationStatus `json:"status,omitempty"`
}

// RevokedAgent is one entry of the VPC revocation list. A cert fails when its
// SAN names this agent and its NotBefore is at or before RevokedAt. Entries
// are dropped when all certs they match have expired.
type RevokedAgent struct {
	// Agent name in the cert SAN.
	Name string `json:"name"`

	// Revoke time.
	RevokedAt metav1.Time `json:"revokedAt"`
}
