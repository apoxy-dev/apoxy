package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"k8s.io/client-go/rest"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
)

// Enroll makes a new P-256 key and gets a cert for agent in the VPCNetwork
// named vpc. c is the vpc.apoxy.dev REST client of the project apiserver,
// for example clientset.VpcV1alpha1().RESTClient().
func Enroll(ctx context.Context, c rest.Interface, vpc, agent string) (*Credential, error) {
	if err := ValidateAgentName(agent); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate agent key: %w", err)
	}
	// The server sets all names in the cert, so the CSR carries only the key.
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}
	req := &vpcv1alpha1.AgentEnrollment{
		Spec: vpcv1alpha1.AgentEnrollmentSpec{
			AgentName: agent,
			CSR:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
		},
	}
	resp := &vpcv1alpha1.AgentEnrollment{}
	if err := c.Post().
		Resource("vpcnetworks").
		Name(vpc).
		SubResource("enroll").
		Body(req).
		Do(ctx).
		Into(resp); err != nil {
		return nil, fmt.Errorf("failed to enroll agent %q in VPC %q: %w", agent, vpc, err)
	}
	cred, err := NewCredential(key, []byte(resp.Status.Certificate), []byte(resp.Status.CABundle))
	if err != nil {
		return nil, fmt.Errorf("enroll returned a bad credential: %w", err)
	}
	if cred.ID.Agent != agent {
		return nil, fmt.Errorf("enroll returned a cert for agent %q, not %q", cred.ID.Agent, agent)
	}
	return cred, nil
}

// Revoke revokes all current certs of agent in the VPCNetwork named vpc.
func Revoke(ctx context.Context, c rest.Interface, vpc, agent string) (*vpcv1alpha1.AgentRevocation, error) {
	if err := ValidateAgentName(agent); err != nil {
		return nil, err
	}
	req := &vpcv1alpha1.AgentRevocation{Spec: vpcv1alpha1.AgentRevocationSpec{AgentName: agent}}
	resp := &vpcv1alpha1.AgentRevocation{}
	if err := c.Post().
		Resource("vpcnetworks").
		Name(vpc).
		SubResource("revoke").
		Body(req).
		Do(ctx).
		Into(resp); err != nil {
		return nil, fmt.Errorf("failed to revoke agent %q in VPC %q: %w", agent, vpc, err)
	}
	return resp, nil
}
