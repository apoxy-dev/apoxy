package apiregistration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestToAPIServiceUsesCABundle(t *testing.T) {
	def := &APIServiceDefinition{
		Group:                "core.apoxy.dev",
		Version:              "v1alpha",
		GroupPriorityMinimum: 1000,
		VersionPriority:      100,
	}

	svc := def.ToAPIService("kube-controller", "apoxy", 8443, []byte("ca-bytes"))

	require.Equal(t, []byte("ca-bytes"), svc.Spec.CABundle)
	require.False(t, svc.Spec.InsecureSkipTLSVerify)
	require.Equal(t, "kube-controller", svc.Spec.Service.Name)
	require.Equal(t, "apoxy", svc.Spec.Service.Namespace)
}
