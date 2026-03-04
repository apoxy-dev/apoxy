package apiserver

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

func TestCustomGetAttrs_DomainZone(t *testing.T) {
	dz := &corev1alpha2.DomainZone{
		ObjectMeta: metav1.ObjectMeta{
			Name: "example.com",
		},
		Status: corev1alpha2.DomainZoneStatus{
			Phase: corev1alpha2.DomainZonePhaseActive,
		},
	}

	_, fs, err := customGetAttrs(dz)
	require.NoError(t, err)

	assert.Equal(t, "example.com", fs["metadata.name"])
	assert.Equal(t, "Active", fs["status.phase"])
}

func TestCustomGetAttrs_Proxy(t *testing.T) {
	proxy := &corev1alpha2.Proxy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-proxy",
		},
		Spec: corev1alpha2.ProxySpec{
			Provider: corev1alpha2.InfraProviderCloud,
		},
	}

	_, fs, err := customGetAttrs(proxy)
	require.NoError(t, err)

	assert.Equal(t, "my-proxy", fs["metadata.name"])
	assert.Equal(t, "cloud", fs["spec.provider"])
}

func TestCustomGetAttrs_Backend(t *testing.T) {
	backend := &corev1alpha2.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-backend",
		},
		Spec: corev1alpha2.BackendSpec{
			Protocol: corev1alpha2.BackendProtoH2,
		},
	}

	_, fs, err := customGetAttrs(backend)
	require.NoError(t, err)

	assert.Equal(t, "my-backend", fs["metadata.name"])
	assert.Equal(t, "h2", fs["spec.protocol"])
}
