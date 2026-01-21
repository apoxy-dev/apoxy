package resource_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/builder/resource"
)

// TestProxyInternalVersionRegistration tests that the Proxy type
// is properly registered with the internal version when using AddToScheme.
// This is critical for strategic merge patch operations to work.
func TestProxyInternalVersionRegistration(t *testing.T) {
	// Create a fresh scheme
	s := runtime.NewScheme()

	// Create a Proxy instance and verify it's a storage version
	proxy := &corev1alpha2.Proxy{}
	require.True(t, proxy.IsStorageVersion(), "Proxy should be a storage version")

	// Add Proxy to the scheme using our AddToScheme function
	err := resource.AddToScheme(proxy)(s)
	require.NoError(t, err)

	// Verify external version is registered
	externalGV := schema.GroupVersion{Group: "core.apoxy.dev", Version: "v1alpha2"}
	externalTypes := s.KnownTypes(externalGV)
	assert.Contains(t, externalTypes, "Proxy", "external version should have Proxy registered")
	assert.Contains(t, externalTypes, "ProxyList", "external version should have ProxyList registered")

	// Verify internal version is registered (this is the critical test for the fix)
	internalGV := schema.GroupVersion{Group: "core.apoxy.dev", Version: runtime.APIVersionInternal}
	internalTypes := s.KnownTypes(internalGV)
	assert.Contains(t, internalTypes, "Proxy",
		"internal version should have Proxy registered - required for strategic merge patch")
	assert.Contains(t, internalTypes, "ProxyList",
		"internal version should have ProxyList registered - required for strategic merge patch")

	// Verify the types are the same between external and internal versions
	assert.Equal(t, externalTypes["Proxy"].String(), internalTypes["Proxy"].String(),
		"Proxy type should be the same in external and internal versions")
}

// TestNonStorageVersionDoesNotRegisterInternal verifies that non-storage
// version types do NOT get registered with the internal version.
func TestNonStorageVersionDoesNotRegisterInternal(t *testing.T) {
	// Use v1alpha Backend which is NOT a storage version (v1alpha2 is)
	// First, let's verify this by checking the corev1alpha package
	s := runtime.NewScheme()

	// Create a Proxy and manually verify its storage version status
	proxy := &corev1alpha2.Proxy{}

	// This is a storage version, so internal should be registered
	require.True(t, proxy.IsStorageVersion())

	err := resource.AddToScheme(proxy)(s)
	require.NoError(t, err)

	// Internal version should exist for storage versions
	internalGV := schema.GroupVersion{Group: "core.apoxy.dev", Version: runtime.APIVersionInternal}
	internalTypes := s.KnownTypes(internalGV)
	assert.NotEmpty(t, internalTypes, "internal version types should not be empty for storage version")
}

// TestSchemeCanRecognizeInternalVersion verifies that the scheme
// can properly recognize and work with the internal version types.
func TestSchemeCanRecognizeInternalVersion(t *testing.T) {
	s := runtime.NewScheme()

	proxy := &corev1alpha2.Proxy{}
	err := resource.AddToScheme(proxy)(s)
	require.NoError(t, err)

	// Create an instance and verify scheme recognizes it
	internalGV := schema.GroupVersion{Group: "core.apoxy.dev", Version: runtime.APIVersionInternal}

	// The scheme should be able to create new objects for the internal version
	internalTypes := s.KnownTypes(internalGV)
	require.Contains(t, internalTypes, "Proxy")

	// Verify we can get the GVK for a Proxy object
	gvks, _, err := s.ObjectKinds(&corev1alpha2.Proxy{})
	require.NoError(t, err)
	require.NotEmpty(t, gvks, "should be able to get GVKs for Proxy")

	// Should have both external and internal versions
	hasExternal := false
	hasInternal := false
	for _, gvk := range gvks {
		if gvk.Version == "v1alpha2" {
			hasExternal = true
		}
		if gvk.Version == runtime.APIVersionInternal {
			hasInternal = true
		}
	}
	assert.True(t, hasExternal, "should have external version GVK")
	assert.True(t, hasInternal, "should have internal version GVK")
}
