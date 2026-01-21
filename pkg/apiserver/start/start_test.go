package start_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/builder/resource"
	builderrest "github.com/apoxy-dev/apoxy/pkg/apiserver/builder/rest"
)

// TestStorageProviderImplementsObjectAware verifies that storageProviderWithFn
// implements ObjectAwareStorageProvider correctly.
func TestStorageProviderImplementsObjectAware(t *testing.T) {
	proxy := &corev1alpha2.Proxy{}
	sp := builderrest.NewStorageProviderWithFn(proxy, nil)

	// Verify it implements ObjectAwareStorageProvider
	objAware, ok := sp.(builderrest.ObjectAwareStorageProvider)
	require.True(t, ok, "NewStorageProviderWithFn should return ObjectAwareStorageProvider")

	// Verify GetObject returns the correct object
	obj := objAware.GetObject()
	assert.NotNil(t, obj, "GetObject should return non-nil")

	// Verify the returned object is the same type
	_, isProxy := obj.(*corev1alpha2.Proxy)
	assert.True(t, isProxy, "GetObject should return the Proxy type")
}

// TestProxyImplementsObjectWithStatusSubResource verifies that Proxy
// correctly implements the ObjectWithStatusSubResource interface.
func TestProxyImplementsObjectWithStatusSubResource(t *testing.T) {
	var proxy interface{} = &corev1alpha2.Proxy{}

	// Verify it implements ObjectWithStatusSubResource
	statusObj, ok := proxy.(resource.ObjectWithStatusSubResource)
	require.True(t, ok, "Proxy should implement ObjectWithStatusSubResource")

	// Verify GetStatus returns a valid StatusSubResource
	status := statusObj.GetStatus()
	assert.NotNil(t, status, "GetStatus should return non-nil")
	assert.Equal(t, "status", status.SubResourceName(), "SubResourceName should be 'status'")
}

// TestStatusRESTCreation verifies that StatusREST can be created correctly.
func TestStatusRESTCreation(t *testing.T) {
	var proxy interface{} = &corev1alpha2.Proxy{}
	statusObj := proxy.(resource.ObjectWithStatusSubResource)

	// Create a minimal mock store
	statusREST := &builderrest.StatusREST{
		Store: &genericregistry.Store{},
		Obj:   statusObj,
	}

	// Verify the StatusREST was created with correct fields
	assert.NotNil(t, statusREST.Store, "Store should not be nil")
	assert.NotNil(t, statusREST.Obj, "Obj should not be nil")
}

// TestStatusSubresourceDetection verifies the detection logic for status subresources.
func TestStatusSubresourceDetection(t *testing.T) {
	tests := []struct {
		name            string
		obj             resource.Object
		expectStatus    bool
	}{
		{
			name:         "Proxy has status subresource",
			obj:          &corev1alpha2.Proxy{},
			expectStatus: true,
		},
		{
			name:         "Backend has status subresource",
			obj:          &corev1alpha2.Backend{},
			expectStatus: true,
		},
		{
			name:         "Tunnel has status subresource",
			obj:          &corev1alpha2.Tunnel{},
			expectStatus: true,
		},
		{
			name:         "TunnelAgent has status subresource",
			obj:          &corev1alpha2.TunnelAgent{},
			expectStatus: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp := builderrest.NewStorageProviderWithFn(tt.obj, nil)

			// Check ObjectAwareStorageProvider
			objAware, ok := sp.(builderrest.ObjectAwareStorageProvider)
			require.True(t, ok, "should implement ObjectAwareStorageProvider")

			// Check ObjectWithStatusSubResource
			_, hasStatus := objAware.GetObject().(resource.ObjectWithStatusSubResource)
			assert.Equal(t, tt.expectStatus, hasStatus, "status subresource detection mismatch")
		})
	}
}
