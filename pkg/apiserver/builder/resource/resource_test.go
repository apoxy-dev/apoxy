package resource

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// mockObject is a test implementation of Object
type mockObject struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	isStorageVersion  bool
}

func (m *mockObject) GetObjectMeta() *metav1.ObjectMeta {
	return &m.ObjectMeta
}

func (m *mockObject) NamespaceScoped() bool {
	return false
}

func (m *mockObject) New() runtime.Object {
	return &mockObject{isStorageVersion: m.isStorageVersion}
}

func (m *mockObject) NewList() runtime.Object {
	return &mockObjectList{}
}

func (m *mockObject) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "test.apoxy.dev",
		Version:  "v1",
		Resource: "mockobjects",
	}
}

func (m *mockObject) IsStorageVersion() bool {
	return m.isStorageVersion
}

func (m *mockObject) DeepCopyObject() runtime.Object {
	return &mockObject{
		TypeMeta:         m.TypeMeta,
		ObjectMeta:       *m.ObjectMeta.DeepCopy(),
		isStorageVersion: m.isStorageVersion,
	}
}

// mockObjectList is a test implementation of ObjectList
type mockObjectList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []mockObject `json:"items"`
}

func (m *mockObjectList) DeepCopyObject() runtime.Object {
	return &mockObjectList{
		TypeMeta: m.TypeMeta,
		ListMeta: *m.ListMeta.DeepCopy(),
	}
}

func TestAddToScheme_StorageVersion_RegistersInternalVersion(t *testing.T) {
	// Create a storage version object
	obj := &mockObject{isStorageVersion: true}

	// Create a fresh scheme
	s := runtime.NewScheme()

	// Add the object to the scheme
	err := AddToScheme(obj)(s)
	require.NoError(t, err)

	// Verify external version is registered
	externalGV := schema.GroupVersion{Group: "test.apoxy.dev", Version: "v1"}
	externalTypes := s.KnownTypes(externalGV)
	assert.Contains(t, externalTypes, "mockObject", "external version should have mockObject registered")
	assert.Contains(t, externalTypes, "mockObjectList", "external version should have mockObjectList registered")

	// Verify internal version is registered (this is the fix we're testing)
	internalGV := schema.GroupVersion{Group: "test.apoxy.dev", Version: runtime.APIVersionInternal}
	internalTypes := s.KnownTypes(internalGV)
	assert.Contains(t, internalTypes, "mockObject", "internal version should have mockObject registered for storage version")
	assert.Contains(t, internalTypes, "mockObjectList", "internal version should have mockObjectList registered for storage version")

	// Verify the registered type names match what we expect
	assert.Equal(t, externalTypes["mockObject"].String(), internalTypes["mockObject"].String(),
		"external and internal types should be the same")
}

func TestAddToScheme_NonStorageVersion_DoesNotRegisterInternalVersion(t *testing.T) {
	// Create a non-storage version object
	obj := &mockObject{isStorageVersion: false}

	// Create a fresh scheme
	s := runtime.NewScheme()

	// Add the object to the scheme
	err := AddToScheme(obj)(s)
	require.NoError(t, err)

	// Verify external version is registered
	externalGV := schema.GroupVersion{Group: "test.apoxy.dev", Version: "v1"}
	externalTypes := s.KnownTypes(externalGV)
	assert.Contains(t, externalTypes, "mockObject", "external version should have mockObject registered")

	// Verify internal version is NOT registered for non-storage version
	internalGV := schema.GroupVersion{Group: "test.apoxy.dev", Version: runtime.APIVersionInternal}
	internalTypes := s.KnownTypes(internalGV)
	assert.NotContains(t, internalTypes, "mockObject", "internal version should NOT have mockObject registered for non-storage version")
	assert.NotContains(t, internalTypes, "mockObjectList", "internal version should NOT have mockObjectList registered for non-storage version")
}
