package controllers

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

func TestResourceIsAvailable(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, gwapiv1.Install(scheme))
	require.NoError(t, gwapiv1alpha2.Install(scheme))

	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{
		gwapiv1.SchemeGroupVersion,
		gwapiv1alpha2.SchemeGroupVersion,
	})
	mapper.Add(gwapiv1.SchemeGroupVersion.WithKind("Gateway"), meta.RESTScopeNamespace)
	mapper.Add(gwapiv1.SchemeGroupVersion.WithKind("HTTPRoute"), meta.RESTScopeNamespace)

	ok, gvk, err := resourceIsAvailable(scheme, mapper, &gwapiv1.Gateway{})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "gateway.networking.k8s.io/v1, Kind=Gateway", gvk)

	ok, gvk, err = resourceIsAvailable(scheme, mapper, &gwapiv1alpha2.TLSRoute{})
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, "gateway.networking.k8s.io/v1alpha2, Kind=TLSRoute", gvk)
}
