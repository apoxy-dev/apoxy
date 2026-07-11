package apiserver

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kuser "k8s.io/apiserver/pkg/authentication/user"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	a3yclient "github.com/apoxy-dev/apoxy/client/versioned"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/auth"
)

// TestAPIServerIntegrationSecretStore exercises the write-only SecretStore
// surface end to end: values go in through the values subresource, never come
// back out through the main resource, and only internal identities may read
// them back.
func TestAPIServerIntegrationSecretStore(t *testing.T) {
	srv := startTestServer(
		t,
		WithSimpleAuth(),
		WithResource(&corev1alpha.SecretStore{}),
		WithResource(&computev1alpha1.Service{}),
		WithResource(&computev1alpha1.ServiceRevision{}),
		WithSecretValuesAuthz(func(u kuser.Info) bool {
			return u != nil && slices.Contains(u.GetGroups(), "internal")
		}),
	)
	t.Cleanup(srv.cancel)

	user := newClientset(t, srv.addr,
		WithTransportWrapper(auth.NewTransportWrapperFunc("someone@example.com", []string{"project:test"}, nil)))
	internal := newClientset(t, srv.addr,
		WithTransportWrapper(auth.NewTransportWrapperFunc("controller", []string{"internal"}, nil)))

	ctx := context.Background()
	stores := user.CoreV1alpha().SecretStores()

	_, err := stores.Create(ctx, &corev1alpha.SecretStore{
		ObjectMeta: metav1.ObjectMeta{Name: "st"},
		Spec:       corev1alpha.SecretStoreSpec{Scopes: []string{"compute:web-*"}},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	// Scope syntax is validated at write time.
	_, err = stores.Create(ctx, &corev1alpha.SecretStore{
		ObjectMeta: metav1.ObjectMeta{Name: "bad"},
		Spec:       corev1alpha.SecretStoreSpec{Scopes: []string{":"}},
	}, metav1.CreateOptions{})
	require.True(t, apierrors.IsInvalid(err), "want Invalid for bad scope, got %v", err)

	// Values arrive via merge-patch on the subresource.
	patchValues(t, user, "st", `{"data":{"a":"1","b":"2"}}`)

	// The main resource shows key names + digests but never values.
	got, err := stores.Get(ctx, "st", metav1.GetOptions{})
	require.NoError(t, err)
	require.Nil(t, got.Data, "main-resource GET must not return values")
	require.Len(t, got.Status.Keys, 2)
	require.Equal(t, "a", got.Status.Keys[0].Name)
	require.Equal(t, "b", got.Status.Keys[1].Name)

	list, err := stores.List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	for i := range list.Items {
		require.Nil(t, list.Items[i].Data, "LIST must not return values")
	}

	// A regular identity cannot read values back.
	err = user.CoreV1alpha().RESTClient().Get().
		Resource("secretstores").Name("st").SubResource("values").
		Do(ctx).Error()
	require.True(t, apierrors.IsForbidden(err), "want Forbidden for user values GET, got %v", err)

	// An internal identity can, and the document echoes the parent's scopes
	// so the resolver enforces them without a second (cached) read.
	vals := &corev1alpha.SecretStoreValues{}
	require.NoError(t, internal.CoreV1alpha().RESTClient().Get().
		Resource("secretstores").Name("st").SubResource("values").
		Do(ctx).Into(vals))
	require.Equal(t, map[string]string{"a": "1", "b": "2"}, vals.Data)
	require.Equal(t, []string{"compute:web-*"}, vals.Scopes)

	// merge-patch null deletes a key; new keys merge in.
	patchValues(t, user, "st", `{"data":{"b":null,"c":"3"}}`)
	vals = &corev1alpha.SecretStoreValues{}
	require.NoError(t, internal.CoreV1alpha().RESTClient().Get().
		Resource("secretstores").Name("st").SubResource("values").
		Do(ctx).Into(vals))
	require.Equal(t, map[string]string{"a": "1", "c": "3"}, vals.Data)

	got, err = stores.Get(ctx, "st", metav1.GetOptions{})
	require.NoError(t, err)
	require.Len(t, got.Status.Keys, 2)
	require.Equal(t, "a", got.Status.Keys[0].Name)
	require.Equal(t, "c", got.Status.Keys[1].Name)

	// A spec update through the main resource does not disturb stored values.
	got.Spec.Scopes = []string{"compute:web-*", "compute:api"}
	got.Data = map[string]string{"a": "OVERWRITE-ATTEMPT"}
	_, err = stores.Update(ctx, got, metav1.UpdateOptions{})
	require.NoError(t, err)
	vals = &corev1alpha.SecretStoreValues{}
	require.NoError(t, internal.CoreV1alpha().RESTClient().Get().
		Resource("secretstores").Name("st").SubResource("values").
		Do(ctx).Into(vals))
	require.Equal(t, map[string]string{"a": "1", "c": "3"}, vals.Data,
		"main-resource update must not change values")
	require.Equal(t, []string{"compute:web-*", "compute:api"}, vals.Scopes,
		"values document must echo updated scopes")

	// Admission: a Service binding an existing key on an in-scope name is
	// admitted; out-of-scope names, missing keys, and missing stores are not.
	services := user.ComputeV1alpha1().Services()
	mkSvc := func(name, store, key string) *computev1alpha1.Service {
		return &computev1alpha1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: computev1alpha1.ServiceSpec{
				Template: computev1alpha1.ServiceTemplateSpec{
					Spec: computev1alpha1.ServiceConfigSpec{
						ServiceConfig: computev1alpha1.ServiceConfig{
							Backend: &computev1alpha1.BackendConfig{Protocol: computev1alpha1.HTTP1},
						},
						Bindings: []computev1alpha1.Binding{{
							Name: "TOKEN", Type: computev1alpha1.SecretBindingType,
							Secret: &computev1alpha1.SecretBinding{Store: corev1alpha.ObjectName(store), Key: key},
						}},
					},
				},
				Source: computev1alpha1.ServiceSource{
					OCI: &computev1alpha1.BundleRef{Repo: "registry.example.com/x"},
				},
			},
		}
	}

	_, err = services.Create(ctx, mkSvc("web-1", "st", "a"), metav1.CreateOptions{})
	require.NoError(t, err, "in-scope service with existing key must be admitted")

	_, err = services.Create(ctx, mkSvc("api-1", "st", "a"), metav1.CreateOptions{})
	require.True(t, apierrors.IsForbidden(err), "out-of-scope name must be rejected, got %v", err)

	_, err = services.Create(ctx, mkSvc("web-2", "st", "missing"), metav1.CreateOptions{})
	require.True(t, apierrors.IsForbidden(err), "missing key must be rejected, got %v", err)
	require.Contains(t, err.Error(), "apoxy secret set st missing")

	_, err = services.Create(ctx, mkSvc("web-3", "nope", "a"), metav1.CreateOptions{})
	require.True(t, apierrors.IsForbidden(err), "missing store must be rejected, got %v", err)
	require.Contains(t, err.Error(), "create the SecretStore first")
}

func patchValues(t *testing.T, c *a3yclient.Clientset, store, patch string) {
	t.Helper()
	require.NoError(t, c.CoreV1alpha().RESTClient().
		Patch(types.MergePatchType).
		Resource("secretstores").Name(store).SubResource("values").
		Body([]byte(patch)).
		Do(context.Background()).Error())
}
