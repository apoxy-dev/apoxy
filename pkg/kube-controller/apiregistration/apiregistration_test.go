package apiregistration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	fakeclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
)

func TestRegisterAPIServicesRetriesUpdateConflicts(t *testing.T) {
	t.Parallel()

	existing := CoreV1Alpha.ToAPIService("kube-controller", "apoxy", 443, []byte("old-ca"))
	existing.ResourceVersion = "1"

	clientset := fakeclientset.NewSimpleClientset(existing)
	registration := &APIRegistration{apiRegC: clientset}

	updateAttempts := 0
	clientset.PrependReactor("update", "apiservices", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updateAttempts++
		update := action.(k8stesting.UpdateAction)
		obj := update.GetObject().(*apiregistrationv1.APIService)
		if obj.Name != existing.Name {
			return false, nil, nil
		}
		if updateAttempts == 1 {
			return true, nil, apierrors.NewConflict(update.GetResource().GroupResource(), obj.Name, nil)
		}
		obj = obj.DeepCopy()
		obj.ResourceVersion = "2"
		if err := clientset.Tracker().Update(apiregistrationv1.SchemeGroupVersion.WithResource("apiservices"), obj, ""); err != nil {
			return true, nil, err
		}
		return true, obj, nil
	})

	err := registration.RegisterAPIServices(context.Background(), "kube-controller", "apoxy", 443, []byte("new-ca"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, updateAttempts, 2)

	svc, err := clientset.ApiregistrationV1().APIServices().Get(context.Background(), existing.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, []byte("new-ca"), svc.Spec.CABundle)
	require.Equal(t, int32(443), *svc.Spec.Service.Port)
}

func TestRegisterAPIServicesDeletesStaleServiceRegistrations(t *testing.T) {
	t.Parallel()

	stale := ControllersV1Alpha1.ToAPIService("kube-controller", "apoxy", 443, []byte("old-ca"))
	clientset := fakeclientset.NewSimpleClientset(stale)
	registration := &APIRegistration{apiRegC: clientset}

	err := registration.RegisterAPIServices(context.Background(), "kube-controller", "apoxy", 443, []byte("new-ca"))
	require.NoError(t, err)

	_, err = clientset.ApiregistrationV1().APIServices().Get(context.Background(), stale.Name, metav1.GetOptions{})
	require.Error(t, err)
	require.True(t, apierrors.IsNotFound(err))

	_, err = clientset.ApiregistrationV1().APIServices().Get(context.Background(), CoreV1Alpha.GetAPIServiceName(), metav1.GetOptions{})
	require.NoError(t, err)
}
