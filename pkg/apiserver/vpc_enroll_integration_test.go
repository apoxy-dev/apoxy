package apiserver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	genericregistry "k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/rest"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
)

// echoEnroll returns the request with a status that names the VPCNetwork.
type echoEnroll struct{}

func (echoEnroll) New() runtime.Object   { return &vpcv1alpha1.AgentEnrollment{} }
func (echoEnroll) Destroy()              {}
func (echoEnroll) NamespaceScoped() bool { return false }

func (echoEnroll) Create(_ context.Context, name string, obj runtime.Object, _ rest.ValidateObjectFunc, _ *metav1.CreateOptions) (runtime.Object, error) {
	out := obj.(*vpcv1alpha1.AgentEnrollment).DeepCopy()
	out.Status.Certificate = "cert-for-" + name
	return out, nil
}

// TestAPIServerIntegrationVPCEnrollMount checks that a deployment can mount
// the vpcnetworks/enroll subresource and that its body kind decodes.
func TestAPIServerIntegrationVPCEnrollMount(t *testing.T) {
	srv := startTestServer(t,
		WithResource(&vpcv1alpha1.VPCNetwork{}),
		WithStorage(vpcv1alpha1.SchemeGroupVersion.WithResource("vpcnetworks/enroll"),
			func(*runtime.Scheme, genericregistry.RESTOptionsGetter) (rest.Storage, error) {
				return echoEnroll{}, nil
			}),
	)
	t.Cleanup(srv.cancel)

	var out vpcv1alpha1.AgentEnrollment
	err := newClientset(t, srv.addr).VpcV1alpha1().RESTClient().Post().
		Resource("vpcnetworks").Name("net").SubResource("enroll").
		Body(&vpcv1alpha1.AgentEnrollment{Spec: vpcv1alpha1.AgentEnrollmentSpec{AgentName: "laptop", CSR: "csr"}}).
		Do(context.Background()).
		Into(&out)
	require.NoError(t, err)
	require.Equal(t, "laptop", out.Spec.AgentName)
	require.Equal(t, "cert-for-net", out.Status.Certificate)
}
