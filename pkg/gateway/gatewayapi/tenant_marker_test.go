package gatewayapi

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

// TestProcessBackendDestinationSettingInputDerived pins the v1 scope of the
// input-derived flag: Backend endpoints and dynamic-proxy Backends set it;
// nothing else in processDestination does.
func TestProcessBackendDestinationSettingInputDerived(t *testing.T) {
	cases := []struct {
		name    string
		backend *corev1alpha2.Backend
	}{
		{
			name: "fqdn endpoints",
			backend: &corev1alpha2.Backend{
				ObjectMeta: metav1.ObjectMeta{Name: "b-fqdn"},
				Spec: corev1alpha2.BackendSpec{
					Endpoints: []corev1alpha2.BackendEndpoint{{FQDN: "api.example.com"}},
				},
			},
		},
		{
			name: "ip endpoints",
			backend: &corev1alpha2.Backend{
				ObjectMeta: metav1.ObjectMeta{Name: "b-ip"},
				Spec: corev1alpha2.BackendSpec{
					Endpoints: []corev1alpha2.BackendEndpoint{{IP: "203.0.113.10"}},
				},
			},
		},
		{
			name: "dynamic proxy",
			backend: &corev1alpha2.Backend{
				ObjectMeta: metav1.ObjectMeta{Name: "b-dfp"},
				Spec: corev1alpha2.BackendSpec{
					DynamicProxy: &corev1alpha2.DynamicProxySpec{
						DnsCacheConfig: &corev1alpha2.DynamicProxyDnsCacheConfig{},
					},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &Translator{}
			resources := &Resources{Backends: []*corev1alpha2.Backend{tc.backend}}
			ds, err := tr.processBackendDestinationSetting(gwapiv1.BackendObjectReference{
				Name: gwapiv1.ObjectName(tc.backend.Name),
				Port: ptr.To(gwapiv1.PortNumber(8080)),
			}, resources)
			if err != nil {
				t.Fatalf("processBackendDestinationSetting: %v", err)
			}
			if !ds.InputDerived {
				t.Fatalf("backend destination setting is not input-derived")
			}
		})
	}
}
