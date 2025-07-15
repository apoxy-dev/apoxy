package apiregistration

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"k8s.io/utils/ptr"
)

// APIServiceDefinition defines a Kubernetes API service
type APIServiceDefinition struct {
	Group   string
	Version string
	// Priority values for API service registration
	GroupPriorityMinimum int32
	VersionPriority      int32
}

// GetAPIServiceName returns the name of the APIService resource
func (a *APIServiceDefinition) GetAPIServiceName() string {
	return a.Version + "." + a.Group
}

// ToAPIService converts the definition to a Kubernetes APIService object
func (a *APIServiceDefinition) ToAPIService(serviceName, namespace string, port int, caBundle []byte) *apiregistrationv1.APIService {
	return &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name: a.GetAPIServiceName(),
		},
		Spec: apiregistrationv1.APIServiceSpec{
			Group:                a.Group,
			Version:              a.Version,
			GroupPriorityMinimum: a.GroupPriorityMinimum,
			VersionPriority:      a.VersionPriority,
			Service: &apiregistrationv1.ServiceReference{
				Name:      serviceName,
				Namespace: namespace,
				Port:      ptr.To(int32(port)),
			},
			CABundle:              caBundle,
			InsecureSkipTLSVerify: false,
		},
	}
}

// All Apoxy API Group Version Kinds
var (
	// Config API
	ConfigV1Alpha1 = &APIServiceDefinition{
		Group:                "config.apoxy.dev",
		Version:              "v1alpha1",
		GroupPriorityMinimum: 1000,
		VersionPriority:      100,
	}

	// Controllers API
	ControllersV1Alpha1 = &APIServiceDefinition{
		Group:                "controllers.apoxy.dev",
		Version:              "v1alpha1",
		GroupPriorityMinimum: 1000,
		VersionPriority:      100,
	}

	// Core API
	CoreV1Alpha = &APIServiceDefinition{
		Group:                "core.apoxy.dev",
		Version:              "v1alpha",
		GroupPriorityMinimum: 1000,
		VersionPriority:      100,
	}

	// Extensions API
	ExtensionsV1Alpha1 = &APIServiceDefinition{
		Group:                "extensions.apoxy.dev",
		Version:              "v1alpha1",
		GroupPriorityMinimum: 1000,
		VersionPriority:      100,
	}

	ExtensionsV1Alpha2 = &APIServiceDefinition{
		Group:                "extensions.apoxy.dev",
		Version:              "v1alpha2",
		GroupPriorityMinimum: 1000,
		VersionPriority:      100,
	}

	// Gateway API
	GatewayV1 = &APIServiceDefinition{
		Group:                "gateway.apoxy.dev",
		Version:              "v1",
		GroupPriorityMinimum: 1000,
		VersionPriority:      100,
	}

	// Policy API
	PolicyV1Alpha1 = &APIServiceDefinition{
		Group:                "policy.apoxy.dev",
		Version:              "v1alpha1",
		GroupPriorityMinimum: 1000,
		VersionPriority:      100,
	}

	// AllAPIServices is a list of all API services to be registered
	AllAPIServices = []*APIServiceDefinition{
		ConfigV1Alpha1,
		ControllersV1Alpha1,
		CoreV1Alpha,
		ExtensionsV1Alpha1,
		ExtensionsV1Alpha2,
		GatewayV1,
		PolicyV1Alpha1,
	}
)
