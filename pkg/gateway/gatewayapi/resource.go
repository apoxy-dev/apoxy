// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package gatewayapi

import (
	"cmp"
	"reflect"
	"slices"

	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gwapiv1b1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	mcsapi "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
)

const (
	// StandaloneControllerName is the new default controller name for standalone gateways.
	StandaloneControllerName = "apoxy.dev/gatewayclass-standalone"
	// LegacyControllerName is the old default controller name (kept for backwards compatibility).
	LegacyControllerName = "gateway.apoxy.dev/gatewayclass-controller"
	// CloudControllerName is the controller name for cloud-managed gateways.
	CloudControllerName = "apoxy.dev/gatewayclass-cloud"

	// DefaultControllerName is an alias for StandaloneControllerName.
	// Deprecated: Use StandaloneControllerName instead.
	DefaultControllerName = StandaloneControllerName
)

type XdsIRMap map[string]*ir.Xds

// Resources holds the Gateway API and related
// resources that the translators needs as inputs.
// +k8s:deepcopy-gen=true
type Resources struct {
	// This field is only used for marshalling/unmarshalling purposes and is not used by
	// the translator
	GatewayClass          *gwapiv1.GatewayClass                      `json:"gatewayClass,omitempty" yaml:"gatewayClass,omitempty"`
	Gateways              []*gwapiv1.Gateway                         `json:"gateways,omitempty" yaml:"gateways,omitempty"`
	HTTPRoutes            []*gwapiv1.HTTPRoute                       `json:"httpRoutes,omitempty" yaml:"httpRoutes,omitempty"`
	GRPCRoutes            []*gwapiv1a2.GRPCRoute                     `json:"grpcRoutes,omitempty" yaml:"grpcRoutes,omitempty"`
	TLSRoutes             []*gwapiv1a2.TLSRoute                      `json:"tlsRoutes,omitempty" yaml:"tlsRoutes,omitempty"`
	TCPRoutes             []*gwapiv1a2.TCPRoute                      `json:"tcpRoutes,omitempty" yaml:"tcpRoutes,omitempty"`
	UDPRoutes             []*gwapiv1a2.UDPRoute                      `json:"udpRoutes,omitempty" yaml:"udpRoutes,omitempty"`
	ReferenceGrants       []*gwapiv1b1.ReferenceGrant                `json:"referenceGrants,omitempty" yaml:"referenceGrants,omitempty"`
	Namespaces            []*v1.Namespace                            `json:"namespaces,omitempty" yaml:"namespaces,omitempty"`
	Services              []*v1.Service                              `json:"services,omitempty" yaml:"services,omitempty"`
	ServiceImports        []*mcsapi.ServiceImport                    `json:"serviceImports,omitempty" yaml:"serviceImports,omitempty"`
	EndpointSlices        []*discoveryv1.EndpointSlice               `json:"endpointSlices,omitempty" yaml:"endpointSlices,omitempty"`
	Secrets               []*v1.Secret                               `json:"secrets,omitempty" yaml:"secrets,omitempty"`
	ConfigMaps            []*v1.ConfigMap                            `json:"configMaps,omitempty" yaml:"configMaps,omitempty"`
	ExtensionRefFilters   []unstructured.Unstructured                `json:"extensionRefFilters,omitempty" yaml:"extensionRefFilters,omitempty"`
	EdgeFunctionBackends  []*extensionsv1alpha2.EdgeFunction         `json:"edgeFunctionBackends,omitempty" yaml:"edgeFunctionBackends,omitempty"`
	EdgeFunctionRevisions []*extensionsv1alpha2.EdgeFunctionRevision `json:"edgeFunctionFilters,omitempty" yaml:"edgeFunctionFilters,omitempty"`
	Backends              []*corev1alpha2.Backend                    `json:"backends,omitempty" yaml:"backends,omitempty"`
	Proxies               []*corev1alpha2.Proxy                      `json:"proxies,omitempty" yaml:"proxies,omitempty"`
}

func NewResources() *Resources {
	return &Resources{
		Gateways:            []*gwapiv1.Gateway{},
		HTTPRoutes:          []*gwapiv1.HTTPRoute{},
		GRPCRoutes:          []*gwapiv1a2.GRPCRoute{},
		TLSRoutes:           []*gwapiv1a2.TLSRoute{},
		Services:            []*v1.Service{},
		EndpointSlices:      []*discoveryv1.EndpointSlice{},
		Secrets:             []*v1.Secret{},
		ConfigMaps:          []*v1.ConfigMap{},
		ReferenceGrants:     []*gwapiv1b1.ReferenceGrant{},
		Namespaces:          []*v1.Namespace{},
		ExtensionRefFilters: []unstructured.Unstructured{},
	}
}

func (r *Resources) GetNamespace(name string) *v1.Namespace {
	for _, ns := range r.Namespaces {
		if ns.Name == name {
			return ns
		}
	}

	return nil
}

func (r *Resources) GetService(namespace, name string) *v1.Service {
	for _, svc := range r.Services {
		if svc.Namespace == namespace && svc.Name == name {
			return svc
		}
	}

	return nil
}

func (r *Resources) GetServiceImport(namespace, name string) *mcsapi.ServiceImport {
	for _, svcImp := range r.ServiceImports {
		if svcImp.Namespace == namespace && svcImp.Name == name {
			return svcImp
		}
	}

	return nil
}

func (r *Resources) GetSecret(namespace, name string) *v1.Secret {
	for _, secret := range r.Secrets {
		if secret.Namespace == namespace && secret.Name == name {
			return secret
		}
	}

	return nil
}

func (r *Resources) GetConfigMap(namespace, name string) *v1.ConfigMap {
	for _, configMap := range r.ConfigMaps {
		if configMap.Namespace == namespace && configMap.Name == name {
			return configMap
		}
	}

	return nil
}

func (r *Resources) GetEndpointSlicesForBackend(svcNamespace, svcName string, backendKind string) []*discoveryv1.EndpointSlice {
	var endpointSlices []*discoveryv1.EndpointSlice
	for _, endpointSlice := range r.EndpointSlices {
		var backendSelectorLabel string
		switch backendKind {
		case KindService:
			backendSelectorLabel = discoveryv1.LabelServiceName
		case KindServiceImport:
			backendSelectorLabel = mcsapi.LabelServiceName
		}
		if svcNamespace == endpointSlice.Namespace &&
			endpointSlice.GetLabels()[backendSelectorLabel] == svcName {
			endpointSlices = append(endpointSlices, endpointSlice)
		}
	}
	return endpointSlices
}

func (r *Resources) GetEdgeFunctionBackend(name string) *extensionsv1alpha2.EdgeFunction {
	for _, edgeFunc := range r.EdgeFunctionBackends {
		if edgeFunc.Name == name {
			return edgeFunc
		}
	}

	return nil
}

func (r *Resources) GetBackend(name string) *corev1alpha2.Backend {
	for _, backend := range r.Backends {
		if backend.Name == name {
			return backend
		}
	}
	return nil
}

func (r *Resources) GetProxy(name string) (*corev1alpha2.Proxy, bool) {
	for _, proxy := range r.Proxies {
		if proxy.Name == name {
			return proxy, true
		}
	}
	return nil, false
}

// ControllerResources holds all the GatewayAPI resources per GatewayClass
type ControllerResources []*Resources

// DeepCopy creates a new ControllerResources.
// It is handwritten since the tooling was unable to copy into a new slice
func (c *ControllerResources) DeepCopy() *ControllerResources {
	if c == nil {
		return nil
	}
	out := make(ControllerResources, len(*c))
	copy(out, *c)
	return &out
}

// Equal implements the Comparable interface used by watchable.DeepEqual to skip unnecessary updates.
func (c *ControllerResources) Equal(y *ControllerResources) bool {
	// Deep copy to avoid modifying the original ordering.
	c = c.DeepCopy()
	c.sort()
	y = y.DeepCopy()
	y.sort()
	return reflect.DeepEqual(c, y)
}

func (c *ControllerResources) sort() {
	slices.SortFunc(*c, func(c1, c2 *Resources) int {
		return cmp.Compare(c1.GatewayClass.Name, c2.GatewayClass.Name)
	})
}
