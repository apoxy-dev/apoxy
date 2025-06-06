/*
Copyright 2025 Apoxy, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by informer-gen. DO NOT EDIT.

package informers

import (
	"fmt"

	v1alpha1 "github.com/apoxy-dev/apoxy/api/controllers/v1alpha1"
	v1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	extensionsv1alpha1 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha1"
	v1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	v1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
	policyv1alpha1 "github.com/apoxy-dev/apoxy/api/policy/v1alpha1"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	cache "k8s.io/client-go/tools/cache"
)

// GenericInformer is type of SharedIndexInformer which will locate and delegate to other
// sharedInformers based on type
type GenericInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() cache.GenericLister
}

type genericInformer struct {
	informer cache.SharedIndexInformer
	resource schema.GroupResource
}

// Informer returns the SharedIndexInformer.
func (f *genericInformer) Informer() cache.SharedIndexInformer {
	return f.informer
}

// Lister returns the GenericLister.
func (f *genericInformer) Lister() cache.GenericLister {
	return cache.NewGenericLister(f.Informer().GetIndexer(), f.resource)
}

// ForResource gives generic access to a shared informer of the matching type
// TODO extend this to unknown resources with a client pool
func (f *sharedInformerFactory) ForResource(resource schema.GroupVersionResource) (GenericInformer, error) {
	switch resource {
	// Group=controllers.apoxy.dev, Version=v1alpha1
	case v1alpha1.SchemeGroupVersion.WithResource("proxies"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Controllers().V1alpha1().Proxies().Informer()}, nil

		// Group=core.apoxy.dev, Version=v1alpha
	case v1alpha.SchemeGroupVersion.WithResource("addresses"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Core().V1alpha().Addresses().Informer()}, nil
	case v1alpha.SchemeGroupVersion.WithResource("backends"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Core().V1alpha().Backends().Informer()}, nil
	case v1alpha.SchemeGroupVersion.WithResource("domains"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Core().V1alpha().Domains().Informer()}, nil
	case v1alpha.SchemeGroupVersion.WithResource("domainzones"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Core().V1alpha().DomainZones().Informer()}, nil
	case v1alpha.SchemeGroupVersion.WithResource("proxies"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Core().V1alpha().Proxies().Informer()}, nil
	case v1alpha.SchemeGroupVersion.WithResource("tunnelnodes"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Core().V1alpha().TunnelNodes().Informer()}, nil

		// Group=extensions.apoxy.dev, Version=v1alpha1
	case extensionsv1alpha1.SchemeGroupVersion.WithResource("edgefunctions"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Extensions().V1alpha1().EdgeFunctions().Informer()}, nil
	case extensionsv1alpha1.SchemeGroupVersion.WithResource("edgefunctionrevisions"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Extensions().V1alpha1().EdgeFunctionRevisions().Informer()}, nil

		// Group=extensions.apoxy.dev, Version=v1alpha2
	case v1alpha2.SchemeGroupVersion.WithResource("edgefunctions"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Extensions().V1alpha2().EdgeFunctions().Informer()}, nil
	case v1alpha2.SchemeGroupVersion.WithResource("edgefunctionrevisions"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Extensions().V1alpha2().EdgeFunctionRevisions().Informer()}, nil

		// Group=gateway.apoxy.dev, Version=v1
	case v1.SchemeGroupVersion.WithResource("grpcroutes"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Gateway().V1().GRPCRoutes().Informer()}, nil
	case v1.SchemeGroupVersion.WithResource("gateways"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Gateway().V1().Gateways().Informer()}, nil
	case v1.SchemeGroupVersion.WithResource("gatewayclasses"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Gateway().V1().GatewayClasses().Informer()}, nil
	case v1.SchemeGroupVersion.WithResource("httproutes"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Gateway().V1().HTTPRoutes().Informer()}, nil

		// Group=policy.apoxy.dev, Version=v1alpha1
	case policyv1alpha1.SchemeGroupVersion.WithResource("ratelimits"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Policy().V1alpha1().RateLimits().Informer()}, nil

	}

	return nil, fmt.Errorf("no informer found for %v", resource)
}
