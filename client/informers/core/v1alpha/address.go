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

package v1alpha

import (
	"context"
	time "time"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	internalinterfaces "github.com/apoxy-dev/apoxy/client/informers/internalinterfaces"
	v1alpha "github.com/apoxy-dev/apoxy/client/listers/core/v1alpha"
	versioned "github.com/apoxy-dev/apoxy/client/versioned"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// AddressInformer provides access to a shared informer and lister for
// Addresses.
type AddressInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha.AddressLister
}

type addressInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewAddressInformer constructs a new informer for Address type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewAddressInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredAddressInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredAddressInformer constructs a new informer for Address type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredAddressInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CoreV1alpha().Addresses().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CoreV1alpha().Addresses().Watch(context.TODO(), options)
			},
		},
		&corev1alpha.Address{},
		resyncPeriod,
		indexers,
	)
}

func (f *addressInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredAddressInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *addressInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&corev1alpha.Address{}, f.defaultInformer)
}

func (f *addressInformer) Lister() v1alpha.AddressLister {
	return v1alpha.NewAddressLister(f.Informer().GetIndexer())
}
