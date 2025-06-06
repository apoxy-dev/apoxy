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
// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeBackends implements BackendInterface
type FakeBackends struct {
	Fake *FakeCoreV1alpha
}

var backendsResource = v1alpha.SchemeGroupVersion.WithResource("backends")

var backendsKind = v1alpha.SchemeGroupVersion.WithKind("Backend")

// Get takes name of the backend, and returns the corresponding backend object, and an error if there is any.
func (c *FakeBackends) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha.Backend, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(backendsResource, name), &v1alpha.Backend{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.Backend), err
}

// List takes label and field selectors, and returns the list of Backends that match those selectors.
func (c *FakeBackends) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha.BackendList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(backendsResource, backendsKind, opts), &v1alpha.BackendList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha.BackendList{ListMeta: obj.(*v1alpha.BackendList).ListMeta}
	for _, item := range obj.(*v1alpha.BackendList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested backends.
func (c *FakeBackends) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(backendsResource, opts))
}

// Create takes the representation of a backend and creates it.  Returns the server's representation of the backend, and an error, if there is any.
func (c *FakeBackends) Create(ctx context.Context, backend *v1alpha.Backend, opts v1.CreateOptions) (result *v1alpha.Backend, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(backendsResource, backend), &v1alpha.Backend{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.Backend), err
}

// Update takes the representation of a backend and updates it. Returns the server's representation of the backend, and an error, if there is any.
func (c *FakeBackends) Update(ctx context.Context, backend *v1alpha.Backend, opts v1.UpdateOptions) (result *v1alpha.Backend, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(backendsResource, backend), &v1alpha.Backend{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.Backend), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeBackends) UpdateStatus(ctx context.Context, backend *v1alpha.Backend, opts v1.UpdateOptions) (*v1alpha.Backend, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(backendsResource, "status", backend), &v1alpha.Backend{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.Backend), err
}

// Delete takes name of the backend and deletes it. Returns an error if one occurs.
func (c *FakeBackends) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(backendsResource, name, opts), &v1alpha.Backend{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeBackends) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(backendsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha.BackendList{})
	return err
}

// Patch applies the patch and returns the patched backend.
func (c *FakeBackends) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha.Backend, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(backendsResource, name, pt, data, subresources...), &v1alpha.Backend{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.Backend), err
}
