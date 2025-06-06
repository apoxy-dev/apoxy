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

	v1alpha1 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeEdgeFunctions implements EdgeFunctionInterface
type FakeEdgeFunctions struct {
	Fake *FakeExtensionsV1alpha1
}

var edgefunctionsResource = v1alpha1.SchemeGroupVersion.WithResource("edgefunctions")

var edgefunctionsKind = v1alpha1.SchemeGroupVersion.WithKind("EdgeFunction")

// Get takes name of the edgeFunction, and returns the corresponding edgeFunction object, and an error if there is any.
func (c *FakeEdgeFunctions) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.EdgeFunction, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(edgefunctionsResource, name), &v1alpha1.EdgeFunction{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.EdgeFunction), err
}

// List takes label and field selectors, and returns the list of EdgeFunctions that match those selectors.
func (c *FakeEdgeFunctions) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.EdgeFunctionList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(edgefunctionsResource, edgefunctionsKind, opts), &v1alpha1.EdgeFunctionList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.EdgeFunctionList{ListMeta: obj.(*v1alpha1.EdgeFunctionList).ListMeta}
	for _, item := range obj.(*v1alpha1.EdgeFunctionList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested edgeFunctions.
func (c *FakeEdgeFunctions) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(edgefunctionsResource, opts))
}

// Create takes the representation of a edgeFunction and creates it.  Returns the server's representation of the edgeFunction, and an error, if there is any.
func (c *FakeEdgeFunctions) Create(ctx context.Context, edgeFunction *v1alpha1.EdgeFunction, opts v1.CreateOptions) (result *v1alpha1.EdgeFunction, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(edgefunctionsResource, edgeFunction), &v1alpha1.EdgeFunction{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.EdgeFunction), err
}

// Update takes the representation of a edgeFunction and updates it. Returns the server's representation of the edgeFunction, and an error, if there is any.
func (c *FakeEdgeFunctions) Update(ctx context.Context, edgeFunction *v1alpha1.EdgeFunction, opts v1.UpdateOptions) (result *v1alpha1.EdgeFunction, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(edgefunctionsResource, edgeFunction), &v1alpha1.EdgeFunction{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.EdgeFunction), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeEdgeFunctions) UpdateStatus(ctx context.Context, edgeFunction *v1alpha1.EdgeFunction, opts v1.UpdateOptions) (*v1alpha1.EdgeFunction, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(edgefunctionsResource, "status", edgeFunction), &v1alpha1.EdgeFunction{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.EdgeFunction), err
}

// Delete takes name of the edgeFunction and deletes it. Returns an error if one occurs.
func (c *FakeEdgeFunctions) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(edgefunctionsResource, name, opts), &v1alpha1.EdgeFunction{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeEdgeFunctions) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(edgefunctionsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.EdgeFunctionList{})
	return err
}

// Patch applies the patch and returns the patched edgeFunction.
func (c *FakeEdgeFunctions) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.EdgeFunction, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(edgefunctionsResource, name, pt, data, subresources...), &v1alpha1.EdgeFunction{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.EdgeFunction), err
}
