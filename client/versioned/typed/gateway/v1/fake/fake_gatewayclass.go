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

	v1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeGatewayClasses implements GatewayClassInterface
type FakeGatewayClasses struct {
	Fake *FakeGatewayV1
}

var gatewayclassesResource = v1.SchemeGroupVersion.WithResource("gatewayclasses")

var gatewayclassesKind = v1.SchemeGroupVersion.WithKind("GatewayClass")

// Get takes name of the gatewayClass, and returns the corresponding gatewayClass object, and an error if there is any.
func (c *FakeGatewayClasses) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.GatewayClass, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(gatewayclassesResource, name), &v1.GatewayClass{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.GatewayClass), err
}

// List takes label and field selectors, and returns the list of GatewayClasses that match those selectors.
func (c *FakeGatewayClasses) List(ctx context.Context, opts metav1.ListOptions) (result *v1.GatewayClassList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(gatewayclassesResource, gatewayclassesKind, opts), &v1.GatewayClassList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.GatewayClassList{ListMeta: obj.(*v1.GatewayClassList).ListMeta}
	for _, item := range obj.(*v1.GatewayClassList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested gatewayClasses.
func (c *FakeGatewayClasses) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(gatewayclassesResource, opts))
}

// Create takes the representation of a gatewayClass and creates it.  Returns the server's representation of the gatewayClass, and an error, if there is any.
func (c *FakeGatewayClasses) Create(ctx context.Context, gatewayClass *v1.GatewayClass, opts metav1.CreateOptions) (result *v1.GatewayClass, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(gatewayclassesResource, gatewayClass), &v1.GatewayClass{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.GatewayClass), err
}

// Update takes the representation of a gatewayClass and updates it. Returns the server's representation of the gatewayClass, and an error, if there is any.
func (c *FakeGatewayClasses) Update(ctx context.Context, gatewayClass *v1.GatewayClass, opts metav1.UpdateOptions) (result *v1.GatewayClass, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(gatewayclassesResource, gatewayClass), &v1.GatewayClass{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.GatewayClass), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeGatewayClasses) UpdateStatus(ctx context.Context, gatewayClass *v1.GatewayClass, opts metav1.UpdateOptions) (*v1.GatewayClass, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(gatewayclassesResource, "status", gatewayClass), &v1.GatewayClass{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.GatewayClass), err
}

// Delete takes name of the gatewayClass and deletes it. Returns an error if one occurs.
func (c *FakeGatewayClasses) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(gatewayclassesResource, name, opts), &v1.GatewayClass{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeGatewayClasses) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(gatewayclassesResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1.GatewayClassList{})
	return err
}

// Patch applies the patch and returns the patched gatewayClass.
func (c *FakeGatewayClasses) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.GatewayClass, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(gatewayclassesResource, name, pt, data, subresources...), &v1.GatewayClass{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.GatewayClass), err
}
