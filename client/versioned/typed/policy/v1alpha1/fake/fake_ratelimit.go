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

	v1alpha1 "github.com/apoxy-dev/apoxy/api/policy/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeRateLimits implements RateLimitInterface
type FakeRateLimits struct {
	Fake *FakePolicyV1alpha1
}

var ratelimitsResource = v1alpha1.SchemeGroupVersion.WithResource("ratelimits")

var ratelimitsKind = v1alpha1.SchemeGroupVersion.WithKind("RateLimit")

// Get takes name of the rateLimit, and returns the corresponding rateLimit object, and an error if there is any.
func (c *FakeRateLimits) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.RateLimit, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(ratelimitsResource, name), &v1alpha1.RateLimit{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.RateLimit), err
}

// List takes label and field selectors, and returns the list of RateLimits that match those selectors.
func (c *FakeRateLimits) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.RateLimitList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(ratelimitsResource, ratelimitsKind, opts), &v1alpha1.RateLimitList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.RateLimitList{ListMeta: obj.(*v1alpha1.RateLimitList).ListMeta}
	for _, item := range obj.(*v1alpha1.RateLimitList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested rateLimits.
func (c *FakeRateLimits) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(ratelimitsResource, opts))
}

// Create takes the representation of a rateLimit and creates it.  Returns the server's representation of the rateLimit, and an error, if there is any.
func (c *FakeRateLimits) Create(ctx context.Context, rateLimit *v1alpha1.RateLimit, opts v1.CreateOptions) (result *v1alpha1.RateLimit, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(ratelimitsResource, rateLimit), &v1alpha1.RateLimit{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.RateLimit), err
}

// Update takes the representation of a rateLimit and updates it. Returns the server's representation of the rateLimit, and an error, if there is any.
func (c *FakeRateLimits) Update(ctx context.Context, rateLimit *v1alpha1.RateLimit, opts v1.UpdateOptions) (result *v1alpha1.RateLimit, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(ratelimitsResource, rateLimit), &v1alpha1.RateLimit{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.RateLimit), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeRateLimits) UpdateStatus(ctx context.Context, rateLimit *v1alpha1.RateLimit, opts v1.UpdateOptions) (*v1alpha1.RateLimit, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(ratelimitsResource, "status", rateLimit), &v1alpha1.RateLimit{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.RateLimit), err
}

// Delete takes name of the rateLimit and deletes it. Returns an error if one occurs.
func (c *FakeRateLimits) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(ratelimitsResource, name, opts), &v1alpha1.RateLimit{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeRateLimits) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(ratelimitsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.RateLimitList{})
	return err
}

// Patch applies the patch and returns the patched rateLimit.
func (c *FakeRateLimits) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.RateLimit, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(ratelimitsResource, name, pt, data, subresources...), &v1alpha1.RateLimit{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.RateLimit), err
}
