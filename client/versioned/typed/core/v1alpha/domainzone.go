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

package v1alpha

import (
	"context"
	"time"

	v1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	scheme "github.com/apoxy-dev/apoxy/client/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// DomainZonesGetter has a method to return a DomainZoneInterface.
// A group's client should implement this interface.
type DomainZonesGetter interface {
	DomainZones() DomainZoneInterface
}

// DomainZoneInterface has methods to work with DomainZone resources.
type DomainZoneInterface interface {
	Create(ctx context.Context, domainZone *v1alpha.DomainZone, opts v1.CreateOptions) (*v1alpha.DomainZone, error)
	Update(ctx context.Context, domainZone *v1alpha.DomainZone, opts v1.UpdateOptions) (*v1alpha.DomainZone, error)
	UpdateStatus(ctx context.Context, domainZone *v1alpha.DomainZone, opts v1.UpdateOptions) (*v1alpha.DomainZone, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha.DomainZone, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha.DomainZoneList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha.DomainZone, err error)
	DomainZoneExpansion
}

// domainZones implements DomainZoneInterface
type domainZones struct {
	client rest.Interface
}

// newDomainZones returns a DomainZones
func newDomainZones(c *CoreV1alphaClient) *domainZones {
	return &domainZones{
		client: c.RESTClient(),
	}
}

// Get takes name of the domainZone, and returns the corresponding domainZone object, and an error if there is any.
func (c *domainZones) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha.DomainZone, err error) {
	result = &v1alpha.DomainZone{}
	err = c.client.Get().
		Resource("domainzones").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of DomainZones that match those selectors.
func (c *domainZones) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha.DomainZoneList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha.DomainZoneList{}
	err = c.client.Get().
		Resource("domainzones").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested domainZones.
func (c *domainZones) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("domainzones").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a domainZone and creates it.  Returns the server's representation of the domainZone, and an error, if there is any.
func (c *domainZones) Create(ctx context.Context, domainZone *v1alpha.DomainZone, opts v1.CreateOptions) (result *v1alpha.DomainZone, err error) {
	result = &v1alpha.DomainZone{}
	err = c.client.Post().
		Resource("domainzones").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(domainZone).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a domainZone and updates it. Returns the server's representation of the domainZone, and an error, if there is any.
func (c *domainZones) Update(ctx context.Context, domainZone *v1alpha.DomainZone, opts v1.UpdateOptions) (result *v1alpha.DomainZone, err error) {
	result = &v1alpha.DomainZone{}
	err = c.client.Put().
		Resource("domainzones").
		Name(domainZone.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(domainZone).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *domainZones) UpdateStatus(ctx context.Context, domainZone *v1alpha.DomainZone, opts v1.UpdateOptions) (result *v1alpha.DomainZone, err error) {
	result = &v1alpha.DomainZone{}
	err = c.client.Put().
		Resource("domainzones").
		Name(domainZone.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(domainZone).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the domainZone and deletes it. Returns an error if one occurs.
func (c *domainZones) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("domainzones").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *domainZones) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("domainzones").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched domainZone.
func (c *domainZones) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha.DomainZone, err error) {
	result = &v1alpha.DomainZone{}
	err = c.client.Patch(pt).
		Resource("domainzones").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
