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
// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// HTTPRouteLister helps list HTTPRoutes.
// All objects returned here must be treated as read-only.
type HTTPRouteLister interface {
	// List lists all HTTPRoutes in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.HTTPRoute, err error)
	// Get retrieves the HTTPRoute from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.HTTPRoute, error)
	HTTPRouteListerExpansion
}

// hTTPRouteLister implements the HTTPRouteLister interface.
type hTTPRouteLister struct {
	indexer cache.Indexer
}

// NewHTTPRouteLister returns a new HTTPRouteLister.
func NewHTTPRouteLister(indexer cache.Indexer) HTTPRouteLister {
	return &hTTPRouteLister{indexer: indexer}
}

// List lists all HTTPRoutes in the indexer.
func (s *hTTPRouteLister) List(selector labels.Selector) (ret []*v1.HTTPRoute, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.HTTPRoute))
	})
	return ret, err
}

// Get retrieves the HTTPRoute from the index for a given name.
func (s *hTTPRouteLister) Get(name string) (*v1.HTTPRoute, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("httproute"), name)
	}
	return obj.(*v1.HTTPRoute), nil
}
