package apiserver

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	genericregistry "k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/rest"
	pkgserver "k8s.io/apiserver/pkg/server"
)

type StorageProvider func(s *runtime.Scheme, g genericregistry.RESTOptionsGetter) (rest.Storage, error)

func buildAPIGroupInfos(scheme *runtime.Scheme,
	codecs serializer.CodecFactory,
	apiMap map[schema.GroupVersionResource]StorageProvider,
	g genericregistry.RESTOptionsGetter,
	parameterCodec runtime.ParameterCodec) ([]*pkgserver.APIGroupInfo, error) {
	groups := map[string]struct{}{}
	if parameterCodec == nil {
		parameterCodec = metav1.ParameterCodec
	}
	for gvr := range apiMap {
		groups[gvr.Group] = struct{}{}
	}
	apiGroups := []*pkgserver.APIGroupInfo{}
	for group := range groups {
		apis := map[string]map[string]rest.Storage{}
		for gvr, storageProviderFunc := range apiMap {
			if gvr.Group == group {
				if _, found := apis[gvr.Version]; !found {
					apis[gvr.Version] = map[string]rest.Storage{}
				}
				storage, err := storageProviderFunc(scheme, g)
				if err != nil {
					return nil, err
				}
				apis[gvr.Version][gvr.Resource] = storage
			}
		}
		apiGroupInfo := pkgserver.NewDefaultAPIGroupInfo(group, scheme, parameterCodec, codecs)
		apiGroupInfo.VersionedResourcesStorageMap = apis
		apiGroups = append(apiGroups, &apiGroupInfo)
	}
	return apiGroups, nil
}
