package apiserver

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/version"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/util/compatibility"
)

func NewScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()

	// Whitelist the unversioned API types for any apiserver.
	unversioned := schema.GroupVersion{
		Group:   "",
		Version: "v1",
	}
	metav1.AddToGroupVersion(scheme, unversioned)

	scheme.AddUnversionedTypes(unversioned,
		&metav1.Status{},
		&metav1.WatchEvent{},
		&metav1.APIVersions{},
		&metav1.APIGroupList{},
		&metav1.APIGroup{},
		&metav1.APIResourceList{},
	)
	return scheme
}

// ExtraConfig holds custom apiserver config
type ExtraConfig struct {
	Scheme         *runtime.Scheme
	Codecs         serializer.CodecFactory
	APIs           map[schema.GroupVersionResource]StorageProvider
	ServingInfo    *genericapiserver.SecureServingInfo
	Version        *version.Info
	ParameterCodec runtime.ParameterCodec
}

// Config defines the config for the apiserver
type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}

// ApoxyServer contains state for an Apoxy API server.
type ApoxyServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig
	ExtraConfig   *ExtraConfig
}

// CompletedConfig embeds a private pointer that cannot be instantiated outside of this package.
type CompletedConfig struct {
	*completedConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (cfg *Config) Complete() CompletedConfig {
	cfg.GenericConfig.EffectiveVersion = compatibility.DefaultBuildEffectiveVersion()

	c := completedConfig{}
	c.GenericConfig = cfg.GenericConfig.Complete()
	c.ExtraConfig = &cfg.ExtraConfig
	return CompletedConfig{&c}
}

// New returns a new instance of ApoxyServer from the given config.
func (c completedConfig) New() (*ApoxyServer, error) {
	genericServer, err := c.GenericConfig.New("apoxy-apiserver", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}

	s := &ApoxyServer{
		GenericAPIServer: genericServer,
	}

	// Add new APIs through inserting into APIs
	apiGroups, err := buildAPIGroupInfos(c.ExtraConfig.Scheme, c.ExtraConfig.Codecs, c.ExtraConfig.APIs, c.GenericConfig.RESTOptionsGetter, c.ExtraConfig.ParameterCodec)
	if err != nil {
		return nil, err
	}
	for _, apiGroup := range apiGroups {
		if err := s.GenericAPIServer.InstallAPIGroup(apiGroup); err != nil {
			return nil, err
		}
	}

	return s, nil
}
