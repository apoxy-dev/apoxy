package start

import (
	"context"
	"fmt"
	"io"
	"net"

	serverapiserver "github.com/apoxy-dev/apoxy/pkg/apiserver/server/apiserver"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/registry/generic"
	genericapiserver "k8s.io/apiserver/pkg/server"
	apiserveropts "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	netutils "k8s.io/utils/net"
	openapicommon "k8s.io/kube-openapi/pkg/common"
)

type RecommendedConfigFn func(*genericapiserver.RecommendedConfig) *genericapiserver.RecommendedConfig

type ServerOptions struct {
	StdOut io.Writer
	StdErr io.Writer

	RecommendedOptions *apiserveropts.RecommendedOptions
}

func NewServerOptions(codec runtime.Codec) *ServerOptions {
	return &ServerOptions{
		StdOut: io.Discard,
		StdErr: io.Discard,
		RecommendedOptions: apiserveropts.NewRecommendedOptions(
			"/registry/apoxy",
			codec,
		),
	}
}

type ApoxyServerOptions struct {
	scheme               *runtime.Scheme
	codecs               serializer.CodecFactory
	codec                runtime.Codec
	recommendedConfigFns []RecommendedConfigFn
	apis                 map[schema.GroupVersionResource]serverapiserver.StorageProvider
	serverOptions        *ServerOptions
}

func NewApoxyServerOptions(
	scheme *runtime.Scheme,
	codecs serializer.CodecFactory,
	codec runtime.Codec,
	recommendedConfigFns []RecommendedConfigFn,
	apis map[schema.GroupVersionResource]serverapiserver.StorageProvider,
	serverOptions *ServerOptions,
) *ApoxyServerOptions {
	if serverOptions == nil {
		serverOptions = NewServerOptions(codec)
	}

	return &ApoxyServerOptions{
		scheme:               scheme,
		codecs:               codecs,
		codec:                codec,
		recommendedConfigFns: recommendedConfigFns,
		apis:                 apis,
		serverOptions:        serverOptions,
	}
}

func (o *ApoxyServerOptions) ApplyRecommendedConfigFns(in *genericapiserver.RecommendedConfig) *genericapiserver.RecommendedConfig {
	for _, fn := range o.recommendedConfigFns {
		in = fn(in)
	}
	return in
}

func SetOpenAPIDefinitionFn(scheme *runtime.Scheme, name, version string, defs openapicommon.GetOpenAPIDefinitions) RecommendedConfigFn {
	return func(config *genericapiserver.RecommendedConfig) *genericapiserver.RecommendedConfig {
		config.OpenAPIV3Config = genericapiserver.DefaultOpenAPIV3Config(defs, openapi.NewDefinitionNamer(scheme))
		config.OpenAPIV3Config.Info.Title = name
		config.OpenAPIV3Config.Info.Version = version

		config.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(defs, openapi.NewDefinitionNamer(scheme))
		config.OpenAPIConfig.Info.Title = name
		config.OpenAPIConfig.Info.Version = version
		return config
	}
}

func (o *ApoxyServerOptions) Config() (*serverapiserver.Config, error) {
	if ro := o.serverOptions.RecommendedOptions; ro != nil && ro.SecureServing != nil {
		if err := ro.SecureServing.MaybeDefaultWithSelfSignedCerts(
			"localhost",
			nil,
			[]net.IP{netutils.ParseIPSloppy("127.0.0.1")},
		); err != nil {
			return nil, fmt.Errorf("error creating self-signed certificates: %w", err)
		}
	}

	serverConfig := genericapiserver.NewRecommendedConfig(o.codecs)
	// Config fns run twice on purpose, bracketing ApplyTo. The first pass
	// populates fields ApplyTo depends on (e.g. ClientConfig, which
	// Admission.ApplyTo uses to build its kube client). The second pass
	// overrides fields ApplyTo writes that the caller wants suppressed —
	// notably c.FlowControl, which FeatureOptions.ApplyTo sets whenever
	// EnablePriorityAndFairness is true (its default).
	serverConfig = o.ApplyRecommendedConfigFns(serverConfig)

	if ro := o.serverOptions.RecommendedOptions; ro != nil {
		if err := ro.ApplyTo(serverConfig); err != nil {
			return nil, err
		}
	}

	serverConfig = o.ApplyRecommendedConfigFns(serverConfig)
	serverConfig.RESTOptionsGetter = o

	return &serverapiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig: serverapiserver.ExtraConfig{
			Scheme: o.scheme,
			Codecs: o.codecs,
			APIs:   o.apis,
		},
	}, nil
}

func (o ApoxyServerOptions) GetRESTOptions(resource schema.GroupResource, _ runtime.Object) (generic.RESTOptions, error) {
	return generic.RESTOptions{
		StorageConfig: &storagebackend.ConfigForResource{
			GroupResource: resource,
			Config: storagebackend.Config{
				Codec: o.codec,
			},
		},
		ResourcePrefix: resource.String(),
	}, nil
}

func (o ApoxyServerOptions) RunApoxyServer(ctx context.Context) (<-chan struct{}, error) {
	config, err := o.Config()
	if err != nil {
		return nil, err
	}

	completed := config.Complete()
	server, err := completed.New()
	if err != nil {
		return nil, err
	}

	server.GenericAPIServer.AddPostStartHookOrDie("start-apoxy-server-informers", func(context genericapiserver.PostStartHookContext) error {
		if completed.GenericConfig.SharedInformerFactory != nil {
			completed.GenericConfig.SharedInformerFactory.Start(context.Context.Done())
		}
		return nil
	})

	prepared := server.GenericAPIServer.PrepareRun()
	stoppedCh, _, err := prepared.NonBlockingRunWithContext(ctx, prepared.ShutdownTimeout)
	if err != nil {
		return nil, err
	}
	return stoppedCh, nil
}
