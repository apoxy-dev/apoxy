// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"errors"
	"fmt"
	"sort"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tracecfg "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tracingtype "github.com/envoyproxy/go-control-plane/envoy/type/tracing/v3"
	xdstype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/utils/protocov"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
)

const (
	envoyOpenTelemetry = "envoy.tracers.opentelemetry"
)

type typConfigGen func() (*anypb.Any, error)

func buildHCMTracing(tracing *ir.Tracing) (*hcm.HttpConnectionManager_Tracing, error) {
	if tracing == nil {
		return nil, nil
	}

	var providerName string
	var providerConfig typConfigGen

	switch tracing.Provider.Type {
	case egv1a1.TracingProviderTypeOpenTelemetry:
		providerName = envoyOpenTelemetry

		providerConfig = func() (*anypb.Any, error) {
			config := &tracecfg.OpenTelemetryConfig{
				GrpcService: &corev3.GrpcService{
					TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{
							ClusterName: tracing.Destination.Name,
							Authority:   tracing.Authority,
						},
					},
				},
				ServiceName: tracing.ServiceName,
			}

			return protocov.ToAnyWithError(config)
		}
	default:
		return nil, fmt.Errorf("unknown tracing provider type: %s", tracing.Provider.Type)
	}

	ocAny, err := providerConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tracing configuration: %w", err)
	}

	tags := make([]*tracingtype.CustomTag, 0, len(tracing.CustomTags))
	// TODO: consider add some default tags for better UX
	for k, v := range tracing.CustomTags {
		switch v.Type {
		case egv1a1.CustomTagTypeLiteral:
			tags = append(tags, &tracingtype.CustomTag{
				Tag: k,
				Type: &tracingtype.CustomTag_Literal_{
					Literal: &tracingtype.CustomTag_Literal{
						Value: v.Literal.Value,
					},
				},
			})
		case egv1a1.CustomTagTypeEnvironment:
			defaultVal := ""
			if v.Environment.DefaultValue != nil {
				defaultVal = *v.Environment.DefaultValue
			}

			tags = append(tags, &tracingtype.CustomTag{
				Tag: k,
				Type: &tracingtype.CustomTag_Environment_{
					Environment: &tracingtype.CustomTag_Environment{
						Name:         v.Environment.Name,
						DefaultValue: defaultVal,
					},
				},
			})
		case egv1a1.CustomTagTypeRequestHeader:
			defaultVal := ""
			if v.RequestHeader.DefaultValue != nil {
				defaultVal = *v.RequestHeader.DefaultValue
			}

			tags = append(tags, &tracingtype.CustomTag{
				Tag: k,
				Type: &tracingtype.CustomTag_RequestHeader{
					RequestHeader: &tracingtype.CustomTag_Header{
						Name:         v.RequestHeader.Name,
						DefaultValue: defaultVal,
					},
				},
			})
		default:
			return nil, fmt.Errorf("unknown custom tag type: %s", v.Type)
		}
	}
	// sort tags by tag name, make result consistent
	sort.Slice(tags, func(i, j int) bool {
		return tags[i].Tag < tags[j].Tag
	})

	// Default to 100% sampling if a rate is not specified.
	samplingRate := tracing.SamplingRate
	if samplingRate == 0 {
		samplingRate = 100.0
	}

	return &hcm.HttpConnectionManager_Tracing{
		ClientSampling: &xdstype.Percent{
			Value: 100.0,
		},
		OverallSampling: &xdstype.Percent{
			Value: 100.0,
		},
		RandomSampling: &xdstype.Percent{
			Value: samplingRate,
		},
		Provider: &tracecfg.Tracing_Http{
			Name: providerName,
			ConfigType: &tracecfg.Tracing_Http_TypedConfig{
				TypedConfig: ocAny,
			},
		},
		CustomTags:        tags,
		SpawnUpstreamSpan: wrapperspb.Bool(true),
	}, nil
}

func processClusterForTracing(tCtx *types.ResourceVersionTable, tracing *ir.Tracing) error {
	if tracing == nil {
		return nil
	}

	if err := addXdsCluster(tCtx, &xdsClusterArgs{
		name:         tracing.Destination.Name,
		settings:     tracing.Destination.Settings,
		tSocket:      nil,
		endpointType: EndpointTypeDNS,
	}); err != nil && !errors.Is(err, ErrXdsClusterExists) {
		return err
	}
	return nil
}
