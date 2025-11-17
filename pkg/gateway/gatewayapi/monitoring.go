package gatewayapi

import (
	envoy_v1alpha1 "github.com/envoyproxy/gateway/api/v1alpha1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	apoxy_v1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/backplane/otel"
	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

// processTracing processes the tracing configuration from the proxy spec
// If the proxy spec.Monitoring.Tracing.Enabled flag is set, the Tracing struct
// is returned with the ServiceName of envoy-backplane and the Destination set
// to emit data to localhost:4317. The Tags set in the ProxyTracing struct
// are mapped to appropriate CustomTags.
func (t *Translator) processTracing(gateway *gwapiv1.Gateway, proxies []*apoxy_v1alpha2.Proxy) *ir.Tracing {
	if gateway.Spec.Infrastructure == nil ||
		gateway.Spec.Infrastructure.ParametersRef == nil ||
		gateway.Spec.Infrastructure.ParametersRef.Kind != "Proxy" {
		return nil
	}
	for _, proxy := range proxies {
		if proxy.Name != gateway.Spec.Infrastructure.ParametersRef.Name {
			continue
		}
		if proxy.Spec.Telemetry == nil ||
			proxy.Spec.Telemetry.Tracing == nil ||
			!proxy.Spec.Telemetry.Tracing.Enabled {
			return nil
		}
		log.Infof("Enabling tracing for proxy %s", proxy.Name)
		tracing := &ir.Tracing{
			ServiceName: "envoy-backplane",
			Provider: envoy_v1alpha1.TracingProvider{
				Type: envoy_v1alpha1.TracingProviderTypeOpenTelemetry,
			},
			Destination: ir.RouteDestination{
				Name: "otel_collector",
				Settings: []*ir.DestinationSetting{
					{
						Protocol: ir.HTTP2,
						Endpoints: []*ir.DestinationEndpoint{
							{
								Host: "127.0.0.1",
								Port: otel.DefaultCollectorPort,
							},
						},
					},
				},
			},
		}

		// Process custom tags if any
		if len(proxy.Spec.Telemetry.Tracing.Tags) > 0 {
			tracing.CustomTags = make(map[string]envoy_v1alpha1.CustomTag)
			for tagName, tagValue := range proxy.Spec.Telemetry.Tracing.Tags {
				if tagValue.Header != "" {
					// If header is specified, use RequestHeader tag type
					tracing.CustomTags[tagName] = envoy_v1alpha1.CustomTag{
						Type: envoy_v1alpha1.CustomTagTypeRequestHeader,
						RequestHeader: &envoy_v1alpha1.RequestHeaderCustomTag{
							Name: tagValue.Header,
						},
					}
					// If value is also specified, use it as default value
					if tagValue.Value != "" {
						defaultValue := tagValue.Value
						tracing.CustomTags[tagName].RequestHeader.DefaultValue = &defaultValue
					}
				} else if tagValue.Value != "" {
					// If only value is specified, use Literal tag type
					tracing.CustomTags[tagName] = envoy_v1alpha1.CustomTag{
						Type: envoy_v1alpha1.CustomTagTypeLiteral,
						Literal: &envoy_v1alpha1.LiteralCustomTag{
							Value: tagValue.Value,
						},
					}
				}
			}
		}

		return tracing
	}

	return nil
}
