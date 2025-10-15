package v1alpha

import (
	v1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

// convertBackendSpecFromV1Alpha1ToV1Alpha2 converts a v1alpha BackendSpec to v1alpha2
func convertBackendSpecFromV1Alpha1ToV1Alpha2(in *BackendSpec) *v1alpha2.BackendSpec {
	if in == nil {
		return nil
	}

	endpoints := make([]v1alpha2.BackendEndpoint, len(in.Endpoints))
	for i, ep := range in.Endpoints {
		endpoints[i] = v1alpha2.BackendEndpoint{
			FQDN: ep.FQDN,
			IP:   ep.IP,
		}
	}

	return &v1alpha2.BackendSpec{
		Endpoints:    endpoints,
		DynamicProxy: convertDynamicProxySpecFromV1Alpha1ToV1Alpha2(in.DynamicProxy),
		Protocol:     v1alpha2.BackendProto(in.Protocol),
	}
}

// convertBackendSpecFromV1Alpha2ToV1Alpha1 converts a v1alpha2 BackendSpec to v1alpha
func convertBackendSpecFromV1Alpha2ToV1Alpha1(in *v1alpha2.BackendSpec) *BackendSpec {
	if in == nil {
		return nil
	}

	endpoints := make([]BackendEndpoint, len(in.Endpoints))
	for i, ep := range in.Endpoints {
		endpoints[i] = BackendEndpoint{
			FQDN: ep.FQDN,
			IP:   ep.IP,
		}
	}

	return &BackendSpec{
		Endpoints:    endpoints,
		DynamicProxy: convertDynamicProxySpecFromV1Alpha2ToV1Alpha1(in.DynamicProxy),
		Protocol:     BackendProto(in.Protocol),
	}
}

// convertDynamicProxySpecFromV1Alpha1ToV1Alpha2 converts a v1alpha DynamicProxySpec to v1alpha2
func convertDynamicProxySpecFromV1Alpha1ToV1Alpha2(in *DynamicProxySpec) *v1alpha2.DynamicProxySpec {
	if in == nil {
		return nil
	}

	return &v1alpha2.DynamicProxySpec{
		DnsCacheConfig: convertDynamicProxyDnsCacheConfigFromV1Alpha1ToV1Alpha2(in.DnsCacheConfig),
	}
}

// convertDynamicProxySpecFromV1Alpha2ToV1Alpha1 converts a v1alpha2 DynamicProxySpec to v1alpha
func convertDynamicProxySpecFromV1Alpha2ToV1Alpha1(in *v1alpha2.DynamicProxySpec) *DynamicProxySpec {
	if in == nil {
		return nil
	}

	return &DynamicProxySpec{
		DnsCacheConfig: convertDynamicProxyDnsCacheConfigFromV1Alpha2ToV1Alpha1(in.DnsCacheConfig),
	}
}

// convertDynamicProxyDnsCacheConfigFromV1Alpha1ToV1Alpha2 converts a v1alpha DynamicProxyDnsCacheConfig to v1alpha2
func convertDynamicProxyDnsCacheConfigFromV1Alpha1ToV1Alpha2(in *DynamicProxyDnsCacheConfig) *v1alpha2.DynamicProxyDnsCacheConfig {
	if in == nil {
		return nil
	}

	return &v1alpha2.DynamicProxyDnsCacheConfig{
		DNSLookupFamily:   v1alpha2.DynamicProxyDNSLookupFamily(in.DNSLookupFamily),
		DNSRefreshRate:    in.DNSRefreshRate,
		DNSMinRefreshRate: in.DNSMinRefreshRate,
		HostTTL:           in.HostTTL,
		MaxHosts:          in.MaxHosts,
		DNSQueryTimeout:   in.DNSQueryTimeout,
	}
}

// convertDynamicProxyDnsCacheConfigFromV1Alpha2ToV1Alpha1 converts a v1alpha2 DynamicProxyDnsCacheConfig to v1alpha
func convertDynamicProxyDnsCacheConfigFromV1Alpha2ToV1Alpha1(in *v1alpha2.DynamicProxyDnsCacheConfig) *DynamicProxyDnsCacheConfig {
	if in == nil {
		return nil
	}

	return &DynamicProxyDnsCacheConfig{
		DNSLookupFamily:   DynamicProxyDNSLookupFamily(in.DNSLookupFamily),
		DNSRefreshRate:    in.DNSRefreshRate,
		DNSMinRefreshRate: in.DNSMinRefreshRate,
		HostTTL:           in.HostTTL,
		MaxHosts:          in.MaxHosts,
		DNSQueryTimeout:   in.DNSQueryTimeout,
	}
}

// convertBackendStatusFromV1Alpha1ToV1Alpha2 converts a v1alpha BackendStatus to v1alpha2
func convertBackendStatusFromV1Alpha1ToV1Alpha2(in *BackendStatus) *v1alpha2.BackendStatus {
	if in == nil {
		return nil
	}

	return &v1alpha2.BackendStatus{
		Conditions: in.Conditions,
	}
}

// convertBackendStatusFromV1Alpha2ToV1Alpha1 converts a v1alpha2 BackendStatus to v1alpha
func convertBackendStatusFromV1Alpha2ToV1Alpha1(in *v1alpha2.BackendStatus) *BackendStatus {
	if in == nil {
		return nil
	}

	return &BackendStatus{
		Conditions: in.Conditions,
	}
}
