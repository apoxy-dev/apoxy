// Package tenantmeta carries tenant attribution on translated xDS clusters.
//
// The translator knows which clusters exist because of customer
// configuration (Backend endpoints and similar) and which tenant a cluster
// serves. Downstream consumers (the backplane xDS patcher) previously
// recovered both by parsing cluster names and sniffing endpoint FQDN shapes.
// This package makes the attribution a typed marker on
// Cluster.Metadata.FilterMetadata, written at translation time, so the
// name-shape contract is no longer load-bearing.
package tenantmeta

import (
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

// FilterMetadataKey is the FilterMetadata key holding the marker.
const FilterMetadataKey = "apoxy.dev/tenant"

const (
	tenantKeyField    = "tenant_key"
	inputDerivedField = "input_derived"
)

// Marker is the tenant attribution of one cluster.
type Marker struct {
	// TenantKey identifies the tenant the cluster serves. Empty in
	// single-project topologies, where the consumer knows its one project.
	TenantKey string
	// InputDerived is true when the cluster's endpoints come from customer
	// configuration (Backend FQDN/IP endpoints, Backend dynamic proxy).
	// Internal clusters (telemetry, ratelimit, ext services, residents)
	// never set it.
	InputDerived bool
}

// Mark writes the marker into the cluster's filter metadata. A zero marker
// writes nothing: an absent key is what identifies internal clusters.
func Mark(c *clusterv3.Cluster, m Marker) {
	if c == nil || (!m.InputDerived && m.TenantKey == "") {
		return
	}
	if c.Metadata == nil {
		c.Metadata = &corev3.Metadata{}
	}
	if c.Metadata.FilterMetadata == nil {
		c.Metadata.FilterMetadata = make(map[string]*structpb.Struct)
	}
	c.Metadata.FilterMetadata[FilterMetadataKey] = &structpb.Struct{
		Fields: map[string]*structpb.Value{
			tenantKeyField:    structpb.NewStringValue(m.TenantKey),
			inputDerivedField: structpb.NewBoolValue(m.InputDerived),
		},
	}
}

// FromCluster reads the marker back. ok is false when the cluster carries no
// marker (an internal cluster or a translation predating the marker).
func FromCluster(c *clusterv3.Cluster) (m Marker, ok bool) {
	md := c.GetMetadata().GetFilterMetadata()[FilterMetadataKey]
	if md == nil {
		return Marker{}, false
	}
	fields := md.GetFields()
	return Marker{
		TenantKey:    fields[tenantKeyField].GetStringValue(),
		InputDerived: fields[inputDerivedField].GetBoolValue(),
	}, true
}
