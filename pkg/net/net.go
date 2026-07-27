package net

import "fmt"

const (
	// ApoxyNetDomainSuffix is the domain suffix used for the Apoxy endpoints serving
	// customer traffic (both internal and external).
	ApoxyNetDomainSuffix = "apoxy.net"

	// EdgeFuncSubdomain is the subdomain used for the Apoxy endpoints serving
	// customer traffic (both internal and external).
	EdgeFuncSubdomain = "func"
	// TunnelSubdomain is the subdomain used for the Apoxy endpoints serving
	// customer traffic (both internal and external).
	TunnelSubdomain = "tun"
	// VPCSubdomain is the subdomain used for VPCService endpoints reachable
	// over the VPC relay overlay. Kept distinct from TunnelSubdomain so the
	// datapath (VTEP netns vs. legacy lwtunnel) can be selected from the
	// FQDN alone.
	VPCSubdomain = "vpc"
)

var (
	// EdgeFuncDomain is the domain used for the Apoxy endpoints serving
	// customer traffic (both internal and external).
	EdgeFuncDomain = fmt.Sprintf("%s.%s", EdgeFuncSubdomain, ApoxyNetDomainSuffix)

	// TunnelDomain is the domain used for the Apoxy endpoints serving
	// customer traffic (both internal and external).
	TunnelDomain = fmt.Sprintf("%s.%s", TunnelSubdomain, ApoxyNetDomainSuffix)

	// VPCDomain is the domain under which VPCService endpoints are published
	// by the per-project backplane DNS servers.
	VPCDomain = fmt.Sprintf("%s.%s", VPCSubdomain, ApoxyNetDomainSuffix)
)
