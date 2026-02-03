package v1alpha

import (
	v1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

// convertDomainSpecFromV1Alpha1ToV1Alpha2 converts a v1alpha DomainSpec to v1alpha2
func convertDomainSpecFromV1Alpha1ToV1Alpha2(in *DomainSpec) *v1alpha2.DomainSpec {
	if in == nil {
		return nil
	}

	out := &v1alpha2.DomainSpec{
		Zone:           in.Zone,
		CustomDomains:  in.CustomDomains,
		Target:         *convertDomainTargetSpecFromV1Alpha1ToV1Alpha2(&in.Target),
		TLS:            convertDomainTLSSpecFromV1Alpha1ToV1Alpha2(in.TLS),
		ForwardingSpec: convertDomainForwardingSpecFromV1Alpha1ToV1Alpha2(in.ForwardingSpec),
		Filters:        convertLocalObjectReferencesFromV1Alpha1ToV1Alpha2(in.Filters),
	}

	return out
}

// convertDomainSpecFromV1Alpha2ToV1Alpha1 converts a v1alpha2 DomainSpec to v1alpha1
func convertDomainSpecFromV1Alpha2ToV1Alpha1(in *v1alpha2.DomainSpec) *DomainSpec {
	if in == nil {
		return nil
	}

	out := &DomainSpec{
		Zone:           in.Zone,
		CustomDomains:  in.CustomDomains,
		Target:         *convertDomainTargetSpecFromV1Alpha2ToV1Alpha1(&in.Target),
		TLS:            convertDomainTLSSpecFromV1Alpha2ToV1Alpha1(in.TLS),
		ForwardingSpec: convertDomainForwardingSpecFromV1Alpha2ToV1Alpha1(in.ForwardingSpec),
		Filters:        convertLocalObjectReferencesFromV1Alpha2ToV1Alpha1(in.Filters),
	}

	return out
}

// convertDomainTargetSpecFromV1Alpha1ToV1Alpha2 converts a v1alpha DomainTargetSpec to v1alpha2
func convertDomainTargetSpecFromV1Alpha1ToV1Alpha2(in *DomainTargetSpec) *v1alpha2.DomainTargetSpec {
	if in == nil {
		return nil
	}

	return &v1alpha2.DomainTargetSpec{
		DNS: convertDomainTargetDNSFromV1Alpha1ToV1Alpha2(in.DNS),
		Ref: convertLocalObjectReferenceFromV1Alpha1ToV1Alpha2(in.Ref),
	}
}

// convertDomainTargetSpecFromV1Alpha2ToV1Alpha1 converts a v1alpha2 DomainTargetSpec to v1alpha1
func convertDomainTargetSpecFromV1Alpha2ToV1Alpha1(in *v1alpha2.DomainTargetSpec) *DomainTargetSpec {
	if in == nil {
		return nil
	}

	return &DomainTargetSpec{
		DNS: convertDomainTargetDNSFromV1Alpha2ToV1Alpha1(in.DNS),
		Ref: convertLocalObjectReferenceFromV1Alpha2ToV1Alpha1(in.Ref),
	}
}

// convertDomainTargetDNSFromV1Alpha1ToV1Alpha2 converts a v1alpha DomainTargetDNS to v1alpha2
func convertDomainTargetDNSFromV1Alpha1ToV1Alpha2(in *DomainTargetDNS) *v1alpha2.DomainTargetDNS {
	if in == nil {
		return nil
	}

	return &v1alpha2.DomainTargetDNS{
		DNSOnly: in.DNSOnly,
		IPs:     in.IPs,
		FQDN:    in.FQDN,
		TXT:     in.TXT,
		MX:      in.MX,
		DKIM:    in.DKIM,
		SPF:     in.SPF,
		DMARC:   in.DMARC,
		CAA:     in.CAA,
		SRV:     in.SRV,
		NS:      in.NS,
		DS:      in.DS,
		DNSKEY:  in.DNSKEY,
		TTL:     in.TTL,
	}
}

// convertDomainTargetDNSFromV1Alpha2ToV1Alpha1 converts a v1alpha2 DomainTargetDNS to v1alpha1
func convertDomainTargetDNSFromV1Alpha2ToV1Alpha1(in *v1alpha2.DomainTargetDNS) *DomainTargetDNS {
	if in == nil {
		return nil
	}

	return &DomainTargetDNS{
		DNSOnly: in.DNSOnly,
		IPs:     in.IPs,
		FQDN:    in.FQDN,
		TXT:     in.TXT,
		MX:      in.MX,
		DKIM:    in.DKIM,
		SPF:     in.SPF,
		DMARC:   in.DMARC,
		CAA:     in.CAA,
		SRV:     in.SRV,
		NS:      in.NS,
		DS:      in.DS,
		DNSKEY:  in.DNSKEY,
		TTL:     in.TTL,
	}
}

// convertDomainTLSSpecFromV1Alpha1ToV1Alpha2 converts a v1alpha DomainTLSSpec to v1alpha2
func convertDomainTLSSpecFromV1Alpha1ToV1Alpha2(in *DomainTLSSpec) *v1alpha2.DomainTLSSpec {
	if in == nil {
		return nil
	}

	return &v1alpha2.DomainTLSSpec{
		CertificateAuthority: in.CertificateAuthority,
	}
}

// convertDomainTLSSpecFromV1Alpha2ToV1Alpha1 converts a v1alpha2 DomainTLSSpec to v1alpha1
func convertDomainTLSSpecFromV1Alpha2ToV1Alpha1(in *v1alpha2.DomainTLSSpec) *DomainTLSSpec {
	if in == nil {
		return nil
	}

	return &DomainTLSSpec{
		CertificateAuthority: in.CertificateAuthority,
	}
}

// convertDomainForwardingSpecFromV1Alpha1ToV1Alpha2 converts a v1alpha DomainForwardingSpec to v1alpha2
func convertDomainForwardingSpecFromV1Alpha1ToV1Alpha2(in *DomainForwardingSpec) *v1alpha2.DomainForwardingSpec {
	if in == nil {
		return nil
	}

	rules := make([]v1alpha2.ForwardingRule, len(in.ForwardingRules))
	for i, rule := range in.ForwardingRules {
		rules[i] = *convertForwardingRuleFromV1Alpha1ToV1Alpha2(&rule)
	}

	return &v1alpha2.DomainForwardingSpec{
		ForwardingRules: rules,
	}
}

// convertDomainForwardingSpecFromV1Alpha2ToV1Alpha1 converts a v1alpha2 DomainForwardingSpec to v1alpha1
func convertDomainForwardingSpecFromV1Alpha2ToV1Alpha1(in *v1alpha2.DomainForwardingSpec) *DomainForwardingSpec {
	if in == nil {
		return nil
	}

	rules := make([]ForwardingRule, len(in.ForwardingRules))
	for i, rule := range in.ForwardingRules {
		rules[i] = *convertForwardingRuleFromV1Alpha2ToV1Alpha1(&rule)
	}

	return &DomainForwardingSpec{
		ForwardingRules: rules,
	}
}

// convertForwardingRuleFromV1Alpha1ToV1Alpha2 converts a v1alpha ForwardingRule to v1alpha2
func convertForwardingRuleFromV1Alpha1ToV1Alpha2(in *ForwardingRule) *v1alpha2.ForwardingRule {
	if in == nil {
		return nil
	}

	portRanges := make([]v1alpha2.PortRange, len(in.PortRanges))
	for i, pr := range in.PortRanges {
		portRanges[i] = v1alpha2.PortRange{
			StartPort: pr.StartPort,
			EndPort:   pr.EndPort,
		}
	}

	return &v1alpha2.ForwardingRule{
		Protocol:   v1alpha2.ProtocolType(in.Protocol),
		PortRanges: portRanges,
		TargetPort: in.TargetPort,
	}
}

// convertForwardingRuleFromV1Alpha2ToV1Alpha1 converts a v1alpha2 ForwardingRule to v1alpha1
func convertForwardingRuleFromV1Alpha2ToV1Alpha1(in *v1alpha2.ForwardingRule) *ForwardingRule {
	if in == nil {
		return nil
	}

	portRanges := make([]PortRange, len(in.PortRanges))
	for i, pr := range in.PortRanges {
		portRanges[i] = PortRange{
			StartPort: pr.StartPort,
			EndPort:   pr.EndPort,
		}
	}

	return &ForwardingRule{
		Protocol:   ProtocolType(in.Protocol),
		PortRanges: portRanges,
		TargetPort: in.TargetPort,
	}
}

// convertLocalObjectReferenceFromV1Alpha1ToV1Alpha2 converts a v1alpha LocalObjectReference to v1alpha2
func convertLocalObjectReferenceFromV1Alpha1ToV1Alpha2(in *LocalObjectReference) *v1alpha2.LocalObjectReference {
	if in == nil {
		return nil
	}

	return &v1alpha2.LocalObjectReference{
		Group: v1alpha2.Group(in.Group),
		Kind:  v1alpha2.Kind(in.Kind),
		Name:  v1alpha2.ObjectName(in.Name),
	}
}

// convertLocalObjectReferenceFromV1Alpha2ToV1Alpha1 converts a v1alpha2 LocalObjectReference to v1alpha1
func convertLocalObjectReferenceFromV1Alpha2ToV1Alpha1(in *v1alpha2.LocalObjectReference) *LocalObjectReference {
	if in == nil {
		return nil
	}

	return &LocalObjectReference{
		Group: string(in.Group),
		Kind:  string(in.Kind),
		Name:  string(in.Name),
	}
}

// convertLocalObjectReferencesFromV1Alpha1ToV1Alpha2 converts a slice of v1alpha LocalObjectReference to v1alpha2
func convertLocalObjectReferencesFromV1Alpha1ToV1Alpha2(in []*LocalObjectReference) []*v1alpha2.LocalObjectReference {
	if in == nil {
		return nil
	}

	out := make([]*v1alpha2.LocalObjectReference, len(in))
	for i, ref := range in {
		out[i] = convertLocalObjectReferenceFromV1Alpha1ToV1Alpha2(ref)
	}
	return out
}

// convertLocalObjectReferencesFromV1Alpha2ToV1Alpha1 converts a slice of v1alpha2 LocalObjectReference to v1alpha1
func convertLocalObjectReferencesFromV1Alpha2ToV1Alpha1(in []*v1alpha2.LocalObjectReference) []*LocalObjectReference {
	if in == nil {
		return nil
	}

	out := make([]*LocalObjectReference, len(in))
	for i, ref := range in {
		out[i] = convertLocalObjectReferenceFromV1Alpha2ToV1Alpha1(ref)
	}
	return out
}

// convertDomainStatusFromV1Alpha1ToV1Alpha2 converts a v1alpha DomainStatus to v1alpha2
func convertDomainStatusFromV1Alpha1ToV1Alpha2(in *DomainStatus) *v1alpha2.DomainStatus {
	if in == nil {
		return nil
	}

	fqdnStatus := make([]v1alpha2.FQDNStatus, len(in.FQDNStatus))
	for i, fs := range in.FQDNStatus {
		fqdnStatus[i] = v1alpha2.FQDNStatus{
			FQDN:       fs.FQDN,
			Phase:      v1alpha2.FQDNPhase(fs.Phase),
			Conditions: fs.Conditions,
		}
	}

	return &v1alpha2.DomainStatus{
		Phase:      v1alpha2.DomainPhase(in.Phase),
		FQDNStatus: fqdnStatus,
	}
}

// convertDomainStatusFromV1Alpha2ToV1Alpha1 converts a v1alpha2 DomainStatus to v1alpha1
func convertDomainStatusFromV1Alpha2ToV1Alpha1(in *v1alpha2.DomainStatus) *DomainStatus {
	if in == nil {
		return nil
	}

	fqdnStatus := make([]FQDNStatus, len(in.FQDNStatus))
	for i, fs := range in.FQDNStatus {
		fqdnStatus[i] = FQDNStatus{
			FQDN:       fs.FQDN,
			Phase:      FQDNPhase(fs.Phase),
			Conditions: fs.Conditions,
		}
	}

	return &DomainStatus{
		Phase:      DomainPhase(in.Phase),
		FQDNStatus: fqdnStatus,
	}
}
