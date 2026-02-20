package v1alpha

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha3 "github.com/apoxy-dev/apoxy/api/core/v1alpha3"
)

// convertDomainSpecFromV1Alpha1ToV1Alpha3 converts a v1alpha DomainSpec (flat DNS) to v1alpha3 (struct DNS).
func convertDomainSpecFromV1Alpha1ToV1Alpha3(in *DomainSpec) *v1alpha3.DomainSpec {
	if in == nil {
		return nil
	}

	return &v1alpha3.DomainSpec{
		Zone:           in.Zone,
		CustomDomains:  in.CustomDomains,
		Target:         *convertDomainTargetSpecToV1Alpha3(&in.Target),
		TLS:            convertDomainTLSSpecToV1Alpha3(in.TLS),
		ForwardingSpec: convertDomainForwardingSpecToV1Alpha3(in.ForwardingSpec),
		Filters:        convertLocalObjectReferencesToV1Alpha3(in.Filters),
	}
}

// convertDomainSpecFromV1Alpha3ToV1Alpha1 converts a v1alpha3 DomainSpec (struct DNS) to v1alpha (flat DNS).
func convertDomainSpecFromV1Alpha3ToV1Alpha1(in *v1alpha3.DomainSpec) *DomainSpec {
	if in == nil {
		return nil
	}

	return &DomainSpec{
		Zone:           in.Zone,
		CustomDomains:  in.CustomDomains,
		Target:         *convertDomainTargetSpecFromV1Alpha3(&in.Target),
		TLS:            convertDomainTLSSpecFromV1Alpha3(in.TLS),
		ForwardingSpec: convertDomainForwardingSpecFromV1Alpha3(in.ForwardingSpec),
		Filters:        convertLocalObjectReferencesFromV1Alpha3(in.Filters),
	}
}

func convertDomainTargetSpecToV1Alpha3(in *DomainTargetSpec) *v1alpha3.DomainTargetSpec {
	if in == nil {
		return nil
	}

	return &v1alpha3.DomainTargetSpec{
		DNS: convertDomainTargetDNSToV1Alpha3(in.DNS),
		Ref: convertLocalObjectReferenceToV1Alpha3(in.Ref),
	}
}

func convertDomainTargetSpecFromV1Alpha3(in *v1alpha3.DomainTargetSpec) *DomainTargetSpec {
	if in == nil {
		return nil
	}

	return &DomainTargetSpec{
		DNS: convertDomainTargetDNSFromV1Alpha3(in.DNS),
		Ref: convertLocalObjectReferenceFromV1Alpha3(in.Ref),
	}
}

// convertDomainTargetDNSToV1Alpha3 converts flat v1alpha DNS fields to v1alpha3 per-record structs.
func convertDomainTargetDNSToV1Alpha3(in *DomainTargetDNS) *v1alpha3.DomainTargetDNS {
	if in == nil {
		return nil
	}

	out := &v1alpha3.DomainTargetDNS{}

	if len(in.IPs) > 0 {
		out.IPs = &v1alpha3.DNSAddressRecords{
			Addresses: in.IPs,
			TTL:       in.TTL,
		}
	}
	if in.FQDN != nil {
		out.FQDN = &v1alpha3.DNSCNAMERecord{
			Name: *in.FQDN,
			TTL:  in.TTL,
		}
	}
	if len(in.TXT) > 0 {
		out.TXT = &v1alpha3.DNSTXTRecords{
			Values: in.TXT,
			TTL:    in.TTL,
		}
	}
	if len(in.MX) > 0 {
		out.MX = &v1alpha3.DNSMXRecords{
			Values: in.MX,
			TTL:    in.TTL,
		}
	}
	if len(in.DKIM) > 0 {
		out.DKIM = &v1alpha3.DNSDKIMRecords{
			Values: in.DKIM,
			TTL:    in.TTL,
		}
	}
	if len(in.SPF) > 0 {
		out.SPF = &v1alpha3.DNSSPFRecords{
			Values: in.SPF,
			TTL:    in.TTL,
		}
	}
	if len(in.DMARC) > 0 {
		out.DMARC = &v1alpha3.DNSDMARCRecords{
			Values: in.DMARC,
			TTL:    in.TTL,
		}
	}
	if len(in.CAA) > 0 {
		out.CAA = &v1alpha3.DNSCAARecords{
			Values: in.CAA,
			TTL:    in.TTL,
		}
	}
	if len(in.SRV) > 0 {
		out.SRV = &v1alpha3.DNSSRVRecords{
			Values: in.SRV,
			TTL:    in.TTL,
		}
	}
	if len(in.NS) > 0 {
		out.NS = &v1alpha3.DNSNSRecords{
			Nameservers: in.NS,
			TTL:         in.TTL,
		}
	}
	if len(in.DS) > 0 {
		out.DS = &v1alpha3.DNSDSRecords{
			Values: in.DS,
			TTL:    in.TTL,
		}
	}
	if len(in.DNSKEY) > 0 {
		out.DNSKEY = &v1alpha3.DNSDNSKEYRecords{
			Values: in.DNSKEY,
			TTL:    in.TTL,
		}
	}

	return out
}

// convertDomainTargetDNSFromV1Alpha3 converts v1alpha3 per-record struct DNS to flat v1alpha DNS.
func convertDomainTargetDNSFromV1Alpha3(in *v1alpha3.DomainTargetDNS) *DomainTargetDNS {
	if in == nil {
		return nil
	}

	out := &DomainTargetDNS{}
	var firstTTL *int32

	if in.IPs != nil {
		out.IPs = in.IPs.Addresses
		if firstTTL == nil {
			firstTTL = in.IPs.TTL
		}
	}
	if in.FQDN != nil {
		out.FQDN = &in.FQDN.Name
		if firstTTL == nil {
			firstTTL = in.FQDN.TTL
		}
	}
	if in.TXT != nil {
		out.TXT = in.TXT.Values
		if firstTTL == nil {
			firstTTL = in.TXT.TTL
		}
	}
	if in.MX != nil {
		out.MX = in.MX.Values
		if firstTTL == nil {
			firstTTL = in.MX.TTL
		}
	}
	if in.DKIM != nil {
		out.DKIM = in.DKIM.Values
		if firstTTL == nil {
			firstTTL = in.DKIM.TTL
		}
	}
	if in.SPF != nil {
		out.SPF = in.SPF.Values
		if firstTTL == nil {
			firstTTL = in.SPF.TTL
		}
	}
	if in.DMARC != nil {
		out.DMARC = in.DMARC.Values
		if firstTTL == nil {
			firstTTL = in.DMARC.TTL
		}
	}
	if in.CAA != nil {
		out.CAA = in.CAA.Values
		if firstTTL == nil {
			firstTTL = in.CAA.TTL
		}
	}
	if in.SRV != nil {
		out.SRV = in.SRV.Values
		if firstTTL == nil {
			firstTTL = in.SRV.TTL
		}
	}
	if in.NS != nil {
		out.NS = in.NS.Nameservers
		if firstTTL == nil {
			firstTTL = in.NS.TTL
		}
	}
	if in.DS != nil {
		out.DS = in.DS.Values
		if firstTTL == nil {
			firstTTL = in.DS.TTL
		}
	}
	if in.DNSKEY != nil {
		out.DNSKEY = in.DNSKEY.Values
		if firstTTL == nil {
			firstTTL = in.DNSKEY.TTL
		}
	}

	out.TTL = firstTTL
	return out
}

func convertDomainTLSSpecToV1Alpha3(in *DomainTLSSpec) *v1alpha3.DomainTLSSpec {
	if in == nil {
		return nil
	}

	return &v1alpha3.DomainTLSSpec{
		CertificateAuthority: in.CertificateAuthority,
	}
}

func convertDomainTLSSpecFromV1Alpha3(in *v1alpha3.DomainTLSSpec) *DomainTLSSpec {
	if in == nil {
		return nil
	}

	return &DomainTLSSpec{
		CertificateAuthority: in.CertificateAuthority,
	}
}

func convertDomainForwardingSpecToV1Alpha3(in *DomainForwardingSpec) *v1alpha3.DomainForwardingSpec {
	if in == nil {
		return nil
	}

	rules := make([]v1alpha3.ForwardingRule, len(in.ForwardingRules))
	for i, rule := range in.ForwardingRules {
		portRanges := make([]v1alpha3.PortRange, len(rule.PortRanges))
		for j, pr := range rule.PortRanges {
			portRanges[j] = v1alpha3.PortRange{
				StartPort: pr.StartPort,
				EndPort:   pr.EndPort,
			}
		}
		rules[i] = v1alpha3.ForwardingRule{
			Protocol:   v1alpha3.ProtocolType(rule.Protocol),
			PortRanges: portRanges,
			TargetPort: rule.TargetPort,
		}
	}

	return &v1alpha3.DomainForwardingSpec{
		ForwardingRules: rules,
	}
}

func convertDomainForwardingSpecFromV1Alpha3(in *v1alpha3.DomainForwardingSpec) *DomainForwardingSpec {
	if in == nil {
		return nil
	}

	rules := make([]ForwardingRule, len(in.ForwardingRules))
	for i, rule := range in.ForwardingRules {
		portRanges := make([]PortRange, len(rule.PortRanges))
		for j, pr := range rule.PortRanges {
			portRanges[j] = PortRange{
				StartPort: pr.StartPort,
				EndPort:   pr.EndPort,
			}
		}
		rules[i] = ForwardingRule{
			Protocol:   ProtocolType(rule.Protocol),
			PortRanges: portRanges,
			TargetPort: rule.TargetPort,
		}
	}

	return &DomainForwardingSpec{
		ForwardingRules: rules,
	}
}

func convertLocalObjectReferenceToV1Alpha3(in *LocalObjectReference) *v1alpha3.LocalObjectReference {
	if in == nil {
		return nil
	}

	return &v1alpha3.LocalObjectReference{
		Group: v1alpha3.Group(in.Group),
		Kind:  v1alpha3.Kind(in.Kind),
		Name:  v1alpha3.ObjectName(in.Name),
	}
}

func convertLocalObjectReferenceFromV1Alpha3(in *v1alpha3.LocalObjectReference) *LocalObjectReference {
	if in == nil {
		return nil
	}

	return &LocalObjectReference{
		Group: string(in.Group),
		Kind:  string(in.Kind),
		Name:  string(in.Name),
	}
}

func convertLocalObjectReferencesToV1Alpha3(in []*LocalObjectReference) []*v1alpha3.LocalObjectReference {
	if in == nil {
		return nil
	}

	out := make([]*v1alpha3.LocalObjectReference, len(in))
	for i, ref := range in {
		out[i] = convertLocalObjectReferenceToV1Alpha3(ref)
	}
	return out
}

func convertLocalObjectReferencesFromV1Alpha3(in []*v1alpha3.LocalObjectReference) []*LocalObjectReference {
	if in == nil {
		return nil
	}

	out := make([]*LocalObjectReference, len(in))
	for i, ref := range in {
		out[i] = convertLocalObjectReferenceFromV1Alpha3(ref)
	}
	return out
}

func convertDomainStatusFromV1Alpha1ToV1Alpha3(in *DomainStatus) *v1alpha3.DomainStatus {
	if in == nil {
		return nil
	}

	out := &v1alpha3.DomainStatus{}

	// Build top-level Ready condition from Phase.
	switch in.Phase {
	case DomainPhaseActive:
		out.Conditions = append(out.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			Reason:             "DomainActive",
			Message:            "Domain is ready",
			LastTransitionTime: metav1.Now(),
		})
	case DomainPhaseError:
		out.Conditions = append(out.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "ValidationFailed",
			Message:            "Domain has errors",
			LastTransitionTime: metav1.Now(),
		})
	default:
		out.Conditions = append(out.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "DNSNotReady",
			Message:            "Domain is pending",
			LastTransitionTime: metav1.Now(),
		})
	}

	// Forward conditions from the first FQDNStatus (if any).
	if len(in.FQDNStatus) > 0 {
		for _, cond := range in.FQDNStatus[0].Conditions {
			if cond.Type == "Ready" {
				continue
			}
			out.Conditions = append(out.Conditions, cond)
		}
	}

	return out
}

func convertDomainStatusFromV1Alpha3ToV1Alpha1(in *v1alpha3.DomainStatus) *DomainStatus {
	if in == nil {
		return nil
	}

	out := &DomainStatus{}

	// Derive Phase from the top-level Ready condition.
	out.Phase = DomainPhasePending
	for _, cond := range in.Conditions {
		if cond.Type == "Ready" {
			if cond.Status == metav1.ConditionTrue {
				out.Phase = DomainPhaseActive
			} else {
				switch cond.Reason {
				case "ValidationFailed", "CertificateError", "InvalidTargetRef":
					out.Phase = DomainPhaseError
				default:
					out.Phase = DomainPhasePending
				}
			}
			break
		}
	}

	// Derive a single FQDNStatus from the top-level conditions.
	if len(in.Conditions) > 0 {
		fqdnPhase := FQDNPhaseActive
		for _, cond := range in.Conditions {
			if cond.Type == "Ready" {
				if cond.Status == metav1.ConditionTrue {
					fqdnPhase = FQDNPhaseActive
				} else {
					switch cond.Reason {
					case "ZoneNotReady":
						fqdnPhase = FQDNPhaseWaitingForZone
					case "DNSNotReady", "CNAMENotConfigured", "ConfiguringDNS":
						fqdnPhase = FQDNPhaseWaitingForDNS
					default:
						fqdnPhase = FQDNPhaseError
					}
				}
				break
			}
		}
		out.FQDNStatus = []FQDNStatus{
			{
				FQDN:       "",
				Phase:      fqdnPhase,
				Conditions: in.Conditions,
			},
		}
	}

	return out
}
