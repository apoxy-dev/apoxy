package admission

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"

	corev1alpha3 "github.com/apoxy-dev/apoxy/api/core/v1alpha3"
	"github.com/apoxy-dev/apoxy/client/versioned/fake"
)

func int32Ptr(v int32) *int32 { return &v }
func strPtr(s string) *string { return &s }

func TestDomainToDomainRecords_Ref(t *testing.T) {
	domain := &corev1alpha3.Domain{
		ObjectMeta: metav1.ObjectMeta{Name: "example"},
		Spec: corev1alpha3.DomainSpec{
			Zone: "example.com",
			Target: corev1alpha3.DomainTargetSpec{
				Ref: &corev1alpha3.LocalObjectReference{
					Group: "core.apoxy.dev",
					Kind:  "Proxy",
					Name:  "my-proxy",
				},
			},
			TLS: &corev1alpha3.DomainTLSSpec{CertificateAuthority: "letsencrypt"},
		},
	}

	records := DomainToDomainRecords(domain)

	require.Len(t, records, 1)
	r := records[0]
	assert.Equal(t, "example.ref", r.Name)
	assert.Equal(t, "example", r.Spec.Name)
	assert.Equal(t, "example.com", r.Spec.Zone)
	assert.NotNil(t, r.Spec.Target.Ref)
	assert.Equal(t, corev1alpha3.ObjectName("my-proxy"), r.Spec.Target.Ref.Name)
	assert.NotNil(t, r.Spec.TLS)
	assert.Equal(t, "letsencrypt", r.Spec.TLS.CertificateAuthority)
	assert.True(t, isReflected(&r))
}

func TestDomainToDomainRecords_DNS(t *testing.T) {
	domain := &corev1alpha3.Domain{
		ObjectMeta: metav1.ObjectMeta{Name: "example"},
		Spec: corev1alpha3.DomainSpec{
			Zone: "example.com",
			Target: corev1alpha3.DomainTargetSpec{
				DNS: &corev1alpha3.DomainTargetDNS{
					IPs: &corev1alpha3.DNSAddressRecords{
						Addresses: []string{"1.2.3.4", "5.6.7.8"},
						TTL:       int32Ptr(60),
					},
					TXT: &corev1alpha3.DNSTXTRecords{
						Values: []string{"v=spf1 include:example.com ~all"},
						TTL:    int32Ptr(300),
					},
					NS: &corev1alpha3.DNSNSRecords{
						Nameservers: []string{"ns1.example.com", "ns2.example.com"},
						TTL:         int32Ptr(3600),
					},
				},
			},
		},
	}

	records := DomainToDomainRecords(domain)

	require.Len(t, records, 3)

	// IPs record.
	ips := findRecord(records, "example.ips")
	require.NotNil(t, ips)
	assert.Equal(t, "example", ips.Spec.Name)
	assert.Equal(t, "example.com", ips.Spec.Zone)
	require.NotNil(t, ips.Spec.Target.DNS)
	assert.Equal(t, []string{"1.2.3.4", "5.6.7.8"}, ips.Spec.Target.DNS.IPs)
	assert.Equal(t, int32Ptr(60), ips.Spec.TTL)
	assert.True(t, isReflected(ips))

	// TXT record.
	txt := findRecord(records, "example.txt")
	require.NotNil(t, txt)
	require.NotNil(t, txt.Spec.Target.DNS)
	assert.Equal(t, []string{"v=spf1 include:example.com ~all"}, txt.Spec.Target.DNS.TXT)
	assert.Equal(t, int32Ptr(300), txt.Spec.TTL)

	// NS record.
	ns := findRecord(records, "example.ns")
	require.NotNil(t, ns)
	require.NotNil(t, ns.Spec.Target.DNS)
	assert.Equal(t, []string{"ns1.example.com", "ns2.example.com"}, ns.Spec.Target.DNS.NS)
	assert.Equal(t, int32Ptr(3600), ns.Spec.TTL)
}

func TestDomainToDomainRecords_FQDN(t *testing.T) {
	domain := &corev1alpha3.Domain{
		ObjectMeta: metav1.ObjectMeta{Name: "example"},
		Spec: corev1alpha3.DomainSpec{
			Zone: "example.com",
			Target: corev1alpha3.DomainTargetSpec{
				DNS: &corev1alpha3.DomainTargetDNS{
					FQDN: &corev1alpha3.DNSCNAMERecord{
						Name: "target.example.com",
						TTL:  int32Ptr(120),
					},
				},
			},
		},
	}

	records := DomainToDomainRecords(domain)

	require.Len(t, records, 1)
	r := records[0]
	assert.Equal(t, "example.fqdn", r.Name)
	require.NotNil(t, r.Spec.Target.DNS)
	require.NotNil(t, r.Spec.Target.DNS.FQDN)
	assert.Equal(t, "target.example.com", *r.Spec.Target.DNS.FQDN)
	assert.Equal(t, int32Ptr(120), r.Spec.TTL)
}

func TestDomainToDomainRecords_CustomDomains(t *testing.T) {
	domain := &corev1alpha3.Domain{
		ObjectMeta: metav1.ObjectMeta{Name: "example"},
		Spec: corev1alpha3.DomainSpec{
			Zone: "example.com",
			Target: corev1alpha3.DomainTargetSpec{
				Ref: &corev1alpha3.LocalObjectReference{
					Group: "core.apoxy.dev",
					Kind:  "Proxy",
					Name:  "my-proxy",
				},
			},
			TLS:           &corev1alpha3.DomainTLSSpec{CertificateAuthority: "letsencrypt"},
			CustomDomains: []string{"custom.example.org"},
		},
	}

	records := DomainToDomainRecords(domain)

	require.Len(t, records, 2)

	// Main ref record.
	ref := findRecord(records, "example.ref")
	require.NotNil(t, ref)

	// Custom domain record.
	cd := findRecord(records, "custom.example.org.ref")
	require.NotNil(t, cd)
	assert.Equal(t, "custom.example.org", cd.Spec.Name)
	assert.Equal(t, "", cd.Spec.Zone) // standalone
	require.NotNil(t, cd.Spec.Target.Ref)
	assert.Equal(t, corev1alpha3.Kind("DomainRecord"), cd.Spec.Target.Ref.Kind)
	assert.Equal(t, corev1alpha3.ObjectName("example.ref"), cd.Spec.Target.Ref.Name)
	assert.NotNil(t, cd.Spec.TLS)
	assert.True(t, isReflected(cd))
}

func TestDomainRecordsToDomainSpec_Ref(t *testing.T) {
	records := []corev1alpha3.DomainRecord{
		{
			Spec: corev1alpha3.DomainRecordSpec{
				Zone: "example.com",
				Name: "example",
				Target: corev1alpha3.DomainRecordTarget{
					Ref: &corev1alpha3.LocalObjectReference{
						Group: "core.apoxy.dev",
						Kind:  "Proxy",
						Name:  "my-proxy",
					},
				},
				TLS: &corev1alpha3.DomainTLSSpec{CertificateAuthority: "letsencrypt"},
			},
		},
	}

	spec := DomainRecordsToDomainSpec(records)

	assert.Equal(t, "example.com", spec.Zone)
	require.NotNil(t, spec.Target.Ref)
	assert.Equal(t, corev1alpha3.ObjectName("my-proxy"), spec.Target.Ref.Name)
	assert.NotNil(t, spec.TLS)
}

func TestDomainRecordsToDomainSpec_DNS(t *testing.T) {
	records := []corev1alpha3.DomainRecord{
		{
			Spec: corev1alpha3.DomainRecordSpec{
				Zone: "example.com",
				Name: "example",
				TTL:  int32Ptr(60),
				Target: corev1alpha3.DomainRecordTarget{
					DNS: &corev1alpha3.DomainRecordTargetDNS{
						IPs: []string{"1.2.3.4"},
					},
				},
			},
		},
		{
			Spec: corev1alpha3.DomainRecordSpec{
				Zone: "example.com",
				Name: "example",
				TTL:  int32Ptr(300),
				Target: corev1alpha3.DomainRecordTarget{
					DNS: &corev1alpha3.DomainRecordTargetDNS{
						MX: []string{"10 mail.example.com"},
					},
				},
			},
		},
	}

	spec := DomainRecordsToDomainSpec(records)

	assert.Equal(t, "example.com", spec.Zone)
	require.NotNil(t, spec.Target.DNS)
	require.NotNil(t, spec.Target.DNS.IPs)
	assert.Equal(t, []string{"1.2.3.4"}, spec.Target.DNS.IPs.Addresses)
	assert.Equal(t, int32Ptr(60), spec.Target.DNS.IPs.TTL)
	require.NotNil(t, spec.Target.DNS.MX)
	assert.Equal(t, []string{"10 mail.example.com"}, spec.Target.DNS.MX.Values)
	assert.Equal(t, int32Ptr(300), spec.Target.DNS.MX.TTL)
}

func TestDomainRecordsToDomainSpec_CustomDomain(t *testing.T) {
	records := []corev1alpha3.DomainRecord{
		{
			Spec: corev1alpha3.DomainRecordSpec{
				Name: "custom.example.org",
				// Zone is empty => standalone
				Target: corev1alpha3.DomainRecordTarget{
					Ref: &corev1alpha3.LocalObjectReference{
						Group: "core.apoxy.dev",
						Kind:  "DomainRecord",
						Name:  "example.ref",
					},
				},
				TLS: &corev1alpha3.DomainTLSSpec{CertificateAuthority: "letsencrypt"},
			},
		},
	}

	spec := DomainRecordsToDomainSpec(records)

	assert.Contains(t, spec.CustomDomains, "custom.example.org")
	assert.NotNil(t, spec.TLS)
}

func TestDomainRecordsToDomainSpec_FQDN(t *testing.T) {
	records := []corev1alpha3.DomainRecord{
		{
			Spec: corev1alpha3.DomainRecordSpec{
				Zone: "example.com",
				Name: "example",
				TTL:  int32Ptr(120),
				Target: corev1alpha3.DomainRecordTarget{
					DNS: &corev1alpha3.DomainRecordTargetDNS{
						FQDN: strPtr("target.example.com"),
					},
				},
			},
		},
	}

	spec := DomainRecordsToDomainSpec(records)

	require.NotNil(t, spec.Target.DNS)
	require.NotNil(t, spec.Target.DNS.FQDN)
	assert.Equal(t, "target.example.com", spec.Target.DNS.FQDN.Name)
	assert.Equal(t, int32Ptr(120), spec.Target.DNS.FQDN.TTL)
}

func TestRoundTrip_DomainToRecordsAndBack(t *testing.T) {
	original := corev1alpha3.DomainSpec{
		Zone: "example.com",
		Target: corev1alpha3.DomainTargetSpec{
			DNS: &corev1alpha3.DomainTargetDNS{
				IPs: &corev1alpha3.DNSAddressRecords{
					Addresses: []string{"1.2.3.4"},
					TTL:       int32Ptr(60),
				},
				TXT: &corev1alpha3.DNSTXTRecords{
					Values: []string{"hello"},
					TTL:    int32Ptr(300),
				},
			},
		},
	}
	domain := &corev1alpha3.Domain{
		ObjectMeta: metav1.ObjectMeta{Name: "example"},
		Spec:       original,
	}

	records := DomainToDomainRecords(domain)
	spec := DomainRecordsToDomainSpec(records)

	assert.Equal(t, original.Zone, spec.Zone)
	require.NotNil(t, spec.Target.DNS)
	require.NotNil(t, spec.Target.DNS.IPs)
	assert.Equal(t, original.Target.DNS.IPs.Addresses, spec.Target.DNS.IPs.Addresses)
	assert.Equal(t, original.Target.DNS.IPs.TTL, spec.Target.DNS.IPs.TTL)
	require.NotNil(t, spec.Target.DNS.TXT)
	assert.Equal(t, original.Target.DNS.TXT.Values, spec.Target.DNS.TXT.Values)
	assert.Equal(t, original.Target.DNS.TXT.TTL, spec.Target.DNS.TXT.TTL)
}

func TestIsReflected(t *testing.T) {
	domain := &corev1alpha3.Domain{}
	assert.False(t, isReflected(domain))

	domain.Annotations = map[string]string{ReflectedAnnotation: "true"}
	assert.True(t, isReflected(domain))

	domain.Annotations[ReflectedAnnotation] = "false"
	assert.False(t, isReflected(domain))
}

func TestAdmitDomain_SkipsReflected(t *testing.T) {
	client := fake.NewSimpleClientset()
	plugin := &DomainRecordReflection{
		Handler: admission.NewHandler(admission.Create, admission.Update, admission.Delete),
		client:  client,
	}

	domain := &corev1alpha3.Domain{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "example",
			Annotations: map[string]string{ReflectedAnnotation: "true"},
		},
		Spec: corev1alpha3.DomainSpec{
			Zone: "example.com",
			Target: corev1alpha3.DomainTargetSpec{
				Ref: &corev1alpha3.LocalObjectReference{
					Group: "core.apoxy.dev",
					Kind:  "Proxy",
					Name:  "my-proxy",
				},
			},
		},
	}

	attrs := admission.NewAttributesRecord(
		domain,
		nil,
		schema.GroupVersionKind{Group: "core.apoxy.dev", Version: "v1alpha3", Kind: "Domain"},
		"",
		"example",
		domainGVR,
		"",
		admission.Create,
		&metav1.CreateOptions{},
		false,
		nil,
	)

	err := plugin.Admit(context.Background(), attrs, nil)
	require.NoError(t, err)

	// No DomainRecords should have been created.
	list, err := client.CoreV1alpha3().DomainRecords().List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, list.Items)
}

func TestAdmitDomain_CreatesDomainRecords(t *testing.T) {
	client := fake.NewSimpleClientset()
	plugin := &DomainRecordReflection{
		Handler: admission.NewHandler(admission.Create, admission.Update, admission.Delete),
		client:  client,
	}

	domain := &corev1alpha3.Domain{
		ObjectMeta: metav1.ObjectMeta{Name: "example"},
		Spec: corev1alpha3.DomainSpec{
			Zone: "example.com",
			Target: corev1alpha3.DomainTargetSpec{
				Ref: &corev1alpha3.LocalObjectReference{
					Group: "core.apoxy.dev",
					Kind:  "Proxy",
					Name:  "my-proxy",
				},
			},
		},
	}

	attrs := admission.NewAttributesRecord(
		domain,
		nil,
		schema.GroupVersionKind{Group: "core.apoxy.dev", Version: "v1alpha3", Kind: "Domain"},
		"",
		"example",
		domainGVR,
		"",
		admission.Create,
		&metav1.CreateOptions{},
		false,
		nil,
	)

	err := plugin.Admit(context.Background(), attrs, nil)
	require.NoError(t, err)

	list, err := client.CoreV1alpha3().DomainRecords().List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	assert.Equal(t, "example.ref", list.Items[0].Name)
	assert.True(t, isReflected(&list.Items[0]))
}

func TestAdmitDomainRecord_CreatesDomain(t *testing.T) {
	client := fake.NewSimpleClientset()
	plugin := &DomainRecordReflection{
		Handler: admission.NewHandler(admission.Create, admission.Update, admission.Delete),
		client:  client,
	}

	dr := &corev1alpha3.DomainRecord{
		ObjectMeta: metav1.ObjectMeta{Name: "example.ips"},
		Spec: corev1alpha3.DomainRecordSpec{
			Zone: "example.com",
			Name: "example",
			TTL:  int32Ptr(60),
			Target: corev1alpha3.DomainRecordTarget{
				DNS: &corev1alpha3.DomainRecordTargetDNS{
					IPs: []string{"1.2.3.4"},
				},
			},
		},
	}

	attrs := admission.NewAttributesRecord(
		dr,
		nil,
		schema.GroupVersionKind{Group: "core.apoxy.dev", Version: "v1alpha3", Kind: "DomainRecord"},
		"",
		"example.ips",
		domainRecordGVR,
		"",
		admission.Create,
		&metav1.CreateOptions{},
		false,
		nil,
	)

	err := plugin.Admit(context.Background(), attrs, nil)
	require.NoError(t, err)

	// A reflected Domain should have been created.
	domain, err := client.CoreV1alpha3().Domains().Get(context.Background(), "example", metav1.GetOptions{})
	require.NoError(t, err)
	assert.True(t, isReflected(domain))
	assert.Equal(t, "example.com", domain.Spec.Zone)
	require.NotNil(t, domain.Spec.Target.DNS)
	require.NotNil(t, domain.Spec.Target.DNS.IPs)
	assert.Equal(t, []string{"1.2.3.4"}, domain.Spec.Target.DNS.IPs.Addresses)
}

func TestAdmitDomainRecord_SkipsIfUserManagedDomainExists(t *testing.T) {
	// Pre-create a user-managed (non-reflected) Domain.
	existingDomain := &corev1alpha3.Domain{
		ObjectMeta: metav1.ObjectMeta{Name: "example"},
		Spec: corev1alpha3.DomainSpec{
			Zone: "example.com",
			Target: corev1alpha3.DomainTargetSpec{
				Ref: &corev1alpha3.LocalObjectReference{
					Group: "core.apoxy.dev",
					Kind:  "Proxy",
					Name:  "my-proxy",
				},
			},
		},
	}
	client := fake.NewSimpleClientset(existingDomain)
	plugin := &DomainRecordReflection{
		Handler: admission.NewHandler(admission.Create, admission.Update, admission.Delete),
		client:  client,
	}

	dr := &corev1alpha3.DomainRecord{
		ObjectMeta: metav1.ObjectMeta{Name: "example.ips"},
		Spec: corev1alpha3.DomainRecordSpec{
			Zone: "example.com",
			Name: "example",
			TTL:  int32Ptr(60),
			Target: corev1alpha3.DomainRecordTarget{
				DNS: &corev1alpha3.DomainRecordTargetDNS{
					IPs: []string{"9.9.9.9"},
				},
			},
		},
	}

	attrs := admission.NewAttributesRecord(
		dr,
		nil,
		schema.GroupVersionKind{Group: "core.apoxy.dev", Version: "v1alpha3", Kind: "DomainRecord"},
		"",
		"example.ips",
		domainRecordGVR,
		"",
		admission.Create,
		&metav1.CreateOptions{},
		false,
		nil,
	)

	err := plugin.Admit(context.Background(), attrs, nil)
	require.NoError(t, err)

	// Domain should NOT be updated (still user-managed).
	domain, err := client.CoreV1alpha3().Domains().Get(context.Background(), "example", metav1.GetOptions{})
	require.NoError(t, err)
	assert.False(t, isReflected(domain))
	// Spec should be unchanged.
	require.NotNil(t, domain.Spec.Target.Ref)
	assert.Equal(t, corev1alpha3.ObjectName("my-proxy"), domain.Spec.Target.Ref.Name)
}

func TestAdmitDomainRecord_SkipsReflected(t *testing.T) {
	client := fake.NewSimpleClientset()
	plugin := &DomainRecordReflection{
		Handler: admission.NewHandler(admission.Create, admission.Update, admission.Delete),
		client:  client,
	}

	dr := &corev1alpha3.DomainRecord{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "example.ref",
			Annotations: map[string]string{ReflectedAnnotation: "true"},
		},
		Spec: corev1alpha3.DomainRecordSpec{
			Zone: "example.com",
			Name: "example",
			Target: corev1alpha3.DomainRecordTarget{
				Ref: &corev1alpha3.LocalObjectReference{
					Group: "core.apoxy.dev",
					Kind:  "Proxy",
					Name:  "my-proxy",
				},
			},
		},
	}

	attrs := admission.NewAttributesRecord(
		dr,
		nil,
		schema.GroupVersionKind{Group: "core.apoxy.dev", Version: "v1alpha3", Kind: "DomainRecord"},
		"",
		"example.ref",
		domainRecordGVR,
		"",
		admission.Create,
		&metav1.CreateOptions{},
		false,
		nil,
	)

	err := plugin.Admit(context.Background(), attrs, nil)
	require.NoError(t, err)

	// No Domain should be created.
	list, err := client.CoreV1alpha3().Domains().List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, list.Items)
}

func TestAdmitNonTargetResource(t *testing.T) {
	client := fake.NewSimpleClientset()
	plugin := &DomainRecordReflection{
		Handler: admission.NewHandler(admission.Create, admission.Update, admission.Delete),
		client:  client,
	}

	attrs := admission.NewAttributesRecord(
		nil,
		nil,
		schema.GroupVersionKind{Group: "core.apoxy.dev", Version: "v1alpha3", Kind: "Backend"},
		"",
		"test",
		schema.GroupVersionResource{Group: "core.apoxy.dev", Version: "v1alpha3", Resource: "backends"},
		"",
		admission.Create,
		&runtime.Unknown{},
		false,
		nil,
	)

	err := plugin.Admit(context.Background(), attrs, nil)
	require.NoError(t, err)
}

func TestDomainToDomainRecords_AllDNSFields(t *testing.T) {
	domain := &corev1alpha3.Domain{
		ObjectMeta: metav1.ObjectMeta{Name: "all-dns"},
		Spec: corev1alpha3.DomainSpec{
			Zone: "example.com",
			Target: corev1alpha3.DomainTargetSpec{
				DNS: &corev1alpha3.DomainTargetDNS{
					IPs:    &corev1alpha3.DNSAddressRecords{Addresses: []string{"1.2.3.4"}},
					FQDN:   &corev1alpha3.DNSCNAMERecord{Name: "cname.example.com"},
					TXT:    &corev1alpha3.DNSTXTRecords{Values: []string{"txt-val"}},
					MX:     &corev1alpha3.DNSMXRecords{Values: []string{"10 mx.example.com"}},
					DKIM:   &corev1alpha3.DNSDKIMRecords{Values: []string{"dkim-val"}},
					SPF:    &corev1alpha3.DNSSPFRecords{Values: []string{"spf-val"}},
					DMARC:  &corev1alpha3.DNSDMARCRecords{Values: []string{"dmarc-val"}},
					CAA:    &corev1alpha3.DNSCAARecords{Values: []string{"caa-val"}},
					SRV:    &corev1alpha3.DNSSRVRecords{Values: []string{"srv-val"}},
					NS:     &corev1alpha3.DNSNSRecords{Nameservers: []string{"ns1.example.com"}},
					DS:     &corev1alpha3.DNSDSRecords{Values: []string{"ds-val"}},
					DNSKEY: &corev1alpha3.DNSDNSKEYRecords{Values: []string{"dnskey-val"}},
				},
			},
		},
	}

	records := DomainToDomainRecords(domain)

	assert.Len(t, records, 12)

	names := make(map[string]bool)
	for _, r := range records {
		names[r.Name] = true
		assert.True(t, isReflected(&r))
	}
	assert.True(t, names["all-dns.ips"])
	assert.True(t, names["all-dns.fqdn"])
	assert.True(t, names["all-dns.txt"])
	assert.True(t, names["all-dns.mx"])
	assert.True(t, names["all-dns.dkim"])
	assert.True(t, names["all-dns.spf"])
	assert.True(t, names["all-dns.dmarc"])
	assert.True(t, names["all-dns.caa"])
	assert.True(t, names["all-dns.srv"])
	assert.True(t, names["all-dns.ns"])
	assert.True(t, names["all-dns.ds"])
	assert.True(t, names["all-dns.dnskey"])
}

func TestDomainRecordSpecEqual(t *testing.T) {
	a := &corev1alpha3.DomainRecord{
		Spec: corev1alpha3.DomainRecordSpec{
			Zone: "example.com",
			Name: "example",
			TTL:  int32Ptr(60),
			Target: corev1alpha3.DomainRecordTarget{
				DNS: &corev1alpha3.DomainRecordTargetDNS{
					IPs: []string{"1.2.3.4"},
				},
			},
		},
	}
	b := &corev1alpha3.DomainRecord{
		Spec: corev1alpha3.DomainRecordSpec{
			Zone: "example.com",
			Name: "example",
			TTL:  int32Ptr(60),
			Target: corev1alpha3.DomainRecordTarget{
				DNS: &corev1alpha3.DomainRecordTargetDNS{
					IPs: []string{"1.2.3.4"},
				},
			},
		},
	}
	assert.True(t, domainRecordSpecEqual(a, b))

	// Change TTL.
	b.Spec.TTL = int32Ptr(120)
	assert.False(t, domainRecordSpecEqual(a, b))
}

func findRecord(records []corev1alpha3.DomainRecord, name string) *corev1alpha3.DomainRecord {
	for i := range records {
		if records[i].Name == name {
			return &records[i]
		}
	}
	return nil
}
