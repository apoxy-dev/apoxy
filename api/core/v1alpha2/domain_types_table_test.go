package v1alpha2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ptr[T any](v T) *T { return &v }

func TestGetDomainColumns(t *testing.T) {
	tests := []struct {
		name      string
		domain    *Domain
		wantType  string
		wantValue string
		wantTTL   int32
	}{
		{
			name: "ref gateway",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				Ref: &LocalObjectReference{Kind: "Gateway", Name: "default"},
			}}},
			wantType:  "Ref",
			wantValue: "gateway://default",
			wantTTL:   10,
		},
		{
			name: "ref tunnel",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				Ref: &LocalObjectReference{Kind: "Tunnel", Name: "my-tunnel"},
			}}},
			wantType:  "Ref",
			wantValue: "tunnel://my-tunnel",
			wantTTL:   10,
		},
		{
			name: "ref tunnel node",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				Ref: &LocalObjectReference{Kind: "TunnelNode", Name: "node-1"},
			}}},
			wantType:  "Ref",
			wantValue: "tunnel://node-1",
			wantTTL:   10,
		},
		{
			name: "ref edge function",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				Ref: &LocalObjectReference{Kind: "EdgeFunction", Name: "my-func"},
			}}},
			wantType:  "Ref",
			wantValue: "func://my-func",
			wantTTL:   10,
		},
		{
			name: "ref unknown kind",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				Ref: &LocalObjectReference{Kind: "CustomThing", Name: "foo"},
			}}},
			wantType:  "Ref",
			wantValue: "CustomThing://foo",
			wantTTL:   10,
		},
		{
			name: "dns single ipv4",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{IPs: []string{"1.2.3.4"}, TTL: ptr[int32](60)},
			}}},
			wantType:  "DNS:A",
			wantValue: "1.2.3.4",
			wantTTL:   60,
		},
		{
			name: "dns multiple ipv4",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{IPs: []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"}, TTL: ptr[int32](300)},
			}}},
			wantType:  "DNS:A",
			wantValue: "1.2.3.4 (+2)",
			wantTTL:   300,
		},
		{
			name: "dns single ipv6",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{IPs: []string{"fc00::1"}, TTL: ptr[int32](120)},
			}}},
			wantType:  "DNS:AAAA",
			wantValue: "fc00::1",
			wantTTL:   120,
		},
		{
			name: "dns multiple ipv6",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{IPs: []string{"fc00::1", "fc00::2"}, TTL: ptr[int32](20)},
			}}},
			wantType:  "DNS:AAAA",
			wantValue: "fc00::1 (+1)",
			wantTTL:   20,
		},
		{
			name: "dns ipv4 nil ttl",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{IPs: []string{"10.0.0.1"}},
			}}},
			wantType:  "DNS:A",
			wantValue: "10.0.0.1",
			wantTTL:   0,
		},
		{
			name: "dns cname",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{FQDN: ptr("www.example.com"), TTL: ptr[int32](3600)},
			}}},
			wantType:  "DNS:CNAME",
			wantValue: "www.example.com",
			wantTTL:   3600,
		},
		{
			name: "dns cname long truncated",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{FQDN: ptr("this-is-a-very-long-subdomain.example.com"), TTL: ptr[int32](60)},
			}}},
			wantType:  "DNS:CNAME",
			wantValue: "this-is-a-very-long-subdoma...",
			wantTTL:   60,
		},
		{
			name: "dns txt records",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{TXT: []string{"v=spf1 ..."}, TTL: ptr[int32](20)},
			}}},
			wantType:  "DNS:TXT",
			wantValue: "",
			wantTTL:   20,
		},
		{
			name: "dns mx records",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{MX: []string{"10 mail.example.com"}, TTL: ptr[int32](20)},
			}}},
			wantType:  "DNS:MX",
			wantValue: "",
			wantTTL:   20,
		},
		{
			name: "dns multiple record types",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{
					TXT: []string{"v=spf1"},
					MX:  []string{"10 mail.example.com"},
					NS:  []string{"ns1.example.com"},
					TTL: ptr[int32](300),
				},
			}}},
			wantType:  "DNS:TXT,MX,NS",
			wantValue: "",
			wantTTL:   300,
		},
		{
			name: "dns srv and caa",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{
					SRV: []string{"0 5 5060 sip.example.com"},
					CAA: []string{"0 issue letsencrypt.org"},
					TTL: ptr[int32](60),
				},
			}}},
			wantType:  "DNS:SRV,CAA",
			wantValue: "",
			wantTTL:   60,
		},
		{
			name: "dns dkim spf dmarc",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{
					DKIM:  []string{"v=DKIM1;..."},
					SPF:   []string{"v=spf1 ..."},
					DMARC: []string{"v=DMARC1;..."},
					TTL:   ptr[int32](20),
				},
			}}},
			wantType:  "DNS:DKIM,SPF,DMARC",
			wantValue: "",
			wantTTL:   20,
		},
		{
			name: "dns ds and dnskey",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{
					DS:     []string{"12345 8 2 ..."},
					DNSKEY: []string{"257 3 8 ..."},
					TTL:    ptr[int32](20),
				},
			}}},
			wantType:  "DNS:DS,DNSKEY",
			wantValue: "",
			wantTTL:   20,
		},
		{
			name: "dns empty - no records",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{},
			}}},
			wantType:  "—",
			wantValue: "",
			wantTTL:   0,
		},
		{
			name: "dns empty with ttl still returns dash",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{TTL: ptr[int32](60)},
			}}},
			wantType:  "—",
			wantValue: "",
			wantTTL:   0,
		},
		{
			name:      "no target",
			domain:    &Domain{Spec: DomainSpec{}},
			wantType:  "—",
			wantValue: "",
			wantTTL:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typ, value, ttl := getDomainColumns(tt.domain)
			assert.Equal(t, tt.wantType, typ, "type")
			assert.Equal(t, tt.wantValue, value, "value")
			assert.Equal(t, tt.wantTTL, ttl, "ttl")
		})
	}
}

func TestDomainConvertToTable(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()

	domain := &Domain{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test",
			CreationTimestamp: now,
			ResourceVersion:   "42",
		},
		Spec: DomainSpec{
			Zone: "example.com",
			Target: DomainTargetSpec{
				Ref: &LocalObjectReference{Kind: "Gateway", Name: "default"},
			},
		},
		Status: DomainStatus{Phase: "Active"},
	}

	table, err := domain.ConvertToTable(ctx, &metav1.TableOptions{})
	require.NoError(t, err)

	assert.Len(t, table.ColumnDefinitions, 7)
	assert.Equal(t, "Name", table.ColumnDefinitions[0].Name)
	assert.Equal(t, "Zone", table.ColumnDefinitions[1].Name)
	assert.Equal(t, "Type", table.ColumnDefinitions[2].Name)
	assert.Equal(t, "Value", table.ColumnDefinitions[3].Name)
	assert.Equal(t, "TTL", table.ColumnDefinitions[4].Name)
	assert.Equal(t, "Status", table.ColumnDefinitions[5].Name)
	assert.Equal(t, "Age", table.ColumnDefinitions[6].Name)

	require.Len(t, table.Rows, 1)
	cells := table.Rows[0].Cells
	assert.Len(t, cells, 7)
	assert.Equal(t, "test", cells[0])
	assert.Equal(t, "example.com", cells[1])
	assert.Equal(t, "Ref", cells[2])
	assert.Equal(t, "gateway://default", cells[3])
	assert.Equal(t, int32(10), cells[4])
	assert.Equal(t, "Active", cells[5])
	assert.NotNil(t, table.Rows[0].Object.Object)
	assert.Equal(t, "42", table.ResourceVersion)
}

func TestDomainConvertToTableNoHeaders(t *testing.T) {
	ctx := context.Background()

	domain := &Domain{
		ObjectMeta: metav1.ObjectMeta{Name: "test", CreationTimestamp: metav1.Now()},
		Spec:       DomainSpec{Target: DomainTargetSpec{}},
	}

	table, err := domain.ConvertToTable(ctx, &metav1.TableOptions{NoHeaders: true})
	require.NoError(t, err)

	assert.Empty(t, table.ColumnDefinitions)
	require.Len(t, table.Rows, 1)
	assert.Len(t, table.Rows[0].Cells, 7)
}

func TestDomainListConvertToTable(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()
	remaining := int64(5)

	list := &DomainList{
		ListMeta: metav1.ListMeta{
			ResourceVersion:    "99",
			Continue:           "token",
			RemainingItemCount: &remaining,
		},
		Items: []Domain{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "a", CreationTimestamp: now},
				Spec: DomainSpec{
					Zone:   "z.com",
					Target: DomainTargetSpec{DNS: &DomainTargetDNS{IPs: []string{"1.2.3.4"}, TTL: ptr[int32](60)}},
				},
				Status: DomainStatus{Phase: "Active"},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "b", CreationTimestamp: now},
				Spec: DomainSpec{
					Zone:   "z.com",
					Target: DomainTargetSpec{Ref: &LocalObjectReference{Kind: "EdgeFunction", Name: "fn"}},
				},
				Status: DomainStatus{Phase: "Pending"},
			},
		},
	}

	table, err := list.ConvertToTable(ctx, &metav1.TableOptions{})
	require.NoError(t, err)

	assert.Len(t, table.ColumnDefinitions, 7)
	assert.Len(t, table.Rows, 2)

	// Row 0: DNS A record
	assert.Equal(t, "a", table.Rows[0].Cells[0])
	assert.Equal(t, "DNS:A", table.Rows[0].Cells[2])
	assert.Equal(t, "1.2.3.4", table.Rows[0].Cells[3])
	assert.Equal(t, int32(60), table.Rows[0].Cells[4])

	// Row 1: Ref
	assert.Equal(t, "b", table.Rows[1].Cells[0])
	assert.Equal(t, "Ref", table.Rows[1].Cells[2])
	assert.Equal(t, "func://fn", table.Rows[1].Cells[3])
	assert.Equal(t, int32(10), table.Rows[1].Cells[4])

	// List metadata preserved
	assert.Equal(t, "99", table.ResourceVersion)
	assert.Equal(t, "token", table.Continue)
	assert.Equal(t, &remaining, table.RemainingItemCount)
}
