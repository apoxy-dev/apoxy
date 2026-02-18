package v1alpha2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ptr[T any](v T) *T { return &v }

func TestGetDomainRows(t *testing.T) {
	tests := []struct {
		name string
		domain *Domain
		want []domainRow
	}{
		{
			name: "ref gateway",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				Ref: &LocalObjectReference{Kind: "Gateway", Name: "default"},
			}}},
			want: []domainRow{{typ: "Ref", value: "gateway://default", ttl: 10}},
		},
		{
			name: "ref tunnel",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				Ref: &LocalObjectReference{Kind: "Tunnel", Name: "my-tunnel"},
			}}},
			want: []domainRow{{typ: "Ref", value: "tunnel://my-tunnel", ttl: 10}},
		},
		{
			name: "ref tunnel node",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				Ref: &LocalObjectReference{Kind: "TunnelNode", Name: "node-1"},
			}}},
			want: []domainRow{{typ: "Ref", value: "tunnel://node-1", ttl: 10}},
		},
		{
			name: "ref edge function",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				Ref: &LocalObjectReference{Kind: "EdgeFunction", Name: "my-func"},
			}}},
			want: []domainRow{{typ: "Ref", value: "func://my-func", ttl: 10}},
		},
		{
			name: "ref unknown kind",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				Ref: &LocalObjectReference{Kind: "CustomThing", Name: "foo"},
			}}},
			want: []domainRow{{typ: "Ref", value: "CustomThing://foo", ttl: 10}},
		},
		{
			name: "dns single ipv4",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{IPs: []string{"1.2.3.4"}, TTL: ptr[int32](60)},
			}}},
			want: []domainRow{{typ: "DNS:A", value: "1.2.3.4", ttl: 60}},
		},
		{
			name: "dns multiple ipv4",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{IPs: []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"}, TTL: ptr[int32](300)},
			}}},
			want: []domainRow{{typ: "DNS:A", value: "1.2.3.4 (+2)", ttl: 300}},
		},
		{
			name: "dns single ipv6",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{IPs: []string{"fc00::1"}, TTL: ptr[int32](120)},
			}}},
			want: []domainRow{{typ: "DNS:AAAA", value: "fc00::1", ttl: 120}},
		},
		{
			name: "dns multiple ipv6",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{IPs: []string{"fc00::1", "fc00::2"}, TTL: ptr[int32](20)},
			}}},
			want: []domainRow{{typ: "DNS:AAAA", value: "fc00::1 (+1)", ttl: 20}},
		},
		{
			name: "dns ipv4 nil ttl",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{IPs: []string{"10.0.0.1"}},
			}}},
			want: []domainRow{{typ: "DNS:A", value: "10.0.0.1", ttl: 0}},
		},
		{
			name: "dns cname",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{FQDN: ptr("www.example.com"), TTL: ptr[int32](3600)},
			}}},
			want: []domainRow{{typ: "DNS:CNAME", value: "www.example.com", ttl: 3600}},
		},
		{
			name: "dns cname long truncated",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{FQDN: ptr("this-is-a-very-long-subdomain.example.com"), TTL: ptr[int32](60)},
			}}},
			want: []domainRow{{typ: "DNS:CNAME", value: "this-is-a-very-long-subdoma...", ttl: 60}},
		},
		{
			name: "dns txt records",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{TXT: []string{"v=spf1 ..."}, TTL: ptr[int32](20)},
			}}},
			want: []domainRow{{typ: "DNS:TXT", value: "v=spf1 ...", ttl: 20}},
		},
		{
			name: "dns mx records",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{MX: []string{"10 mail.example.com"}, TTL: ptr[int32](20)},
			}}},
			want: []domainRow{{typ: "DNS:MX", value: "10 mail.example.com", ttl: 20}},
		},
		{
			name: "dns multiple record types produce multiple rows",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{
					TXT: []string{"v=spf1"},
					MX:  []string{"10 mail.example.com"},
					NS:  []string{"ns1.example.com"},
					TTL: ptr[int32](300),
				},
			}}},
			want: []domainRow{
				{typ: "DNS:TXT", value: "v=spf1", ttl: 300},
				{typ: "DNS:MX", value: "10 mail.example.com", ttl: 300},
				{typ: "DNS:NS", value: "ns1.example.com", ttl: 300},
			},
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
			want: []domainRow{
				{typ: "DNS:SRV", value: "0 5 5060 sip.example.com", ttl: 60},
				{typ: "DNS:CAA", value: "0 issue letsencrypt.org", ttl: 60},
			},
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
			want: []domainRow{
				{typ: "DNS:DKIM", value: "v=DKIM1;...", ttl: 20},
				{typ: "DNS:SPF", value: "v=spf1 ...", ttl: 20},
				{typ: "DNS:DMARC", value: "v=DMARC1;...", ttl: 20},
			},
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
			want: []domainRow{
				{typ: "DNS:DS", value: "12345 8 2 ...", ttl: 20},
				{typ: "DNS:DNSKEY", value: "257 3 8 ...", ttl: 20},
			},
		},
		{
			name: "dns ipv4 with txt",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{
					IPs: []string{"1.2.3.4"},
					TXT: []string{"v=spf1 include:example.com ~all"},
					TTL: ptr[int32](300),
				},
			}}},
			want: []domainRow{
				{typ: "DNS:A", value: "1.2.3.4", ttl: 300},
				{typ: "DNS:TXT", value: "v=spf1 include:example.com ...", ttl: 300},
			},
		},
		{
			name: "dns ipv4 with txt and mx",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{
					IPs: []string{"1.2.3.4", "5.6.7.8"},
					TXT: []string{"v=spf1"},
					MX:  []string{"10 mail.example.com"},
					TTL: ptr[int32](60),
				},
			}}},
			want: []domainRow{
				{typ: "DNS:A", value: "1.2.3.4 (+1)", ttl: 60},
				{typ: "DNS:TXT", value: "v=spf1", ttl: 60},
				{typ: "DNS:MX", value: "10 mail.example.com", ttl: 60},
			},
		},
		{
			name: "ref with dns txt",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				Ref: &LocalObjectReference{Kind: "Gateway", Name: "gw"},
				DNS: &DomainTargetDNS{
					TXT: []string{"v=spf1"},
					TTL: ptr[int32](300),
				},
			}}},
			want: []domainRow{
				{typ: "Ref", value: "gateway://gw", ttl: 10},
				{typ: "DNS:TXT", value: "v=spf1", ttl: 300},
			},
		},
		{
			name: "dns empty - no records",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{},
			}}},
			want: []domainRow{{typ: "—"}},
		},
		{
			name: "dns empty with ttl still returns dash",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{TTL: ptr[int32](60)},
			}}},
			want: []domainRow{{typ: "—"}},
		},
		{
			name:   "no target",
			domain: &Domain{Spec: DomainSpec{}},
			want:   []domainRow{{typ: "—"}},
		},
		{
			name: "dns multiple txt values collapsed",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{
					TXT: []string{"v=spf1 include:example.com ~all", "google-verification=abc"},
					TTL: ptr[int32](300),
				},
			}}},
			want: []domainRow{
				{typ: "DNS:TXT", value: "v=spf1 include:example.com ... (+1)", ttl: 300},
			},
		},
		{
			name: "dns multiple mx values collapsed",
			domain: &Domain{Spec: DomainSpec{Target: DomainTargetSpec{
				DNS: &DomainTargetDNS{
					MX:  []string{"10 mail.example.com", "20 mail2.example.com"},
					TTL: ptr[int32](300),
				},
			}}},
			want: []domainRow{
				{typ: "DNS:MX", value: "10 mail.example.com (+1)", ttl: 300},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := getDomainRows(tt.domain)
			require.Len(t, rows, len(tt.want), "row count")
			for i, w := range tt.want {
				assert.Equal(t, w.typ, rows[i].typ, "row %d type", i)
				assert.Equal(t, w.value, rows[i].value, "row %d value", i)
				assert.Equal(t, w.ttl, rows[i].ttl, "row %d ttl", i)
			}
		})
	}
}

func TestFormatMultiValue(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		maxLen int
		want   string
	}{
		{"empty", nil, 30, ""},
		{"single short", []string{"hello"}, 30, "hello"},
		{"single long", []string{"this-is-a-very-long-string-that-exceeds"}, 30, "this-is-a-very-long-string-..."},
		{"two values", []string{"first", "second"}, 30, "first (+1)"},
		{"three values", []string{"first", "second", "third"}, 30, "first (+2)"},
		{"two values with truncation", []string{"this-is-a-very-long-string-that-exceeds", "other"}, 30, "this-is-a-very-long-string-... (+1)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, formatMultiValue(tt.values, tt.maxLen))
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

func TestDomainConvertToTableMultiRow(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()

	domain := &Domain{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "multi",
			CreationTimestamp: now,
			ResourceVersion:   "7",
		},
		Spec: DomainSpec{
			Zone: "example.com",
			Target: DomainTargetSpec{
				Ref: &LocalObjectReference{Kind: "Gateway", Name: "gw"},
				DNS: &DomainTargetDNS{
					TXT: []string{"v=spf1"},
					TTL: ptr[int32](300),
				},
			},
		},
		Status: DomainStatus{Phase: "Active"},
	}

	table, err := domain.ConvertToTable(ctx, &metav1.TableOptions{})
	require.NoError(t, err)

	require.Len(t, table.Rows, 2)

	// First row: all fields populated
	row0 := table.Rows[0].Cells
	assert.Equal(t, "multi", row0[0])
	assert.Equal(t, "example.com", row0[1])
	assert.Equal(t, "Ref", row0[2])
	assert.Equal(t, "gateway://gw", row0[3])
	assert.Equal(t, int32(10), row0[4])
	assert.Equal(t, "Active", row0[5])
	assert.NotNil(t, table.Rows[0].Object.Object)

	// Second row: continuation — Name, Zone, Status, Age blank
	row1 := table.Rows[1].Cells
	assert.Equal(t, "", row1[0])
	assert.Equal(t, "", row1[1])
	assert.Equal(t, "DNS:TXT", row1[2])
	assert.Equal(t, "v=spf1", row1[3])
	assert.Equal(t, int32(300), row1[4])
	assert.Equal(t, "", row1[5])
	assert.Equal(t, "", row1[6])
	assert.Nil(t, table.Rows[1].Object.Object)
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
	require.Len(t, table.Rows, 2)

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

func TestDomainListConvertToTableMultiRow(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()

	list := &DomainList{
		ListMeta: metav1.ListMeta{ResourceVersion: "1"},
		Items: []Domain{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "multi", CreationTimestamp: now},
				Spec: DomainSpec{
					Zone: "example.com",
					Target: DomainTargetSpec{
						DNS: &DomainTargetDNS{
							IPs: []string{"1.2.3.4"},
							TXT: []string{"v=spf1"},
							MX:  []string{"10 mail.example.com"},
							TTL: ptr[int32](300),
						},
					},
				},
				Status: DomainStatus{Phase: "Active"},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "simple", CreationTimestamp: now},
				Spec: DomainSpec{
					Zone:   "example.com",
					Target: DomainTargetSpec{Ref: &LocalObjectReference{Kind: "Gateway", Name: "gw"}},
				},
				Status: DomainStatus{Phase: "Active"},
			},
		},
	}

	table, err := list.ConvertToTable(ctx, &metav1.TableOptions{})
	require.NoError(t, err)

	// 3 rows for "multi" (A + TXT + MX) + 1 row for "simple"
	require.Len(t, table.Rows, 4)

	// Row 0: first row for "multi" — populated
	assert.Equal(t, "multi", table.Rows[0].Cells[0])
	assert.Equal(t, "example.com", table.Rows[0].Cells[1])
	assert.Equal(t, "DNS:A", table.Rows[0].Cells[2])
	assert.Equal(t, "1.2.3.4", table.Rows[0].Cells[3])
	assert.Equal(t, "Active", table.Rows[0].Cells[5])
	assert.NotNil(t, table.Rows[0].Object.Object)

	// Row 1: continuation for "multi" — Name/Zone/Status/Age blank
	assert.Equal(t, "", table.Rows[1].Cells[0])
	assert.Equal(t, "", table.Rows[1].Cells[1])
	assert.Equal(t, "DNS:TXT", table.Rows[1].Cells[2])
	assert.Equal(t, "v=spf1", table.Rows[1].Cells[3])
	assert.Equal(t, "", table.Rows[1].Cells[5])
	assert.Equal(t, "", table.Rows[1].Cells[6])
	assert.Nil(t, table.Rows[1].Object.Object)

	// Row 2: continuation for "multi"
	assert.Equal(t, "", table.Rows[2].Cells[0])
	assert.Equal(t, "DNS:MX", table.Rows[2].Cells[2])
	assert.Equal(t, "10 mail.example.com", table.Rows[2].Cells[3])
	assert.Nil(t, table.Rows[2].Object.Object)

	// Row 3: "simple" — new domain, populated
	assert.Equal(t, "simple", table.Rows[3].Cells[0])
	assert.Equal(t, "Ref", table.Rows[3].Cells[2])
	assert.Equal(t, "gateway://gw", table.Rows[3].Cells[3])
	assert.NotNil(t, table.Rows[3].Object.Object)
}
