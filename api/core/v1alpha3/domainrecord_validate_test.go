package v1alpha3

import (
	"context"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func int32Ptr(v int32) *int32 { return &v }

func TestValidateUpdate_StatusTypeServerAuthoritative(t *testing.T) {
	tests := []struct {
		name       string
		old        *DomainRecord
		updated    *DomainRecord
		wantErr    bool
		errField   string
		errMessage string
	}{
		{
			name: "correct status.type on A record passes",
			old: &DomainRecord{
				ObjectMeta: metav1.ObjectMeta{Name: "example--a"},
				Spec: DomainRecordSpec{
					Name: "example",
					TTL:  int32Ptr(60),
					Target: DomainRecordTarget{
						DNS: &DomainRecordTargetDNS{
							A: []string{"1.2.3.4"},
						},
					},
				},
				Status: DomainRecordStatus{Type: "A"},
			},
			updated: &DomainRecord{
				ObjectMeta: metav1.ObjectMeta{Name: "example--a"},
				Spec: DomainRecordSpec{
					Name: "example",
					TTL:  int32Ptr(60),
					Target: DomainRecordTarget{
						DNS: &DomainRecordTargetDNS{
							A: []string{"5.6.7.8"},
						},
					},
				},
				Status: DomainRecordStatus{Type: "A"},
			},
			wantErr: false,
		},
		{
			name: "correct status.type on Ref record passes",
			old: &DomainRecord{
				ObjectMeta: metav1.ObjectMeta{Name: "example--ref"},
				Spec: DomainRecordSpec{
					Name: "example",
					TTL:  int32Ptr(60),
					Target: DomainRecordTarget{
						Ref: &LocalObjectReference{
							Group: "core.apoxy.dev",
							Kind:  "Proxy",
							Name:  "my-proxy",
						},
					},
				},
				Status: DomainRecordStatus{Type: "Ref"},
			},
			updated: &DomainRecord{
				ObjectMeta: metav1.ObjectMeta{Name: "example--ref"},
				Spec: DomainRecordSpec{
					Name: "example",
					TTL:  int32Ptr(60),
					Target: DomainRecordTarget{
						Ref: &LocalObjectReference{
							Group: "core.apoxy.dev",
							Kind:  "Proxy",
							Name:  "other-proxy",
						},
					},
				},
				Status: DomainRecordStatus{Type: "Ref"},
			},
			wantErr: false,
		},
		{
			name: "tampered status.type on A record is rejected",
			old: &DomainRecord{
				ObjectMeta: metav1.ObjectMeta{Name: "example--a"},
				Spec: DomainRecordSpec{
					Name: "example",
					TTL:  int32Ptr(60),
					Target: DomainRecordTarget{
						DNS: &DomainRecordTargetDNS{
							A: []string{"1.2.3.4"},
						},
					},
				},
				Status: DomainRecordStatus{Type: "A"},
			},
			updated: &DomainRecord{
				ObjectMeta: metav1.ObjectMeta{Name: "example--a"},
				Spec: DomainRecordSpec{
					Name: "example",
					TTL:  int32Ptr(60),
					Target: DomainRecordTarget{
						DNS: &DomainRecordTargetDNS{
							A: []string{"1.2.3.4"},
						},
					},
				},
				Status: DomainRecordStatus{Type: "A/AAAA"},
			},
			wantErr:    true,
			errField:   "status.type",
			errMessage: `must be "A" (derived from spec)`,
		},
		{
			name: "empty status.type on AAAA record is rejected",
			old: &DomainRecord{
				ObjectMeta: metav1.ObjectMeta{Name: "example--aaaa"},
				Spec: DomainRecordSpec{
					Name: "example",
					TTL:  int32Ptr(60),
					Target: DomainRecordTarget{
						DNS: &DomainRecordTargetDNS{
							AAAA: []string{"2001:db8::1"},
						},
					},
				},
				Status: DomainRecordStatus{Type: "AAAA"},
			},
			updated: &DomainRecord{
				ObjectMeta: metav1.ObjectMeta{Name: "example--aaaa"},
				Spec: DomainRecordSpec{
					Name: "example",
					TTL:  int32Ptr(60),
					Target: DomainRecordTarget{
						DNS: &DomainRecordTargetDNS{
							AAAA: []string{"2001:db8::1"},
						},
					},
				},
				Status: DomainRecordStatus{Type: ""},
			},
			wantErr:    true,
			errField:   "status.type",
			errMessage: `must be "AAAA" (derived from spec)`,
		},
		{
			name: "tampered status.type on CNAME record is rejected",
			old: &DomainRecord{
				ObjectMeta: metav1.ObjectMeta{Name: "example--fqdn"},
				Spec: DomainRecordSpec{
					Name: "example",
					TTL:  int32Ptr(60),
					Target: DomainRecordTarget{
						DNS: &DomainRecordTargetDNS{
							FQDN: strPtr("other.example.com"),
						},
					},
				},
				Status: DomainRecordStatus{Type: "CNAME"},
			},
			updated: &DomainRecord{
				ObjectMeta: metav1.ObjectMeta{Name: "example--fqdn"},
				Spec: DomainRecordSpec{
					Name: "example",
					TTL:  int32Ptr(60),
					Target: DomainRecordTarget{
						DNS: &DomainRecordTargetDNS{
							FQDN: strPtr("other.example.com"),
						},
					},
				},
				Status: DomainRecordStatus{Type: "A"},
			},
			wantErr:    true,
			errField:   "status.type",
			errMessage: `must be "CNAME" (derived from spec)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.updated.ValidateUpdate(context.Background(), tt.old)
			if !tt.wantErr {
				assert.Empty(t, errs, "expected no validation errors")
				return
			}
			require.NotEmpty(t, errs, "expected validation errors")
			var found bool
			for _, e := range errs {
				if e.Field == tt.errField {
					found = true
					assert.Contains(t, e.Detail, tt.errMessage)
				}
			}
			assert.True(t, found, "expected error on field %q, got: %v", tt.errField, errs)
		})
	}
}

func TestValidateUpdate_Immutability(t *testing.T) {
	base := func() *DomainRecord {
		return &DomainRecord{
			ObjectMeta: metav1.ObjectMeta{Name: "example--a"},
			Spec: DomainRecordSpec{
				Name: "example",
				Zone: "example.com",
				TTL:  int32Ptr(60),
				Target: DomainRecordTarget{
					DNS: &DomainRecordTargetDNS{
						A: []string{"1.2.3.4"},
					},
				},
			},
			Status: DomainRecordStatus{Type: "A"},
		}
	}

	tests := []struct {
		name       string
		mutate     func(r *DomainRecord)
		wantErr    bool
		errField   string
		errDetail  string
	}{
		{
			name:    "same spec — no error",
			mutate:  func(r *DomainRecord) {},
			wantErr: false,
		},
		{
			name: "spec.name changed",
			mutate: func(r *DomainRecord) {
				r.Spec.Name = "other"
				r.Name = "other--a" // keep metadata.name consistent
			},
			wantErr:   true,
			errField:  "spec.name",
			errDetail: "immutable",
		},
		{
			name: "spec.zone changed",
			mutate: func(r *DomainRecord) {
				r.Spec.Zone = "other.com"
			},
			wantErr:   true,
			errField:  "spec.zone",
			errDetail: "immutable",
		},
		{
			name: "target key changed (a → txt)",
			mutate: func(r *DomainRecord) {
				r.Spec.Target.DNS = &DomainRecordTargetDNS{
					TXT: []string{"v=spf1 include:example.com ~all"},
				}
				r.Name = "example--txt" // keep metadata.name consistent
			},
			wantErr:   true,
			errField:  "spec.target",
			errDetail: "cannot change target field key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := base()
			updated := base()
			tt.mutate(updated)

			errs := updated.ValidateUpdate(context.Background(), old)
			if !tt.wantErr {
				assert.Empty(t, errs, "expected no validation errors")
				return
			}
			require.NotEmpty(t, errs, "expected validation errors")
			var found bool
			for _, e := range errs {
				if e.Field == tt.errField {
					found = true
					assert.Contains(t, e.Detail, tt.errDetail)
				}
			}
			assert.True(t, found, "expected error on field %q, got: %v", tt.errField, errs)
		})
	}
}

func TestValidateUpdate_DeletionBypassesValidation(t *testing.T) {
	now := metav1.Now()
	// An object with an invalid spec (e.g. after a schema migration dropped
	// fields) that is being deleted should pass validation so that finalizers
	// can be removed.
	deleting := &DomainRecord{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "foobar.example.com--ips",
			DeletionTimestamp: &now,
		},
		Spec: DomainRecordSpec{
			Name: "foobar.example.com",
			TTL:  int32Ptr(300),
			Target: DomainRecordTarget{
				DNS: &DomainRecordTargetDNS{}, // Empty — fields dropped by migration.
			},
		},
		Status: DomainRecordStatus{Type: "A/AAAA"},
	}
	old := &DomainRecord{
		ObjectMeta: metav1.ObjectMeta{Name: "foobar.example.com--ips"},
		Spec:       deleting.Spec,
		Status:     deleting.Status,
	}

	errs := deleting.ValidateUpdate(context.Background(), old)
	assert.Empty(t, errs, "expected no validation errors when object is being deleted")
}

func TestDefault_RefTargetGetsTLS(t *testing.T) {
	tests := []struct {
		name    string
		record  *DomainRecord
		wantTLS bool
	}{
		{
			name: "ref target with no TLS gets TLS defaulted",
			record: &DomainRecord{
				Spec: DomainRecordSpec{
					Name: "example",
					Target: DomainRecordTarget{
						Ref: &LocalObjectReference{
							Group: "gateway.networking.k8s.io",
							Kind:  "Gateway",
							Name:  "my-gw",
						},
					},
				},
			},
			wantTLS: true,
		},
		{
			name: "ref target with existing TLS is not overwritten",
			record: &DomainRecord{
				Spec: DomainRecordSpec{
					Name: "example",
					Target: DomainRecordTarget{
						Ref: &LocalObjectReference{
							Group: "gateway.networking.k8s.io",
							Kind:  "Gateway",
							Name:  "my-gw",
						},
					},
					TLS: &DomainTLSSpec{CertificateAuthority: "letsencrypt"},
				},
			},
			wantTLS: true,
		},
		{
			name: "DNS target does not get TLS defaulted",
			record: &DomainRecord{
				Spec: DomainRecordSpec{
					Name: "example",
					Target: DomainRecordTarget{
						DNS: &DomainRecordTargetDNS{
							A: []string{"1.2.3.4"},
						},
					},
				},
			},
			wantTLS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origTLS := tt.record.Spec.TLS
			tt.record.Default()
			if tt.wantTLS {
				require.NotNil(t, tt.record.Spec.TLS, "expected spec.tls to be non-nil")
				// If TLS was already set, ensure it wasn't overwritten.
				if origTLS != nil {
					assert.Equal(t, origTLS.CertificateAuthority, tt.record.Spec.TLS.CertificateAuthority)
				}
			} else {
				assert.Nil(t, tt.record.Spec.TLS, "expected spec.tls to remain nil")
			}
		})
	}
}

// TestValidate_TLSDisabled covers the opt-out that makes an HTTP-only ref
// target expressible. Default() writes `tls: {}` for every ref target, so
// leaving the block off is not a way to decline a certificate — `disabled:
// true` is. Enabled() is what the controllers branch on, so it must agree with
// the field in all three shapes.
func TestValidate_TLSDisabled(t *testing.T) {
	refTarget := DomainRecordTarget{
		Ref: &LocalObjectReference{
			Group: "gateway.networking.k8s.io",
			Kind:  "Gateway",
			Name:  "my-gw",
		},
	}

	tests := []struct {
		name        string
		tls         *DomainTLSSpec
		wantEnabled bool
		wantErr     string // Substring of the expected field error; empty means valid.
	}{
		{
			name:        "no TLS block at all",
			tls:         nil,
			wantEnabled: false,
		},
		{
			name:        "defaulted empty block means TLS on",
			tls:         &DomainTLSSpec{},
			wantEnabled: true,
		},
		{
			name:        "explicitly disabled",
			tls:         &DomainTLSSpec{Disabled: true},
			wantEnabled: false,
		},
		{
			name:        "explicit CA with TLS on",
			tls:         &DomainTLSSpec{CertificateAuthority: "letsencrypt"},
			wantEnabled: true,
		},
		{
			// Contradictory: naming who should issue while switching issuance
			// off. Rejected rather than silently honoring one half.
			name:        "CA named while disabled",
			tls:         &DomainTLSSpec{CertificateAuthority: "letsencrypt", Disabled: true},
			wantEnabled: false,
			wantErr:     "spec.tls.certificateAuthority",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantEnabled, tt.tls.Enabled(), "Enabled() must match the field")

			dr := &DomainRecord{
				ObjectMeta: metav1.ObjectMeta{Name: "example--ref"},
				Spec: DomainRecordSpec{
					Name:   "example",
					Target: refTarget,
					TLS:    tt.tls,
				},
			}

			errs := dr.Validate(context.Background())
			if tt.wantErr == "" {
				assert.Empty(t, errs, "expected no validation errors")
				return
			}
			require.Len(t, errs, 1, "expected exactly one validation error")
			assert.Contains(t, errs[0].Error(), tt.wantErr)
		})
	}
}

func strPtr(s string) *string { return &s }

func manyIPv4(n int) []string {
	ips := make([]string, n)
	for i := range ips {
		ips[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	return ips
}

func dnsDomainRecord(key string, target DomainRecordTargetDNS) *DomainRecord {
	return &DomainRecord{
		ObjectMeta: metav1.ObjectMeta{Name: "example--" + key},
		Spec:       DomainRecordSpec{Name: "example", TTL: int32Ptr(60), Target: DomainRecordTarget{DNS: &target}},
		Status:     DomainRecordStatus{Type: strings.ToUpper(key)},
	}
}

func TestValidate_ValueLimits(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		target DomainRecordTargetDNS
		// wantErr is the field of the expected error; empty means valid.
		wantErr string
	}{
		{name: "64 A values", key: "a", target: DomainRecordTargetDNS{A: manyIPv4(64)}},
		{name: "65 A values", key: "a", target: DomainRecordTargetDNS{A: manyIPv4(65)}, wantErr: "spec.target.dns"},
		// 4049 bytes in 16 quoted strings with a space between them are 4096 bytes.
		{name: "TXT value of 4096 bytes in zone file form", key: "txt", target: DomainRecordTargetDNS{TXT: []string{strings.Repeat("x", 4049)}}},
		{name: "TXT value of 4097 bytes in zone file form", key: "txt", target: DomainRecordTargetDNS{TXT: []string{"a", strings.Repeat("x", 4050)}}, wantErr: "spec.target.dns.txt[1]"},
		{name: "DKIM value with escaped quotes", key: "dkim", target: DomainRecordTargetDNS{DKIM: []string{strings.Repeat(`"`, 2040)}}, wantErr: "spec.target.dns.dkim[0]"},
		{name: "SPF value with bytes that are not ASCII", key: "spf", target: DomainRecordTargetDNS{SPF: []string{strings.Repeat("é", 512)}}, wantErr: "spec.target.dns.spf[0]"},
		// The quoted form of U+200B is the 6 bytes \u200b, and 5 of them stay.
		{name: "TXT value with a rune that is not printable", key: "txt", target: DomainRecordTargetDNS{TXT: []string{strings.Repeat("x", 4040) + "\u200b"}}},
		{name: "TXT value with a new line", key: "txt", target: DomainRecordTargetDNS{TXT: []string{strings.Repeat("x", 4048) + "\n"}}},
		{name: "DMARC value of 4096 bytes in zone file form", key: "dmarc", target: DomainRecordTargetDNS{DMARC: []string{strings.Repeat("x", 4049)}}},
		{name: "MX value of 4096 bytes", key: "mx", target: DomainRecordTargetDNS{MX: []string{"10 " + strings.Repeat("m", 4093)}}},
		{name: "MX value of 4097 bytes", key: "mx", target: DomainRecordTargetDNS{MX: []string{"10 " + strings.Repeat("m", 4094)}}, wantErr: "spec.target.dns.mx[0]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := dnsDomainRecord(tt.key, tt.target).Validate(context.Background())
			if tt.wantErr == "" {
				assert.Empty(t, errs)
				return
			}
			require.Len(t, errs, 1, "errors: %v", errs)
			assert.Equal(t, tt.wantErr, errs[0].Field)
		})
	}
}

func TestValidateUpdate_ValueLimits(t *testing.T) {
	tests := []struct {
		name     string
		old, new DomainRecordTargetDNS
		ttl      int32
		wantErr  bool
	}{
		{name: "record over the limit with the same values", old: DomainRecordTargetDNS{A: manyIPv4(65)}, new: DomainRecordTargetDNS{A: manyIPv4(65)}, ttl: 300},
		{name: "record over the limit with fewer values that are still over", old: DomainRecordTargetDNS{A: manyIPv4(66)}, new: DomainRecordTargetDNS{A: manyIPv4(65)}, ttl: 60, wantErr: true},
		{name: "record over the limit with values under the limit", old: DomainRecordTargetDNS{A: manyIPv4(66)}, new: DomainRecordTargetDNS{A: manyIPv4(64)}, ttl: 60},
		{name: "record under the limit with values over the limit", old: DomainRecordTargetDNS{A: manyIPv4(1)}, new: DomainRecordTargetDNS{A: manyIPv4(65)}, ttl: 60, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updated := dnsDomainRecord("a", tt.new)
			updated.Spec.TTL = int32Ptr(tt.ttl)
			errs := updated.ValidateUpdate(context.Background(), dnsDomainRecord("a", tt.old))
			if !tt.wantErr {
				assert.Empty(t, errs)
				return
			}
			require.Len(t, errs, 1, "errors: %v", errs)
			assert.Equal(t, "spec.target.dns", errs[0].Field)
		})
	}
}
