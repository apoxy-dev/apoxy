package v1alpha3

import (
	"context"
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

func strPtr(s string) *string { return &s }
