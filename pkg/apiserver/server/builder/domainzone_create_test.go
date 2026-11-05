package builder

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	corev1alpha3 "github.com/apoxy-dev/apoxy/api/core/v1alpha3"
)

// TestDomainZoneCreateDropsStatus checks that a DomainZone created in each
// served version is stored with no status: a client cannot set the phase or
// the registration of a new zone.
func TestDomainZoneCreateDropsStatus(t *testing.T) {
	registeredAt := metav1.Now()
	cases := []struct {
		name string
		// storage returns the zone of the request in the storage version.
		storage func(t *testing.T) *corev1alpha3.DomainZone
	}{
		{
			name: "v1alpha",
			storage: func(t *testing.T) *corev1alpha3.DomainZone {
				return toStorage(t, &corev1alpha.DomainZone{
					ObjectMeta: metav1.ObjectMeta{Name: "example.com"},
					Spec:       corev1alpha.DomainZoneSpec{RegistrationConfig: &corev1alpha.RegistrationConfig{RegistrationPeriodYears: 1}},
					Status: corev1alpha.DomainZoneStatus{
						Phase:              corev1alpha.DomainZonePhasePendingNameservers,
						RegistrationStatus: &corev1alpha.RegistrationStatus{RegisteredAt: &registeredAt},
						Claim:              &corev1alpha.ZoneClaimStatus{Held: true},
					},
				})
			},
		},
		{
			name: "v1alpha2",
			storage: func(t *testing.T) *corev1alpha3.DomainZone {
				return toStorage(t, &corev1alpha2.DomainZone{
					ObjectMeta: metav1.ObjectMeta{Name: "example.com"},
					Spec:       corev1alpha2.DomainZoneSpec{RegistrationConfig: &corev1alpha2.RegistrationConfig{RegistrationPeriodYears: 1}},
					Status: corev1alpha2.DomainZoneStatus{
						Phase:              corev1alpha2.DomainZonePhasePendingNameservers,
						RegistrationStatus: &corev1alpha2.RegistrationStatus{RegisteredAt: &registeredAt},
						Claim:              &corev1alpha2.ZoneClaimStatus{Held: true},
					},
				})
			},
		},
		{
			name: "v1alpha3",
			storage: func(*testing.T) *corev1alpha3.DomainZone {
				return &corev1alpha3.DomainZone{
					ObjectMeta: metav1.ObjectMeta{Name: "example.com"},
					Spec:       corev1alpha3.DomainZoneSpec{RegistrationConfig: &corev1alpha3.RegistrationConfig{RegistrationPeriodYears: 1}},
					Status: corev1alpha3.DomainZoneStatus{
						Phase:              corev1alpha3.DomainZonePhasePendingNameservers,
						RegistrationStatus: &corev1alpha3.RegistrationStatus{RegisteredAt: &registeredAt},
						Claim:              &corev1alpha3.ZoneClaimStatus{Held: true},
					},
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zone := tc.storage(t)
			if zone.Status.Phase == "" {
				t.Fatal("the zone of the request has no status after the conversion")
			}

			(&defaultStrategy{}).PrepareForCreate(context.Background(), zone)

			if zone.Status.Phase != "" || zone.Status.RegistrationStatus != nil || zone.Status.Claim != nil {
				t.Errorf("status after create = %+v, want none", zone.Status)
			}
			if zone.Spec.RegistrationConfig == nil {
				t.Error("spec.registrationConfig is gone, want it kept")
			}
		})
	}
}

// toStorage converts a zone of an older version to the storage version.
func toStorage(t *testing.T, zone interface {
	ConvertToStorageVersion(runtime.Object) error
}) *corev1alpha3.DomainZone {
	t.Helper()
	storage := &corev1alpha3.DomainZone{}
	if err := zone.ConvertToStorageVersion(storage); err != nil {
		t.Fatalf("failed to convert the zone: %v", err)
	}
	return storage
}
