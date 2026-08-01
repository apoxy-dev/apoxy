// SPDX-License-Identifier: AGPL-3.0-only

package builder

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

// tracksGeneration decides, per resource, whether metadata.generation is real
// or permanently zero. Getting it wrong is silent: a zero generation makes
// GenerationChangedPredicate drop every update rather than only status-only
// ones.
func TestServerTracksGeneration(t *testing.T) {
	svc := &computev1alpha1.Service{}
	backend := &corev1alpha.Backend{}

	cases := []struct {
		name        string
		build       func() *Server
		wantService bool
		wantBackend bool
	}{
		{
			name:  "off by default",
			build: NewServerBuilder,
		},
		{
			name: "per-resource opt-in covers only that resource",
			build: func() *Server {
				return NewServerBuilder().WithGenerationTrackingFor(svc)
			},
			wantService: true,
		},
		{
			name: "server-wide switch covers every resource",
			build: func() *Server {
				return NewServerBuilder().WithGenerationTracking()
			},
			wantService: true,
			wantBackend: true,
		},
		{
			name: "multiple resources in one call",
			build: func() *Server {
				return NewServerBuilder().WithGenerationTrackingFor(svc, backend)
			},
			wantService: true,
			wantBackend: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.build()
			if got := s.tracksGeneration(svc); got != tc.wantService {
				t.Errorf("tracksGeneration(Service) = %v, want %v", got, tc.wantService)
			}
			if got := s.tracksGeneration(backend); got != tc.wantBackend {
				t.Errorf("tracksGeneration(Backend) = %v, want %v", got, tc.wantBackend)
			}
		})
	}
}

// The opt-in is consulted when a resource is registered, so callers must not
// have to order WithGenerationTrackingFor against WithResourceAndStorage.
// defaultResources() already carries one load-bearing ordering rule; a second
// invisible one would be a trap.
func TestGenerationTrackingForIsOrderIndependent(t *testing.T) {
	cases := []struct {
		name  string
		build func(*computev1alpha1.Service) *Server
	}{
		{
			name: "opt-in before registration",
			build: func(svc *computev1alpha1.Service) *Server {
				return NewServerBuilder().
					WithGenerationTrackingFor(svc).
					WithResourceAndStorage(svc, nil)
			},
		},
		{
			name: "opt-in after registration",
			build: func(svc *computev1alpha1.Service) *Server {
				return NewServerBuilder().
					WithResourceAndStorage(svc, nil).
					WithGenerationTrackingFor(svc)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &computev1alpha1.Service{}
			if s := tc.build(svc); !s.tracksGeneration(svc) {
				t.Fatalf("tracksGeneration(%s) = false, want true", svc.GetGroupVersionResource())
			}
		})
	}
}

func TestDefaultStrategyPrepareForCreate(t *testing.T) {
	cases := []struct {
		name            string
		trackGeneration bool
		want            int64
	}{
		{name: "tracked seeds generation 1", trackGeneration: true, want: 1},
		{name: "untracked leaves generation zero", trackGeneration: false, want: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := &defaultStrategy{trackGeneration: tc.trackGeneration}
			svc := &computev1alpha1.Service{}

			strategy.PrepareForCreate(context.Background(), svc)

			if got := svc.Generation; got != tc.want {
				t.Errorf("Generation = %d, want %d", got, tc.want)
			}
		})
	}
}

// A spec change must bump; anything else must not. The "labels only" row is
// the whole point of the predicate this feeds — the minting reconciler writes
// its own status, and a bump there would make it re-enqueue itself forever.
func TestDefaultStrategyPrepareForUpdate(t *testing.T) {
	withSpec := func(gen int64, liveRevision string) *computev1alpha1.Service {
		svc := &computev1alpha1.Service{}
		svc.Generation = gen
		svc.Spec.LiveRevision = liveRevision
		return svc
	}

	cases := []struct {
		name            string
		trackGeneration bool
		old             *computev1alpha1.Service
		mutate          func(*computev1alpha1.Service)
		want            int64
	}{
		{
			name:            "spec change bumps",
			trackGeneration: true,
			old:             withSpec(1, "api-v1"),
			mutate:          func(s *computev1alpha1.Service) { s.Spec.LiveRevision = "api-v2" },
			want:            2,
		},
		{
			name:            "identical spec does not bump",
			trackGeneration: true,
			old:             withSpec(1, "api-v1"),
			mutate:          func(s *computev1alpha1.Service) {},
			want:            1,
		},
		{
			name:            "labels only does not bump",
			trackGeneration: true,
			old:             withSpec(1, "api-v1"),
			mutate: func(s *computev1alpha1.Service) {
				s.Labels = map[string]string{"team": "compute"}
			},
			want: 1,
		},
		{
			name:            "untracked never bumps",
			trackGeneration: false,
			old:             withSpec(0, "api-v1"),
			mutate:          func(s *computev1alpha1.Service) { s.Spec.LiveRevision = "api-v2" },
			want:            0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := &defaultStrategy{trackGeneration: tc.trackGeneration}
			updated := tc.old.DeepCopy()
			tc.mutate(updated)

			strategy.PrepareForUpdate(context.Background(), updated, tc.old)

			if got := updated.Generation; got != tc.want {
				t.Errorf("Generation = %d, want %d", got, tc.want)
			}
		})
	}
}

// specChanged reaches Spec by reflection, so it has to degrade safely on
// types that don't follow the `Spec <Kind>Spec` convention rather than panic
// or report a spurious change.
func TestSpecChanged(t *testing.T) {
	cases := []struct {
		name   string
		newObj runtime.Object
		oldObj runtime.Object
		want   bool
	}{
		{
			name:   "differing spec",
			newObj: &computev1alpha1.Service{Spec: computev1alpha1.ServiceSpec{LiveRevision: "api-v2"}},
			oldObj: &computev1alpha1.Service{Spec: computev1alpha1.ServiceSpec{LiveRevision: "api-v1"}},
			want:   true,
		},
		{
			name:   "identical spec",
			newObj: &computev1alpha1.Service{Spec: computev1alpha1.ServiceSpec{LiveRevision: "api-v1"}},
			oldObj: &computev1alpha1.Service{Spec: computev1alpha1.ServiceSpec{LiveRevision: "api-v1"}},
			want:   false,
		},
		{
			name:   "type without a Spec field",
			newObj: &metav1.Status{Message: "a"},
			oldObj: &metav1.Status{Message: "b"},
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := specChanged(tc.newObj, tc.oldObj); got != tc.want {
				t.Errorf("specChanged() = %v, want %v", got, tc.want)
			}
		})
	}
}
