package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// svc builds a valid VPCService that each case degrades in one way.
func svc(mutate func(*VPCService)) *VPCService {
	s := &VPCService{
		ObjectMeta: metav1.ObjectMeta{Name: "payments"},
		Spec: VPCServiceSpec{
			NetworkRef: VPCNetworkRef{Name: "corp"},
			Selector:   &metav1.LabelSelector{MatchLabels: map[string]string{"app": "payments"}},
		},
	}
	if mutate != nil {
		mutate(s)
	}
	return s
}

func TestVPCServiceValidate(t *testing.T) {
	cases := []struct {
		name     string
		svc      *VPCService
		wantErrs []string // substrings, one per expected field error
	}{
		{
			name: "valid",
			svc:  svc(nil),
		},
		{
			name:     "missing selector",
			svc:      svc(func(s *VPCService) { s.Spec.Selector = nil }),
			wantErrs: []string{"spec.selector: Required value"},
		},
		{
			name:     "empty selector",
			svc:      svc(func(s *VPCService) { s.Spec.Selector = &metav1.LabelSelector{} }),
			wantErrs: []string{"spec.selector", "every Tunnel in the network a member"},
		},
		{
			name: "selector with an unparseable expression",
			svc: svc(func(s *VPCService) {
				s.Spec.Selector = &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{Key: "app", Operator: "Bogus"},
					},
				}
			}),
			wantErrs: []string{"spec.selector"},
		},
		{
			name: "matchExpressions-only selector is valid",
			svc: svc(func(s *VPCService) {
				s.Spec.Selector = &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{Key: LabelNetwork, Operator: metav1.LabelSelectorOpExists},
					},
				}
			}),
		},
		{
			name:     "missing networkRef",
			svc:      svc(func(s *VPCService) { s.Spec.NetworkRef.Name = "" }),
			wantErrs: []string{"spec.networkRef.name: Required value"},
		},
		{
			name:     "malformed hostname",
			svc:      svc(func(s *VPCService) { s.Spec.Hostname = "Not_A_Label" }),
			wantErrs: []string{"spec.hostname"},
		},
		{
			name: "every shape error is reported at once",
			svc: svc(func(s *VPCService) {
				s.Spec.NetworkRef.Name = ""
				s.Spec.Selector = nil
				s.Spec.Hostname = "Not_A_Label"
			}),
			wantErrs: []string{"spec.networkRef.name", "spec.selector", "spec.hostname"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := tc.svc.Validate(context.Background())
			if len(tc.wantErrs) == 0 {
				assert.Empty(t, errs)
				return
			}
			require.NotEmpty(t, errs)
			for _, want := range tc.wantErrs {
				assert.Contains(t, errs.ToAggregate().Error(), want)
			}
		})
	}
}

func TestVPCServiceValidateUpdate(t *testing.T) {
	// An object stored before the selector rule tightened. Its status still
	// has to be writable, or the reconciler spins instead of reporting the
	// problem in Ready.
	stored := svc(func(s *VPCService) { s.Spec.Selector = nil })

	cases := []struct {
		name    string
		old     *VPCService
		updated *VPCService
		wantErr bool
	}{
		{
			name:    "spec-preserving update of a legacy object is ratcheted through",
			old:     stored,
			updated: stored.DeepCopy(),
		},
		{
			name: "metadata-only edit of a legacy object is allowed",
			old:  stored,
			updated: svc(func(s *VPCService) {
				s.Spec.Selector = nil
				s.Labels = map[string]string{"team": "payments"}
			}),
		},
		{
			name: "delete of a legacy object is allowed",
			old:  stored,
			updated: svc(func(s *VPCService) {
				s.Spec.Selector = nil
				now := metav1.Now()
				s.DeletionTimestamp = &now
				s.Finalizers = []string{"vpc.apoxy.dev/finalizer"}
			}),
		},
		{
			name: "spec edit must make the object valid",
			old:  stored,
			updated: svc(func(s *VPCService) {
				s.Spec.Selector = nil
				s.Spec.Hostname = "payments-v2"
			}),
			wantErr: true,
		},
		{
			name:    "spec edit fixing the selector is accepted",
			old:     stored,
			updated: svc(func(s *VPCService) { s.Spec.Hostname = "payments-v2" }),
		},
		{
			name:    "a valid object going invalid is rejected",
			old:     svc(nil),
			updated: svc(func(s *VPCService) { s.Spec.Selector = &metav1.LabelSelector{} }),
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := tc.updated.ValidateUpdate(context.Background(), tc.old)
			if tc.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestVPCServiceEndpointHasUsableAddress(t *testing.T) {
	cases := []struct {
		name  string
		addrs []string
		want  bool
	}{
		{name: "no addresses", addrs: nil},
		{name: "empty address", addrs: []string{""}},
		{name: "garbage only", addrs: []string{"not-an-address"}},
		{name: "overlay prefix", addrs: []string{"fd61::a/96"}, want: true},
		{name: "plain address", addrs: []string{"fd61::a"}, want: true},
		{name: "garbage plus a usable one", addrs: []string{"nope", "100.64.0.1/32"}, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := VPCServiceEndpoint{
				TunnelRef: TunnelRef{Name: "t-a"},
				Addresses: tc.addrs,
			}
			assert.Equal(t, tc.want, ep.HasUsableAddress())
		})
	}
}
