package v1alpha1

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestConvertToTable(t *testing.T) {
	created := metav1.NewTime(time.Now().Add(-5 * time.Minute))
	sectionName := gwapiv1.SectionName("https")

	cases := []struct {
		name string
		obj  interface {
			ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error)
		}
		options   runtime.Object
		columns   []string
		rows      int
		wantCells []interface{}
	}{
		{
			name: "service ready",
			obj: &Service{
				ObjectMeta: metav1.ObjectMeta{Name: "checkout", CreationTimestamp: created},
				Status: ServiceStatus{
					Conditions: []metav1.Condition{{
						Type:   ConditionReady,
						Status: metav1.ConditionTrue,
					}},
				},
			},
			columns:   []string{"Name", "Status", "Age"},
			rows:      1,
			wantCells: []interface{}{"checkout", "Ready", "5m"},
		},
		{
			name: "service not ready shows reason",
			obj: &Service{
				ObjectMeta: metav1.ObjectMeta{Name: "checkout", CreationTimestamp: created},
				Status: ServiceStatus{
					Conditions: []metav1.Condition{{
						Type:   ConditionReady,
						Status: metav1.ConditionFalse,
						Reason: "RevisionNotServing",
					}},
				},
			},
			columns:   []string{"Name", "Status", "Age"},
			rows:      1,
			wantCells: []interface{}{"checkout", "RevisionNotServing", "5m"},
		},
		{
			name: "service unreconciled",
			obj: &Service{
				ObjectMeta: metav1.ObjectMeta{Name: "checkout", CreationTimestamp: created},
			},
			columns:   []string{"Name", "Status", "Age"},
			rows:      1,
			wantCells: []interface{}{"checkout", "Pending", "5m"},
		},
		{
			name: "servicerevision digest shortened",
			obj: &ServiceRevision{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "checkout-3f9a1c7b2d",
					CreationTimestamp: created,
					OwnerReferences:   []metav1.OwnerReference{{Kind: "Service", Name: "checkout"}},
				},
				Spec: ServiceRevisionSpec{
					Bundle: BundleRef{Digest: "sha256:0123456789abcdef0123456789abcdef"},
				},
				Status: ServiceStatus{
					Conditions: []metav1.Condition{{Type: ConditionReady, Status: metav1.ConditionTrue}},
				},
			},
			columns:   []string{"Name", "Service", "Digest", "Ready", "Age"},
			rows:      1,
			wantCells: []interface{}{"checkout-3f9a1c7b2d", "checkout", "sha256:0123456789ab", "True", "5m"},
		},
		{
			name: "servicerevision tag fallback, no owner",
			obj: &ServiceRevision{
				ObjectMeta: metav1.ObjectMeta{Name: "orphan", CreationTimestamp: created},
				Spec:       ServiceRevisionSpec{Bundle: BundleRef{Tag: "v3"}},
			},
			columns:   []string{"Name", "Service", "Digest", "Ready", "Age"},
			rows:      1,
			wantCells: []interface{}{"orphan", "-", "v3", "Unknown", "5m"},
		},
		{
			name: "egressgateway",
			obj: &EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "default", CreationTimestamp: created},
				Spec: EgressGatewaySpec{
					DefaultPolicy: EgressPolicyDenyAll,
					Listeners:     []EgressListener{{Name: "https"}, {Name: "dns"}},
				},
				Status: EgressGatewayStatus{
					Conditions: []metav1.Condition{{Type: EgressGatewayConditionReady, Status: metav1.ConditionTrue}},
				},
			},
			columns:   []string{"Name", "Default Policy", "Listeners", "Ready", "Age"},
			rows:      1,
			wantCells: []interface{}{"default", "deny-all", 2, "True", "5m"},
		},
		{
			name: "egressgateway empty policy",
			obj: &EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "default", CreationTimestamp: created},
			},
			columns:   []string{"Name", "Default Policy", "Listeners", "Ready", "Age"},
			rows:      1,
			wantCells: []interface{}{"default", "-", 0, "Unknown", "5m"},
		},
		{
			name: "egressroute accepted by all parents",
			obj: &EgressRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-openai", CreationTimestamp: created},
				Spec: EgressRouteSpec{
					ParentRefs: []gwapiv1.ParentReference{
						{Name: "default", SectionName: &sectionName},
						{Name: "backup"},
					},
					Rules: []EgressRouteRule{
						{Matches: []EgressRouteMatch{{}, {}}},
						{Matches: []EgressRouteMatch{{}}},
					},
				},
				Status: EgressRouteStatus{
					Parents: []gwapiv1.RouteParentStatus{
						{Conditions: []metav1.Condition{{Type: ConditionAccepted, Status: metav1.ConditionTrue}}},
						{Conditions: []metav1.Condition{{Type: ConditionAccepted, Status: metav1.ConditionTrue}}},
					},
				},
			},
			columns:   []string{"Name", "Parents", "Matches", "Accepted", "Age"},
			rows:      1,
			wantCells: []interface{}{"allow-openai", "default:https,backup", 3, "True", "5m"},
		},
		{
			name: "egressroute rejected by one parent",
			obj: &EgressRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-openai", CreationTimestamp: created},
				Spec: EgressRouteSpec{
					ParentRefs: []gwapiv1.ParentReference{{Name: "default"}},
				},
				Status: EgressRouteStatus{
					Parents: []gwapiv1.RouteParentStatus{
						{Conditions: []metav1.Condition{{Type: ConditionAccepted, Status: metav1.ConditionTrue}}},
						{Conditions: []metav1.Condition{{Type: ConditionAccepted, Status: metav1.ConditionFalse}}},
					},
				},
			},
			columns:   []string{"Name", "Parents", "Matches", "Accepted", "Age"},
			rows:      1,
			wantCells: []interface{}{"allow-openai", "default", 0, "False", "5m"},
		},
		{
			name: "egressroute unreported",
			obj: &EgressRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-openai", CreationTimestamp: created},
			},
			columns:   []string{"Name", "Parents", "Matches", "Accepted", "Age"},
			rows:      1,
			wantCells: []interface{}{"allow-openai", "-", 0, "Unknown", "5m"},
		},
		{
			name: "list carries rows",
			obj: &ServiceList{
				ListMeta: metav1.ListMeta{ResourceVersion: "42"},
				Items: []Service{
					{ObjectMeta: metav1.ObjectMeta{Name: "a", CreationTimestamp: created}},
					{ObjectMeta: metav1.ObjectMeta{Name: "b", CreationTimestamp: created}},
				},
			},
			columns: []string{"Name", "Status", "Age"},
			rows:    2,
		},
		{
			name: "no headers",
			obj: &Service{
				ObjectMeta: metav1.ObjectMeta{Name: "checkout", CreationTimestamp: created},
			},
			options: &metav1.TableOptions{NoHeaders: true},
			columns: nil,
			rows:    1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			table, err := tc.obj.ConvertToTable(context.Background(), tc.options)
			require.NoError(t, err)

			var gotColumns []string
			for _, c := range table.ColumnDefinitions {
				gotColumns = append(gotColumns, c.Name)
			}
			require.Equal(t, tc.columns, gotColumns)
			require.Len(t, table.Rows, tc.rows)
			if tc.wantCells != nil {
				require.Equal(t, tc.wantCells, table.Rows[0].Cells)
			}
			for _, row := range table.Rows {
				require.NotNil(t, row.Object.Object)
			}
		})
	}

	t.Run("list metadata copied", func(t *testing.T) {
		list := &ServiceList{ListMeta: metav1.ListMeta{ResourceVersion: "42", Continue: "next"}}
		table, err := list.ConvertToTable(context.Background(), nil)
		require.NoError(t, err)
		require.Equal(t, "42", table.ResourceVersion)
		require.Equal(t, "next", table.Continue)
	})
}
