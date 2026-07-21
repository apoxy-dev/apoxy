package v1alpha1

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestConvertToTable(t *testing.T) {
	created := metav1.NewTime(time.Now().Add(-5 * time.Minute))

	cases := []struct {
		name     string
		obj      interface {
			ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error)
		}
		options   runtime.Object
		columns   []string
		rows      int
		wantCells []interface{}
	}{
		{
			name: "vpcnetwork",
			obj: &VPCNetwork{
				ObjectMeta: metav1.ObjectMeta{Name: "corp", CreationTimestamp: created},
				Spec:       VPCNetworkSpec{EgressGateway: &EgressGatewaySpec{Enabled: true}},
				Status:     VPCNetworkStatus{OverlayCIDR: "fd00:1234::/72"},
			},
			columns:   []string{"Name", "Egress", "CIDR", "Age"},
			rows:      1,
			wantCells: []interface{}{"corp", "Enabled", "fd00:1234::/72", "5m"},
		},
		{
			name: "vpcnetwork egress disabled by default",
			obj: &VPCNetwork{
				ObjectMeta: metav1.ObjectMeta{Name: "corp", CreationTimestamp: created},
			},
			columns:   []string{"Name", "Egress", "CIDR", "Age"},
			rows:      1,
			wantCells: []interface{}{"corp", "Disabled", "", "5m"},
		},
		{
			name: "vpcservice",
			obj: &VPCService{
				ObjectMeta: metav1.ObjectMeta{Name: "payments", CreationTimestamp: created},
				Spec: VPCServiceSpec{
					NetworkRef: VPCNetworkRef{Name: "corp"},
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "payments"},
					},
				},
				Status: VPCServiceStatus{
					Endpoints: []VPCServiceEndpoint{
						{TunnelRef: TunnelRef{Name: "conn-1"}, Addresses: []string{"fd00::1/96"}},
						{TunnelRef: TunnelRef{Name: "conn-2"}, Addresses: []string{"fd00::2/96"}},
					},
				},
			},
			columns:   []string{"Name", "Network", "Selector", "Endpoints", "Age"},
			rows:      1,
			wantCells: []interface{}{"payments", "corp", "app=payments", "2", "5m"},
		},
		{
			name: "vpcservice nil selector",
			obj: &VPCService{
				ObjectMeta: metav1.ObjectMeta{Name: "payments", CreationTimestamp: created},
				Spec:       VPCServiceSpec{NetworkRef: VPCNetworkRef{Name: "corp"}},
			},
			columns:   []string{"Name", "Network", "Selector", "Endpoints", "Age"},
			rows:      1,
			wantCells: []interface{}{"payments", "corp", "<none>", "0", "5m"},
		},
		{
			name: "relay",
			obj: &Relay{
				ObjectMeta: metav1.ObjectMeta{Name: "relay-0", CreationTimestamp: created},
				Spec:       RelaySpec{Addresses: []string{"1.2.3.4:6081", "[::1]:6081"}},
				Status:     RelayStatus{Ready: true},
			},
			columns:   []string{"Name", "Addresses", "Ready", "Age"},
			rows:      1,
			wantCells: []interface{}{"relay-0", "1.2.3.4:6081,[::1]:6081", "True", "5m"},
		},
		{
			name: "tunnel",
			obj: &Tunnel{
				ObjectMeta: metav1.ObjectMeta{Name: "conn-1", CreationTimestamp: created},
				Spec: TunnelSpec{
					NetworkRef: VPCNetworkRef{Name: "corp"},
					RelayRef:   RelayRef{Name: "relay-0"},
				},
				Status: TunnelStatus{Addresses: []string{"fd00::1/96", "100.64.0.1/32"}},
			},
			columns:   []string{"Name", "Network", "Relay", "Addresses", "Age"},
			rows:      1,
			wantCells: []interface{}{"conn-1", "corp", "relay-0", "fd00::1/96,100.64.0.1/32", "5m"},
		},
		{
			name: "list carries rows and metadata",
			obj: &RelayList{
				ListMeta: metav1.ListMeta{ResourceVersion: "42"},
				Items: []Relay{
					{ObjectMeta: metav1.ObjectMeta{Name: "relay-0", CreationTimestamp: created}},
					{ObjectMeta: metav1.ObjectMeta{Name: "relay-1", CreationTimestamp: created}},
				},
			},
			columns: []string{"Name", "Addresses", "Ready", "Age"},
			rows:    2,
		},
		{
			name: "no headers",
			obj: &VPCNetwork{
				ObjectMeta: metav1.ObjectMeta{Name: "corp", CreationTimestamp: created},
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
		list := &RelayList{ListMeta: metav1.ListMeta{ResourceVersion: "42", Continue: "next"}}
		table, err := list.ConvertToTable(context.Background(), nil)
		require.NoError(t, err)
		require.Equal(t, "42", table.ResourceVersion)
		require.Equal(t, "next", table.Continue)
	})
}
