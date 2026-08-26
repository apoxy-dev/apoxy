package v1alpha1

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

func TestConvertToTable(t *testing.T) {
	snapMeta := SnapshotMeta{
		Timestamp: metav1.NewTime(time.Date(2026, 8, 20, 21, 0, 0, 0, time.UTC)),
		Window:    metav1.Duration{Duration: 24 * time.Hour},
	}
	snapMetrics := MetricsMap{
		MetricHTTPRequests: Measures{MeasureTotal: 1842113, MeasureStatus5xx: 3773},
		MetricHTTPLatency:  Measures{MeasureP99: 412},
	}

	cases := []struct {
		name string
		obj  interface {
			ConvertToTable(context.Context, runtime.Object) (*metav1.Table, error)
		}
		wantCols  int
		wantCells []interface{}
	}{
		{
			name: "metric",
			obj: &Metric{
				ObjectMeta: metav1.ObjectMeta{Name: "http.requests"},
				Spec:       MetricSpec{Type: MetricTypeCounter, Unit: ""},
				Status:     MetricStatus{Source: "http_1m"},
			},
			wantCols:  4,
			wantCells: []interface{}{"http.requests", "counter", "", "http_1m"},
		},
		{
			name: "metric source",
			obj: &MetricSource{
				ObjectMeta: metav1.ObjectMeta{Name: "http_1m"},
				Status: MetricSourceStatus{
					Granularity: "1m",
					Retention:   "400d",
					Fields:      []MetricSourceField{{Name: "bucket"}, {Name: "gateway"}},
				},
			},
			wantCols:  4,
			wantCells: []interface{}{"http_1m", "1m", "400d", "2"},
		},
		{
			name: "gateway snapshot",
			obj: &GatewayMetrics{
				ObjectMeta:   metav1.ObjectMeta{Name: "prod"},
				SnapshotMeta: snapMeta,
				Metrics:      snapMetrics,
			},
			wantCols:  5,
			wantCells: []interface{}{"prod", "24h0m0s", "1842113", "3773", "412"},
		},
		{
			name: "proxy snapshot with no evaluated recipes",
			obj: &ProxyMetrics{
				ObjectMeta:   metav1.ObjectMeta{Name: "default"},
				SnapshotMeta: snapMeta,
			},
			wantCols:  5,
			wantCells: []interface{}{"default", "24h0m0s", "-", "-", "-"},
		},
		{
			name: "tunnel snapshot has no HTTP recipes to print",
			obj: &TunnelMetrics{
				ObjectMeta:   metav1.ObjectMeta{Name: "a1b2c3d4"},
				SnapshotMeta: snapMeta,
				Metrics:      MetricsMap{"network.bytes": Measures{"total": 4096}},
			},
			wantCols:  5,
			wantCells: []interface{}{"a1b2c3d4", "24h0m0s", "-", "-", "-"},
		},
		{
			name: "vpc network snapshot",
			obj: &VPCNetworkMetrics{
				ObjectMeta:   metav1.ObjectMeta{Name: "default"},
				SnapshotMeta: snapMeta,
				Metrics:      snapMetrics,
			},
			wantCols:  5,
			wantCells: []interface{}{"default", "24h0m0s", "1842113", "3773", "412"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			table, err := tc.obj.ConvertToTable(context.Background(), nil)
			if err != nil {
				t.Fatalf("ConvertToTable: %v", err)
			}
			if len(table.ColumnDefinitions) != tc.wantCols {
				t.Fatalf("columns = %d, want %d", len(table.ColumnDefinitions), tc.wantCols)
			}
			if len(table.Rows) != 1 {
				t.Fatalf("rows = %d, want 1", len(table.Rows))
			}
			cells := table.Rows[0].Cells
			if len(cells) != len(tc.wantCells) {
				t.Fatalf("cells = %v, want %v", cells, tc.wantCells)
			}
			for i := range cells {
				if cells[i] != tc.wantCells[i] {
					t.Errorf("cell %d = %v, want %v", i, cells[i], tc.wantCells[i])
				}
			}
		})
	}
}

func TestListConvertToTable(t *testing.T) {
	list := &MetricList{Items: []Metric{
		{ObjectMeta: metav1.ObjectMeta{Name: "http.requests"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "http.latency"}},
	}}
	table, err := list.ConvertToTable(context.Background(), nil)
	if err != nil {
		t.Fatalf("ConvertToTable: %v", err)
	}
	if len(table.Rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(table.Rows))
	}
}
