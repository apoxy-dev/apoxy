package v1alpha2

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestProxyConvertToTable(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()

	tests := []struct {
		name        string
		proxy       *Proxy
		noHeaders   bool
		wantColumns int
		wantRows    int
	}{
		{
			name: "basic proxy with default provider",
			proxy: &Proxy{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "test-proxy",
					CreationTimestamp: now,
				},
				Spec: ProxySpec{},
				Status: ProxyStatus{
					Replicas: []*ProxyReplicaStatus{
						{Name: "replica-1"},
						{Name: "replica-2"},
					},
				},
			},
			noHeaders:   false,
			wantColumns: 5,
			wantRows:    1,
		},
		{
			name: "proxy with kubernetes provider and telemetry",
			proxy: &Proxy{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "k8s-proxy",
					CreationTimestamp: now,
				},
				Spec: ProxySpec{
					Provider: InfraProviderKubernetes,
					Telemetry: &ProxyTelementry{
						Tracing: &ProxyTracing{
							Enabled: true,
						},
						ContentLogs: &ProxyContentLogs{
							RequestBodyEnabled: true,
						},
					},
				},
				Status: ProxyStatus{
					Replicas: []*ProxyReplicaStatus{
						{Name: "replica-1"},
					},
				},
			},
			noHeaders:   false,
			wantColumns: 5,
			wantRows:    1,
		},
		{
			name: "proxy with no headers option",
			proxy: &Proxy{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "no-headers-proxy",
					CreationTimestamp: now,
				},
				Spec: ProxySpec{
					Provider: InfraProviderUnmanaged,
				},
			},
			noHeaders:   true,
			wantColumns: 0,
			wantRows:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &metav1.TableOptions{
				NoHeaders: tt.noHeaders,
			}

			table, err := tt.proxy.ConvertToTable(ctx, opts)
			if err != nil {
				t.Errorf("ConvertToTable() error = %v", err)
				return
			}

			if !tt.noHeaders && len(table.ColumnDefinitions) != tt.wantColumns {
				t.Errorf("ConvertToTable() columns = %v, want %v", len(table.ColumnDefinitions), tt.wantColumns)
			}

			if len(table.Rows) != tt.wantRows {
				t.Errorf("ConvertToTable() rows = %v, want %v", len(table.Rows), tt.wantRows)
			}

			// Verify the row contains expected number of cells (cells are always present, even with NoHeaders)
			if len(table.Rows) > 0 && len(table.Rows[0].Cells) != 5 {
				t.Errorf("ConvertToTable() cells = %v, want %v", len(table.Rows[0].Cells), 5)
			}

			// Verify the object is included in the row
			if len(table.Rows) > 0 && table.Rows[0].Object.Object == nil {
				t.Error("ConvertToTable() row object is nil")
			}
		})
	}
}

func TestProxyListConvertToTable(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()

	tests := []struct {
		name        string
		proxyList   *ProxyList
		noHeaders   bool
		wantColumns int
		wantRows    int
	}{
		{
			name: "empty list",
			proxyList: &ProxyList{
				ListMeta: metav1.ListMeta{
					ResourceVersion: "1",
				},
				Items: []Proxy{},
			},
			noHeaders:   false,
			wantColumns: 5,
			wantRows:    0,
		},
		{
			name: "list with multiple proxies",
			proxyList: &ProxyList{
				ListMeta: metav1.ListMeta{
					ResourceVersion: "2",
				},
				Items: []Proxy{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:              "proxy-1",
							CreationTimestamp: now,
						},
						Spec: ProxySpec{
							Provider: InfraProviderCloud,
						},
						Status: ProxyStatus{
							Replicas: []*ProxyReplicaStatus{
								{Name: "replica-1"},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:              "proxy-2",
							CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
						},
						Spec: ProxySpec{
							Provider: InfraProviderKubernetes,
							Telemetry: &ProxyTelementry{
								AccessLogs: &ProxyAccessLogs{
									JSON: map[string]string{
										"custom": "%REQ(X-CUSTOM)%",
									},
								},
							},
						},
						Status: ProxyStatus{
							Replicas: []*ProxyReplicaStatus{
								{Name: "replica-1"},
								{Name: "replica-2"},
								{Name: "replica-3"},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:              "proxy-3",
							CreationTimestamp: metav1.NewTime(now.Add(-24 * time.Hour)),
						},
						Spec: ProxySpec{
							Provider: InfraProviderUnmanaged,
							Telemetry: &ProxyTelementry{
								ThirdPartySinks: &ThirdPartySinks{
									DatadogLogs: &APIKey{
										Key: "dd-key",
									},
								},
							},
						},
					},
				},
			},
			noHeaders:   false,
			wantColumns: 5,
			wantRows:    3,
		},
		{
			name: "list with continuation",
			proxyList: &ProxyList{
				ListMeta: metav1.ListMeta{
					ResourceVersion:    "3",
					Continue:           "continue-token",
					RemainingItemCount: func() *int64 { v := int64(10); return &v }(),
				},
				Items: []Proxy{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:              "proxy-paginated",
							CreationTimestamp: now,
						},
					},
				},
			},
			noHeaders:   false,
			wantColumns: 5,
			wantRows:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &metav1.TableOptions{
				NoHeaders: tt.noHeaders,
			}

			table, err := tt.proxyList.ConvertToTable(ctx, opts)
			if err != nil {
				t.Errorf("ConvertToTable() error = %v", err)
				return
			}

			if !tt.noHeaders && len(table.ColumnDefinitions) != tt.wantColumns {
				t.Errorf("ConvertToTable() columns = %v, want %v", len(table.ColumnDefinitions), tt.wantColumns)
			}

			if len(table.Rows) != tt.wantRows {
				t.Errorf("ConvertToTable() rows = %v, want %v", len(table.Rows), tt.wantRows)
			}

			// Verify list metadata is preserved
			if table.ResourceVersion != tt.proxyList.ResourceVersion {
				t.Errorf("ConvertToTable() ResourceVersion = %v, want %v", table.ResourceVersion, tt.proxyList.ResourceVersion)
			}

			if table.Continue != tt.proxyList.Continue {
				t.Errorf("ConvertToTable() Continue = %v, want %v", table.Continue, tt.proxyList.Continue)
			}

			if table.RemainingItemCount != tt.proxyList.RemainingItemCount {
				t.Errorf("ConvertToTable() RemainingItemCount = %v, want %v", table.RemainingItemCount, tt.proxyList.RemainingItemCount)
			}
		})
	}
}

func TestGetProxyProvider(t *testing.T) {
	tests := []struct {
		name     string
		proxy    *Proxy
		expected string
	}{
		{
			name:     "empty provider defaults to cloud",
			proxy:    &Proxy{Spec: ProxySpec{}},
			expected: "cloud",
		},
		{
			name:     "cloud provider",
			proxy:    &Proxy{Spec: ProxySpec{Provider: InfraProviderCloud}},
			expected: "cloud",
		},
		{
			name:     "kubernetes provider",
			proxy:    &Proxy{Spec: ProxySpec{Provider: InfraProviderKubernetes}},
			expected: "kubernetes",
		},
		{
			name:     "unmanaged provider",
			proxy:    &Proxy{Spec: ProxySpec{Provider: InfraProviderUnmanaged}},
			expected: "unmanaged",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getProxyProvider(tt.proxy)
			if result != tt.expected {
				t.Errorf("getProxyProvider() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetProxyTelemetryInfo(t *testing.T) {
	tests := []struct {
		name     string
		proxy    *Proxy
		expected string
	}{
		{
			name:     "nil telemetry",
			proxy:    &Proxy{Spec: ProxySpec{}},
			expected: "Default",
		},
		{
			name: "empty telemetry",
			proxy: &Proxy{Spec: ProxySpec{
				Telemetry: &ProxyTelementry{},
			}},
			expected: "Default",
		},
		{
			name: "access logs enabled",
			proxy: &Proxy{Spec: ProxySpec{
				Telemetry: &ProxyTelementry{
					AccessLogs: &ProxyAccessLogs{
						JSON: map[string]string{"key": "value"},
					},
				},
			}},
			expected: "[AccessLogs]",
		},
		{
			name: "content logs enabled",
			proxy: &Proxy{Spec: ProxySpec{
				Telemetry: &ProxyTelementry{
					ContentLogs: &ProxyContentLogs{
						RequestBodyEnabled: true,
					},
				},
			}},
			expected: "[ContentLogs]",
		},
		{
			name: "tracing enabled",
			proxy: &Proxy{Spec: ProxySpec{
				Telemetry: &ProxyTelementry{
					Tracing: &ProxyTracing{
						Enabled: true,
					},
				},
			}},
			expected: "[Tracing]",
		},
		{
			name: "third party sinks",
			proxy: &Proxy{Spec: ProxySpec{
				Telemetry: &ProxyTelementry{
					ThirdPartySinks: &ThirdPartySinks{
						DatadogLogs: &APIKey{Key: "key"},
					},
				},
			}},
			expected: "[3rdParty]",
		},
		{
			name: "multiple features",
			proxy: &Proxy{Spec: ProxySpec{
				Telemetry: &ProxyTelementry{
					AccessLogs: &ProxyAccessLogs{
						JSON: map[string]string{"key": "value"},
					},
					Tracing: &ProxyTracing{
						Enabled: true,
					},
					ThirdPartySinks: &ThirdPartySinks{
						AxiomLogs: &APIKey{Key: "key"},
					},
				},
			}},
			expected: "[AccessLogs Tracing 3rdParty]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getProxyTelemetryInfo(tt.proxy)
			if result != tt.expected {
				t.Errorf("getProxyTelemetryInfo() = %v, want %v", result, tt.expected)
			}
		})
	}
}
