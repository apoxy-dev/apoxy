package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/printers"
)

func TestPrintProxyTable(t *testing.T) {
	now := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	ctx := context.Background()

	tests := []struct {
		name       string
		showLabels bool
		proxy      *corev1alpha2.Proxy
		wantOutput []string
	}{
		{
			name:       "single proxy without labels",
			showLabels: false,
			proxy: &corev1alpha2.Proxy{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "test-proxy",
					CreationTimestamp: now,
				},
				Spec: corev1alpha2.ProxySpec{
					Provider: "cloud",
				},
				Status: corev1alpha2.ProxyStatus{
					Replicas: []*corev1alpha2.ProxyReplicaStatus{
						{Name: "replica-1"},
						{Name: "replica-2"},
					},
				},
			},
			wantOutput: []string{
				"NAME",
				"PROVIDER",
				"STATUS",
				"test-proxy",
				"cloud",
				"Ready (2)",
			},
		},
		{
			name:       "single proxy with labels",
			showLabels: true,
			proxy: &corev1alpha2.Proxy{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "test-proxy-labels",
					CreationTimestamp: now,
					Labels: map[string]string{
						"env":  "prod",
						"team": "platform",
					},
				},
				Spec: corev1alpha2.ProxySpec{
					Provider: "unmanaged",
				},
				Status: corev1alpha2.ProxyStatus{
					Replicas: []*corev1alpha2.ProxyReplicaStatus{
						{Name: "replica-1"},
					},
				},
			},
			wantOutput: []string{
				"NAME",
				"PROVIDER",
				"STATUS",
				"LABELS",
				"test-proxy-labels",
				"unmanaged",
				"Ready (1)",
				"env=prod", // labels can be in any order
				"team=platform",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table, err := tt.proxy.ConvertToTable(ctx, &metav1.TableOptions{})
			if err != nil {
				t.Fatalf("ConvertToTable failed: %v", err)
			}

			if tt.showLabels {
				addLabelsColumnToTable(table)
			}

			var buf bytes.Buffer
			printer := printers.NewTablePrinter(printers.PrintOptions{})
			if err := printer.PrintObj(table, &buf); err != nil {
				t.Fatalf("PrintObj failed: %v", err)
			}

			output := buf.String()
			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("Output missing expected content %q\nGot:\n%s", want, output)
				}
			}
		})
	}
}

func TestPrintProxyListTable(t *testing.T) {
	now := metav1.NewTime(time.Now().Add(-2 * time.Hour))
	ctx := context.Background()

	proxyList := &corev1alpha2.ProxyList{
		Items: []corev1alpha2.Proxy{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "proxy-1",
					CreationTimestamp: now,
				},
				Spec: corev1alpha2.ProxySpec{
					Provider: "cloud",
				},
				Status: corev1alpha2.ProxyStatus{
					Replicas: []*corev1alpha2.ProxyReplicaStatus{
						{Name: "replica-1"},
						{Name: "replica-2"},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "proxy-2",
					CreationTimestamp: metav1.NewTime(time.Now().Add(-30 * time.Minute)),
					Labels: map[string]string{
						"env": "staging",
					},
				},
				Spec: corev1alpha2.ProxySpec{
					Provider: "unmanaged",
				},
				Status: corev1alpha2.ProxyStatus{},
			},
		},
	}

	tests := []struct {
		name       string
		showLabels bool
		wantOutput []string
	}{
		{
			name:       "list without labels",
			showLabels: false,
			wantOutput: []string{
				"NAME",
				"PROVIDER",
				"STATUS",
				"proxy-1",
				"cloud",
				"Ready (2)",
				"proxy-2",
				"unmanaged",
				"NotReady",
			},
		},
		{
			name:       "list with labels",
			showLabels: true,
			wantOutput: []string{
				"NAME",
				"PROVIDER",
				"STATUS",
				"LABELS",
				"proxy-1",
				"cloud",
				"Ready (2)",
				"proxy-2",
				"unmanaged",
				"NotReady",
				"env=staging",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table, err := proxyList.ConvertToTable(ctx, &metav1.TableOptions{})
			if err != nil {
				t.Fatalf("ConvertToTable failed: %v", err)
			}

			if tt.showLabels {
				addLabelsColumnToTable(table)
			}

			var buf bytes.Buffer
			printer := printers.NewTablePrinter(printers.PrintOptions{})
			if err := printer.PrintObj(table, &buf); err != nil {
				t.Fatalf("PrintObj failed: %v", err)
			}

			output := buf.String()
			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("Output missing expected content %q\nGot:\n%s", want, output)
				}
			}
		})
	}
}

func TestLabelsToString(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{
			name:   "empty labels",
			labels: map[string]string{},
			want:   "",
		},
		{
			name: "single label",
			labels: map[string]string{
				"key": "value",
			},
			want: "key=value",
		},
		{
			name: "multiple labels",
			labels: map[string]string{
				"env":  "prod",
				"team": "platform",
			},
			// The output can be in any order due to map iteration
			// We'll check both possible outputs
			want: "env=prod,team=platform", // or "team=platform,env=prod"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := labelsToString(tt.labels)

			if tt.name == "multiple labels" {
				// For multiple labels, check that both expected key-value pairs are present
				if !strings.Contains(got, "env=prod") || !strings.Contains(got, "team=platform") {
					t.Errorf("labelsToString() = %v, want to contain both env=prod and team=platform", got)
				}
				if strings.Count(got, ",") != 1 {
					t.Errorf("labelsToString() = %v, expected exactly one comma", got)
				}
			} else {
				if got != tt.want {
					t.Errorf("labelsToString() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
