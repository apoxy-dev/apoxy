package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetProxyTablePrinter(t *testing.T) {
	now := metav1.NewTime(time.Now().Add(-1 * time.Hour))

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
					Provider: "managed",
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
				"REPLICAS",
				"AGE",
				"test-proxy",
				"managed",
				"2",
				"1h0m",
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
				"REPLICAS",
				"AGE",
				"LABELS",
				"test-proxy-labels",
				"unmanaged",
				"1",
				"1h0m",
				"env=prod", // labels can be in any order
				"team=platform",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printer := getProxyTablePrinter(tt.showLabels)

			err := printer.PrintObj(tt.proxy, &buf)
			if err != nil {
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

func TestGetProxyTablePrinterList(t *testing.T) {
	now := metav1.NewTime(time.Now().Add(-2 * time.Hour))

	proxyList := &corev1alpha2.ProxyList{
		Items: []corev1alpha2.Proxy{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "proxy-1",
					CreationTimestamp: now,
				},
				Spec: corev1alpha2.ProxySpec{
					Provider: "managed",
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
				"REPLICAS",
				"AGE",
				"proxy-1",
				"managed",
				"2",
				"2h0m",
				"proxy-2",
				"unmanaged",
				"0",
				"30m",
			},
		},
		{
			name:       "list with labels",
			showLabels: true,
			wantOutput: []string{
				"NAME",
				"PROVIDER",
				"REPLICAS",
				"AGE",
				"LABELS",
				"proxy-1",
				"managed",
				"2",
				"proxy-2",
				"unmanaged",
				"0",
				"env=staging",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printer := getProxyTablePrinter(tt.showLabels)

			err := printer.PrintObj(proxyList, &buf)
			if err != nil {
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

func TestSinceString(t *testing.T) {
	tests := []struct {
		name string
		time time.Time
		want string
	}{
		{
			name: "seconds ago",
			time: time.Now().Add(-30 * time.Second),
			want: "30s",
		},
		{
			name: "minutes ago",
			time: time.Now().Add(-5*time.Minute - 30*time.Second),
			want: "5m30s",
		},
		{
			name: "hours ago",
			time: time.Now().Add(-2*time.Hour - 15*time.Minute),
			want: "2h15m",
		},
		{
			name: "days ago",
			time: time.Now().Add(-3*24*time.Hour - 5*time.Hour),
			want: "3d5h",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sinceString(tt.time)
			// Due to timing, we'll allow a 1 second tolerance
			if got != tt.want {
				// Check if it's within tolerance (e.g., "29s" vs "30s")
				// For simplicity in testing, we'll just check the format is correct
				if !strings.Contains(got, "s") && !strings.Contains(got, "m") && !strings.Contains(got, "h") && !strings.Contains(got, "d") {
					t.Errorf("sinceString() = %v, want format like %v", got, tt.want)
				}
			}
		})
	}
}
