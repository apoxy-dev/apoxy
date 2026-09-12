package helmrules

import (
	"strings"
	"testing"
)

func TestRulesFromPrometheusRule(t *testing.T) {
	cases := []struct {
		name     string
		manifest string
		want     string
		wantErr  string
	}{
		{
			name: "rule with groups",
			manifest: `---
# Source: apoxy-gateway/templates/backplane_prometheusrule.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: gw
spec:
  groups:
  - name: g
    rules:
    - alert: A
      expr: up == 0
`,
			want: "groups:\n- name: g\n  rules:\n  - alert: A\n    expr: up == 0\n",
		},
		{
			name:     "other kind",
			manifest: "kind: ConfigMap\nspec:\n  groups: []\n",
			wantErr:  "not a PrometheusRule",
		},
		{
			name:     "no spec",
			manifest: "kind: PrometheusRule\nmetadata:\n  name: gw\n",
			wantErr:  "no spec",
		},
		{
			name:     "not yaml",
			manifest: "kind: [",
			wantErr:  "parse the rendered manifest",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RulesFromPrometheusRule(tc.manifest)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("rules = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCheckDashboard(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantErr string
	}{
		{name: "panels", content: `{"panels":[{"type":"row"}]}`},
		{name: "no panels", content: `{"title":"x"}`, wantErr: "no panels"},
		{name: "not json", content: `{`, wantErr: "parse the dashboard"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckDashboard(tc.content)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
